#include "HawkeyeTfe.h"
#include "HawkCreateCore.h"
#include "HawkScb.h"
#include "HawkShc.h"
#include "HawkProtectPath.h"
#include "HawkOperations.h"


/* Hawkeye TFE */
#define HawkCreatePlaintextFo(_Ctx) ((_Ctx)->CallbackData->Iopb->TargetFileObject)

static ACCESS_MASK
HawkCreateResolveRequestedAccess(
    __in ACCESS_MASK RequestedAccess
    )
{
    ACCESS_MASK accessMask;

    accessMask = RequestedAccess;
    if (FlagOn(accessMask, MAXIMUM_ALLOWED))
    {
        accessMask |= FILE_ALL_ACCESS;
        ClearFlag(accessMask, MAXIMUM_ALLOWED);
    }

    return accessMask;
}

static VOID
HawkCreateFinalizeAccessState(
    __in PFLT_CALLBACK_DATA CallbackData
    )
{
    PACCESS_STATE accessState;
    PIO_SECURITY_CONTEXT ioSecurityContext;
    ACCESS_MASK grantedAccess;

    ioSecurityContext = CallbackData->Iopb->Parameters.Create.SecurityContext;
    if (!ioSecurityContext || !ioSecurityContext->AccessState)
        return;

    accessState = ioSecurityContext->AccessState;
    grantedAccess = HawkCreateResolveRequestedAccess(ioSecurityContext->DesiredAccess);
    accessState->PreviouslyGrantedAccess |= grantedAccess;
    accessState->RemainingDesiredAccess = 0;
}

static VOID
HawkShcCloseShadowOpen(
    __inout PHAWK_STREAM_HANDLE_CONTEXT Shc
    )
{
    if (Shc->AliasHandle != NULL)
    {
        FltClose(Shc->AliasHandle);
        Shc->AliasHandle = NULL;
    }

    if (Shc->ShadowFileObject != NULL)
    {
        ObDereferenceObject(Shc->ShadowFileObject);
        Shc->ShadowFileObject = NULL;
    }
}

static VOID
HawkCreateTeardownShadowOpen(
    __inout PHAWK_CREATE_CONTEXT Ctx
    )
{
    if (!Ctx->StreamCtx)
        return;

    HawkShcCloseShadowOpen(Ctx->StreamCtx);
}

static ULONG_PTR
HawkCreateOpenInformation(
    __in PHAWK_CREATE_CONTEXT Ctx
    )
{
    if (Ctx->AliasOpenInfo != 0)
        return Ctx->AliasOpenInfo;

    return FILE_OPENED;
}

static VOID
HawkCreateFinishPreComplete(
    __inout PHAWK_CREATE_CONTEXT Ctx
    )
{
    PFLT_CALLBACK_DATA callbackData;
    PFILE_OBJECT plaintextFo;

    callbackData = Ctx->CallbackData;
    plaintextFo = HawkCreatePlaintextFo(Ctx);

    callbackData->IoStatus.Status = STATUS_SUCCESS;
    callbackData->IoStatus.Information = HawkCreateOpenInformation(Ctx);
    HawkCreateFinalizeAccessState(callbackData);

    plaintextFo->FileName.Length = 0;
    FltSetCallbackDataDirty(callbackData);
}

static VOID
HawkCreateFinishPreCompleteFailure(
    __inout PHAWK_CREATE_CONTEXT Ctx,
    __in NTSTATUS Status,
    __out FLT_PREOP_CALLBACK_STATUS *RetValue
    )
{
    PFLT_CALLBACK_DATA callbackData;

    callbackData = Ctx->CallbackData;
    callbackData->IoStatus.Status = Status;
    callbackData->IoStatus.Information = 0;
    FltSetCallbackDataDirty(callbackData);
    *RetValue = FLT_PREOP_COMPLETE;
}

static ULONG
HawkCreateShadowOpenAttributes(
    __in PFLT_CALLBACK_DATA CallbackData
    )
{
    ULONG attributes;

    attributes = OBJ_KERNEL_HANDLE;
    if (!FlagOn(CallbackData->Iopb->OperationFlags, SL_CASE_SENSITIVE))
        attributes |= OBJ_CASE_INSENSITIVE;

    return attributes;
}

static VOID
HawkCreateInitShadowOpenAttributes(
    __inout PHAWK_CREATE_CONTEXT Ctx
    )
{
    InitializeObjectAttributes(
        &Ctx->ObjectAttributes,
        &Ctx->PathKey,
        HawkCreateShadowOpenAttributes(Ctx->CallbackData),
        NULL,
        NULL);
}

static VOID
HawkCreateCtxInit(
    __out PHAWK_CREATE_CONTEXT Ctx,
    __in PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects
    )
{
    RtlZeroMemory(Ctx, sizeof(HAWK_CREATE_CONTEXT));
    Ctx->CallbackData = Data;
    Ctx->RelatedObjects = FltObjects;
    Ctx->CreateOptions = Data->Iopb->Parameters.Create.Options & 0x00ffffff;
    Ctx->CreateDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0x000000ff;
    Ctx->DesiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    Ctx->AliasOpenInfo = FILE_OPENED;
}

static VOID
HawkCreateCtxCleanup(
    __in PHAWK_CREATE_CONTEXT Ctx
    )
{
    if (Ctx->CriticalRegionActive)
    {
        KeLeaveCriticalRegion();
        Ctx->CriticalRegionActive = FALSE;
    }
    if (Ctx->StreamCtx && !Ctx->StreamCtxAttached)
    {
        HawkCleanStreamHandleContext(Ctx->StreamCtx, FLT_STREAMHANDLE_CONTEXT);
        ExFreePoolWithTag(Ctx->StreamCtx, HAWK_POOL_TAG);
        Ctx->StreamCtx = NULL;
    }
}

static PHAWK_SCB
HawkScbFromFileObject(
    __in_opt PFILE_OBJECT FileObject
    )
{
    PHAWK_SCB scb;

    if (FileObject == NULL || FileObject->Type != IO_TYPE_FILE)
        return NULL;

    scb = (PHAWK_SCB)FileObject->FsContext;
    if (scb == NULL || scb->Header.NodeTypeCode != HAWK_SCB_TYPE_CODE)
        return NULL;

    return scb;
}

static VOID
HawkCreateRestoreRelatedRedirect(
    __inout PHAWK_CREATE_CONTEXT Ctx
    )
{
    PFILE_OBJECT plaintextFo;

    if (!Ctx->RelatedOpenRedirected)
        return;

    plaintextFo = HawkCreatePlaintextFo(Ctx);
    if (plaintextFo == NULL)
        return;

    plaintextFo->RelatedFileObject = Ctx->SavedRelatedFileObject;
    Ctx->RelatedOpenRedirected = FALSE;
    FltSetCallbackDataDirty(Ctx->CallbackData);
}

static VOID
HawkCreateRollbackPlaintextBind(
    __inout PHAWK_CREATE_CONTEXT Ctx
    )
{
    PFILE_OBJECT plaintextFo;
    PHAWK_SCB scb;
    PHAWK_STREAM_HANDLE_CONTEXT shc;

    if (!Ctx->StreamCtxAttached)
        return;

    plaintextFo = HawkCreatePlaintextFo(Ctx);
    shc = Ctx->StreamCtx;
    scb = HawkScbFromFileObject(plaintextFo);

    plaintextFo->FsContext = NULL;
    plaintextFo->FsContext2 = NULL;

    if (scb != NULL && shc != NULL)
    {
        HawkDecrementScbHandles(scb);
        HawkDereferenceScb(scb, shc);
    }

    Ctx->StreamCtxAttached = FALSE;
}

static VOID
HawkCreateRedirectRelatedToShadow(
    __inout PHAWK_CREATE_CONTEXT Ctx
    )
{
    PFILE_OBJECT plaintextFo;
    PFILE_OBJECT relatedFo;
    PHAWK_STREAM_HANDLE_CONTEXT relatedShc;

    plaintextFo = HawkCreatePlaintextFo(Ctx);
    Ctx->SavedRelatedFileObject =
        plaintextFo != NULL ? plaintextFo->RelatedFileObject : NULL;
    Ctx->RelatedOpenRedirected = FALSE;

    if (plaintextFo == NULL)
        return;

    relatedFo = plaintextFo->RelatedFileObject;
    if (HawkScbFromFileObject(relatedFo) == NULL)
        return;

    relatedShc = (PHAWK_STREAM_HANDLE_CONTEXT)relatedFo->FsContext2;
    if (relatedShc == NULL || relatedShc->ShadowFileObject == NULL)
        return;

    plaintextFo->RelatedFileObject = relatedShc->ShadowFileObject;
    Ctx->RelatedOpenRedirected = TRUE;
    FltSetCallbackDataDirty(Ctx->CallbackData);
}

static BOOLEAN
HawkCreateTryFinishAttachedOpen(
    __inout PHAWK_CREATE_CONTEXT Ctx,
    __out FLT_PREOP_CALLBACK_STATUS *RetValue
    )
{
    PFILE_OBJECT plaintextFo;

    *RetValue = FLT_PREOP_SUCCESS_NO_CALLBACK;
    plaintextFo = HawkCreatePlaintextFo(Ctx);
    if (HawkScbFromFileObject(plaintextFo) == NULL)
        return FALSE;

    HawkCreateFinishPreComplete(Ctx);
    *RetValue = FLT_PREOP_COMPLETE;
    return TRUE;
}

static BOOLEAN
HawkCreateTryBeginProtectedPath(
    __inout PHAWK_CREATE_CONTEXT Ctx
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (FlagOn(Ctx->CreateOptions, FILE_DIRECTORY_FILE))
        return FALSE;

    Ctx->PathKey.Length = 0;
    status = HawkGetFilePathInCreate(Ctx->CallbackData, Ctx->RelatedObjects, &Ctx->PathKey);
    if (!NT_SUCCESS(status))
        return FALSE;

    if (Ctx->PathKey.Length <= 6)
        return FALSE;

    RtlDowncaseUnicodeString(&Ctx->PathKey, &Ctx->PathKey, FALSE);
    if (!HawkIsProtectedTxtFile(&Ctx->PathKey))
        return FALSE;

    Ctx->IsProtectedOpen = TRUE;

    KeEnterCriticalRegion();
    Ctx->CriticalRegionActive = TRUE;
    Ctx->StreamCtx = ExAllocatePoolWithTag(
        NonPagedPool, sizeof(HAWK_STREAM_HANDLE_CONTEXT), HAWK_POOL_TAG);
    if (!Ctx->StreamCtx)
        return FALSE;

    HawkShcInitialize(Ctx->StreamCtx, &Ctx->PathKey);
    return TRUE;
}

static BOOLEAN
HawkCreateProbeOpenIndicatesExistingFile(
    __in ULONG_PTR OpenInformation
    )
{
    return (OpenInformation == FILE_OPENED ||
            OpenInformation == FILE_EXISTS);
}

static VOID
HawkCreateProbeRecordTargetState(
    __inout PHAWK_CREATE_CONTEXT Ctx,
    __in PFILE_OBJECT ProbeFileObject
    )
{
    FltIsDirectory(ProbeFileObject, Ctx->RelatedObjects->Instance, &Ctx->TargetIsDirectory);
    if (Ctx->TargetIsDirectory)
        return;

    Ctx->IsEncrypted = HawkIsEncryptedFile(Ctx->RelatedObjects, ProbeFileObject);
}

static VOID
HawkCreateProbeTarget(
    __inout PHAWK_CREATE_CONTEXT Ctx
    )
{
    NTSTATUS status;
    HANDLE probeHandle;
    PFILE_OBJECT probeFileObject;
    IO_STATUS_BLOCK iosb;

    if (Ctx->PathKey.Length == 0)
        return;

    HawkCreateInitShadowOpenAttributes(Ctx);

    probeHandle = NULL;
    probeFileObject = NULL;
    iosb.Status = STATUS_SUCCESS;
    iosb.Information = 0;
    status = FltCreateFile(
        g_HawkFilter.Filter,
        Ctx->RelatedObjects->Instance,
        &probeHandle,
        FILE_READ_DATA,
        &Ctx->ObjectAttributes,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
        NULL,
        0,
        IO_IGNORE_SHARE_ACCESS_CHECK);
    if (!NT_SUCCESS(status) || probeHandle == NULL)
        return;

    if (HawkCreateProbeOpenIndicatesExistingFile(iosb.Information))
        Ctx->TargetExists = TRUE;

    status = ObReferenceObjectByHandle(
        probeHandle,
        FILE_READ_DATA,
        *IoFileObjectType,
        KernelMode,
        &probeFileObject,
        NULL);
    if (NT_SUCCESS(status) && probeFileObject != NULL)
    {
        HawkCreateProbeRecordTargetState(Ctx, probeFileObject);
        ObDereferenceObject(probeFileObject);
    }

    FltClose(probeHandle);
}

static BOOLEAN
HawkCreateShadowOpenCreatedOrTruncated(
    __in ULONG_PTR OpenInformation
    )
{
    return (OpenInformation == FILE_CREATED ||
            OpenInformation == FILE_OVERWRITTEN ||
            OpenInformation == FILE_SUPERSEDED);
}

static BOOLEAN
HawkCreateOpenShadowFile(
    __inout PHAWK_CREATE_CONTEXT Ctx,
    __in ULONG ExtraCreateOptions,
    __out_opt PBOOLEAN CreatedOrTruncated
    )
{
    NTSTATUS status;
    PHAWK_STREAM_HANDLE_CONTEXT shc;
    IO_STATUS_BLOCK iosb;
    ULONG createOptions;
    ULONG_PTR openInformation;

    shc = Ctx->StreamCtx;
    if (shc == NULL)
        return FALSE;

    if (CreatedOrTruncated != NULL)
        *CreatedOrTruncated = FALSE;

    createOptions = (Ctx->CreateOptions | ExtraCreateOptions)
                    & ~(FILE_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE);

    iosb.Status = STATUS_SUCCESS;
    iosb.Information = 0;
    status = FltCreateFile(
        g_HawkFilter.Filter,
        Ctx->RelatedObjects->Instance,
        &shc->AliasHandle,
        Ctx->DesiredAccess,
        &Ctx->ObjectAttributes,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        Ctx->CreateDisposition,
        createOptions,
        NULL,
        0,
        IO_IGNORE_SHARE_ACCESS_CHECK);
    if (!NT_SUCCESS(status) || shc->AliasHandle == NULL)
        return FALSE;

    Ctx->TargetExists = TRUE;
    openInformation = iosb.Information;
    Ctx->AliasOpenInfo = openInformation ? openInformation : FILE_OPENED;
    if (CreatedOrTruncated != NULL &&
        HawkCreateShadowOpenCreatedOrTruncated(openInformation))
    {
        *CreatedOrTruncated = TRUE;
    }

    status = ObReferenceObjectByHandle(
        shc->AliasHandle,
        Ctx->DesiredAccess,
        *IoFileObjectType,
        KernelMode,
        &shc->ShadowFileObject,
        NULL);

    return NT_SUCCESS(status) && shc->ShadowFileObject != NULL;
}

static ULONG
HawkCreateShadowOpenExtraOptions(
    __in PHAWK_CREATE_CONTEXT Ctx
    )
{
    BOOLEAN wantsRead;
    BOOLEAN wantsWrite;

    wantsRead = FlagOn(Ctx->DesiredAccess, FILE_READ_DATA);
    wantsWrite = FlagOn(Ctx->DesiredAccess, FILE_WRITE_DATA);

    if (wantsWrite && wantsRead)
        return FILE_NON_DIRECTORY_FILE;

    if (wantsWrite)
        return Ctx->TargetExists ? 0 : FILE_NON_DIRECTORY_FILE;

    if (wantsRead)
        return FILE_NON_DIRECTORY_FILE;

    return 0;
}

static BOOLEAN
HawkCreateNeedsShadowMetadataOpen(
    __in PHAWK_CREATE_CONTEXT Ctx
    )
{
    if (FlagOn(Ctx->DesiredAccess, FILE_READ_DATA | FILE_WRITE_DATA))
        return FALSE;

    return Ctx->IsEncrypted;
}

static BOOLEAN
HawkCreateOpenShadow(
    __inout PHAWK_CREATE_CONTEXT Ctx,
    __out PBOOLEAN CreatedOrTruncated
    )
{
    ULONG extraCreateOptions;

    if (CreatedOrTruncated != NULL)
        *CreatedOrTruncated = FALSE;

    if (!FlagOn(Ctx->DesiredAccess, FILE_READ_DATA | FILE_WRITE_DATA))
    {
        if (!HawkCreateNeedsShadowMetadataOpen(Ctx))
            return FALSE;

        extraCreateOptions = 0;
    }
    else
    {
        extraCreateOptions = HawkCreateShadowOpenExtraOptions(Ctx);
    }

    return HawkCreateOpenShadowFile(Ctx, extraCreateOptions, CreatedOrTruncated);
}

static VOID
HawkCreateRefreshShadowEncryptionState(
    __inout PHAWK_CREATE_CONTEXT Ctx
    )
{
    PHAWK_STREAM_HANDLE_CONTEXT shc;

    if (Ctx->IsEncrypted)
        return;

    shc = Ctx->StreamCtx;
    if (shc == NULL || shc->ShadowFileObject == NULL)
        return;

    Ctx->IsEncrypted = HawkIsEncryptedFile(Ctx->RelatedObjects, shc->ShadowFileObject);
}

static BOOLEAN
HawkCreateShadowContextReady(
    __in PHAWK_CREATE_CONTEXT Ctx
    )
{
    PHAWK_STREAM_HANDLE_CONTEXT shc;

    shc = Ctx->StreamCtx;
    return (shc != NULL && shc->ShadowFileObject != NULL);
}

static BOOLEAN
HawkCreatePrepareShadowContent(
    __inout PHAWK_CREATE_CONTEXT Ctx,
    __in BOOLEAN CreatedOrTruncated
    )
{
    BOOLEAN wantsRead;
    BOOLEAN wantsWrite;
    PHAWK_STREAM_HANDLE_CONTEXT shc;

    if (!HawkCreateShadowContextReady(Ctx))
        return FALSE;

    HawkCreateRefreshShadowEncryptionState(Ctx);

    wantsRead = FlagOn(Ctx->DesiredAccess, FILE_READ_DATA);
    wantsWrite = FlagOn(Ctx->DesiredAccess, FILE_WRITE_DATA);
    shc = Ctx->StreamCtx;

    if (CreatedOrTruncated && wantsWrite)
        return HawkCreateFileHeader(Ctx->RelatedObjects, shc);

    if (Ctx->TargetExists && wantsWrite)
    {
        if (!wantsRead && !Ctx->IsEncrypted)
            return FALSE;

        if (!Ctx->IsEncrypted)
        {
            return HawkEncryptFileGradually(
                Ctx->RelatedObjects->Instance,
                Ctx->RelatedObjects->Filter,
                Ctx->RelatedObjects->Volume,
                shc->ShadowFileObject,
                shc);
        }
        return TRUE;
    }
    return Ctx->IsEncrypted;
}

static VOID
HawkCreateResetPlaintextViewAfterTruncate(
    __in PFILE_OBJECT PlaintextFo
    )
{
    PHAWK_SCB scb;

    if (PlaintextFo == NULL)
        return;

    scb = PlaintextFo->FsContext;
    if (scb == NULL || scb->Header.NodeTypeCode != HAWK_SCB_TYPE_CODE)
        return;

    ExAcquireResourceExclusiveLite(scb->Header.Resource, TRUE);
    if (scb->Header.PagingIoResource)
        ExAcquireResourceExclusiveLite(scb->Header.PagingIoResource, TRUE);

    CcPurgeCacheSection(&scb->SectionObjectPointers, NULL, 0, FALSE);
    scb->Header.AllocationSize.QuadPart = 0;
    scb->Header.FileSize.QuadPart = 0;
    scb->Header.ValidDataLength.QuadPart = 0;
    PlaintextFo->CurrentByteOffset.QuadPart = 0;

    if (PlaintextFo->SectionObjectPointer &&
         PlaintextFo->SectionObjectPointer->SharedCacheMap)
    {
        CcSetFileSizes(PlaintextFo, (PCC_FILE_SIZES)&scb->Header.AllocationSize);
    }

    if (scb->Header.PagingIoResource)
        ExReleaseResourceLite(scb->Header.PagingIoResource);
    ExReleaseResourceLite(scb->Header.Resource);
}

static BOOLEAN
HawkCreateIsOverwriteOpen(
    __in PHAWK_CREATE_CONTEXT Ctx
    )
{
    switch (Ctx->CreateDisposition)
    {
    case FILE_SUPERSEDE:
    case FILE_OVERWRITE:
    case FILE_OVERWRITE_IF:
        return TRUE;
    default:
        return FALSE;
    }
}

static VOID
HawkCreateTruncateShadowOnDisk(
    __inout PHAWK_CREATE_CONTEXT Ctx
    )
{
    PHAWK_STREAM_HANDLE_CONTEXT shc;
    PFILE_OBJECT shadowFo;
    PFSRTL_COMMON_FCB_HEADER shadowFcb;
    FILE_END_OF_FILE_INFORMATION eofInfo;

    shc = Ctx->StreamCtx;
    shadowFo = shc->ShadowFileObject;
    shadowFcb = (PFSRTL_COMMON_FCB_HEADER)shadowFo->FsContext;

    eofInfo.EndOfFile.QuadPart = HAWK_FS_HEADER_SIZE + HAWK_FS_KEY_SIZE;
    FltSetInformationFile(
        Ctx->RelatedObjects->Instance,
        shadowFo,
        &eofInfo,
        sizeof(eofInfo),
        FileEndOfFileInformation);
    shc->TruncatedOnOpen = TRUE;

    if (shadowFcb != NULL && shadowFcb->Resource != NULL &&
        shadowFo->SectionObjectPointer != NULL)
    {
        ExAcquireResourceExclusiveLite(shadowFcb->Resource, TRUE);
        CcPurgeCacheSection(shadowFo->SectionObjectPointer, NULL, 0, FALSE);
        ExReleaseResourceLite(shadowFcb->Resource);
    }
}

static BOOLEAN
HawkCreateTryFlushPlaintextSection(
    __inout PHAWK_CREATE_CONTEXT Ctx
    )
{
    PFILE_OBJECT plaintextFo;
    BOOLEAN needsFlush;

    needsFlush = FlagOn(Ctx->DesiredAccess, FILE_WRITE_DATA) ||
                 FlagOn(Ctx->CreateOptions, FILE_DELETE_ON_CLOSE);
    if (!needsFlush)
        return TRUE;

    plaintextFo = HawkCreatePlaintextFo(Ctx);
    if (MmFlushImageSection(plaintextFo->SectionObjectPointer, MmFlushForWrite))
        return TRUE;

    Ctx->CallbackData->IoStatus.Status =
        FlagOn(Ctx->CreateOptions, FILE_DELETE_ON_CLOSE) ?
            STATUS_CANNOT_DELETE : STATUS_SHARING_VIOLATION;
    return FALSE;
}

static VOID
HawkCreateBindPlaintextAndPreComplete(
    __inout PHAWK_CREATE_CONTEXT Ctx,
    __out FLT_PREOP_CALLBACK_STATUS *RetValue
    )
{
    PFILE_OBJECT plaintextFo;
    BOOLEAN overwriteOpen;

    overwriteOpen = HawkCreateIsOverwriteOpen(Ctx);
    plaintextFo = HawkCreatePlaintextFo(Ctx);

    if (overwriteOpen)
        HawkCreateTruncateShadowOnDisk(Ctx);

    if (!HawkBindPlaintextFileObject(Ctx->StreamCtx, plaintextFo))
    {
        HawkCreateTeardownShadowOpen(Ctx);
        HawkCreateFinishPreCompleteFailure(Ctx, STATUS_INSUFFICIENT_RESOURCES, RetValue);
        return;
    }

    if (overwriteOpen)
        HawkCreateResetPlaintextViewAfterTruncate(plaintextFo);

    Ctx->StreamCtxAttached = TRUE;

    if (!HawkCreateTryFlushPlaintextSection(Ctx))
    {
        NTSTATUS status;

        status = Ctx->CallbackData->IoStatus.Status;
        HawkCreateRollbackPlaintextBind(Ctx);
        HawkCreateTeardownShadowOpen(Ctx);
        HawkCreateFinishPreCompleteFailure(Ctx, status, RetValue);
        return;
    }

    HawkCreateFinishPreComplete(Ctx);
    *RetValue = FLT_PREOP_COMPLETE;
}

static VOID
HawkCreateTryFlushExistingScb(
    __inout PHAWK_CREATE_CONTEXT Ctx
    )
{
    PHAWK_SCB scb;
    BOOLEAN needsFlush;

    if (Ctx->StreamCtx == NULL || HawkCreateIsOverwriteOpen(Ctx))
        return;

    if (!HawkFindScb(&Ctx->StreamCtx->PathKey, &scb))
        return;

    needsFlush = FlagOn(Ctx->DesiredAccess, FILE_WRITE_DATA) ||
                 FlagOn(Ctx->CreateOptions, FILE_DELETE_ON_CLOSE);
    if (!needsFlush)
        return;

    if (MmFlushImageSection(&scb->SectionObjectPointers, MmFlushForWrite))
        return;

    Ctx->CallbackData->IoStatus.Status =
        FlagOn(Ctx->CreateOptions, FILE_DELETE_ON_CLOSE) ?
            STATUS_CANNOT_DELETE : STATUS_SHARING_VIOLATION;
}

static FLT_PREOP_CALLBACK_STATUS
HawkCreatePassthroughOpen(
    __inout PHAWK_CREATE_CONTEXT Ctx
    )
{
    HawkCreateTryFlushExistingScb(Ctx);
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static BOOLEAN
HawkCreateTryProtectedPreComplete(
    __inout PHAWK_CREATE_CONTEXT Ctx,
    __out FLT_PREOP_CALLBACK_STATUS *RetValue
    )
{
    BOOLEAN createdOrTruncated;
    BOOLEAN shadowReady;

    createdOrTruncated = FALSE;
    shadowReady = HawkCreateOpenShadow(Ctx, &createdOrTruncated);
    if (shadowReady)
        shadowReady = HawkCreatePrepareShadowContent(Ctx, createdOrTruncated);

    if (!shadowReady)
        return FALSE;

    HawkCreateBindPlaintextAndPreComplete(Ctx, RetValue);
    return TRUE;
}

/* Hawkeye TFE: create */
FLT_PREOP_CALLBACK_STATUS
HawkPreCreate(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    PHAWK_CREATE_CONTEXT ctx;
    WCHAR normalizedPathBuffer[HAWK_FILE_NAME_LEN] = {0};
    FLT_PREOP_CALLBACK_STATUS ret;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (FLT_IS_FASTIO_OPERATION(Data))
        return FLT_PREOP_DISALLOW_FASTIO;

    ctx = ExAllocatePoolWithTag(NonPagedPool, sizeof(HAWK_CREATE_CONTEXT), HAWK_POOL_TAG);
    if (ctx == NULL)
    {
        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Data->IoStatus.Information = 0;
        FltSetCallbackDataDirty(Data);
        return FLT_PREOP_COMPLETE;
    }

    ret = FLT_PREOP_SUCCESS_NO_CALLBACK;
    HawkCreateCtxInit(ctx, Data, FltObjects);
    ctx->PathKey.Buffer = normalizedPathBuffer;
    ctx->PathKey.MaximumLength = sizeof(normalizedPathBuffer);

    HawkCreateRedirectRelatedToShadow(ctx);

    if (HawkCreateTryFinishAttachedOpen(ctx, &ret))
        goto Exit;

    if (!HawkCreateTryBeginProtectedPath(ctx))
    {
        if (ctx->IsProtectedOpen)
            HawkCreateFinishPreCompleteFailure(ctx, STATUS_INSUFFICIENT_RESOURCES, &ret);
        goto Exit;
    }

    HawkCreateProbeTarget(ctx);

    if (ctx->TargetExists && ctx->TargetIsDirectory)
    {
        ret = HawkCreatePassthroughOpen(ctx);
        goto Exit;
    }

    if (HawkCreateTryProtectedPreComplete(ctx, &ret))
        goto Exit;

    HawkCreateTeardownShadowOpen(ctx);
    ret = HawkCreatePassthroughOpen(ctx);

Exit:
    if (ret != FLT_PREOP_COMPLETE)
        HawkCreateRestoreRelatedRedirect(ctx);

    HawkCreateCtxCleanup(ctx);
    ExFreePoolWithTag(ctx, HAWK_POOL_TAG);
    return ret;
}

static BOOLEAN
HawkPostCreateIsProtectedPath(
    __in PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __out PUNICODE_STRING NormalizedPath
    )
{
    NTSTATUS status;

    if (!NT_SUCCESS(Data->IoStatus.Status))
        return FALSE;

    NormalizedPath->Length = 0;
    status = HawkGetFilePathInCreate(Data, FltObjects, NormalizedPath);
    if (!NT_SUCCESS(status))
        return FALSE;

    RtlDowncaseUnicodeString(NormalizedPath, NormalizedPath, FALSE);
    return HawkIsProtectedTxtFile(NormalizedPath);
}

static BOOLEAN
HawkPostCreateIsTruncateOpen(
    __in PFLT_CALLBACK_DATA Data
    )
{
    ULONG disposition;

    disposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0x000000ff;
    switch (disposition)
    {
    case FILE_SUPERSEDE:
    case FILE_OVERWRITE:
    case FILE_OVERWRITE_IF:
        return TRUE;
    default:
        return FALSE;
    }
}

static BOOLEAN
HawkPostCreateBindShc(
    __in PFILE_OBJECT FileObject,
    __in PUNICODE_STRING NormalizedPath,
    __inout PHAWK_STREAM_HANDLE_CONTEXT Shc,
    __out PHAWK_SCB *BoundScb
    )
{
    PHAWK_SCB scb;

    *BoundScb = NULL;
    scb = HawkScbFromFileObject(FileObject);
    if (scb != NULL)
    {
        HawkShcBindToScb(Shc, scb);
        *BoundScb = scb;
        return TRUE;
    }

    if (HawkFindScb(NormalizedPath, &scb))
    {
        HawkShcBindToScb(Shc, scb);
        *BoundScb = scb;
        return TRUE;
    }

    Shc->PathStorage = ExAllocatePoolWithTag(
        NonPagedPool, HAWK_FILE_NAME_LEN * sizeof(WCHAR), HAWK_POOL_TAG);
    if (Shc->PathStorage == NULL)
        return FALSE;

    RtlCopyMemory(Shc->PathStorage, NormalizedPath->Buffer, NormalizedPath->Length);
    Shc->PathKey.Buffer = Shc->PathStorage;
    Shc->PathKey.Length = NormalizedPath->Length;
    Shc->PathKey.MaximumLength = HAWK_FILE_NAME_LEN * sizeof(WCHAR);
    return TRUE;
}

static VOID
HawkPostCreateFlushScbCache(
    __in PHAWK_SCB Scb
    )
{
    KeEnterCriticalRegion();
    ExAcquireSharedStarveExclusive(Scb->Header.PagingIoResource, TRUE);
    CcFlushCache(&Scb->SectionObjectPointers, NULL, 0, NULL);
    ExReleaseResourceLite(Scb->Header.PagingIoResource);
    KeLeaveCriticalRegion();
}

/* Hawkeye TFE: PostCreate */
FLT_POSTOP_CALLBACK_STATUS
HawkPostCreate(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
    WCHAR pathBuf[HAWK_FILE_NAME_LEN];
    UNICODE_STRING normalizedPath;
    PFILE_OBJECT fileObject;
    PHAWK_STREAM_HANDLE_CONTEXT shc;
    PHAWK_STREAM_HANDLE_CONTEXT oldShc;
    PHAWK_SCB scb;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    normalizedPath.Buffer = pathBuf;
    normalizedPath.Length = 0;
    normalizedPath.MaximumLength = sizeof(pathBuf);
    if (!HawkPostCreateIsProtectedPath(Data, FltObjects, &normalizedPath))
        return FLT_POSTOP_FINISHED_PROCESSING;

    fileObject = Data->Iopb->TargetFileObject;
    status = FltAllocateContext(
        FltObjects->Filter,
        FLT_STREAMHANDLE_CONTEXT,
        sizeof(HAWK_STREAM_HANDLE_CONTEXT),
        NonPagedPool,
        &shc);
    if (!NT_SUCCESS(status))
        return FLT_POSTOP_FINISHED_PROCESSING;

    RtlZeroMemory(shc, sizeof(HAWK_STREAM_HANDLE_CONTEXT));
    shc->IsProtectedOpen = TRUE;

    if (!HawkPostCreateBindShc(fileObject, &normalizedPath, shc, &scb))
    {
        FltReleaseContext(shc);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    status = FltSetStreamHandleContext(
        FltObjects->Instance,
        fileObject,
        FLT_SET_CONTEXT_KEEP_IF_EXISTS,
        shc,
        &oldShc);
    if (!NT_SUCCESS(status))
    {
        FltReleaseContext(shc);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (oldShc != NULL)
        FltReleaseContext(oldShc);
    FltReleaseContext(shc);

    if (scb != NULL && !HawkPostCreateIsTruncateOpen(Data))
        HawkPostCreateFlushScbCache(scb);

    return FLT_POSTOP_FINISHED_PROCESSING;
}
