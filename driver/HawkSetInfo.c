#include "HawkeyeTfe.h"
#include "HawkScb.h"
#include "HawkPlaintextCache.h"
#include "HawkOperations.h"
#include "HawkProtectPath.h"


/* Hawkeye TFE */
static VOID
HawkRenamePathsInitUnicodeStrings(
    __inout PHAWK_RENAME_PATHS Paths
    )
{
    USHORT maxChars = HAWK_FILE_NAME_LEN * sizeof(WCHAR);

    Paths->TargetPath.Buffer = Paths->TargetPathBuffer;
    Paths->TargetPath.Length = 0;
    Paths->TargetPath.MaximumLength = maxChars;

    Paths->TargetPathKey.Buffer = Paths->TargetPathKeyStorage;
    Paths->TargetPathKey.Length = 0;
    Paths->TargetPathKey.MaximumLength = maxChars;
}

static PHAWK_RENAME_PATHS
HawkAllocateRenamePaths(
    VOID
    )
{
    PHAWK_RENAME_PATHS paths;

    paths = ExAllocatePoolWithTag(NonPagedPool, sizeof(HAWK_RENAME_PATHS), HAWK_POOL_TAG);
    if (paths == NULL)
        return NULL;

    RtlZeroMemory(paths, sizeof(HAWK_RENAME_PATHS));
    HawkRenamePathsInitUnicodeStrings(paths);
    return paths;
}

static VOID
HawkFreeRenamePaths(
    __in_opt PHAWK_RENAME_PATHS Paths
    )
{
    if (Paths != NULL)
        ExFreePoolWithTag(Paths, HAWK_POOL_TAG);
}

static FLT_PREOP_CALLBACK_STATUS
HawkPreSetInformationDispatchPlaintext(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    PHAWK_IRP_CONTEXT irpContext;
    FLT_PREOP_CALLBACK_STATUS retValue;

    KeEnterCriticalRegion();
    irpContext = HawkCreateIrpContext(
        Data, FltObjects, CompletionContext, FltIsOperationSynchronous(Data));
    if (irpContext == NULL)
    {
        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        KeLeaveCriticalRegion();
        return FLT_PREOP_COMPLETE;
    }

    retValue = HawkCommonSetInformation(irpContext, CompletionContext);
    if (retValue == FLT_PREOP_SUCCESS_WITH_CALLBACK && *CompletionContext == NULL)
        retValue = FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (retValue != FLT_PREOP_PENDING)
        HawkDeleteIrpContext(irpContext);

    KeLeaveCriticalRegion();
    return retValue;
}

static FLT_PREOP_CALLBACK_STATUS
HawkPreSetInformationHandleProtectedDisposition(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PHAWK_STREAM_HANDLE_CONTEXT Shc,
    __in PFILE_OBJECT FileObject,
    __in PFLT_IO_PARAMETER_BLOCK Iopb
    )
{
    PFILE_DISPOSITION_INFORMATION dispositionInfo = Iopb->Parameters.SetFileInformation.InfoBuffer;
    PHAWK_SCB scb = NULL;
    NTSTATUS status;

    status = FltSetInformationFile(
        FltObjects->Instance,
        FileObject,
        dispositionInfo,
        Iopb->Parameters.SetFileInformation.Length,
        FileDispositionInformation);
    if (NT_SUCCESS(status) && dispositionInfo->DeleteFile)
    {
        if (HawkFindScb(&Shc->PathKey, &scb))
            HawkRenameScb(&Shc->PathKey, NULL);
    }

    Data->IoStatus.Status = status;
    return FLT_PREOP_COMPLETE;
}

static FLT_PREOP_CALLBACK_STATUS
HawkPreSetInformationHandleProtectedRename(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PHAWK_STREAM_HANDLE_CONTEXT Shc,
    __in PFILE_OBJECT FileObject,
    __in PFLT_IO_PARAMETER_BLOCK Iopb
    )
{
    PFILE_RENAME_INFORMATION renameInfo = Iopb->Parameters.SetFileInformation.InfoBuffer;
    PHAWK_RENAME_PATHS renamePaths;
    PHAWK_SCB scb = NULL;
    NTSTATUS status;

    renamePaths = HawkAllocateRenamePaths();
    if (renamePaths == NULL ||
         !HawkResolveRenameTarget(renameInfo, &Shc->PathKey, &renamePaths->TargetPath))
    {
        HawkFreeRenamePaths(renamePaths);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        return FLT_PREOP_COMPLETE;
    }

    RtlDowncaseUnicodeString(
        &renamePaths->TargetPathKey, &renamePaths->TargetPath, FALSE);
    if (!HawkIsProtectedTxtFile(&renamePaths->TargetPathKey))
    {
        HawkFreeRenamePaths(renamePaths);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        return FLT_PREOP_COMPLETE;
    }

    status = FltSetInformationFile(
        FltObjects->Instance,
        FileObject,
        renameInfo,
        Iopb->Parameters.SetFileInformation.Length,
        FileRenameInformation);
    if (NT_SUCCESS(status))
    {
        if (HawkFindScb(&Shc->PathKey, &scb))
        {
            MmFlushImageSection(&scb->SectionObjectPointers, MmFlushForDelete);
            HawkRenameScb(&Shc->PathKey, &renamePaths->TargetPathKey);
        }
    }

    HawkFreeRenamePaths(renamePaths);
    Data->IoStatus.Status = status;
    return FLT_PREOP_COMPLETE;
}

static FLT_PREOP_CALLBACK_STATUS
HawkPreSetInformationHandleProtectedEndOfFile(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PHAWK_STREAM_HANDLE_CONTEXT Shc,
    __in PFILE_OBJECT FileObject,
    __in PFLT_IO_PARAMETER_BLOCK Iopb
    )
{
    PFILE_END_OF_FILE_INFORMATION eofInfo;
    PFSRTL_COMMON_FCB_HEADER fcbHeader;
    PHAWK_SCB scb = NULL;
    NTSTATUS status;

    if (Iopb->Parameters.SetFileInformation.AdvanceOnly)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (!HawkFindScb(&Shc->PathKey, &scb))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    eofInfo = Iopb->Parameters.SetFileInformation.InfoBuffer;
    status = FltSetInformationFile(
        FltObjects->Instance,
        FileObject,
        eofInfo,
        Iopb->Parameters.SetFileInformation.Length,
        FileEndOfFileInformation);
    if (NT_SUCCESS(Data->IoStatus.Status))
    {
        fcbHeader = FileObject->FsContext;
        scb->Header.FileSize.QuadPart =
            fcbHeader->FileSize.QuadPart - HAWK_FS_HEADER_SIZE - HAWK_FS_KEY_SIZE;
        scb->Header.ValidDataLength.QuadPart =
            fcbHeader->ValidDataLength.QuadPart - HAWK_FS_HEADER_SIZE - HAWK_FS_KEY_SIZE;
    }

    Data->IoStatus.Status = status;
    return FLT_PREOP_COMPLETE;
}

static FLT_PREOP_CALLBACK_STATUS
HawkPreSetInformationDispatchProtectedOpen(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PHAWK_STREAM_HANDLE_CONTEXT Shc,
    __in PFILE_OBJECT FileObject,
    __in PFLT_IO_PARAMETER_BLOCK Iopb
    )
{
    switch (Iopb->Parameters.SetFileInformation.FileInformationClass)
    {
    case FileDispositionInformation:
        return HawkPreSetInformationHandleProtectedDisposition(
            Data, FltObjects, Shc, FileObject, Iopb);

    case FileRenameInformation:
        return HawkPreSetInformationHandleProtectedRename(
            Data, FltObjects, Shc, FileObject, Iopb);

    case FileEndOfFileInformation:
        return HawkPreSetInformationHandleProtectedEndOfFile(
            Data, FltObjects, Shc, FileObject, Iopb);

    case FileValidDataLengthInformation:
        break;

    default:
        break;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static VOID
HawkPreSetInformationRedirectRenameParentOfTarget(
    __inout PFLT_CALLBACK_DATA Data
    )
{
    PFILE_OBJECT relatedFileObject = Data->Iopb->Parameters.SetFileInformation.ParentOfTarget;
    PHAWK_SCB scb;
    PHAWK_STREAM_HANDLE_CONTEXT shc;

    if (relatedFileObject == NULL)
        return;

    scb = HawkResolvePlaintextScbFromFileObject(relatedFileObject);
    if (scb == NULL)
        return;

    shc = (PHAWK_STREAM_HANDLE_CONTEXT)relatedFileObject->FsContext2;
    Data->Iopb->Parameters.SetFileInformation.ParentOfTarget = shc->ShadowFileObject;
    FltSetCallbackDataDirty(Data);
}

/* Hawkeye TFE: SetInfo */
FLT_PREOP_CALLBACK_STATUS
HawkPreSetInformation(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    PHAWK_STREAM_HANDLE_CONTEXT shc = NULL;
    FLT_PREOP_CALLBACK_STATUS retValue;

    *CompletionContext = NULL;

    if (FLT_IS_FASTIO_OPERATION(Data))
        return FLT_PREOP_DISALLOW_FASTIO;

    if (HawkResolvePlaintextScbFromFileObject(fileObject) != NULL)
        return HawkPreSetInformationDispatchPlaintext(Data, FltObjects, CompletionContext);

    FltGetStreamHandleContext(FltObjects->Instance, fileObject, &shc);
    if (shc != NULL)
    {
        if (shc->IsProtectedOpen)
        {
            retValue = HawkPreSetInformationDispatchProtectedOpen(
                Data, FltObjects, shc, fileObject, Data->Iopb);
            FltReleaseContext(shc);
            return retValue;
        }
        FltReleaseContext(shc);
    }

    HawkPreSetInformationRedirectRenameParentOfTarget(Data);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static PVOID
HawkCommonSetInformationAllocInfoCopy(
    __in PVOID InfoBuffer,
    __in ULONG Length
    )
{
    PVOID newBuf;

    newBuf = ExAllocatePoolWithTag(NonPagedPool, Length, HAWK_POOL_TAG);
    if (newBuf == NULL)
        return NULL;

    RtlCopyMemory(newBuf, InfoBuffer, Length);
    return newBuf;
}

static BOOLEAN
HawkCommonSetInformationTryInitPlaintextCache(
    __in PFILE_OBJECT FileObject,
    __in PHAWK_SCB Scb,
    __in PFLT_IO_PARAMETER_BLOCK Iopb
    )
{
    if (FileObject->SectionObjectPointer->DataSectionObject == NULL)
        return FALSE;
    if (FileObject->SectionObjectPointer->SharedCacheMap != NULL)
        return FALSE;
    if (FlagOn(Iopb->IrpFlags, IRP_PAGING_IO))
        return FALSE;

    CcInitializeCacheMap(
        FileObject,
        (PCC_FILE_SIZES)&Scb->Header.AllocationSize,
        FALSE,
        &g_HawkCcCallbacks,
        Scb);
    return TRUE;
}

static VOID
HawkCommonSetInformationRedirectToShadow(
    __inout PFLT_CALLBACK_DATA Data,
    __in PFLT_IO_PARAMETER_BLOCK Iopb,
    __in PHAWK_STREAM_HANDLE_CONTEXT Shc
    )
{
    Iopb->TargetFileObject = Shc->ShadowFileObject;
    FltSetCallbackDataDirty(Data);
}

static FLT_PREOP_CALLBACK_STATUS
HawkCommonSetInformationHandoffAdvanceOnly(
    __inout PFLT_CALLBACK_DATA Data,
    __in PFLT_IO_PARAMETER_BLOCK Iopb,
    __in PHAWK_STREAM_HANDLE_CONTEXT Shc,
    __in PVOID ProxyBuffer,
    __inout PVOID *CompletionContext
    )
{
    PHAWK_PRE2POST_CONTEXT p2pCtx;

    Iopb->Parameters.SetFileInformation.InfoBuffer = ProxyBuffer;
    HawkCommonSetInformationRedirectToShadow(Data, Iopb, Shc);

    p2pCtx = ExAllocateFromNPagedLookasideList(&g_HawkP2PLookaside);
    if (p2pCtx == NULL)
    {
        ExFreePoolWithTag(ProxyBuffer, HAWK_POOL_TAG);
        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        return FLT_PREOP_COMPLETE;
    }

    RtlZeroMemory(p2pCtx, sizeof(HAWK_PRE2POST_CONTEXT));
    p2pCtx->HandoffPtr = ProxyBuffer;
    *CompletionContext = p2pCtx;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS
HawkCommonSetInformationDispatchDisposition(
    __inout PFLT_CALLBACK_DATA Data,
    __in PFLT_IO_PARAMETER_BLOCK Iopb,
    __in PFLT_INSTANCE Instance,
    __in PHAWK_STREAM_HANDLE_CONTEXT Shc
    )
{
    PFILE_DISPOSITION_INFORMATION dispositionInfo;
    PVOID proxyBuffer;
    ULONG infoLength = Iopb->Parameters.SetFileInformation.Length;
    NTSTATUS status;

    proxyBuffer = ExAllocatePoolWithTag(NonPagedPool, infoLength, HAWK_POOL_TAG);
    RtlCopyMemory(
        proxyBuffer,
        Iopb->Parameters.SetFileInformation.InfoBuffer,
        infoLength);
    dispositionInfo = (PFILE_DISPOSITION_INFORMATION)proxyBuffer;
    status = FltSetInformationFile(
        Instance,
        Shc->ShadowFileObject,
        dispositionInfo,
        infoLength,
        FileDispositionInformation);
    if (NT_SUCCESS(status))
    {
        if (dispositionInfo->DeleteFile)
        {
            if (!MmFlushImageSection(
                    Iopb->TargetFileObject->SectionObjectPointer, MmFlushForDelete))
            {
                Data->IoStatus.Status = STATUS_CANNOT_DELETE;
            }
            Iopb->TargetFileObject->DeletePending = TRUE;
        }
        else
        {
            Iopb->TargetFileObject->DeletePending = FALSE;
        }
    }

    ExFreePoolWithTag(proxyBuffer, HAWK_POOL_TAG);
    Data->IoStatus.Status = status;
    return FLT_PREOP_COMPLETE;
}

static FLT_PREOP_CALLBACK_STATUS
HawkCommonSetInformationDispatchRename(
    __inout PFLT_CALLBACK_DATA Data,
    __in PFLT_IO_PARAMETER_BLOCK Iopb,
    __in PFLT_INSTANCE Instance,
    __in PHAWK_STREAM_HANDLE_CONTEXT Shc
    )
{
    PFILE_RENAME_INFORMATION renameInfo = Iopb->Parameters.SetFileInformation.InfoBuffer;
    PHAWK_RENAME_PATHS renamePaths;
    NTSTATUS status;

    renamePaths = HawkAllocateRenamePaths();
    if (renamePaths == NULL ||
         !HawkResolveRenameTarget(renameInfo, &Shc->PathKey, &renamePaths->TargetPath))
    {
        HawkFreeRenamePaths(renamePaths);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        return FLT_PREOP_COMPLETE;
    }

    RtlDowncaseUnicodeString(
        &renamePaths->TargetPathKey, &renamePaths->TargetPath, FALSE);
    if (!HawkIsProtectedTxtFile(&renamePaths->TargetPathKey))
    {
        HawkFreeRenamePaths(renamePaths);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        return FLT_PREOP_COMPLETE;
    }

    status = FltSetInformationFile(
        Instance,
        Shc->ShadowFileObject,
        Iopb->Parameters.SetFileInformation.InfoBuffer,
        Iopb->Parameters.SetFileInformation.Length,
        FileRenameInformation);
    if (NT_SUCCESS(status))
    {
        MmFlushImageSection(
            Iopb->TargetFileObject->SectionObjectPointer, MmFlushForDelete);
        HawkRenameScb(&Shc->PathKey, &renamePaths->TargetPathKey);
    }

    HawkFreeRenamePaths(renamePaths);
    Data->IoStatus.Status = status;
    return FLT_PREOP_COMPLETE;
}

static FLT_PREOP_CALLBACK_STATUS
HawkCommonSetInformationDispatchPosition(
    __inout PFLT_CALLBACK_DATA Data,
    __in PFLT_IO_PARAMETER_BLOCK Iopb,
    __in PFLT_INSTANCE Instance,
    __in PHAWK_STREAM_HANDLE_CONTEXT Shc
    )
{
    PFILE_POSITION_INFORMATION positionInfo = Iopb->Parameters.SetFileInformation.InfoBuffer;
    NTSTATUS status;

    status = FltSetInformationFile(
        Instance,
        Shc->ShadowFileObject,
        positionInfo,
        Iopb->Parameters.SetFileInformation.Length,
        FilePositionInformation);
    if (NT_SUCCESS(status))
    {
        Iopb->TargetFileObject->CurrentByteOffset.QuadPart =
            positionInfo->CurrentByteOffset.QuadPart;
    }

    Data->IoStatus.Status = status;
    return FLT_PREOP_COMPLETE;
}

static FLT_PREOP_CALLBACK_STATUS
HawkCommonSetInformationDispatchAllocation(
    __inout PFLT_CALLBACK_DATA Data,
    __in PFLT_IO_PARAMETER_BLOCK Iopb,
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject,
    __in PHAWK_SCB Scb,
    __in PHAWK_STREAM_HANDLE_CONTEXT Shc,
    __inout PVOID *CompletionContext
    )
{
    PFILE_ALLOCATION_INFORMATION allocationInfo;
    PFSRTL_COMMON_FCB_HEADER fcbHeader;
    PVOID proxyBuffer;
    ULONG infoLength = Iopb->Parameters.SetFileInformation.Length;
    BOOLEAN cacheInitialized = FALSE;
    NTSTATUS status;
    FLT_PREOP_CALLBACK_STATUS retValue;

    retValue = FltCheckOplock(&Scb->Lock.Oplock, Data, NULL, NULL, NULL);
    if (retValue == FLT_PREOP_PENDING || retValue == FLT_PREOP_COMPLETE)
        return retValue;

    proxyBuffer = ExAllocatePoolWithTag(NonPagedPool, infoLength, HAWK_POOL_TAG);
    RtlCopyMemory(
        proxyBuffer,
        Iopb->Parameters.SetFileInformation.InfoBuffer,
        infoLength);
    allocationInfo = (PFILE_ALLOCATION_INFORMATION)proxyBuffer;
    if (!Iopb->Parameters.SetFileInformation.AdvanceOnly)
    {
        allocationInfo->AllocationSize.LowPart += HAWK_FS_HEADER_SIZE + HAWK_FS_KEY_SIZE;
        status = FltSetInformationFile(
            Instance,
            Shc->ShadowFileObject,
            allocationInfo,
            infoLength,
            FileAllocationInformation);
        if (NT_SUCCESS(status))
        {
            cacheInitialized = HawkCommonSetInformationTryInitPlaintextCache(
                FileObject, Scb, Iopb);
            fcbHeader = Shc->ShadowFileObject->FsContext;
            Scb->Header.AllocationSize.LowPart = fcbHeader->AllocationSize.LowPart;
            CcSetFileSizes(FileObject, (PCC_FILE_SIZES)&Scb->Header.AllocationSize);
            if (cacheInitialized)
                CcUninitializeCacheMap(FileObject, NULL, NULL);
        }

        ExFreePoolWithTag(proxyBuffer, HAWK_POOL_TAG);
        Data->IoStatus.Status = status;
        return FLT_PREOP_COMPLETE;
    }

    allocationInfo->AllocationSize.LowPart += HAWK_FS_HEADER_SIZE + HAWK_FS_KEY_SIZE;
    return HawkCommonSetInformationHandoffAdvanceOnly(
        Data, Iopb, Shc, proxyBuffer, CompletionContext);
}

static FLT_PREOP_CALLBACK_STATUS
HawkCommonSetInformationDispatchEndOfFile(
    __inout PFLT_CALLBACK_DATA Data,
    __in PFLT_IO_PARAMETER_BLOCK Iopb,
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject,
    __in PHAWK_SCB Scb,
    __in PHAWK_STREAM_HANDLE_CONTEXT Shc,
    __inout PVOID *CompletionContext
    )
{
    PFILE_END_OF_FILE_INFORMATION eofInfo;
    PVOID proxyBuffer;
    ULONG infoLength = Iopb->Parameters.SetFileInformation.Length;
    ULONG setEof;
    BOOLEAN cacheInitialized = FALSE;
    NTSTATUS status;
    FLT_PREOP_CALLBACK_STATUS retValue;

    retValue = FltCheckOplock(&Scb->Lock.Oplock, Data, NULL, NULL, NULL);
    if (retValue == FLT_PREOP_PENDING || retValue == FLT_PREOP_COMPLETE)
        return retValue;

    proxyBuffer = HawkCommonSetInformationAllocInfoCopy(
        Iopb->Parameters.SetFileInformation.InfoBuffer, infoLength);
    if (proxyBuffer == NULL)
    {
        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        return FLT_PREOP_COMPLETE;
    }

    eofInfo = (PFILE_END_OF_FILE_INFORMATION)proxyBuffer;
    if (!Iopb->Parameters.SetFileInformation.AdvanceOnly)
    {
        setEof = eofInfo->EndOfFile.LowPart;
        eofInfo->EndOfFile.LowPart += HAWK_FS_HEADER_SIZE + HAWK_FS_KEY_SIZE;
        status = FltSetInformationFile(
            Instance,
            Shc->ShadowFileObject,
            eofInfo,
            infoLength,
            FileEndOfFileInformation);
        if (NT_SUCCESS(status))
        {
            LONGLONG oldEof = Scb->Header.FileSize.QuadPart;
            LONGLONG newVdl;
            BOOLEAN shrinking;

            if ((LONGLONG)setEof <= oldEof)
                newVdl = setEof;
            else
                newVdl = Scb->Header.ValidDataLength.QuadPart;
            shrinking = ((LONGLONG)setEof < oldEof);

            KeEnterCriticalRegion();
            ExAcquireResourceExclusiveLite(Scb->Header.Resource, TRUE);
            if (shrinking && Scb->Header.PagingIoResource)
                ExAcquireResourceExclusiveLite(Scb->Header.PagingIoResource, TRUE);

            cacheInitialized = HawkCommonSetInformationTryInitPlaintextCache(
                FileObject, Scb, Iopb);
            Scb->Header.FileSize.QuadPart = setEof;
            Scb->Header.ValidDataLength.QuadPart = newVdl;
            if (Scb->Header.AllocationSize.QuadPart < Scb->Header.FileSize.QuadPart)
                Scb->Header.AllocationSize.QuadPart = Scb->Header.FileSize.QuadPart;
            if (shrinking)
                HawkPurgePlaintextCacheTail(FileObject, Scb, setEof);
            else
                HawkSyncPlaintextCache(FileObject, Scb);

            if (shrinking && Scb->Header.PagingIoResource)
                ExReleaseResourceLite(Scb->Header.PagingIoResource);
            ExReleaseResourceLite(Scb->Header.Resource);
            KeLeaveCriticalRegion();

            if (cacheInitialized)
                CcUninitializeCacheMap(FileObject, NULL, NULL);
        }

        ExFreePoolWithTag(proxyBuffer, HAWK_POOL_TAG);
        Data->IoStatus.Status = status;
        return FLT_PREOP_COMPLETE;
    }

    eofInfo->EndOfFile.LowPart += HAWK_FS_HEADER_SIZE + HAWK_FS_KEY_SIZE;
    return HawkCommonSetInformationHandoffAdvanceOnly(
        Data, Iopb, Shc, proxyBuffer, CompletionContext);
}

static FLT_PREOP_CALLBACK_STATUS
HawkCommonSetInformationDispatchValidDataLength(
    __inout PFLT_CALLBACK_DATA Data,
    __in PFLT_IO_PARAMETER_BLOCK Iopb,
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject,
    __in PHAWK_SCB Scb,
    __in PHAWK_STREAM_HANDLE_CONTEXT Shc,
    __inout PVOID *CompletionContext
    )
{
    PFILE_VALID_DATA_LENGTH_INFORMATION vdlInfo;
    PFSRTL_COMMON_FCB_HEADER fcbHeader;
    PVOID proxyBuffer;
    ULONG infoLength = Iopb->Parameters.SetFileInformation.Length;
    ULONG setVdl;
    BOOLEAN cacheInitialized = FALSE;
    NTSTATUS status;

    proxyBuffer = ExAllocatePoolWithTag(NonPagedPool, infoLength, HAWK_POOL_TAG);
    RtlCopyMemory(
        proxyBuffer,
        Iopb->Parameters.SetFileInformation.InfoBuffer,
        infoLength);
    vdlInfo = (PFILE_VALID_DATA_LENGTH_INFORMATION)proxyBuffer;
    if (!Iopb->Parameters.SetFileInformation.AdvanceOnly)
    {
        setVdl = vdlInfo->ValidDataLength.LowPart;
        vdlInfo->ValidDataLength.LowPart += HAWK_FS_HEADER_SIZE + HAWK_FS_KEY_SIZE;
        status = FltSetInformationFile(
            Instance,
            Shc->ShadowFileObject,
            vdlInfo,
            infoLength,
            FileValidDataLengthInformation);
        if (NT_SUCCESS(status))
        {
            cacheInitialized = HawkCommonSetInformationTryInitPlaintextCache(
                FileObject, Scb, Iopb);
            fcbHeader = Shc->ShadowFileObject->FsContext;
            Scb->Header.AllocationSize.LowPart = fcbHeader->AllocationSize.LowPart;
            Scb->Header.ValidDataLength.LowPart = setVdl;
            CcSetFileSizes(FileObject, (PCC_FILE_SIZES)&Scb->Header.AllocationSize);
            if (cacheInitialized)
                CcUninitializeCacheMap(FileObject, NULL, NULL);
        }

        ExFreePoolWithTag(proxyBuffer, HAWK_POOL_TAG);
        Data->IoStatus.Status = status;
        return FLT_PREOP_COMPLETE;
    }

    vdlInfo->ValidDataLength.LowPart += HAWK_FS_HEADER_SIZE + HAWK_FS_KEY_SIZE;
    return HawkCommonSetInformationHandoffAdvanceOnly(
        Data, Iopb, Shc, proxyBuffer, CompletionContext);
}

FLT_PREOP_CALLBACK_STATUS
HawkCommonSetInformation(
    __in PHAWK_IRP_CONTEXT IrpContext,
    __inout PVOID *CompletionContext
    )
{
    PFLT_CALLBACK_DATA data = IrpContext->CallbackData;
    PFLT_IO_PARAMETER_BLOCK iopb = data->Iopb;
    PHAWK_FLT_OBJECTS fltObjects = &IrpContext->RelatedObjects;
    PFILE_OBJECT fileObject = iopb->TargetFileObject;
    PHAWK_SCB scb;
    PHAWK_STREAM_HANDLE_CONTEXT shc;

    scb = (PHAWK_SCB)fileObject->FsContext;
    shc = (PHAWK_STREAM_HANDLE_CONTEXT)fileObject->FsContext2;

    switch (iopb->Parameters.SetFileInformation.FileInformationClass)
    {
    case FileBasicInformation:
        HawkCommonSetInformationRedirectToShadow(data, iopb, shc);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    case FileDispositionInformation:
        return HawkCommonSetInformationDispatchDisposition(
            data, iopb, fltObjects->Instance, shc);

    case FileRenameInformation:
        return HawkCommonSetInformationDispatchRename(
            data, iopb, fltObjects->Instance, shc);

    case FilePositionInformation:
        return HawkCommonSetInformationDispatchPosition(
            data, iopb, fltObjects->Instance, shc);

    case FileLinkInformation:
        HawkCommonSetInformationRedirectToShadow(data, iopb, shc);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    case FileAllocationInformation:
        return HawkCommonSetInformationDispatchAllocation(
            data, iopb, fltObjects->Instance, fileObject, scb, shc, CompletionContext);

    case FileEndOfFileInformation:
        return HawkCommonSetInformationDispatchEndOfFile(
            data, iopb, fltObjects->Instance, fileObject, scb, shc, CompletionContext);

    case FileValidDataLengthInformation:
        return HawkCommonSetInformationDispatchValidDataLength(
            data, iopb, fltObjects->Instance, fileObject, scb, shc, CompletionContext);

    default:
        HawkCommonSetInformationRedirectToShadow(data, iopb, shc);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
}

FLT_POSTOP_CALLBACK_STATUS
HawkPostSetInformation(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
    PHAWK_PRE2POST_CONTEXT p2pCtx = CompletionContext;
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    PHAWK_SCB scb = iopb->TargetFileObject->FsContext;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    if (scb->Header.NodeTypeCode == HAWK_SCB_TYPE_CODE)
    {
        if (p2pCtx)
        {
            ExFreePoolWithTag(p2pCtx->HandoffPtr, HAWK_POOL_TAG);
            ExFreeToNPagedLookasideList(&g_HawkP2PLookaside, p2pCtx);
        }
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static FLT_PREOP_CALLBACK_STATUS
HawkPreSetPassThroughToShadow(
    __inout PFLT_CALLBACK_DATA Data
    )
{
    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    PHAWK_SCB scb = NULL;
    PHAWK_STREAM_HANDLE_CONTEXT shc = NULL;

    if (fileObject != NULL && fileObject->Type == IO_TYPE_FILE)
        scb = fileObject->FsContext;
    if (scb != NULL && scb->Header.NodeTypeCode == HAWK_SCB_TYPE_CODE)
    {
        shc = (PHAWK_STREAM_HANDLE_CONTEXT)Data->Iopb->TargetFileObject->FsContext2;
        Data->Iopb->TargetFileObject = shc->ShadowFileObject;
        FltSetCallbackDataDirty(Data);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
HawkPreSetEa(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    if (FLT_IS_FASTIO_OPERATION(Data))
        return FLT_PREOP_DISALLOW_FASTIO;
    return HawkPreSetPassThroughToShadow(Data);
}

FLT_PREOP_CALLBACK_STATUS
HawkPreSetQuota(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    if (FLT_IS_FASTIO_OPERATION(Data))
        return FLT_PREOP_DISALLOW_FASTIO;
    return HawkPreSetPassThroughToShadow(Data);
}

FLT_PREOP_CALLBACK_STATUS
HawkPreSetSecurity(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    if (FLT_IS_FASTIO_OPERATION(Data))
        return FLT_PREOP_DISALLOW_FASTIO;
    return HawkPreSetPassThroughToShadow(Data);
}

FLT_PREOP_CALLBACK_STATUS
HawkPreSetVolumeInformation(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    if (FLT_IS_FASTIO_OPERATION(Data))
        return FLT_PREOP_DISALLOW_FASTIO;
    return HawkPreSetPassThroughToShadow(Data);
}
