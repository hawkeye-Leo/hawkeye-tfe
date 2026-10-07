#include "HawkeyeTfe.h"
#include "HawkScb.h"
#include "HawkOperations.h"
#include "HawkFsp.h"
#include "HawkCipher.h"


/* Hawkeye TFE */
static FLT_PREOP_CALLBACK_STATUS
HawkPreReadCompleteMdlRead(
    __inout PFLT_CALLBACK_DATA Data
    )
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    CcMdlReadComplete(iopb->TargetFileObject, iopb->Parameters.Read.MdlAddress);
    Data->IoStatus.Information = 0;
    Data->IoStatus.Status = STATUS_SUCCESS;
    iopb->Parameters.Write.MdlAddress = NULL;
    return FLT_PREOP_COMPLETE;
}

static FLT_PREOP_CALLBACK_STATUS
HawkPreReadDispatchPlaintextRead(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    PHAWK_IRP_CONTEXT irpContext;
    FLT_PREOP_CALLBACK_STATUS retValue;

    if (FlagOn(iopb->MinorFunction, IRP_MN_COMPLETE))
        return HawkPreReadCompleteMdlRead(Data);

    irpContext = HawkCreateIrpContext(
        Data, FltObjects, CompletionContext, FltIsOperationSynchronous(Data));
    if (irpContext == NULL)
    {
        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        return FLT_PREOP_COMPLETE;
    }

    retValue = HawkCommonRead(irpContext, CompletionContext);
    if (retValue == FLT_PREOP_COMPLETE)
        HawkDeleteIrpContext(irpContext);
    else if (retValue == FLT_PREOP_SUCCESS_WITH_CALLBACK && *CompletionContext == NULL)
        retValue = FLT_PREOP_SUCCESS_NO_CALLBACK;

    return retValue;
}

static FLT_PREOP_CALLBACK_STATUS
HawkPreReadHandlePlaintextFileObject(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    FLT_PREOP_CALLBACK_STATUS retValue;

    KeEnterCriticalRegion();
    retValue = HawkPreReadDispatchPlaintextRead(Data, FltObjects, CompletionContext);
    KeLeaveCriticalRegion();
    return retValue;
}

static VOID
HawkPreReadFlushProtectedOpenCache(
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject
    )
{
    PHAWK_STREAM_HANDLE_CONTEXT shc = NULL;
    PHAWK_SCB protectedOpenScb = NULL;

    FltGetStreamHandleContext(Instance, FileObject, &shc);
    if (shc == NULL)
        return;

    if (shc->IsProtectedOpen && HawkFindScb(&shc->PathKey, &protectedOpenScb))
        CcFlushCache(&protectedOpenScb->SectionObjectPointers, NULL, 0, NULL);

    FltReleaseContext(shc);
}

/* Hawkeye TFE: read */
FLT_PREOP_CALLBACK_STATUS
HawkPreRead(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    PHAWK_SCB scb;

    *CompletionContext = NULL;
    if (FLT_IS_FASTIO_OPERATION(Data))
        return FLT_PREOP_DISALLOW_FASTIO;

    scb = HawkResolvePlaintextScbFromFileObject(fileObject);
    if (scb != NULL)
        return HawkPreReadHandlePlaintextFileObject(Data, FltObjects, CompletionContext);

    HawkPreReadFlushProtectedOpenCache(FltObjects->Instance, fileObject);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS
HawkCommonReadCompleteIo(
    __inout PFLT_CALLBACK_DATA Data,
    __in NTSTATUS Status,
    __in ULONG_PTR Information
    )
{
    Data->IoStatus.Status = Status;
    Data->IoStatus.Information = Information;
    return FLT_PREOP_COMPLETE;
}

static VOID
HawkCommonReadMarkFspPending(
    __out PBOOLEAN PostOperation,
    __out PFLT_PREOP_CALLBACK_STATUS RetValue
    )
{
    *PostOperation = TRUE;
    *RetValue = FLT_PREOP_PENDING;
}

static PHAWK_PRE2POST_CONTEXT
HawkCommonReadAllocatePre2Post(
    __inout PFLT_CALLBACK_DATA Data
    )
{
    PHAWK_PRE2POST_CONTEXT p2pCtx;

    p2pCtx = ExAllocateFromNPagedLookasideList(&g_HawkP2PLookaside);
    if (p2pCtx == NULL)
    {
        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Data->IoStatus.Information = 0;
        return NULL;
    }

    RtlZeroMemory(p2pCtx, sizeof(HAWK_PRE2POST_CONTEXT));
    return p2pCtx;
}

static BOOLEAN
HawkCommonReadShouldDeferCachedMdl(
    __in PFLT_IO_PARAMETER_BLOCK Iopb,
    __in BOOLEAN NonCachedIo,
    __in BOOLEAN Wait,
    __in ULONG ByteCount,
    __in ULONG StartVbo
    )
{
    if (NonCachedIo)
        return FALSE;
    if (!FlagOn(Iopb->MinorFunction, IRP_MN_MDL))
        return FALSE;
    if (Wait)
        return FALSE;

    return TRUE;
}

static BOOLEAN
HawkCommonReadFlushBeforeNonCached(
    __inout PFLT_CALLBACK_DATA Data,
    __in PHAWK_SCB Scb,
    __in PFLT_IO_PARAMETER_BLOCK Iopb,
    __in BOOLEAN Wait,
    __in BOOLEAN NonCachedIo,
    __in BOOLEAN PagingIo,
    __out PBOOLEAN PostOperation,
    __out PFLT_PREOP_CALLBACK_STATUS RetValue
    )
{
    if (!NonCachedIo || PagingIo ||
         Iopb->TargetFileObject->SectionObjectPointer->DataSectionObject == NULL)
    {
        return TRUE;
    }

    if (!ExAcquireResourceExclusiveLite(Scb->Header.Resource, Wait))
    {
        HawkCommonReadMarkFspPending(PostOperation, RetValue);
        return FALSE;
    }

    ExAcquireResourceSharedLite(Scb->Header.PagingIoResource, TRUE);
    CcFlushCache(&Scb->SectionObjectPointers, NULL, 0, (PIO_STATUS_BLOCK)&Data->IoStatus.Status);
    ExReleaseResourceLite(Scb->Header.PagingIoResource);
    ExReleaseResourceLite(Scb->Header.Resource);
    if (!NT_SUCCESS(Data->IoStatus.Status))
    {
        *RetValue = FLT_PREOP_COMPLETE;
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN
HawkCommonReadTryAcquireScb(
    __in PHAWK_SCB Scb,
    __in BOOLEAN Wait,
    __in BOOLEAN PagingIo,
    __in BOOLEAN NonCachedIo,
    __out PBOOLEAN PostOperation,
    __out PFLT_PREOP_CALLBACK_STATUS RetValue
    )
{
    if (PagingIo)
    {
        if (!ExAcquireResourceSharedLite(Scb->Header.PagingIoResource, Wait))
        {
            HawkCommonReadMarkFspPending(PostOperation, RetValue);
            return FALSE;
        }
        return TRUE;
    }

    if (!Wait && NonCachedIo)
    {
        if (!ExAcquireSharedWaitForExclusive(Scb->Header.Resource, Wait))
        {
            HawkCommonReadMarkFspPending(PostOperation, RetValue);
            return FALSE;
        }
        return TRUE;
    }

    if (!ExAcquireResourceSharedLite(Scb->Header.Resource, Wait))
    {
        HawkCommonReadMarkFspPending(PostOperation, RetValue);
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN
HawkCommonReadVerifySharing(
    __inout PFLT_CALLBACK_DATA Data,
    __in PHAWK_SCB Scb,
    __in BOOLEAN PagingIo,
    __out PFLT_PREOP_CALLBACK_STATUS RetValue
    )
{
    FLT_PREOP_CALLBACK_STATUS oplockStatus;

    if (PagingIo)
        return TRUE;

    oplockStatus = FltCheckOplock(&Scb->Lock.Oplock, Data, NULL, NULL, NULL);
    if (oplockStatus == FLT_PREOP_PENDING || oplockStatus == FLT_PREOP_COMPLETE)
    {
        *RetValue = oplockStatus;
        return FALSE;
    }

    if (!FltCheckLockForReadAccess(&Scb->Lock.FileLock, Data))
    {
        Data->IoStatus.Status = STATUS_FILE_LOCK_CONFLICT;
        *RetValue = FLT_PREOP_COMPLETE;
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN
HawkCommonReadPrepareLength(
    __in PHAWK_SCB Scb,
    __in ULONG StartVbo,
    __inout PULONG ByteCount,
    __inout PFLT_CALLBACK_DATA Data,
    __out PFLT_PREOP_CALLBACK_STATUS RetValue
    )
{
    ULONG fileSize = Scb->Header.FileSize.LowPart;

    if (StartVbo >= fileSize)
    {
        Data->IoStatus.Information = 0;
        Data->IoStatus.Status = STATUS_END_OF_FILE;
        *RetValue = FLT_PREOP_COMPLETE;
        return FALSE;
    }

    if (*ByteCount > fileSize - StartVbo)
        *ByteCount = fileSize - StartVbo;
    return TRUE;
}

static PVOID
HawkCommonReadResolveUserBuffer(
    __in PFLT_IO_PARAMETER_BLOCK Iopb
    )
{
    if (Iopb->Parameters.Read.MdlAddress != NULL)
    {
        return MmGetSystemAddressForMdlSafe(
            Iopb->Parameters.Read.MdlAddress, NormalPagePriority);
    }

    return Iopb->Parameters.Read.ReadBuffer;
}

static BOOLEAN
HawkCommonReadAllocProxyBuffer(
    __in ULONG BytesToRead,
    __in ULONG StartVbo,
    __out PVOID *ProxyBuffer
    )
{
    PVOID newBuf;

    *ProxyBuffer = NULL;

    newBuf = ExAllocatePoolWithTag(NonPagedPool, BytesToRead, HAWK_POOL_TAG);
    if (newBuf == NULL)
        return FALSE;

    *ProxyBuffer = newBuf;
    return TRUE;
}

static BOOLEAN
HawkCommonReadBuildProxyMdl(
    __inout PFLT_CALLBACK_DATA Data,
    __in PVOID ProxyBuffer,
    __in ULONG BytesToRead,
    __in ULONG StartVbo,
    __out PMDL *ProxyMdl
    )
{
    PMDL newMdl;

    *ProxyMdl = NULL;
    if (!FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_IRP_OPERATION))
        return TRUE;

    newMdl = IoAllocateMdl(ProxyBuffer, BytesToRead, FALSE, FALSE, NULL);
    if (newMdl == NULL)
        return FALSE;

    MmBuildMdlForNonPagedPool(newMdl);
    *ProxyMdl = newMdl;
    return TRUE;
}

static VOID
HawkCommonReadRedirectToShadowRead(
    __inout PFLT_CALLBACK_DATA Data,
    __in PFLT_IO_PARAMETER_BLOCK Iopb,
    __in PFILE_OBJECT ShadowFileObject,
    __in ULONG ByteCount,
    __in PVOID ProxyBuffer,
    __in PMDL ProxyMdl
    )
{
    Iopb->TargetFileObject = ShadowFileObject;
    Iopb->Parameters.Read.Length = ByteCount;
    Iopb->Parameters.Read.ByteOffset.QuadPart += HAWK_FS_HEADER_SIZE + HAWK_FS_KEY_SIZE;
    Iopb->Parameters.Read.ReadBuffer = ProxyBuffer;
    Iopb->Parameters.Read.MdlAddress = ProxyMdl;
    FltSetCallbackDataDirty(Data);
}

static VOID
HawkCommonReadHandoffPre2Post(
    __inout PHAWK_PRE2POST_CONTEXT P2pCtx,
    __in PHAWK_IRP_CONTEXT IrpContext,
    __in PHAWK_SCB Scb,
    __in ULONG StartVbo,
    __in PVOID ProxyBuffer,
    __in PMDL ProxyMdl,
    __in PVOID UserBuffer,
    __inout PVOID *CompletionContext,
    __inout PHAWK_PRE2POST_CONTEXT *OwnedP2pCtx
    )
{
    P2pCtx->HandoffPtr = ProxyBuffer;
    P2pCtx->HandoffMdl = ProxyMdl;
    P2pCtx->IrpContext = IrpContext;
    P2pCtx->BoundScb = Scb;
    P2pCtx->CacheOffset = StartVbo;
    P2pCtx->UserBuffer = UserBuffer;
    *CompletionContext = P2pCtx;
    *OwnedP2pCtx = NULL;
}

static VOID
HawkCommonReadDispatchNonCached(
    __inout PFLT_CALLBACK_DATA Data,
    __in PFLT_IO_PARAMETER_BLOCK Iopb,
    __in PHAWK_IRP_CONTEXT IrpContext,
    __in PHAWK_SCB Scb,
    __in PFILE_OBJECT ShadowFileObject,
    __in ULONG StartVbo,
    __inout PULONG ByteCount,
    __in PVOID UserBuffer,
    __inout PHAWK_PRE2POST_CONTEXT *OwnedP2pCtx,
    __inout PVOID *CompletionContext,
    __out PFLT_PREOP_CALLBACK_STATUS RetValue
    )
{
    ULONG validDataLength = Scb->Header.ValidDataLength.LowPart;
    ULONG bytesToRead;
    PVOID proxyBuffer = NULL;
    PMDL proxyMdl = NULL;
    PHAWK_PRE2POST_CONTEXT p2pCtx = *OwnedP2pCtx;

    if (UserBuffer != NULL)
        RtlZeroMemory(UserBuffer, *ByteCount);

    if (StartVbo >= validDataLength)
    {
        Data->IoStatus.Information = *ByteCount;
        Data->IoStatus.Status = STATUS_SUCCESS;
        *RetValue = FLT_PREOP_COMPLETE;
        return;
    }

    *ByteCount = min(validDataLength - StartVbo, *ByteCount);
    bytesToRead = (ULONG)ROUND_TO_SIZE(*ByteCount, HAWK_SECTOR_SIZE);
    if (!HawkCommonReadAllocProxyBuffer(bytesToRead, StartVbo, &proxyBuffer))
    {
        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Data->IoStatus.Information = 0;
        *RetValue = FLT_PREOP_COMPLETE;
        return;
    }

    if (!HawkCommonReadBuildProxyMdl(Data, proxyBuffer, bytesToRead, StartVbo, &proxyMdl))
    {
        ExFreePoolWithTag(proxyBuffer, HAWK_POOL_TAG);
        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Data->IoStatus.Information = 0;
        *RetValue = FLT_PREOP_COMPLETE;
        return;
    }

    HawkCommonReadRedirectToShadowRead(
        Data, Iopb, ShadowFileObject, *ByteCount, proxyBuffer, proxyMdl);
    HawkCommonReadHandoffPre2Post(
        p2pCtx, IrpContext, Scb, StartVbo, proxyBuffer, proxyMdl, UserBuffer,
        CompletionContext, OwnedP2pCtx);
    *RetValue = FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static VOID
HawkCommonReadEnsurePlaintextCacheMap(
    __in PFILE_OBJECT FileObject,
    __in PHAWK_SCB Scb
    )
{
    if (FileObject->PrivateCacheMap != NULL)
        return;

    try
    {
        CcInitializeCacheMap(
            FileObject,
            (PCC_FILE_SIZES)&Scb->Header.AllocationSize,
            FALSE,
            &g_HawkCcCallbacks,
            Scb);
        CcSetReadAheadGranularity(FileObject, HAWK_READ_AHEAD_GRANULARITY);
    }
    except (EXCEPTION_EXECUTE_HANDLER)
    {
        DBG_PRINT(
            "HawkeyeTfe!CommonRead: CcInitializeCacheMap raised exception 0x%08X",
            GetExceptionCode());
    }
}

static VOID
HawkCommonReadDispatchCachedCopy(
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER StartOffset,
    __in ULONG ByteCount,
    __in ULONG StartVbo,
    __in BOOLEAN Wait,
    __in PVOID UserBuffer,
    __inout PFLT_CALLBACK_DATA Data,
    __out PBOOLEAN PostOperation,
    __out PFLT_PREOP_CALLBACK_STATUS RetValue
    )
{
    if (!CcCopyRead(FileObject, StartOffset, ByteCount, Wait, UserBuffer, &Data->IoStatus))
    {
        HawkCommonReadMarkFspPending(PostOperation, RetValue);
        return;
    }

    *RetValue = FLT_PREOP_COMPLETE;
}

static VOID
HawkCommonReadDispatchCachedMdl(
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER StartOffset,
    __in ULONG ByteCount,
    __in ULONG StartVbo,
    __inout PFLT_IO_PARAMETER_BLOCK Iopb,
    __inout PFLT_CALLBACK_DATA Data,
    __out PFLT_PREOP_CALLBACK_STATUS RetValue
    )
{
    CcMdlRead(
        FileObject,
        StartOffset,
        ByteCount,
        &Iopb->Parameters.Read.MdlAddress,
        &Data->IoStatus);
    *RetValue = FLT_PREOP_COMPLETE;
}

static FLT_PREOP_CALLBACK_STATUS
HawkCommonReadFinish(
    __inout PFLT_CALLBACK_DATA Data,
    __in PFLT_IO_PARAMETER_BLOCK Iopb,
    __in PHAWK_IRP_CONTEXT IrpContext,
    __in PHAWK_SCB Scb,
    __in BOOLEAN SynchronousIo,
    __in BOOLEAN PagingIo,
    __in ULONG StartVbo,
    __in ULONG ByteCount,
    __in BOOLEAN PostOperation,
    __in BOOLEAN OplockPostOperation,
    __in BOOLEAN ScbAcquired,
    __inout PHAWK_PRE2POST_CONTEXT *OwnedP2pCtx,
    __inout PFLT_PREOP_CALLBACK_STATUS RetValue
    )
{
    NTSTATUS status;

    if (!PostOperation)
    {
        if (SynchronousIo && !PagingIo)
        {
            Iopb->TargetFileObject->CurrentByteOffset.LowPart =
                StartVbo + (ULONG)Data->IoStatus.Information;
        }
    }
    else if (!OplockPostOperation)
    {
        status = FltLockUserBuffer(Data);
        if (!NT_SUCCESS(status))
        {
            Data->IoStatus.Status = status;
            Data->IoStatus.Information = 0;
            *RetValue = FLT_PREOP_COMPLETE;
        }
        else
        {
            HawkQueueFspWorkItem(IrpContext);
        }
    }

    if (ScbAcquired)
    {
        if (PagingIo)
            ExReleaseResourceLite(Scb->Header.PagingIoResource);
        else
            ExReleaseResourceLite(Scb->Header.Resource);
    }

    if (*OwnedP2pCtx != NULL)
        ExFreeToNPagedLookasideList(&g_HawkP2PLookaside, *OwnedP2pCtx);

    return *RetValue;
}

/* Hawkeye TFE: CommonRead */
FLT_PREOP_CALLBACK_STATUS
HawkCommonRead(
    __in PHAWK_IRP_CONTEXT IrpContext,
    __inout PVOID *CompletionContext
    )
{
    PFLT_CALLBACK_DATA data = IrpContext->CallbackData;
    PFLT_IO_PARAMETER_BLOCK iopb = data->Iopb;
    BOOLEAN wait = BooleanFlagOn(IrpContext->Flags, HAWK_IRP_CTX_FLAG_WAIT);
    BOOLEAN pagingIo = BooleanFlagOn(iopb->IrpFlags, IRP_PAGING_IO);
    BOOLEAN nonCachedIo = BooleanFlagOn(iopb->IrpFlags, IRP_NOCACHE);
    BOOLEAN synchronousIo = BooleanFlagOn(iopb->TargetFileObject->Flags, FO_SYNCHRONOUS_IO);
    BOOLEAN postOperation = FALSE;
    BOOLEAN oplockPostOperation = FALSE;
    BOOLEAN fcbAcquired = FALSE;
    LARGE_INTEGER startOffset = iopb->Parameters.Read.ByteOffset;
    ULONG startVbo = startOffset.LowPart;
    ULONG byteCount = iopb->Parameters.Read.Length;
    PHAWK_SCB scb = iopb->TargetFileObject->FsContext;
    PFILE_OBJECT shadowFileObject;
    PHAWK_STREAM_HANDLE_CONTEXT streamHandleContext;
    PVOID userBuffer;
    PHAWK_PRE2POST_CONTEXT p2pCtx = NULL;
    FLT_PREOP_CALLBACK_STATUS retValue = FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (scb == NULL || scb->Header.NodeTypeCode != HAWK_SCB_TYPE_CODE)
        return HawkCommonReadCompleteIo(data, STATUS_INVALID_PARAMETER, 0);

    if (byteCount == 0)
        return HawkCommonReadCompleteIo(data, STATUS_SUCCESS, 0);

    streamHandleContext = iopb->TargetFileObject->FsContext2;
    if (streamHandleContext == NULL || streamHandleContext->ShadowFileObject == NULL)
        return HawkCommonReadCompleteIo(data, STATUS_INVALID_PARAMETER, 0);
    shadowFileObject = streamHandleContext->ShadowFileObject;

    if (HawkCommonReadShouldDeferCachedMdl(iopb, nonCachedIo, wait, byteCount, startVbo))
    {
        HawkCommonReadMarkFspPending(&postOperation, &retValue);
        goto CleanupAndReturn;
    }

    p2pCtx = HawkCommonReadAllocatePre2Post(data);
    if (p2pCtx == NULL)
        return FLT_PREOP_COMPLETE;

    if (!HawkCommonReadFlushBeforeNonCached(
            data, scb, iopb, wait, nonCachedIo, pagingIo, &postOperation, &retValue))
    {
        goto CleanupAndReturn;
    }

    if (!HawkCommonReadTryAcquireScb(
            scb, wait, pagingIo, nonCachedIo, &postOperation, &retValue))
    {
        goto CleanupAndReturn;
    }
    fcbAcquired = TRUE;

    if (!HawkCommonReadVerifySharing(data, scb, pagingIo, &retValue))
        goto CleanupAndReturn;

    if (!HawkCommonReadPrepareLength(scb, startVbo, &byteCount, data, &retValue))
        goto CleanupAndReturn;

    userBuffer = HawkCommonReadResolveUserBuffer(iopb);
    if (nonCachedIo)
    {
        HawkCommonReadDispatchNonCached(
            data, iopb, IrpContext, scb, shadowFileObject, startVbo, &byteCount,
            userBuffer, &p2pCtx, CompletionContext, &retValue);
        goto CleanupAndReturn;
    }

    HawkCommonReadEnsurePlaintextCacheMap(iopb->TargetFileObject, scb);
    if (!FlagOn(iopb->MinorFunction, IRP_MN_MDL))
    {
        HawkCommonReadDispatchCachedCopy(
            iopb->TargetFileObject, &startOffset, byteCount, startVbo, wait,
            userBuffer, data, &postOperation, &retValue);
    }
    else
    {
        HawkCommonReadDispatchCachedMdl(
            iopb->TargetFileObject, &startOffset, byteCount, startVbo,
            iopb, data, &retValue);
    }

CleanupAndReturn:

    return HawkCommonReadFinish(
        data, iopb, IrpContext, scb, synchronousIo, pagingIo, startVbo, byteCount,
        postOperation, oplockPostOperation, fcbAcquired, &p2pCtx, &retValue);
}

static VOID
HawkPostReadFreePre2Post(
    __inout PHAWK_PRE2POST_CONTEXT P2pCtx
    )
{

    if (P2pCtx->HandoffPtr != NULL)
        ExFreePoolWithTag(P2pCtx->HandoffPtr, HAWK_POOL_TAG);
    if (P2pCtx->IrpContext != NULL)
        HawkDeleteIrpContext(P2pCtx->IrpContext);
    ExFreeToNPagedLookasideList(&g_HawkP2PLookaside, P2pCtx);
}

static PHAWK_SCB
HawkPostReadResolvePlaintextScb(
    __in PHAWK_PRE2POST_CONTEXT P2pCtx,
    __in PFLT_IO_PARAMETER_BLOCK Iopb
    )
{
    PHAWK_SCB scb = (PHAWK_SCB)P2pCtx->BoundScb;

    if (scb == NULL)
        scb = (PHAWK_SCB)Iopb->TargetFileObject->FsContext;
    return scb;
}

static VOID
HawkPostReadDecryptProxyBuffer(
    __in PHAWK_SCB Scb,
    __in PHAWK_PRE2POST_CONTEXT P2pCtx,
    __inout PVOID ProxyBuffer,
    __in ULONG Info
    )
{
    ULONG validDataLen = Scb->Header.ValidDataLength.LowPart;
    ULONG readOffset = P2pCtx->CacheOffset;

    if (validDataLen > readOffset)
    {
        ULONG toDecrypt = min(validDataLen - readOffset, Info);

        HawkXorDecrypt(
            ProxyBuffer,
            readOffset,
            toDecrypt,
            ProxyBuffer,
            (PCHAR)g_HawkCipherKey,
            32);
    }
    else
    {
        RtlZeroMemory(ProxyBuffer, Info);
    }
}

static PVOID
HawkPostReadResolveUserBuffer(
    __in PHAWK_PRE2POST_CONTEXT P2pCtx,
    __in PFLT_IO_PARAMETER_BLOCK Iopb
    )
{
    if (P2pCtx->UserBuffer != NULL)
        return P2pCtx->UserBuffer;

    if (Iopb->Parameters.Read.MdlAddress != NULL)
    {
        return MmGetSystemAddressForMdlSafe(
            Iopb->Parameters.Read.MdlAddress, NormalPagePriority);
    }

    return Iopb->Parameters.Read.ReadBuffer;
}

static VOID
HawkPostReadCopyProxyToUser(
    __in PVOID UserBuffer,
    __in PVOID ProxyBuffer,
    __in ULONG Info
    )
{
    if (UserBuffer == NULL || ProxyBuffer == NULL || Info == 0)
        return;
    if (UserBuffer == ProxyBuffer)
        return;

    RtlCopyMemory(UserBuffer, ProxyBuffer, Info);
}

FLT_POSTOP_CALLBACK_STATUS
HawkPostRead(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
    PHAWK_PRE2POST_CONTEXT p2pCtx = CompletionContext;
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    PHAWK_SCB scb;
    PVOID proxyBuffer;
    PVOID userBuffer;
    ULONG info;

    UNREFERENCED_PARAMETER(FltObjects);
    if (p2pCtx == NULL)
        return FLT_POSTOP_FINISHED_PROCESSING;

    proxyBuffer = p2pCtx->HandoffPtr;
    info = (ULONG)Data->IoStatus.Information;

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))
    {
        HawkPostReadFreePre2Post(p2pCtx);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    scb = HawkPostReadResolvePlaintextScb(p2pCtx, iopb);
    if (NT_SUCCESS(Data->IoStatus.Status) && info != 0 && proxyBuffer != NULL)
        HawkPostReadDecryptProxyBuffer(scb, p2pCtx, proxyBuffer, info);

    userBuffer = HawkPostReadResolveUserBuffer(p2pCtx, iopb);
    HawkPostReadCopyProxyToUser(userBuffer, proxyBuffer, info);
    HawkPostReadFreePre2Post(p2pCtx);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static FLT_PREOP_CALLBACK_STATUS
HawkPreMdlRejectPlaintextFileObject(
    __inout PFLT_CALLBACK_DATA Data
    )
{
    PHAWK_SCB scb = HawkResolvePlaintextScbFromFileObject(Data->Iopb->TargetFileObject);

    if (scb == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    Data->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

FLT_PREOP_CALLBACK_STATUS
HawkPreMdlRead(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    if (FLT_IS_FASTIO_OPERATION(Data))
        return FLT_PREOP_DISALLOW_FASTIO;

    return HawkPreMdlRejectPlaintextFileObject(Data);
}

FLT_PREOP_CALLBACK_STATUS
HawkPreMdlReadComplete(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    if (FLT_IS_FASTIO_OPERATION(Data))
        return FLT_PREOP_DISALLOW_FASTIO;

    return HawkPreMdlRejectPlaintextFileObject(Data);
}
