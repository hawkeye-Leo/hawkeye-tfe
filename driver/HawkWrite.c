#include "HawkeyeTfe.h"
#include "HawkScb.h"
#include "HawkPlaintextCache.h"
#include "HawkOperations.h"
#include "HawkFsp.h"
#include "HawkCipher.h"

/* Hawkeye TFE */
static FLT_PREOP_CALLBACK_STATUS
HawkPreWriteDispatchPlaintextWrite(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    PHAWK_IRP_CONTEXT irpContext;
    FLT_PREOP_CALLBACK_STATUS retValue;

    irpContext = HawkCreateIrpContext(
        Data, FltObjects, CompletionContext, FltIsOperationSynchronous(Data));
    if (irpContext == NULL)
    {
        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        return FLT_PREOP_COMPLETE;
    }

    if (FlagOn(iopb->MinorFunction, IRP_MN_COMPLETE))
        retValue = HawkPreWriteCompleteMdl(irpContext);
    else
        retValue = HawkCommonWrite(irpContext, CompletionContext);

    if (retValue == FLT_PREOP_COMPLETE)
        HawkDeleteIrpContext(irpContext);
    else if (retValue == FLT_PREOP_SUCCESS_WITH_CALLBACK && *CompletionContext == NULL)
        retValue = FLT_PREOP_SUCCESS_NO_CALLBACK;

    return retValue;
}

static FLT_PREOP_CALLBACK_STATUS
HawkPreWriteHandlePlaintextFileObject(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    FLT_PREOP_CALLBACK_STATUS retValue;

    KeEnterCriticalRegion();
    retValue = HawkPreWriteDispatchPlaintextWrite(Data, FltObjects, CompletionContext);
    KeLeaveCriticalRegion();
    return retValue;
}

static FLT_PREOP_CALLBACK_STATUS
HawkPreWriteHandleProtectedOpen(
    __inout PFLT_CALLBACK_DATA Data,
    __in PHAWK_STREAM_HANDLE_CONTEXT Shc,
    __in PFLT_IO_PARAMETER_BLOCK Iopb,
    __deref_out_opt PVOID *CompletionContext
    )
{
    PHAWK_SCB protectedOpenScb = NULL;
    PHAWK_PRE2POST_CONTEXT p2p;

    if (FlagOn(Iopb->IrpFlags, IRP_PAGING_IO) ||
         FlagOn(Iopb->IrpFlags, IRP_NOCACHE))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!HawkFindScb(&Shc->PathKey, &protectedOpenScb))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    p2p = ExAllocateFromNPagedLookasideList(&g_HawkP2PLookaside);
    if (p2p == NULL)
    {
        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        return FLT_PREOP_COMPLETE;
    }

    RtlZeroMemory(p2p, sizeof(HAWK_PRE2POST_CONTEXT));
    p2p->BoundScb = protectedOpenScb;
    *CompletionContext = p2p;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS
HawkPreWriteDispatchProtectedOpen(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    PHAWK_STREAM_HANDLE_CONTEXT shc = NULL;
    FLT_PREOP_CALLBACK_STATUS retValue = FLT_PREOP_SUCCESS_NO_CALLBACK;

    FltGetStreamHandleContext(FltObjects->Instance, fileObject, &shc);
    if (shc == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (shc->IsProtectedOpen)
    {
        retValue = HawkPreWriteHandleProtectedOpen(
            Data, shc, Data->Iopb, CompletionContext);
    }

    FltReleaseContext(shc);
    return retValue;
}

/* Hawkeye TFE: write */
FLT_PREOP_CALLBACK_STATUS
HawkPreWrite(
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
        return HawkPreWriteHandlePlaintextFileObject(Data, FltObjects, CompletionContext);

    return HawkPreWriteDispatchProtectedOpen(Data, FltObjects, CompletionContext);
}

static VOID
HawkPostWriteFreePre2PostDraining(
    __inout PHAWK_PRE2POST_CONTEXT P2pCtx
    )
{

    if (P2pCtx->HandoffPtr != NULL)
        ExFreePoolWithTag(P2pCtx->HandoffPtr, HAWK_POOL_TAG);
    if (P2pCtx->VolumeContext != NULL)
        FltReleaseContext(P2pCtx->VolumeContext);
    if (P2pCtx->IrpContext != NULL)
        HawkDeleteIrpContext(P2pCtx->IrpContext);
    ExFreeToNPagedLookasideList(&g_HawkP2PLookaside, P2pCtx);
}

static VOID
HawkPostWriteFreePlaintextPre2Post(
    __inout PHAWK_PRE2POST_CONTEXT P2pCtx
    )
{

    if (P2pCtx->HandoffPtr != NULL)
        ExFreePoolWithTag(P2pCtx->HandoffPtr, HAWK_POOL_TAG);
    if (P2pCtx->VolumeContext != NULL)
        FltReleaseContext(P2pCtx->VolumeContext);
    if (P2pCtx->IrpContext != NULL)
        HawkDeleteIrpContext(P2pCtx->IrpContext);
    ExFreeToNPagedLookasideList(&g_HawkP2PLookaside, P2pCtx);
}

static VOID
HawkPostWriteFreeProtectedOpenPre2Post(
    __inout PHAWK_PRE2POST_CONTEXT P2pCtx
    )
{

    ExFreeToNPagedLookasideList(&g_HawkP2PLookaside, P2pCtx);
}

static VOID
HawkPostWriteSyncCachedFileSizes(
    __in PHAWK_IRP_CONTEXT IrpCtx,
    __in PHAWK_SCB Scb
    )
{
    PFLT_CALLBACK_DATA data = IrpCtx->CallbackData;
    BOOLEAN nonCachedIo = BooleanFlagOn(data->Iopb->IrpFlags, IRP_NOCACHE);

    if (nonCachedIo &&
         CcIsFileCached(IrpCtx->FileObject) &&
         NT_SUCCESS(data->IoStatus.Status))
    {
        CcSetFileSizes(
            IrpCtx->FileObject,
            (PCC_FILE_SIZES)&Scb->Header.AllocationSize);
    }
}

static FLT_POSTOP_CALLBACK_STATUS
HawkPostWriteCompletePlaintextWrite(
    __in PHAWK_PRE2POST_CONTEXT P2pCtx,
    __in PHAWK_SCB Scb
    )
{
    if (P2pCtx->IrpContext != NULL)
        HawkPostWriteSyncCachedFileSizes(P2pCtx->IrpContext, Scb);
    HawkPostWriteFreePlaintextPre2Post(P2pCtx);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static FLT_POSTOP_CALLBACK_STATUS
HawkPostWriteCompleteProtectedOpen(
    __in PHAWK_PRE2POST_CONTEXT P2pCtx
    )
{
    HawkPostWriteFreeProtectedOpenPre2Post(P2pCtx);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS
HawkPostWrite(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
    PHAWK_PRE2POST_CONTEXT p2pCtx = CompletionContext;
    PHAWK_SCB scb;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Data);
    if (p2pCtx == NULL)
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))
    {
        HawkPostWriteFreePre2PostDraining(p2pCtx);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    scb = HawkResolvePlaintextScbFromFileObject(Data->Iopb->TargetFileObject);
    if (scb != NULL)
        return HawkPostWriteCompletePlaintextWrite(p2pCtx, scb);

    return HawkPostWriteCompleteProtectedOpen(p2pCtx);
}

#define HAWK_WRITE_SHADOW_PURGE_VIEW_BYTES  (256 * 1024)
#define HAWK_WRITE_CIPHER_SECTOR_BYTES      4096

static PVOID
HawkWriteAllocateCipherChunk(
    __out PULONG ChunkSize
    )
{
    static const ULONG chunkSizes[] = { 256 * 1024, 64 * 1024, 16 * 1024, 4 * 1024 };
    ULONG i;

    for (i = 0; i < (ULONG)(sizeof(chunkSizes) / sizeof(chunkSizes[0])); ++i)
    {
        PVOID chunk = ExAllocatePoolWithTag(NonPagedPool, chunkSizes[i], HAWK_POOL_TAG);
        if (chunk != NULL)
        {
            *ChunkSize = chunkSizes[i];
            return chunk;
        }
    }

    *ChunkSize = 0;
    return NULL;
}

static VOID
HawkPurgeShadowRangeComputeSpan(
    __in LONGLONG ShadowOffset,
    __in ULONG Length,
    __out PLONGLONG SpanStart,
    __out PLONGLONG SpanEnd
    )
{
    LONGLONG offset = ShadowOffset;
    const LONGLONG viewMask = (LONGLONG)HAWK_WRITE_SHADOW_PURGE_VIEW_BYTES - 1;

    if (offset < 0)
        offset = 0;

    *SpanStart = offset & ~viewMask;
    *SpanEnd = (offset + Length + viewMask) & ~viewMask;
}

static VOID
HawkPurgeShadowRange(
    __in PFILE_OBJECT Shadow,
    __in LONGLONG ShadowOffset,
    __in ULONG Length
    )
{
    PFSRTL_COMMON_FCB_HEADER shadowFcb;
    LARGE_INTEGER purgeOffset;
    LONGLONG spanStart;
    LONGLONG spanEnd;

    if (Shadow == NULL || Length == 0)
        return;

    shadowFcb = (PFSRTL_COMMON_FCB_HEADER)Shadow->FsContext;
    if (shadowFcb == NULL || shadowFcb->Resource == NULL ||
        Shadow->SectionObjectPointer == NULL)
    {
        return;
    }

    HawkPurgeShadowRangeComputeSpan(ShadowOffset, Length, &spanStart, &spanEnd);
    purgeOffset.QuadPart = spanStart;
    ExAcquireResourceExclusiveLite(shadowFcb->Resource, TRUE);
    CcPurgeCacheSection(
        Shadow->SectionObjectPointer,
        &purgeOffset,
        (ULONG)(spanEnd - spanStart),
        FALSE);
    ExReleaseResourceLite(shadowFcb->Resource);
}

static FLT_IO_OPERATION_FLAGS
HawkWriteCipherChunkedSelectIoFlags(
    __in FLT_IO_OPERATION_FLAGS BaseFlags,
    __in ULONG ChunkLength
    )
{
    FLT_IO_OPERATION_FLAGS ioFlags = BaseFlags;

    if (!BooleanFlagOn(BaseFlags, FLTFL_IO_OPERATION_NON_CACHED))
        return ioFlags;

    if ((ChunkLength & (HAWK_WRITE_CIPHER_SECTOR_BYTES - 1)) != 0)
        ClearFlag(ioFlags, FLTFL_IO_OPERATION_NON_CACHED);

    return ioFlags;
}

static NTSTATUS
HawkWriteCipherChunkedWriteOne(
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT Shadow,
    __in ULONG PlainOffset,
    __in ULONG Done,
    __in ULONG ChunkLength,
    __in PVOID ChunkBuffer,
    __in_bcount(ChunkLength) PUCHAR Source,
    __in FLT_IO_OPERATION_FLAGS BaseFlags,
    __out PULONG BytesWritten
    )
{
    LARGE_INTEGER shadowOffset;
    FLT_IO_OPERATION_FLAGS ioFlags;
    ULONG wrote = 0;
    NTSTATUS status;

    shadowOffset.QuadPart =
        (LONGLONG)PlainOffset + Done + HAWK_FS_HEADER_SIZE + HAWK_FS_KEY_SIZE;
    ioFlags = HawkWriteCipherChunkedSelectIoFlags(BaseFlags, ChunkLength);
    HawkXorEncrypt(
        ChunkBuffer,
        Source,
        PlainOffset + Done,
        ChunkLength,
        (PCHAR)g_HawkCipherKey,
        32);
    status = FltWriteFile(
        Instance,
        Shadow,
        &shadowOffset,
        ChunkLength,
        ChunkBuffer,
        ioFlags,
        &wrote,
        NULL,
        NULL);
    if (!NT_SUCCESS(status))
    {
        *BytesWritten = 0;
        return status;
    }
    if (wrote != ChunkLength)
    {
        *BytesWritten = wrote;
        return STATUS_END_OF_FILE;
    }

    *BytesWritten = wrote;
    return STATUS_SUCCESS;
}

static NTSTATUS
HawkWriteCipherChunked(
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT Shadow,
    __in ULONG PlainOffset,
    __in ULONG Length,
    __in PVOID Plain,
    __in FLT_IO_OPERATION_FLAGS Flags
    )
{
    PVOID chunkBuffer;
    ULONG chunkCapacity;
    ULONG done = 0;
    PUCHAR source = (PUCHAR)Plain;
    NTSTATUS status;

    if (Instance == NULL || Shadow == NULL || Plain == NULL || Length == 0)
        return STATUS_INVALID_PARAMETER;

    chunkBuffer = HawkWriteAllocateCipherChunk(&chunkCapacity);
    if (chunkBuffer == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    while (done < Length)
    {
        ULONG chunkLength = chunkCapacity;
        ULONG bytesWritten;

        if (chunkLength > Length - done)
            chunkLength = Length - done;

        status = HawkWriteCipherChunkedWriteOne(
            Instance,
            Shadow,
            PlainOffset,
            done,
            chunkLength,
            chunkBuffer,
            source + done,
            Flags,
            &bytesWritten);
        if (!NT_SUCCESS(status))
        {
            ExFreePoolWithTag(chunkBuffer, HAWK_POOL_TAG);
            return status;
        }

        done += chunkLength;
    }

    ExFreePoolWithTag(chunkBuffer, HAWK_POOL_TAG);
    return STATUS_SUCCESS;
}

static VOID
HawkBypassCachedTruncateWritePurgePlaintextSection(
    __in PHAWK_SCB Scb
    )
{
    if (Scb->SectionObjectPointers.SharedCacheMap != NULL)
        CcPurgeCacheSection(&Scb->SectionObjectPointers, NULL, 0, FALSE);
}

static NTSTATUS
HawkBypassCachedTruncateWriteCipherToShadow(
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT Shadow,
    __in ULONG StartVbo,
    __in ULONG ByteCount,
    __in PVOID PlainBuf
    )
{
    HawkPurgeShadowRange(
        Shadow,
        (LONGLONG)StartVbo + HAWK_FS_HEADER_SIZE + HAWK_FS_KEY_SIZE,
        ByteCount);

    return HawkWriteCipherChunked(
        Instance,
        Shadow,
        StartVbo,
        ByteCount,
        PlainBuf,
        FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET);
}

static VOID
HawkBypassCachedTruncateWriteApplyPlaintextSizes(
    __in PFILE_OBJECT FileObject,
    __in PHAWK_SCB Scb,
    __in LONGLONG NewSize
    )
{
    Scb->Header.FileSize.QuadPart = NewSize;
    Scb->Header.ValidDataLength.QuadPart = NewSize;
    if (Scb->Header.AllocationSize.QuadPart < NewSize)
        Scb->Header.AllocationSize.QuadPart = NewSize;
    HawkPurgePlaintextCacheTail(FileObject, Scb, NewSize);
}

static NTSTATUS
HawkBypassCachedTruncateWriteSyncShadowEof(
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT Shadow,
    __in LONGLONG NewPlaintextSize
    )
{
    FILE_END_OF_FILE_INFORMATION eofInfo;
    PFSRTL_COMMON_FCB_HEADER shadowFcb;
    LARGE_INTEGER purgeOffset;
    NTSTATUS status;

    eofInfo.EndOfFile.QuadPart = NewPlaintextSize + HAWK_FS_HEADER_SIZE + HAWK_FS_KEY_SIZE;
    status = FltSetInformationFile(
        Instance,
        Shadow,
        &eofInfo,
        sizeof(eofInfo),
        FileEndOfFileInformation);
    if (!NT_SUCCESS(status))
        return status;

    shadowFcb = (PFSRTL_COMMON_FCB_HEADER)Shadow->FsContext;
    if (Shadow->SectionObjectPointer != NULL &&
        shadowFcb != NULL && shadowFcb->Resource != NULL)
    {
        purgeOffset.QuadPart = eofInfo.EndOfFile.QuadPart;
        ExAcquireResourceExclusiveLite(shadowFcb->Resource, TRUE);
        CcPurgeCacheSection(Shadow->SectionObjectPointer, &purgeOffset, 0, FALSE);
        ExReleaseResourceLite(shadowFcb->Resource);
    }

    return STATUS_SUCCESS;
}

static VOID
HawkBypassCachedTruncateWriteSeedPlaintextCache(
    __in PFILE_OBJECT FileObject,
    __in PHAWK_SCB Scb,
    __in ULONG StartVbo,
    __in ULONG ByteCount,
    __in PVOID PlainBuf
    )
{
    if (FileObject->PrivateCacheMap == NULL)
    {
        try
        {
            CcInitializeCacheMap(
                FileObject,
                (PCC_FILE_SIZES)&Scb->Header.AllocationSize,
                FALSE,
                &g_HawkCcCallbacks,
                Scb);
        }
        except (STATUS_INSUFFICIENT_RESOURCES)
        {
        }
    }

    if (FileObject->PrivateCacheMap != NULL && ByteCount > 0)
    {
        LARGE_INTEGER writeOffset;

        writeOffset.QuadPart = StartVbo;
        CcCopyWrite(FileObject, &writeOffset, ByteCount, TRUE, PlainBuf);
    }
}

/* Hawkeye TFE: BypassTrunc */
static NTSTATUS
HawkBypassCachedTruncateWrite(
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject,
    __in PFILE_OBJECT Shadow,
    __in PHAWK_SCB Scb,
    __inout PHAWK_STREAM_HANDLE_CONTEXT Shc,
    __in ULONG StartVbo,
    __in ULONG ByteCount,
    __in PVOID PlainBuf
    )
{
    LONGLONG newSize;
    NTSTATUS status;

    HawkBypassCachedTruncateWritePurgePlaintextSection(Scb);

    status = HawkBypassCachedTruncateWriteCipherToShadow(
        Instance, Shadow, StartVbo, ByteCount, PlainBuf);
    if (!NT_SUCCESS(status))
        return status;

    newSize = (LONGLONG)StartVbo + ByteCount;
    HawkBypassCachedTruncateWriteApplyPlaintextSizes(FileObject, Scb, newSize);

    status = HawkBypassCachedTruncateWriteSyncShadowEof(Instance, Shadow, newSize);
    if (!NT_SUCCESS(status))
        return status;

    if (Shc != NULL)
        Shc->PlaintextValidLength = newSize;

    HawkSyncPlaintextCachesForScb(Scb);
    HawkBypassCachedTruncateWriteSeedPlaintextCache(
        FileObject, Scb, StartVbo, ByteCount, PlainBuf);
    return STATUS_SUCCESS;
}

static VOID
HawkDropWritePagingLock(
    __in PHAWK_SCB Scb,
    __inout PBOOLEAN PagingHeld
    )
{
    if (*PagingHeld)
    {
        ExReleaseResourceLite(Scb->Header.PagingIoResource);
        *PagingHeld = FALSE;
    }
}

static VOID
HawkDropWriteMainLock(
    __in PHAWK_SCB Scb,
    __inout PBOOLEAN MainHeld
    )
{
    if (*MainHeld)
    {
        ExReleaseResourceLite(Scb->Header.Resource);
        *MainHeld = FALSE;
    }
}

static VOID
HawkDropWriteLocks(
    __in PHAWK_SCB Scb,
    __inout PBOOLEAN MainHeld,
    __inout PBOOLEAN PagingHeld
    )
{
    HawkDropWritePagingLock(Scb, PagingHeld);
    HawkDropWriteMainLock(Scb, MainHeld);
}

static VOID
HawkReacquireWriteMainLock(
    __in PHAWK_SCB Scb,
    __in BOOLEAN MainHeld,
    __in BOOLEAN MainExclusive,
    __out PBOOLEAN MainOut
    )
{
    if (MainHeld)
    {
        if (MainExclusive)
            ExAcquireResourceExclusiveLite(Scb->Header.Resource, TRUE);
        else
            ExAcquireResourceSharedLite(Scb->Header.Resource, TRUE);
        *MainOut = TRUE;
    }
    else
    {
        *MainOut = FALSE;
    }
}

static VOID
HawkReacquireWritePagingLock(
    __in PHAWK_SCB Scb,
    __in BOOLEAN PagingHeld,
    __out PBOOLEAN PagingOut
    )
{
    if (PagingHeld)
    {
        ExAcquireResourceSharedLite(Scb->Header.PagingIoResource, TRUE);
        *PagingOut = TRUE;
    }
    else
    {
        *PagingOut = FALSE;
    }
}

static VOID
HawkReacquireWriteLocks(
    __in PHAWK_SCB Scb,
    __in BOOLEAN MainHeld,
    __in BOOLEAN MainExclusive,
    __in BOOLEAN PagingHeld,
    __out PBOOLEAN MainOut,
    __out PBOOLEAN PagingOut
    )
{
    HawkReacquireWriteMainLock(Scb, MainHeld, MainExclusive, MainOut);
    HawkReacquireWritePagingLock(Scb, PagingHeld, PagingOut);
}

FLT_PREOP_CALLBACK_STATUS
HawkPreMdlWrite(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    if (FLT_IS_FASTIO_OPERATION(Data))
        return FLT_PREOP_DISALLOW_FASTIO;

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
HawkPreMdlWriteComplete(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    if (FLT_IS_FASTIO_OPERATION(Data))
        return FLT_PREOP_DISALLOW_FASTIO;

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

typedef struct _HAWK_COMMON_WRITE_CTX
{
    PHAWK_IRP_CONTEXT IrpContext;
    PVOID *CompletionContext;
    PFLT_CALLBACK_DATA Data;
    PFLT_IO_PARAMETER_BLOCK Iopb;
    PHAWK_FLT_OBJECTS FltObjects;
    PFILE_OBJECT FileObject;
    PHAWK_SCB Scb;
    PHAWK_STREAM_HANDLE_CONTEXT StreamHandleContext;
    BOOLEAN Wait;
    BOOLEAN PagingIo;
    BOOLEAN NonCachedIo;
    BOOLEAN SynchronousIo;
    BOOLEAN ExtendingFile;
    BOOLEAN ExtendingValidData;
    BOOLEAN WriteToEof;
    BOOLEAN PostOperation;
    BOOLEAN OplockPostOperation;
    BOOLEAN ScbAcquired;
    BOOLEAN ScbAcquiredExclusive;
    BOOLEAN PagingIoResourceAcquired;
    BOOLEAN ScbCanDemoteToShared;
    BOOLEAN CalledByLazyWriter;
    LARGE_INTEGER StartOffset;
    ULONG StartVbo;
    ULONG ByteCount;
    ULONG WriteLen;
    ULONG ValidDataLength;
    ULONG FileSize;
    ULONG InitFileSize;
    PVOID OrigBuf;
    PVOID NewBuf;
    PMDL NewMdl;
    PHAWK_PRE2POST_CONTEXT P2pCtx;
    PHAWK_VOLUME_CONTEXT VolCtx;
    NTSTATUS Status;
    FLT_PREOP_CALLBACK_STATUS RetValue;
} HAWK_COMMON_WRITE_CTX, *PHAWK_COMMON_WRITE_CTX;

static VOID
HawkCommonWriteInitCtx(
    __in PHAWK_IRP_CONTEXT IrpContext,
    __inout PVOID *CompletionContext,
    __out PHAWK_COMMON_WRITE_CTX Ctx
    )
{
    PFLT_CALLBACK_DATA data = IrpContext->CallbackData;
    PFLT_IO_PARAMETER_BLOCK iopb = data->Iopb;
    PFILE_OBJECT fileObject = iopb->TargetFileObject;

    RtlZeroMemory(Ctx, sizeof(HAWK_COMMON_WRITE_CTX));
    Ctx->IrpContext = IrpContext;
    Ctx->CompletionContext = CompletionContext;
    Ctx->Data = data;
    Ctx->Iopb = iopb;
    Ctx->FltObjects = &IrpContext->RelatedObjects;
    Ctx->FileObject = fileObject;
    Ctx->Scb = IrpContext->FileObject->FsContext;
    Ctx->StreamHandleContext =
        (PHAWK_STREAM_HANDLE_CONTEXT)IrpContext->FileObject->FsContext2;
    Ctx->Wait = BooleanFlagOn(IrpContext->Flags, HAWK_IRP_CTX_FLAG_WAIT);
    Ctx->PagingIo = BooleanFlagOn(iopb->IrpFlags, IRP_PAGING_IO);
    Ctx->NonCachedIo = BooleanFlagOn(iopb->IrpFlags, IRP_NOCACHE);
    Ctx->SynchronousIo = BooleanFlagOn(fileObject->Flags, FO_SYNCHRONOUS_IO);
    Ctx->ByteCount = iopb->Parameters.Write.Length;
    Ctx->RetValue = FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static BOOLEAN
HawkCommonWriteHandleEntry(
    __inout PHAWK_COMMON_WRITE_CTX Ctx
    )
{
    if (Ctx->StreamHandleContext == NULL)
    {
        Ctx->Data->IoStatus.Status = STATUS_INVALID_PARAMETER;
        Ctx->Data->IoStatus.Information = 0;
        Ctx->RetValue = FLT_PREOP_COMPLETE;
        return TRUE;
    }

    if (Ctx->ByteCount == 0)
    {
        Ctx->StartOffset = Ctx->Iopb->Parameters.Write.ByteOffset;
        Ctx->StartVbo = Ctx->StartOffset.LowPart;
        if (!Ctx->PagingIo && Ctx->StartVbo == 0)
            Ctx->StreamHandleContext->ZeroLengthCommitted = TRUE;
        Ctx->Data->IoStatus.Information = 0;
        Ctx->Data->IoStatus.Status = STATUS_SUCCESS;
        Ctx->RetValue = FLT_PREOP_COMPLETE;
        return TRUE;
    }

    if (FlagOn(Ctx->Data->Flags, FLTFL_CALLBACK_DATA_IRP_OPERATION) &&
        Ctx->NonCachedIo &&
        FlagOn(Ctx->IrpContext->Flags, HAWK_IRP_CTX_FLAG_IN_FSP) &&
        Ctx->CompletionContext != NULL &&
        *Ctx->CompletionContext != NULL)
    {
        Ctx->Data->IoStatus.Status = STATUS_INVALID_PARAMETER;
        Ctx->Data->IoStatus.Information = 0;
        Ctx->RetValue = FLT_PREOP_COMPLETE;
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN
HawkCommonWriteTryDeferCachedWrite(
    __inout PHAWK_COMMON_WRITE_CTX Ctx
    )
{
    if (Ctx->NonCachedIo ||
         CcCanIWrite(
            Ctx->FileObject,
            Ctx->ByteCount,
            (Ctx->Wait && !BooleanFlagOn(Ctx->IrpContext->Flags, HAWK_IRP_CTX_FLAG_IN_FSP)),
            BooleanFlagOn(Ctx->IrpContext->Flags, HAWK_IRP_CTX_FLAG_DEFERRED_WRITE)))
    {
        return FALSE;
    }

    if (!FLT_IS_IRP_OPERATION(Ctx->Data))
    {
        Ctx->Data->IoStatus.Status = STATUS_INVALID_PARAMETER;
        Ctx->Data->IoStatus.Information = 0;
        Ctx->RetValue = FLT_PREOP_COMPLETE;
        return TRUE;
    }

    if (Ctx->Iopb->Parameters.Write.MdlAddress != NULL)
    {
        Ctx->Data->IoStatus.Status = STATUS_INVALID_PARAMETER;
        Ctx->Data->IoStatus.Information = 0;
        Ctx->RetValue = FLT_PREOP_COMPLETE;
        return TRUE;
    }

    Ctx->Status = FltLockUserBuffer(Ctx->Data);
    if (!NT_SUCCESS(Ctx->Status))
    {
        Ctx->Data->IoStatus.Status = Ctx->Status;
        Ctx->Data->IoStatus.Information = 0;
        Ctx->RetValue = FLT_PREOP_COMPLETE;
        return TRUE;
    }

    {
        BOOLEAN retrying = FlagOn(Ctx->IrpContext->Flags, HAWK_IRP_CTX_FLAG_DEFERRED_WRITE);

        SetFlag(Ctx->IrpContext->Flags, HAWK_IRP_CTX_FLAG_DEFERRED_WRITE);
        CcDeferWrite(
            Ctx->FileObject,
            (PCC_POST_DEFERRED_WRITE)HawkQueueFspWorkItem,
            Ctx->IrpContext,
            NULL,
            Ctx->ByteCount,
            retrying);
    }
    Ctx->Data->IoStatus.Status = STATUS_PENDING;
    Ctx->RetValue = FLT_PREOP_PENDING;
    return TRUE;
}

static BOOLEAN
HawkCommonWriteAllocatePre2PostIfNeeded(
    __inout PHAWK_COMMON_WRITE_CTX Ctx
    )
{
    if (!Ctx->NonCachedIo)
        return TRUE;

    Ctx->P2pCtx = ExAllocateFromNPagedLookasideList(&g_HawkP2PLookaside);
    if (Ctx->P2pCtx != NULL)
        return TRUE;

    Ctx->Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
    Ctx->Data->IoStatus.Information = 0;
    Ctx->RetValue = FLT_PREOP_COMPLETE;
    return FALSE;
}

static BOOLEAN
HawkCommonWriteFlushBeforeNonCached(
    __inout PHAWK_COMMON_WRITE_CTX Ctx
    )
{
    if (!Ctx->NonCachedIo || Ctx->PagingIo ||
         (Ctx->FileObject->SectionObjectPointer->DataSectionObject == NULL))
    {
        return TRUE;
    }

    if (!ExAcquireResourceExclusiveLite(Ctx->Scb->Header.Resource, Ctx->Wait))
    {
        Ctx->PostOperation = TRUE;
        Ctx->RetValue = FLT_PREOP_PENDING;
        return FALSE;
    }

    Ctx->ScbAcquired = TRUE;
    Ctx->ScbAcquiredExclusive = TRUE;
    ExAcquireSharedStarveExclusive(Ctx->Scb->Header.PagingIoResource, TRUE);
    CcFlushCache(
        &Ctx->Scb->SectionObjectPointers,
        NULL,
        0,
        (PIO_STATUS_BLOCK)&Ctx->Data->IoStatus.Status);
    ExReleaseResourceLite(Ctx->Scb->Header.PagingIoResource);
    if (!NT_SUCCESS(Ctx->Data->IoStatus.Status))
    {
        Ctx->RetValue = FLT_PREOP_COMPLETE;
        return FALSE;
    }

    ExAcquireResourceExclusiveLite(Ctx->Scb->Header.PagingIoResource, TRUE);
    Ctx->PagingIoResourceAcquired = TRUE;
    CcPurgeCacheSection(&Ctx->Scb->SectionObjectPointers, NULL, 0, FALSE);
    Ctx->ScbCanDemoteToShared = TRUE;
    return TRUE;
}

static BOOLEAN
HawkCommonWriteAcquireLocks(
    __inout PHAWK_COMMON_WRITE_CTX Ctx
    )
{
    if (Ctx->PagingIo)
    {
        ExAcquireResourceSharedLite(Ctx->Scb->Header.PagingIoResource, TRUE);
        Ctx->PagingIoResourceAcquired = TRUE;
        return TRUE;
    }

    if (!Ctx->Wait && Ctx->NonCachedIo)
    {
        if (!Ctx->ScbAcquired &&
             !ExAcquireSharedWaitForExclusive(Ctx->Scb->Header.Resource, Ctx->Wait))
        {
            Ctx->RetValue = FLT_PREOP_PENDING;
            return FALSE;
        }
    }
    else
    {
        if (!Ctx->ScbAcquired &&
             !ExAcquireResourceSharedLite(Ctx->Scb->Header.Resource, Ctx->Wait))
        {
            Ctx->RetValue = FLT_PREOP_PENDING;
            return FALSE;
        }
    }

    Ctx->ScbAcquired = TRUE;
    return TRUE;
}

static BOOLEAN
HawkCommonWritePreparePagingAndVdlExtend(
    __inout PHAWK_COMMON_WRITE_CTX Ctx
    )
{
    Ctx->FileSize = Ctx->Scb->Header.FileSize.LowPart;
    Ctx->ValidDataLength = Ctx->Scb->Header.ValidDataLength.LowPart;
    if (Ctx->PagingIo)
    {
        if (Ctx->StartVbo >= Ctx->FileSize)
        {
            Ctx->Data->IoStatus.Information = 0;
            Ctx->Data->IoStatus.Status = STATUS_SUCCESS;
            Ctx->RetValue = FLT_PREOP_COMPLETE;
            return FALSE;
        }
        if (Ctx->ByteCount > Ctx->FileSize - Ctx->StartVbo)
            Ctx->ByteCount = Ctx->FileSize - Ctx->StartVbo;
    }

    Ctx->CalledByLazyWriter = (Ctx->Scb->LazyWriterThread == PsGetCurrentThread());
    if (!Ctx->CalledByLazyWriter &&
         (Ctx->WriteToEof || (Ctx->StartVbo + Ctx->ByteCount > Ctx->ValidDataLength)))
    {
        if (Ctx->PagingIo)
        {
            ExReleaseResourceLite(Ctx->Scb->Header.PagingIoResource);
            Ctx->PagingIoResourceAcquired = FALSE;
        }
        else if (!Ctx->ScbAcquiredExclusive)
        {
            ExReleaseResourceLite(Ctx->Scb->Header.Resource);
            Ctx->ScbAcquired = FALSE;
            if (!ExAcquireResourceExclusiveLite(Ctx->Scb->Header.Resource, Ctx->Wait))
            {
                Ctx->RetValue = FLT_PREOP_PENDING;
                return FALSE;
            }
            Ctx->ScbAcquired = TRUE;
            Ctx->ScbAcquiredExclusive = TRUE;
        }

        if (Ctx->PagingIo)
        {
            if (Ctx->StartVbo >= Ctx->FileSize)
            {
                Ctx->Data->IoStatus.Information = 0;
                Ctx->Data->IoStatus.Status = STATUS_SUCCESS;
                Ctx->RetValue = FLT_PREOP_COMPLETE;
                return FALSE;
            }
            if (Ctx->ByteCount > Ctx->FileSize - Ctx->StartVbo)
                Ctx->ByteCount = Ctx->FileSize - Ctx->StartVbo;
        }
    }

    Ctx->InitFileSize = Ctx->FileSize;
    if (Ctx->WriteToEof)
    {
        Ctx->StartVbo = Ctx->FileSize;
        Ctx->StartOffset = Ctx->Scb->Header.FileSize;
    }

    return TRUE;
}

static BOOLEAN
HawkCommonWriteCheckOplockAndFileLock(
    __inout PHAWK_COMMON_WRITE_CTX Ctx
    )
{
    FLT_PREOP_CALLBACK_STATUS oplockStatus;

    if (Ctx->PagingIo)
        return TRUE;

    oplockStatus = FltCheckOplock(&Ctx->Scb->Lock.Oplock, Ctx->Data, NULL, NULL, NULL);
    if (oplockStatus == FLT_PREOP_PENDING || oplockStatus == FLT_PREOP_COMPLETE)
    {
        Ctx->RetValue = oplockStatus;
        return FALSE;
    }

    if (!FltCheckLockForWriteAccess(&Ctx->Scb->Lock.FileLock, Ctx->Data))
    {
        Ctx->Data->IoStatus.Status = STATUS_FILE_LOCK_CONFLICT;
        Ctx->RetValue = FLT_PREOP_COMPLETE;
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN
HawkCommonWriteExtendShadowEofIfNeeded(
    __inout PHAWK_COMMON_WRITE_CTX Ctx
    )
{
    FILE_END_OF_FILE_INFORMATION fileEofInfo;

    if (Ctx->PagingIo || (Ctx->StartVbo + Ctx->ByteCount <= Ctx->FileSize))
        return TRUE;

    Ctx->ExtendingFile = TRUE;
    Ctx->FileSize = Ctx->StartVbo + Ctx->ByteCount;
    fileEofInfo.EndOfFile.QuadPart =
        Ctx->FileSize + HAWK_FS_HEADER_SIZE + HAWK_FS_KEY_SIZE;
    Ctx->Status = FltSetInformationFile(
        Ctx->FltObjects->Instance,
        Ctx->StreamHandleContext->ShadowFileObject,
        &fileEofInfo,
        sizeof(FILE_END_OF_FILE_INFORMATION),
        FileEndOfFileInformation);
    if (!NT_SUCCESS(Ctx->Status))
    {
        Ctx->ExtendingFile = FALSE;
        Ctx->FileSize = Ctx->Scb->Header.FileSize.LowPart;
        DBG_PRINT(
            "HawkeyeTfe!CommonWrite: failed to extend shadow end-of-file, status=0x%08X, FileObject=%p, length=%u",
            Ctx->Status,
            Ctx->FileObject,
            Ctx->StartVbo + Ctx->ByteCount);
        Ctx->Data->IoStatus.Status = Ctx->Status;
        Ctx->Data->IoStatus.Information = 0;
        Ctx->RetValue = FLT_PREOP_COMPLETE;
        return FALSE;
    }

    Ctx->Scb->Header.FileSize.QuadPart = Ctx->FileSize;
    Ctx->Scb->Header.AllocationSize.QuadPart =
        ((PFSRTL_COMMON_FCB_HEADER)
            Ctx->StreamHandleContext->ShadowFileObject->FsContext)->AllocationSize.QuadPart;
    if (Ctx->Scb->Header.AllocationSize.QuadPart < Ctx->Scb->Header.FileSize.QuadPart)
        Ctx->Scb->Header.AllocationSize.QuadPart = Ctx->Scb->Header.FileSize.QuadPart;
    if (CcIsFileCached(Ctx->FileObject))
        CcSetFileSizes(Ctx->FileObject, (PCC_FILE_SIZES)&Ctx->Scb->Header.AllocationSize);

    return TRUE;
}

static VOID
HawkCommonWriteUpdateVdlAndMaybeDemoteScb(
    __inout PHAWK_COMMON_WRITE_CTX Ctx
    )
{
    if (!Ctx->CalledByLazyWriter &&
         (Ctx->StartVbo + Ctx->ByteCount > Ctx->ValidDataLength))
    {
        Ctx->ExtendingValidData = TRUE;
    }
    else if (Ctx->ScbCanDemoteToShared)
    {
        if (Ctx->ScbAcquiredExclusive &&
            ExIsResourceAcquiredExclusiveLite(Ctx->Scb->Header.Resource))
        {
            ExConvertExclusiveToSharedLite(Ctx->Scb->Header.Resource);
            Ctx->ScbAcquiredExclusive = FALSE;
        }
    }

    if (Ctx->ExtendingValidData)
        Ctx->ValidDataLength = Ctx->StartVbo + Ctx->ByteCount;

    if (Ctx->Iopb->Parameters.Write.MdlAddress)
    {
        Ctx->OrigBuf = MmGetSystemAddressForMdlSafe(
            Ctx->Iopb->Parameters.Write.MdlAddress, NormalPagePriority);
    }
    else
    {
        Ctx->OrigBuf = Ctx->Iopb->Parameters.Write.WriteBuffer;
    }
}

static VOID
HawkCommonWriteCompletePassiveCipher(
    __inout PHAWK_COMMON_WRITE_CTX Ctx,
    __in PFILE_OBJECT Shadow,
    __in BOOLEAN UpdateCacheSizes
    )
{
    BOOLEAN heldMain = Ctx->ScbAcquired;
    BOOLEAN heldExclusive = Ctx->ScbAcquiredExclusive;
    BOOLEAN heldPaging = Ctx->PagingIoResourceAcquired;

    HawkDropWriteLocks(Ctx->Scb, &Ctx->ScbAcquired, &Ctx->PagingIoResourceAcquired);
    HawkPurgeShadowRange(
        Shadow,
        (LONGLONG)Ctx->StartVbo + HAWK_FS_HEADER_SIZE + HAWK_FS_KEY_SIZE,
        Ctx->ByteCount);
    Ctx->Status = HawkWriteCipherChunked(
        Ctx->FltObjects->Instance,
        Shadow,
        Ctx->StartVbo,
        Ctx->ByteCount,
        Ctx->OrigBuf,
        FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET);
    HawkReacquireWriteLocks(
        Ctx->Scb,
        heldMain,
        heldExclusive,
        heldPaging,
        &Ctx->ScbAcquired,
        &Ctx->PagingIoResourceAcquired);
    if (!NT_SUCCESS(Ctx->Status))
    {
        Ctx->ExtendingFile = FALSE;
        Ctx->ExtendingValidData = FALSE;
        Ctx->Data->IoStatus.Status = Ctx->Status;
        Ctx->Data->IoStatus.Information = 0;
    }
    else
    {
        Ctx->Data->IoStatus.Status = STATUS_SUCCESS;
        Ctx->Data->IoStatus.Information = Ctx->ByteCount;
        if (UpdateCacheSizes &&
             !Ctx->PagingIo &&
             CcIsFileCached(Ctx->IrpContext->FileObject))
        {
            CcSetFileSizes(
                Ctx->IrpContext->FileObject,
                (PCC_FILE_SIZES)&Ctx->Scb->Header.AllocationSize);
        }
    }

    Ctx->RetValue = FLT_PREOP_COMPLETE;
}

static VOID
HawkCommonWriteDispatchNonCached(
    __inout PHAWK_COMMON_WRITE_CTX Ctx
    )
{
    PFILE_OBJECT shadow = Ctx->StreamHandleContext->ShadowFileObject;

    if (!Ctx->OrigBuf || !shadow)
    {
        Ctx->Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Ctx->Data->IoStatus.Information = 0;
        Ctx->RetValue = FLT_PREOP_COMPLETE;
        return;
    }

    if (KeGetCurrentIrql() == PASSIVE_LEVEL && !Ctx->PagingIo)
    {
        HawkCommonWriteCompletePassiveCipher(Ctx, shadow, TRUE);
        return;
    }

    Ctx->Status = FltGetVolumeContext(
        Ctx->FltObjects->Filter, Ctx->FltObjects->Volume, &Ctx->VolCtx);
    if (!NT_SUCCESS(Ctx->Status) || !Ctx->VolCtx)
    {
        Ctx->Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Ctx->Data->IoStatus.Information = 0;
        Ctx->RetValue = FLT_PREOP_COMPLETE;
        return;
    }

    Ctx->WriteLen = (ULONG)ROUND_TO_SIZE(Ctx->ByteCount, Ctx->VolCtx->SectorSize);
    if (Ctx->WriteLen > 1024 * 1024)
    {
        FltReleaseContext(Ctx->VolCtx);
        Ctx->VolCtx = NULL;
        if (KeGetCurrentIrql() == PASSIVE_LEVEL)
        {
            HawkCommonWriteCompletePassiveCipher(Ctx, shadow, FALSE);
            return;
        }

        Ctx->Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Ctx->Data->IoStatus.Information = 0;
        Ctx->RetValue = FLT_PREOP_COMPLETE;
        return;
    }

    Ctx->NewBuf = ExAllocatePoolWithTag(NonPagedPool, Ctx->WriteLen, HAWK_POOL_TAG);
    if (!Ctx->NewBuf)
    {
        FltReleaseContext(Ctx->VolCtx);
        Ctx->Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Ctx->Data->IoStatus.Information = 0;
        Ctx->RetValue = FLT_PREOP_COMPLETE;
        return;
    }

    Ctx->NewMdl = IoAllocateMdl(Ctx->NewBuf, Ctx->WriteLen, FALSE, FALSE, NULL);
    if (!Ctx->NewMdl)
    {
        ExFreePoolWithTag(Ctx->NewBuf, HAWK_POOL_TAG);
        FltReleaseContext(Ctx->VolCtx);
        Ctx->Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Ctx->Data->IoStatus.Information = 0;
        Ctx->RetValue = FLT_PREOP_COMPLETE;
        return;
    }

    MmBuildMdlForNonPagedPool(Ctx->NewMdl);
    if (KeGetCurrentIrql() == PASSIVE_LEVEL)
    {
        HawkPurgeShadowRange(
            shadow,
            (LONGLONG)Ctx->StartVbo + HAWK_FS_HEADER_SIZE + HAWK_FS_KEY_SIZE,
            Ctx->ByteCount);
    }

    RtlZeroMemory(Ctx->NewBuf, Ctx->WriteLen);
    HawkXorEncrypt(
        Ctx->NewBuf,
        Ctx->OrigBuf,
        (ULONG)Ctx->Iopb->Parameters.Write.ByteOffset.QuadPart,
        Ctx->ByteCount,
        (PCHAR)g_HawkCipherKey,
        32);
    Ctx->Iopb->TargetFileObject = shadow;
    Ctx->Iopb->Parameters.Write.Length = Ctx->ByteCount;
    Ctx->Iopb->Parameters.Write.ByteOffset.QuadPart +=
        HAWK_FS_HEADER_SIZE + HAWK_FS_KEY_SIZE;
    Ctx->Iopb->Parameters.Write.WriteBuffer = Ctx->NewBuf;
    Ctx->Iopb->Parameters.Write.MdlAddress = Ctx->NewMdl;
    FltSetCallbackDataDirty(Ctx->Data);
    Ctx->RetValue = FLT_PREOP_SUCCESS_WITH_CALLBACK;
    Ctx->P2pCtx->HandoffPtr = Ctx->NewBuf;
    Ctx->P2pCtx->VolumeContext = Ctx->VolCtx;
    Ctx->P2pCtx->IrpContext = Ctx->IrpContext;
    *Ctx->CompletionContext = Ctx->P2pCtx;
}

static BOOLEAN
HawkCommonWriteAcquireCachedExclusiveLock(
    __inout PHAWK_COMMON_WRITE_CTX Ctx
    )
{
    if (Ctx->NonCachedIo || Ctx->PagingIo)
        return TRUE;

    if (Ctx->ScbAcquired && !Ctx->ScbAcquiredExclusive)
    {
        ExReleaseResourceLite(Ctx->Scb->Header.Resource);
        Ctx->ScbAcquired = FALSE;
        if (!ExAcquireResourceExclusiveLite(Ctx->Scb->Header.Resource, Ctx->Wait))
        {
            Ctx->RetValue = FLT_PREOP_PENDING;
            return FALSE;
        }
        Ctx->ScbAcquired = TRUE;
        Ctx->ScbAcquiredExclusive = TRUE;
    }
    else if (!Ctx->ScbAcquired)
    {
        if (!ExAcquireResourceExclusiveLite(Ctx->Scb->Header.Resource, Ctx->Wait))
        {
            Ctx->RetValue = FLT_PREOP_PENDING;
            return FALSE;
        }
        Ctx->ScbAcquired = TRUE;
        Ctx->ScbAcquiredExclusive = TRUE;
    }

    return TRUE;
}

static BOOLEAN
HawkCommonWritePrepareCachedPath(
    __inout PHAWK_COMMON_WRITE_CTX Ctx
    )
{
    Ctx->FileObject = Ctx->IrpContext->FileObject;
    Ctx->FileSize = Ctx->Scb->Header.FileSize.LowPart;

    if (FlagOn(Ctx->Data->Flags, FLTFL_CALLBACK_DATA_IRP_OPERATION))
    {
        Ctx->Status = FltLockUserBuffer(Ctx->Data);
        if (!NT_SUCCESS(Ctx->Status))
        {
            Ctx->Data->IoStatus.Status = Ctx->Status;
            Ctx->Data->IoStatus.Information = 0;
            Ctx->RetValue = FLT_PREOP_COMPLETE;
            return FALSE;
        }

        if (Ctx->Iopb->Parameters.Write.MdlAddress)
        {
            Ctx->OrigBuf = MmGetSystemAddressForMdlSafe(
                Ctx->Iopb->Parameters.Write.MdlAddress, NormalPagePriority);
        }
        else
        {
            Ctx->OrigBuf = Ctx->Iopb->Parameters.Write.WriteBuffer;
        }
    }

    if (Ctx->ByteCount > 0 && Ctx->OrigBuf == NULL)
    {
        Ctx->Data->IoStatus.Status = STATUS_INVALID_USER_BUFFER;
        Ctx->Data->IoStatus.Information = 0;
        Ctx->RetValue = FLT_PREOP_COMPLETE;
        return FALSE;
    }

    if (!Ctx->NonCachedIo &&
         !Ctx->PagingIo &&
         KeGetCurrentIrql() == PASSIVE_LEVEL &&
         Ctx->StreamHandleContext->ShadowFileObject &&
         HawkShouldBypassCachedTruncateWrite(
            Ctx->Scb->Header.FileSize.QuadPart, Ctx->StartVbo, Ctx->ByteCount))
    {
        Ctx->Status = HawkBypassCachedTruncateWrite(
            Ctx->FltObjects->Instance,
            Ctx->FileObject,
            Ctx->StreamHandleContext->ShadowFileObject,
            Ctx->Scb,
            Ctx->StreamHandleContext,
            Ctx->StartVbo,
            Ctx->ByteCount,
            Ctx->OrigBuf);
        if (!NT_SUCCESS(Ctx->Status))
        {
            Ctx->Data->IoStatus.Status = Ctx->Status;
            Ctx->Data->IoStatus.Information = 0;
        }
        else
        {
            Ctx->Data->IoStatus.Status = STATUS_SUCCESS;
            Ctx->Data->IoStatus.Information = Ctx->ByteCount;
        }
        Ctx->RetValue = FLT_PREOP_COMPLETE;
        return FALSE;
    }

    if (Ctx->FileObject->PrivateCacheMap == NULL)
    {
        try
        {
            CcInitializeCacheMap(
                Ctx->FileObject,
                (PCC_FILE_SIZES)&Ctx->Scb->Header.AllocationSize,
                FALSE,
                &g_HawkCcCallbacks,
                Ctx->Scb);
            CcSetReadAheadGranularity(Ctx->FileObject, HAWK_READ_AHEAD_GRANULARITY);
        }
        except (STATUS_INSUFFICIENT_RESOURCES)
        {
        }
    }

    if (Ctx->FileObject->PrivateCacheMap == NULL)
    {
        Ctx->Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Ctx->Data->IoStatus.Information = 0;
        Ctx->RetValue = FLT_PREOP_COMPLETE;
        return FALSE;
    }

    HawkPreparePlaintextCachedWrite(
        Ctx->FileObject,
        Ctx->Scb,
        Ctx->StreamHandleContext,
        Ctx->StartVbo,
        Ctx->ByteCount);
    Ctx->FileSize = Ctx->Scb->Header.FileSize.LowPart;
    if (!Ctx->ExtendingFile &&
         !Ctx->ExtendingValidData &&
         (Ctx->StartVbo + Ctx->ByteCount > Ctx->FileSize))
    {
        if (Ctx->StartVbo >= Ctx->FileSize)
        {
            Ctx->Data->IoStatus.Information = 0;
            Ctx->Data->IoStatus.Status = STATUS_SUCCESS;
            Ctx->RetValue = FLT_PREOP_COMPLETE;
            return FALSE;
        }

        Ctx->ByteCount = Ctx->FileSize - Ctx->StartVbo;
        Ctx->Iopb->Parameters.Write.Length = Ctx->ByteCount;
    }

    if (Ctx->Iopb->Parameters.Write.ByteOffset.LowPart >
         Ctx->Scb->Header.ValidDataLength.LowPart)
    {
        CcZeroData(
            Ctx->FileObject,
            &Ctx->Scb->Header.ValidDataLength,
            &Ctx->Iopb->Parameters.Write.ByteOffset,
            Ctx->Wait);
    }

    if (!FlagOn(Ctx->Iopb->MinorFunction, IRP_MN_MDL))
    {
        if (!CcCopyWrite(
                Ctx->FileObject,
                &Ctx->Iopb->Parameters.Write.ByteOffset,
                Ctx->Iopb->Parameters.Write.Length,
                Ctx->Wait,
                Ctx->OrigBuf))
        {
            Ctx->PostOperation = TRUE;
            Ctx->RetValue = FLT_PREOP_PENDING;
            return FALSE;
        }

        Ctx->Data->IoStatus.Information = Ctx->Data->Iopb->Parameters.Write.Length;
        Ctx->Data->IoStatus.Status = STATUS_SUCCESS;
        if (Ctx->StreamHandleContext->ShadowFileObject)
        {
            if (Ctx->StartVbo == 0)
            {
                Ctx->StreamHandleContext->PlaintextValidLength =
                    (LONGLONG)Ctx->ByteCount;
            }
            else if (Ctx->StreamHandleContext->PlaintextValidLength ==
                      (LONGLONG)Ctx->StartVbo)
            {
                Ctx->StreamHandleContext->PlaintextValidLength =
                    (LONGLONG)Ctx->StartVbo + Ctx->ByteCount;
            }
        }
    }
    else
    {
        if (!Ctx->Wait)
        {
            Ctx->Data->IoStatus.Status = STATUS_INVALID_PARAMETER;
            Ctx->Data->IoStatus.Information = 0;
            Ctx->RetValue = FLT_PREOP_COMPLETE;
            return FALSE;
        }

        CcPrepareMdlWrite(
            Ctx->FileObject,
            &Ctx->Iopb->Parameters.Write.ByteOffset,
            Ctx->Iopb->Parameters.Write.Length,
            &Ctx->Iopb->Parameters.Write.MdlAddress,
            &Ctx->Data->IoStatus);
    }

    Ctx->RetValue = FLT_PREOP_COMPLETE;
    return TRUE;
}

static FLT_PREOP_CALLBACK_STATUS
HawkCommonWriteCleanup(
    __inout PHAWK_COMMON_WRITE_CTX Ctx
    )
{
    FILE_VALID_DATA_LENGTH_INFORMATION fileVdlInfo;

    if (!Ctx->PostOperation)
    {
        if (Ctx->SynchronousIo && !Ctx->PagingIo && Ctx->IrpContext->FileObject)
        {
            Ctx->IrpContext->FileObject->CurrentByteOffset.QuadPart =
                (LONGLONG)Ctx->StartVbo + Ctx->Iopb->Parameters.Write.Length;
        }

        if (Ctx->ExtendingFile)
            SetFlag(Ctx->Iopb->TargetFileObject->Flags, FO_FILE_SIZE_CHANGED);

        if (Ctx->ExtendingValidData)
        {
            Ctx->Scb->Header.ValidDataLength.QuadPart = Ctx->ValidDataLength;
            if (!Ctx->PagingIo &&
                 Ctx->ScbAcquiredExclusive &&
                 CcIsFileCached(Ctx->IrpContext->FileObject))
            {
                CcSetFileSizes(
                    Ctx->IrpContext->FileObject,
                    (PCC_FILE_SIZES)&Ctx->Scb->Header.AllocationSize);
            }

            if (!Ctx->PagingIo)
            {
                fileVdlInfo.ValidDataLength.QuadPart =
                    Ctx->ValidDataLength + HAWK_FS_HEADER_SIZE + HAWK_FS_KEY_SIZE;
                FltSetInformationFile(
                    Ctx->FltObjects->Instance,
                    Ctx->StreamHandleContext->ShadowFileObject,
                    &fileVdlInfo,
                    sizeof(FILE_VALID_DATA_LENGTH_INFORMATION),
                    FileValidDataLengthInformation);
                SetFlag(Ctx->Iopb->TargetFileObject->Flags, FO_FILE_MODIFIED);
            }
        }
    }
    else if (!Ctx->OplockPostOperation)
    {
        if (Ctx->ExtendingFile)
        {
            if (Ctx->Scb->Header.PagingIoResource != NULL)
                ExAcquireResourceExclusiveLite(Ctx->Scb->Header.PagingIoResource, TRUE);
            Ctx->Scb->Header.FileSize.LowPart = Ctx->InitFileSize;
            if (Ctx->FileObject->SectionObjectPointer->SharedCacheMap != NULL)
                *CcGetFileSizePointer(Ctx->FileObject) = Ctx->Scb->Header.FileSize;
            if (Ctx->Scb->Header.PagingIoResource != NULL)
                ExReleaseResourceLite(Ctx->Scb->Header.PagingIoResource);
        }
    }

    if (Ctx->P2pCtx != NULL &&
         (Ctx->CompletionContext == NULL || *Ctx->CompletionContext != Ctx->P2pCtx))
    {
        ExFreeToNPagedLookasideList(&g_HawkP2PLookaside, Ctx->P2pCtx);
    }

    if (Ctx->ScbAcquired)
        ExReleaseResourceLite(Ctx->Scb->Header.Resource);
    if (Ctx->PagingIoResourceAcquired)
        ExReleaseResourceLite(Ctx->Scb->Header.PagingIoResource);

    return Ctx->RetValue;
}

/* Hawkeye TFE: CommonWrite */
FLT_PREOP_CALLBACK_STATUS
HawkCommonWrite(
    __in PHAWK_IRP_CONTEXT IrpContext,
    __inout PVOID *CompletionContext
    )
{
    HAWK_COMMON_WRITE_CTX ctx;

    HawkCommonWriteInitCtx(IrpContext, CompletionContext, &ctx);

    if (HawkCommonWriteHandleEntry(&ctx))
        return ctx.RetValue;

    if (HawkCommonWriteTryDeferCachedWrite(&ctx))
        return ctx.RetValue;

    if (!HawkCommonWriteAllocatePre2PostIfNeeded(&ctx))
        return ctx.RetValue;

    ctx.StartOffset = ctx.Iopb->Parameters.Write.ByteOffset;
    ctx.StartVbo = ctx.StartOffset.LowPart;
    ctx.WriteToEof = (ctx.StartOffset.LowPart == FILE_WRITE_TO_END_OF_FILE) &&
                      (ctx.StartOffset.HighPart == -1);
    ctx.Scb = IrpContext->FileObject->FsContext;

    if (!HawkCommonWriteFlushBeforeNonCached(&ctx))
        goto CleanupAndReturn;

    if (!HawkCommonWriteAcquireLocks(&ctx))
        goto CleanupAndReturn;

    if (!HawkCommonWritePreparePagingAndVdlExtend(&ctx))
        goto CleanupAndReturn;

    if (!HawkCommonWriteCheckOplockAndFileLock(&ctx))
        goto CleanupAndReturn;

    if (!HawkCommonWriteExtendShadowEofIfNeeded(&ctx))
        goto CleanupAndReturn;

    HawkCommonWriteUpdateVdlAndMaybeDemoteScb(&ctx);

    if (ctx.NonCachedIo)
    {
        HawkCommonWriteDispatchNonCached(&ctx);
        goto CleanupAndReturn;
    }

    if (!HawkCommonWriteAcquireCachedExclusiveLock(&ctx))
        goto CleanupAndReturn;

    if (!HawkCommonWritePrepareCachedPath(&ctx))
        goto CleanupAndReturn;

CleanupAndReturn:

    return HawkCommonWriteCleanup(&ctx);
}

