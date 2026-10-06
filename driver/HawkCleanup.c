#include "HawkeyeTfe.h"
#include "HawkScb.h"
#include "HawkShc.h"
#include "HawkOperations.h"


/* Hawkeye TFE */
static VOID
HawkCreateIrpContextForCleanupInPlace(
    __out HAWK_IRP_CONTEXT *IrpContext,
    __in PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    RtlZeroMemory(IrpContext, sizeof(HAWK_IRP_CONTEXT));
    IrpContext->MajorFunction = Data->Iopb->MajorFunction;
    IrpContext->FileObject = Data->Iopb->TargetFileObject;
    IrpContext->CallbackData = Data;
    if (FltObjects->Filter)
        IrpContext->RelatedObjects.Filter = FltObjects->Filter;
    if (FltObjects->Volume)
        IrpContext->RelatedObjects.Volume = FltObjects->Volume;
    if (FltObjects->Instance)
        IrpContext->RelatedObjects.Instance = FltObjects->Instance;
    IrpContext->CompletionContext = CompletionContext;
    if (FltIsOperationSynchronous(Data))
        SetFlag(IrpContext->Flags, HAWK_IRP_CTX_FLAG_WAIT);
}

#define HawkCreateIrpContextForCleanup(IrpContext, Data, FltObjects, CompletionContext) \
    HawkCreateIrpContextForCleanupInPlace(&(IrpContext), (Data), (FltObjects), (CompletionContext))

static FLT_PREOP_CALLBACK_STATUS
HawkCleanupHandlePlaintextFileObject(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    HAWK_IRP_CONTEXT irpContextStack;
    FLT_PREOP_CALLBACK_STATUS retValue;

    KeEnterCriticalRegion();
    HawkCreateIrpContextForCleanup(
        irpContextStack,
        Data,
        FltObjects,
        CompletionContext);
    retValue = HawkCommonCleanup(&irpContextStack, CompletionContext);
    KeLeaveCriticalRegion();
    return retValue;
}

static FLT_PREOP_CALLBACK_STATUS
HawkCleanupReleaseOrphanStreamContext(
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject
    )
{
    PHAWK_STREAM_HANDLE_CONTEXT streamHandleContext = NULL;

    FltGetStreamHandleContext(Instance, FileObject, &streamHandleContext);
    if (streamHandleContext != NULL)
        FltReleaseContext(streamHandleContext);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* Hawkeye TFE: Cleanup */
FLT_PREOP_CALLBACK_STATUS
HawkPreCleanup(
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
        return HawkCleanupHandlePlaintextFileObject(Data, FltObjects, CompletionContext);

    if (fileObject != NULL)
        return HawkCleanupReleaseOrphanStreamContext(FltObjects->Instance, fileObject);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static VOID
HawkCommonCleanupFlushModified(
    __in PHAWK_SCB Scb,
    __in PFILE_OBJECT FileObject
    )
{
    if (FlagOn(FileObject->Flags, FO_FILE_MODIFIED))
        CcFlushCache(&Scb->SectionObjectPointers, NULL, 0, NULL);
}

static FLT_PREOP_CALLBACK_STATUS
HawkCommonCleanupHandleAlreadyComplete(
    __inout PFLT_CALLBACK_DATA Data,
    __in PHAWK_SCB Scb,
    __in PFILE_OBJECT FileObject
    )
{
    HawkCommonCleanupFlushModified(Scb, FileObject);
    Data->IoStatus.Status = STATUS_SUCCESS;
    return FLT_PREOP_COMPLETE;
}

static VOID
HawkCommonCleanupDecrementStreamHandle(
    __in PHAWK_SCB Scb
    )
{
    if (Scb->StreamHandleCount == 0)
        DBG_PRINT("HawkeyeTfe!CommonCleanup: stream handle count underflow");
    else
        HawkDecrementScbHandles(Scb);
}

static VOID
HawkCommonCleanupHandleDeleteOnClose(
    __in PHAWK_SCB Scb,
    __in PHAWK_STREAM_HANDLE_CONTEXT StreamHandleContext,
    __in PFILE_OBJECT FileObject
    )
{
    LARGE_INTEGER startOffset;
    LARGE_INTEGER endOffset;

    if (Scb->StreamHandleCount != 0 ||
        !FlagOn(FileObject->Flags, FO_DELETE_ON_CLOSE))
    {
        return;
    }

    HawkRenameScb(&StreamHandleContext->PathKey, NULL);
    if (Scb->Header.ValidDataLength.QuadPart < Scb->Header.FileSize.QuadPart)
    {
        startOffset.QuadPart = Scb->Header.ValidDataLength.QuadPart;
        endOffset.QuadPart = Scb->Header.FileSize.QuadPart;
        CcZeroData(FileObject, &startOffset, &endOffset, TRUE);
    }
}

static VOID
HawkCommonCleanupPurgePlaintextCache(
    __in PHAWK_SCB Scb,
    __in PFILE_OBJECT FileObject
    )
{
    if (Scb->StreamHandleCount != 0 ||
        Scb->SectionObjectPointers.DataSectionObject == NULL)
    {
        return;
    }

    ExAcquireSharedStarveExclusive(Scb->Header.PagingIoResource, TRUE);
    CcFlushCache(&Scb->SectionObjectPointers, NULL, 0, NULL);
    ExReleaseResourceLite(Scb->Header.PagingIoResource);
    CcPurgeCacheSection(FileObject->SectionObjectPointer, NULL, 0, FALSE);
}

static VOID
HawkCommonCleanupCloseShadowHandle(
    __in PHAWK_STREAM_HANDLE_CONTEXT StreamHandleContext
    )
{
    NTSTATUS status;

    if (StreamHandleContext->AliasHandle == NULL)
        return;

    status = FltClose(StreamHandleContext->AliasHandle);
    if (!NT_SUCCESS(status))
        DBG_PRINT("HawkeyeTfe!CommonCleanup: FltClose on shadow handle failed, status=0x%08X", status);
    StreamHandleContext->AliasHandle = NULL;
}

static FLT_PREOP_CALLBACK_STATUS
HawkCommonCleanupTeardownHandle(
    __inout PFLT_CALLBACK_DATA Data,
    __in PHAWK_SCB Scb,
    __in PHAWK_STREAM_HANDLE_CONTEXT StreamHandleContext,
    __in PFILE_OBJECT FileObject
    )
{
    FsRtlFastUnlockAll(
        &Scb->Lock.FileLock,
        FileObject,
        FltGetRequestorProcess(Data),
        NULL);
    HawkCommonCleanupDecrementStreamHandle(Scb);
    HawkCommonCleanupHandleDeleteOnClose(Scb, StreamHandleContext, FileObject);
    HawkCommonCleanupPurgePlaintextCache(Scb, FileObject);
    CcUninitializeCacheMap(FileObject, NULL, NULL);
    HawkCommonCleanupCloseShadowHandle(StreamHandleContext);
    FltCheckOplock(&Scb->Lock.Oplock, Data, NULL, NULL, NULL);
    FileObject->Flags |= FO_CLEANUP_COMPLETE;
    Data->IoStatus.Status = STATUS_SUCCESS;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

FLT_PREOP_CALLBACK_STATUS
HawkCommonCleanup(
    __in PHAWK_IRP_CONTEXT IrpContext,
    __inout PVOID *CompletionContext
    )
{
    PFLT_CALLBACK_DATA data = IrpContext->CallbackData;
    PFILE_OBJECT fileObject = data->Iopb->TargetFileObject;
    PHAWK_SCB scb = (PHAWK_SCB)fileObject->FsContext;
    PHAWK_STREAM_HANDLE_CONTEXT streamHandleContext =
        (PHAWK_STREAM_HANDLE_CONTEXT)fileObject->FsContext2;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (scb == NULL || streamHandleContext == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (FlagOn(fileObject->Flags, FO_CLEANUP_COMPLETE))
        return HawkCommonCleanupHandleAlreadyComplete(data, scb, fileObject);

    return HawkCommonCleanupTeardownHandle(
        data,
        scb,
        streamHandleContext,
        fileObject);
}

FLT_POSTOP_CALLBACK_STATUS
HawkPostCleanup(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static VOID
HawkPreCloseReleaseShadowFileObject(
    __in PHAWK_STREAM_HANDLE_CONTEXT StreamHandleContext
    )
{
    if (StreamHandleContext->ShadowFileObject == NULL)
        return;

    ObDereferenceObject(StreamHandleContext->ShadowFileObject);
    StreamHandleContext->ShadowFileObject = NULL;
}

static VOID
HawkPreCloseDereferenceScb(
    __in PHAWK_SCB Scb,
    __in PHAWK_STREAM_HANDLE_CONTEXT StreamHandleContext
    )
{
    if (Scb->StreamHandleCount > Scb->ObjectRefCount)
    {
        DBG_PRINT(
            "HawkeyeTfe!PreClose: stream handle count (%ld) exceeds object reference count (%ld)",
            Scb->StreamHandleCount,
            Scb->ObjectRefCount);
    }

    HawkDereferenceScb(Scb, StreamHandleContext);
}

static VOID
HawkPreCloseDetachPlaintextFileObject(
    __in PFILE_OBJECT FileObject
    )
{
    FileObject->FsContext = NULL;
    HawkCleanStreamHandleContext(FileObject->FsContext2, FLT_STREAMHANDLE_CONTEXT);
    ExFreePoolWithTag(FileObject->FsContext2, HAWK_POOL_TAG);
    FileObject->FsContext2 = NULL;
    FileObject->SectionObjectPointer = NULL;
}

static FLT_PREOP_CALLBACK_STATUS
HawkPreClosePlaintextFileObject(
    __inout PFLT_CALLBACK_DATA Data,
    __in PFILE_OBJECT FileObject,
    __in PHAWK_SCB Scb
    )
{
    PHAWK_STREAM_HANDLE_CONTEXT streamHandleContext;

    streamHandleContext = (PHAWK_STREAM_HANDLE_CONTEXT)FileObject->FsContext2;
    if (streamHandleContext == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    HawkPreCloseReleaseShadowFileObject(streamHandleContext);
    HawkPreCloseDereferenceScb(Scb, streamHandleContext);
    HawkPreCloseDetachPlaintextFileObject(FileObject);
    Data->IoStatus.Status = STATUS_SUCCESS;
    return FLT_PREOP_COMPLETE;
}

FLT_PREOP_CALLBACK_STATUS
HawkPreClose(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    PHAWK_SCB scb;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (FLT_IS_FASTIO_OPERATION(Data))
        return FLT_PREOP_DISALLOW_FASTIO;

    scb = HawkResolvePlaintextScbFromFileObject(fileObject);
    if (scb == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    return HawkPreClosePlaintextFileObject(Data, fileObject, scb);
}

FLT_POSTOP_CALLBACK_STATUS
HawkPostClose(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);
    return FLT_POSTOP_FINISHED_PROCESSING;
}
