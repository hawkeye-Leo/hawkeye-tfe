#include "HawkeyeTfe.h"
#include "HawkScb.h"
#include "HawkOperations.h"


/* Hawkeye TFE */
PHAWK_STREAM_HANDLE_CONTEXT
HawkRedirectResolveStreamContext(
    __in PFILE_OBJECT FileObject
    )
{
    PHAWK_STREAM_HANDLE_CONTEXT shc;

    if (FileObject == NULL)
        return NULL;

    shc = (PHAWK_STREAM_HANDLE_CONTEXT)FileObject->FsContext2;
    if (shc == NULL || shc->ShadowFileObject == NULL)
        return NULL;

    return shc;
}

VOID
HawkRedirectIrpToShadowFileObject(
    __inout PFLT_CALLBACK_DATA Data,
    __in PHAWK_STREAM_HANDLE_CONTEXT Shc
    )
{
    Data->Iopb->TargetFileObject = Shc->ShadowFileObject;
    FltSetCallbackDataDirty(Data);
}

static VOID
HawkRedirectClearCompletionContext(
    __deref_out_opt PVOID *CompletionContext
    )
{
    if (CompletionContext != NULL)
        *CompletionContext = NULL;
}

static FLT_PREOP_CALLBACK_STATUS
HawkRedirectPlaintextToShadow(
    __inout PFLT_CALLBACK_DATA Data,
    __deref_out_opt PVOID *CompletionContext
    )
{
    PFILE_OBJECT fo = Data->Iopb->TargetFileObject;
    PHAWK_SCB scb;
    PHAWK_STREAM_HANDLE_CONTEXT shc;

    HawkRedirectClearCompletionContext(CompletionContext);
    if (FLT_IS_FASTIO_OPERATION(Data))
        return FLT_PREOP_DISALLOW_FASTIO;

    scb = HawkResolvePlaintextScbFromFileObject(fo);
    if (scb == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    shc = HawkRedirectResolveStreamContext(fo);
    if (shc == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    HawkRedirectIrpToShadowFileObject(Data, shc);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static BOOLEAN
HawkTryRedirectCreateAtShadowFo(
    __inout PFLT_CALLBACK_DATA Data,
    __in PFILE_OBJECT Fo
    )
{
    PHAWK_SCB scb;
    PHAWK_STREAM_HANDLE_CONTEXT shc;

    scb = HawkResolvePlaintextScbFromFileObject(Fo);
    if (scb == NULL)
        return FALSE;

    shc = HawkRedirectResolveStreamContext(Fo);
    if (shc == NULL)
        return FALSE;

    HawkRedirectIrpToShadowFileObject(Data, shc);
    return TRUE;
}

FLT_PREOP_CALLBACK_STATUS
HawkPreCreateMailslot(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID * CompletionContext
    )
{
    if (CompletionContext != NULL)
        *CompletionContext = NULL;
    UNREFERENCED_PARAMETER(FltObjects);
    if (FLT_IS_FASTIO_OPERATION(Data))
        return FLT_PREOP_DISALLOW_FASTIO;
    HawkTryRedirectCreateAtShadowFo(Data, Data->Iopb->TargetFileObject);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
HawkPreCreateNamedPipe(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID * CompletionContext
    )
{
    if (CompletionContext != NULL)
        *CompletionContext = NULL;
    UNREFERENCED_PARAMETER(FltObjects);
    if (FLT_IS_FASTIO_OPERATION(Data))
        return FLT_PREOP_DISALLOW_FASTIO;
    HawkTryRedirectCreateAtShadowFo(Data, Data->Iopb->TargetFileObject);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
HawkPreNetworkQueryOpen(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    if (CompletionContext)
        *CompletionContext = NULL;
    return FLT_PREOP_DISALLOW_FASTIO;
}

FLT_POSTOP_CALLBACK_STATUS
HawkPostNetworkQueryOpen(
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

static FLT_PREOP_CALLBACK_STATUS
HawkPreFastIoCheckPossibleForScb(
    __in PHAWK_SCB Scb,
    __inout PFLT_CALLBACK_DATA Data
    )
{
    if (Data->Iopb->Parameters.FastIoCheckIfPossible.CheckForReadOperation)
    {
        if (FltCheckLockForReadAccess(&Scb->Lock.FileLock, Data))
            return FLT_PREOP_COMPLETE;
    }
    else if (FltCheckLockForWriteAccess(&Scb->Lock.FileLock, Data))
    {
        return FLT_PREOP_COMPLETE;
    }
    return FLT_PREOP_DISALLOW_FASTIO;
}

FLT_PREOP_CALLBACK_STATUS
HawkPreFastIoCheckPossible(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    PHAWK_SCB scb;

    *CompletionContext = NULL;
    UNREFERENCED_PARAMETER(FltObjects);

    scb = HawkResolvePlaintextScbFromFileObject(Data->Iopb->TargetFileObject);
    if (scb == NULL)
        return FLT_PREOP_DISALLOW_FASTIO;

    return HawkPreFastIoCheckPossibleForScb(scb, Data);
}

FLT_PREOP_CALLBACK_STATUS
HawkPreQueryVolumeInformation(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    return HawkRedirectPlaintextToShadow(Data, CompletionContext);
}

/* Hawkeye TFE: Misc */
FLT_PREOP_CALLBACK_STATUS
HawkPreFlush(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    return HawkRedirectPlaintextToShadow(Data, CompletionContext);
}

FLT_PREOP_CALLBACK_STATUS
HawkPreDirectoryControl(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    return HawkRedirectPlaintextToShadow(Data, CompletionContext);
}

FLT_PREOP_CALLBACK_STATUS
HawkPreDeviceControl(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    return HawkRedirectPlaintextToShadow(Data, CompletionContext);
}

FLT_PREOP_CALLBACK_STATUS
HawkPreInternalDeviceControl(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    return HawkRedirectPlaintextToShadow(Data, CompletionContext);
}

static FLT_PREOP_CALLBACK_STATUS
HawkPreFsControlRequestOplock(
    __in PHAWK_SCB Scb,
    __inout PFLT_CALLBACK_DATA Data
    )
{
    ULONG fsControlCode = Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode;
    ULONG oplockCount;
    FLT_PREOP_CALLBACK_STATUS retValue;

    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(Scb->Header.Resource, TRUE);
    if (fsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)
        oplockCount = (ULONG)FsRtlAreThereCurrentFileLocks(&Scb->Lock.FileLock);
    else
        oplockCount = Scb->StreamHandleCount;
    retValue = FltOplockFsctrl(&Scb->Lock.Oplock, Data, oplockCount);
    ExReleaseResourceLite(Scb->Header.Resource);
    KeLeaveCriticalRegion();
    return retValue;
}

static FLT_PREOP_CALLBACK_STATUS
HawkPreFsControlAckOplockBreak(
    __in PHAWK_SCB Scb,
    __inout PFLT_CALLBACK_DATA Data
    )
{
    FLT_PREOP_CALLBACK_STATUS retValue;

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(Scb->Header.Resource, TRUE);
    retValue = FltOplockFsctrl(&Scb->Lock.Oplock, Data, 0);
    ExReleaseResourceLite(Scb->Header.Resource);
    KeLeaveCriticalRegion();
    return retValue;
}

static FLT_PREOP_CALLBACK_STATUS
HawkPreFsControlHandleKernelCall(
    __in PHAWK_SCB Scb,
    __in PHAWK_STREAM_HANDLE_CONTEXT Shc,
    __inout PFLT_CALLBACK_DATA Data
    )
{
    switch (Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode)
    {
        case FSCTL_REQUEST_OPLOCK_LEVEL_1:
        case FSCTL_REQUEST_OPLOCK_LEVEL_2:
        case FSCTL_REQUEST_BATCH_OPLOCK:
        case FSCTL_REQUEST_FILTER_OPLOCK:
            return HawkPreFsControlRequestOplock(Scb, Data);

        case FSCTL_OPLOCK_BREAK_ACKNOWLEDGE:
        case FSCTL_OPLOCK_BREAK_NOTIFY:
        case FSCTL_OPLOCK_BREAK_ACK_NO_2:
        case FSCTL_OPBATCH_ACK_CLOSE_PENDING:
            return HawkPreFsControlAckOplockBreak(Scb, Data);

        default:
            HawkRedirectIrpToShadowFileObject(Data, Shc);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
}

FLT_PREOP_CALLBACK_STATUS
HawkPreFsControl(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    PHAWK_SCB scb;
    PHAWK_STREAM_HANDLE_CONTEXT shc;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    scb = HawkResolvePlaintextScbFromFileObject(fileObject);
    if (scb == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    shc = HawkRedirectResolveStreamContext(fileObject);
    if (shc == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (Data->Iopb->MinorFunction == IRP_MN_KERNEL_CALL)
        return HawkPreFsControlHandleKernelCall(scb, shc, Data);

    HawkRedirectIrpToShadowFileObject(Data, shc);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
HawkPreLockControl(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    return HawkRedirectPlaintextToShadow(Data, CompletionContext);
}

FLT_POSTOP_CALLBACK_STATUS
HawkPostLockControl(
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

FLT_PREOP_CALLBACK_STATUS
HawkPrePnp(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    return HawkRedirectPlaintextToShadow(Data, CompletionContext);
}

FLT_PREOP_CALLBACK_STATUS
HawkPreSystemControl(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    return HawkRedirectPlaintextToShadow(Data, CompletionContext);
}
