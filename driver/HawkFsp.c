#include "HawkeyeTfe.h"
#include "HawkFsp.h"
#include "HawkOperations.h"


/* Hawkeye TFE */
static FLT_PREOP_CALLBACK_STATUS
HawkPreWriteCompleteMdlNotifyCacheManager(
    __inout PFLT_CALLBACK_DATA Data,
    __in PFLT_IO_PARAMETER_BLOCK Iopb
    )
{
    CcMdlWriteComplete(
        Iopb->TargetFileObject,
        &Iopb->Parameters.Write.ByteOffset,
        Iopb->Parameters.Write.MdlAddress);
    Iopb->Parameters.Write.MdlAddress = NULL;
    Data->IoStatus.Information = 0;
    Data->IoStatus.Status = STATUS_SUCCESS;
    return FLT_PREOP_COMPLETE;
}

FLT_PREOP_CALLBACK_STATUS
HawkPreWriteCompleteMdl(
    __in PHAWK_IRP_CONTEXT IrpContext
    )
{
    PFLT_CALLBACK_DATA data = IrpContext->CallbackData;
    PFLT_IO_PARAMETER_BLOCK iopb = data->Iopb;

    if (!FltIsOperationSynchronous(data))
    {
        data->IoStatus.Information = 0;
        data->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        return FLT_PREOP_COMPLETE;
    }

    return HawkPreWriteCompleteMdlNotifyCacheManager(data, iopb);
}

static VOID
HawkFspDispatchMarkRetryContext(
    __inout PHAWK_IRP_CONTEXT IrpContext
    )
{
    SetFlag(IrpContext->Flags, HAWK_IRP_CTX_FLAG_WAIT | HAWK_IRP_CTX_FLAG_IN_FSP);
}

static FLT_PREOP_CALLBACK_STATUS
HawkFspDispatchRunMajorFunction(
    __inout PHAWK_IRP_CONTEXT IrpContext
    )
{
    switch (IrpContext->MajorFunction)
    {
        case IRP_MJ_WRITE:
            return HawkCommonWrite(IrpContext, IrpContext->CompletionContext);

        case IRP_MJ_READ:
            return HawkCommonRead(IrpContext, IrpContext->CompletionContext);

        default:
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
}

static VOID
HawkFspDispatchCompletePendedPreOp(
    __inout PHAWK_IRP_CONTEXT IrpContext,
    __in FLT_PREOP_CALLBACK_STATUS PreopStatus
    )
{
    IoFreeWorkItem(IrpContext->WorkItem);
    FltCompletePendedPreOperation(IrpContext->CallbackData, FLT_PREOP_COMPLETE, NULL);
    if (PreopStatus == FLT_PREOP_COMPLETE)
        HawkDeleteIrpContext(IrpContext);
}

/* Hawkeye TFE: Fsp */
VOID
HawkFspDispatch(
    __in PDEVICE_OBJECT DeviceObject,
    __in PVOID Context
    )
{
    PHAWK_IRP_CONTEXT irpContext = (PHAWK_IRP_CONTEXT)Context;
    FLT_PREOP_CALLBACK_STATUS preopStatus;

    UNREFERENCED_PARAMETER(DeviceObject);

    HawkFspDispatchMarkRetryContext(irpContext);
    KeEnterCriticalRegion();
    preopStatus = HawkFspDispatchRunMajorFunction(irpContext);
    KeLeaveCriticalRegion();
    HawkFspDispatchCompletePendedPreOp(irpContext, preopStatus);
}

static VOID
HawkQueueFspWorkItemInternal(
    __inout PHAWK_IRP_CONTEXT IrpContext
    )
{
    PIO_WORKITEM workItem;

    workItem = IoAllocateWorkItem(g_HawkFilter.DeviceObject);
    IrpContext->WorkItem = workItem;
    IoQueueWorkItem(workItem, HawkFspDispatch, DelayedWorkQueue, IrpContext);
}

VOID
HawkQueueFspWorkItem(
    __in PHAWK_IRP_CONTEXT IrpContext
    )
{
    HawkQueueFspWorkItemInternal(IrpContext);
}
