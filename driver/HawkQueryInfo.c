#include "HawkeyeTfe.h"
#include "HawkScb.h"
#include "HawkRedirect.h"


/* Hawkeye TFE */
/* Hawkeye TFE: QueryInfo */
FLT_PREOP_CALLBACK_STATUS
HawkPreQueryInformation(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    PHAWK_STREAM_HANDLE_CONTEXT shc;
    PHAWK_SCB scb;
    PHAWK_PRE2POST_CONTEXT p2pCtx = NULL;
    ULONG infoLength;
    FLT_PREOP_CALLBACK_STATUS retValue = FLT_PREOP_SUCCESS_NO_CALLBACK;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (FLT_IS_FASTIO_OPERATION(Data))
        return FLT_PREOP_DISALLOW_FASTIO;

    scb = HawkResolvePlaintextScbFromFileObject(fileObject);
    if (scb == NULL)
        goto ReturnRoutine;

    shc = HawkRedirectResolveStreamContext(fileObject);
    if (shc == NULL)
    {
        Data->IoStatus.Status = STATUS_INVALID_PARAMETER;
        retValue = FLT_PREOP_COMPLETE;
        goto ReturnRoutine;
    }

    infoLength = Data->Iopb->Parameters.QueryFileInformation.Length;

    p2pCtx = ExAllocateFromNPagedLookasideList(&g_HawkP2PLookaside);
    if (p2pCtx == NULL)
    {
        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        retValue = FLT_PREOP_COMPLETE;
        goto ReturnRoutine;
    }
    RtlZeroMemory(p2pCtx, sizeof(HAWK_PRE2POST_CONTEXT));

    p2pCtx->HandoffPtr = ExAllocatePoolWithTag(
        NonPagedPool, infoLength, HAWK_POOL_TAG);
    if (p2pCtx->HandoffPtr == NULL)
    {
        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        retValue = FLT_PREOP_COMPLETE;
        goto ReturnRoutine;
    }
    RtlZeroMemory(p2pCtx->HandoffPtr, infoLength);

    HawkRedirectIrpToShadowFileObject(Data, shc);
    p2pCtx->UserBuffer = Data->Iopb->Parameters.QueryFileInformation.InfoBuffer;
    p2pCtx->BoundScb = scb;
    Data->Iopb->Parameters.QueryFileInformation.InfoBuffer = p2pCtx->HandoffPtr;
    *CompletionContext = p2pCtx;
    p2pCtx = NULL;
    retValue = FLT_PREOP_SUCCESS_WITH_CALLBACK;
    FltSetCallbackDataDirty(Data);

ReturnRoutine:
    if (p2pCtx != NULL)
    {
        if (p2pCtx->HandoffPtr != NULL)
            ExFreePoolWithTag(p2pCtx->HandoffPtr, HAWK_POOL_TAG);
        ExFreeToNPagedLookasideList(&g_HawkP2PLookaside, p2pCtx);
    }
    return retValue;
}

static VOID
HawkPostQueryInformationFreePre2Post(
    __inout PHAWK_PRE2POST_CONTEXT P2pCtx
    )
{
    if (P2pCtx->HandoffPtr != NULL)
        ExFreePoolWithTag(P2pCtx->HandoffPtr, HAWK_POOL_TAG);
    ExFreeToNPagedLookasideList(&g_HawkP2PLookaside, P2pCtx);
}

static PHAWK_SCB
HawkPostQueryInformationResolvePlaintextScb(
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
HawkPostQueryInformationPatchPlaintextSizes(
    __in PHAWK_SCB Scb,
    __in PHAWK_PRE2POST_CONTEXT P2pCtx,
    __in PFLT_IO_PARAMETER_BLOCK Iopb
    )
{
    PVOID proxyBuffer = P2pCtx->HandoffPtr;
    FILE_INFORMATION_CLASS infoClass;
    ULONG infoLength;

    if (Scb == NULL || proxyBuffer == NULL)
        return;

    infoClass = Iopb->Parameters.QueryFileInformation.FileInformationClass;
    infoLength = Iopb->Parameters.QueryFileInformation.Length;

    switch (infoClass)
    {
    case FileAllInformation:
        if (infoLength >= sizeof(FILE_BASIC_INFORMATION) + sizeof(FILE_STANDARD_INFORMATION))
        {
            FILE_ALL_INFORMATION *allInfo = (FILE_ALL_INFORMATION *)proxyBuffer;

            allInfo->StandardInformation.EndOfFile.QuadPart =
                Scb->Header.FileSize.QuadPart;
        }
        break;

    case FileNetworkOpenInformation:
        {
            FILE_NETWORK_OPEN_INFORMATION *networkInfo =
                (FILE_NETWORK_OPEN_INFORMATION *)proxyBuffer;

            networkInfo->EndOfFile.QuadPart = Scb->Header.FileSize.QuadPart;
        }
        break;

    case FileStandardInformation:
        {
            FILE_STANDARD_INFORMATION *standardInfo =
                (FILE_STANDARD_INFORMATION *)proxyBuffer;

            standardInfo->EndOfFile.QuadPart = Scb->Header.FileSize.QuadPart;
            standardInfo->AllocationSize.QuadPart =
                Scb->Header.AllocationSize.QuadPart;
        }
        break;

    default:
        break;
    }
}

static VOID
HawkPostQueryInformationCopyProxyToUser(
    __inout PFLT_CALLBACK_DATA Data,
    __in PHAWK_PRE2POST_CONTEXT P2pCtx,
    __in PFLT_IO_PARAMETER_BLOCK Iopb
    )
{
    PVOID userBuffer = P2pCtx->UserBuffer;
    PVOID proxyBuffer = P2pCtx->HandoffPtr;
    ULONG copyLen;

    if (userBuffer == NULL || proxyBuffer == NULL)
        return;

    copyLen = (ULONG)Data->IoStatus.Information;
    if (copyLen == 0 || copyLen > Iopb->Parameters.QueryFileInformation.Length)
        copyLen = Iopb->Parameters.QueryFileInformation.Length;

    RtlCopyMemory(userBuffer, proxyBuffer, copyLen);
    Iopb->Parameters.QueryFileInformation.InfoBuffer = userBuffer;
    FltSetCallbackDataDirty(Data);
}

FLT_POSTOP_CALLBACK_STATUS
HawkPostQueryInformation(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
    PHAWK_PRE2POST_CONTEXT p2pCtx = CompletionContext;
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    PHAWK_SCB scb;

    UNREFERENCED_PARAMETER(FltObjects);
    if (p2pCtx == NULL)
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))
    {
        HawkPostQueryInformationFreePre2Post(p2pCtx);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    scb = HawkPostQueryInformationResolvePlaintextScb(p2pCtx, iopb);
    HawkPostQueryInformationPatchPlaintextSizes(scb, p2pCtx, iopb);
    HawkPostQueryInformationCopyProxyToUser(Data, p2pCtx, iopb);
    HawkPostQueryInformationFreePre2Post(p2pCtx);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
HawkPreQueryEa(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    PHAWK_SCB scb;
    PHAWK_STREAM_HANDLE_CONTEXT shc;

    UNREFERENCED_PARAMETER(FltObjects);
    if (CompletionContext != NULL)
        *CompletionContext = NULL;

    if (FLT_IS_FASTIO_OPERATION(Data))
        return FLT_PREOP_DISALLOW_FASTIO;

    scb = HawkResolvePlaintextScbFromFileObject(fileObject);
    if (scb == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    shc = HawkRedirectResolveStreamContext(fileObject);
    if (shc == NULL)
    {
        Data->IoStatus.Status = STATUS_INVALID_PARAMETER;
        return FLT_PREOP_COMPLETE;
    }

    HawkRedirectIrpToShadowFileObject(Data, shc);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
HawkPreQueryQuota(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    PHAWK_SCB scb;
    PHAWK_STREAM_HANDLE_CONTEXT shc;

    UNREFERENCED_PARAMETER(FltObjects);
    if (CompletionContext != NULL)
        *CompletionContext = NULL;

    if (FLT_IS_FASTIO_OPERATION(Data))
        return FLT_PREOP_DISALLOW_FASTIO;

    scb = HawkResolvePlaintextScbFromFileObject(fileObject);
    if (scb == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    shc = HawkRedirectResolveStreamContext(fileObject);
    if (shc == NULL)
    {
        Data->IoStatus.Status = STATUS_INVALID_PARAMETER;
        return FLT_PREOP_COMPLETE;
    }

    HawkRedirectIrpToShadowFileObject(Data, shc);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
HawkPreQuerySecurity(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    PHAWK_SCB scb;
    PHAWK_STREAM_HANDLE_CONTEXT shc;

    UNREFERENCED_PARAMETER(FltObjects);
    if (CompletionContext != NULL)
        *CompletionContext = NULL;

    if (FLT_IS_FASTIO_OPERATION(Data))
        return FLT_PREOP_DISALLOW_FASTIO;

    scb = HawkResolvePlaintextScbFromFileObject(fileObject);
    if (scb == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    shc = HawkRedirectResolveStreamContext(fileObject);
    if (shc == NULL)
    {
        Data->IoStatus.Status = STATUS_INVALID_PARAMETER;
        return FLT_PREOP_COMPLETE;
    }

    HawkRedirectIrpToShadowFileObject(Data, shc);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
