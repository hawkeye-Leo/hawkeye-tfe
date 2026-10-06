#include "HawkeyeTfe.h"
#include "HawkScb.h"
#include "HawkRedirect.h"


/* Hawkeye TFE */
static VOID
HawkLockPlaintextScbForCcFlush(
    __in PHAWK_SCB Scb
    )
{
    PERESOURCE mainResource = Scb->Header.Resource;

    if (mainResource != NULL)
    {
        if (ExIsResourceAcquiredSharedLite(mainResource))
            ExAcquireResourceSharedLite(mainResource, TRUE);
        else
            ExAcquireResourceExclusiveLite(mainResource, TRUE);
    }
    if (Scb->Header.PagingIoResource != NULL)
        ExAcquireResourceSharedLite(Scb->Header.PagingIoResource, TRUE);
}

/* Hawkeye TFE: CcFlush */
FLT_PREOP_CALLBACK_STATUS
HawkPreAcquireForCcFlush(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    PHAWK_STREAM_HANDLE_CONTEXT shc = fileObject->FsContext2;
    PHAWK_SCB scb = NULL;

    scb = HawkResolvePlaintextScbFromFileObject(fileObject);
    if (scb == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    HawkLockPlaintextScbForCcFlush(scb);
    HawkRedirectIrpToShadowFileObject(Data, shc);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
HawkPostAcquireForCcFlush(
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
HawkPreReleaseForCcFlush(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(FltObjects);

    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    PHAWK_STREAM_HANDLE_CONTEXT shc = fileObject->FsContext2;
    PHAWK_SCB scb = NULL;

    scb = HawkResolvePlaintextScbFromFileObject(fileObject);
    if (scb == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (CompletionContext != NULL)
        *CompletionContext = scb;

    HawkRedirectIrpToShadowFileObject(Data, shc);
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static VOID
HawkUnlockPlaintextScbForCcFlush(
    __in PHAWK_SCB Scb
    )
{
    if (Scb->Header.Resource)
        ExReleaseResourceLite(Scb->Header.Resource);
    if (Scb->Header.PagingIoResource)
        ExReleaseResourceLite(Scb->Header.PagingIoResource);
}

FLT_POSTOP_CALLBACK_STATUS
HawkPostReleaseForCcFlush(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    if (CompletionContext != NULL)
        HawkUnlockPlaintextScbForCcFlush((PHAWK_SCB)CompletionContext);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
HawkPreAcquireForModWrite(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    PHAWK_STREAM_HANDLE_CONTEXT shc = fileObject->FsContext2;
    PHAWK_SCB scb = NULL;

    scb = HawkResolvePlaintextScbFromFileObject(fileObject);
    if (scb == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    HawkRedirectIrpToShadowFileObject(Data, shc);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
HawkPostAcquireForModWrite(
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
HawkPreReleaseForModWrite(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    PHAWK_STREAM_HANDLE_CONTEXT shc = fileObject->FsContext2;
    PHAWK_SCB scb = NULL;

    scb = HawkResolvePlaintextScbFromFileObject(fileObject);
    if (scb == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    HawkRedirectIrpToShadowFileObject(Data, shc);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
HawkPostReleaseForModWrite(
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
HawkPreAcquireForSectionSynchronization(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PFILE_OBJECT targetFileObject = Data->Iopb->TargetFileObject;
    PHAWK_SCB scb = NULL;

    scb = HawkResolvePlaintextScbFromFileObject(targetFileObject);
    if (scb == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    HawkRedirectIrpToShadowFileObject(
        Data,
        (PHAWK_STREAM_HANDLE_CONTEXT)targetFileObject->FsContext2);
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
HawkPostAcquireForSectionSynchronization(
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
HawkPreReleaseForSectionSynchronization(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PFILE_OBJECT targetFileObject = Data->Iopb->TargetFileObject;
    PHAWK_SCB scb = NULL;

    if (FLT_IS_FASTIO_OPERATION(Data))
        return FLT_PREOP_DISALLOW_FASTIO;

    scb = HawkResolvePlaintextScbFromFileObject(targetFileObject);
    if (scb == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    HawkRedirectIrpToShadowFileObject(
        Data,
        (PHAWK_STREAM_HANDLE_CONTEXT)targetFileObject->FsContext2);
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
HawkPostReleaseForSectionSynchronization(
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
