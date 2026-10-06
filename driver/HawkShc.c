#include "HawkeyeTfe.h"
#include "HawkShc.h"


/* Hawkeye TFE */
static VOID
HawkShcResetNormalizedPath(
    __inout PHAWK_STREAM_HANDLE_CONTEXT Shc
    )
{
    if (Shc == NULL)
        return;

    Shc->PathKey.Length = 0;
    Shc->PathKey.Buffer = NULL;
}

static VOID
HawkShcReleaseOwnedPathBuffer(
    __inout PHAWK_STREAM_HANDLE_CONTEXT Shc
    )
{
    if (Shc == NULL)
        return;

    if (Shc->PathStorage != NULL)
    {
        ExFreePoolWithTag(Shc->PathStorage, HAWK_POOL_TAG);
        Shc->PathStorage = NULL;
    }
}

static VOID
HawkShcClearShadowOpen(
    __inout PHAWK_STREAM_HANDLE_CONTEXT Shc
    )
{
    if (Shc == NULL)
        return;

    Shc->AliasHandle = NULL;
    Shc->ShadowFileObject = NULL;
    Shc->PlaintextFileObject = NULL;
}

/* Hawkeye TFE: Shc */
VOID
HawkShcInitialize(
    __out PHAWK_STREAM_HANDLE_CONTEXT Shc,
    __in PCUNICODE_STRING NormalizedPath
    )
{
    if (Shc == NULL || NormalizedPath == NULL)
        return;

    RtlZeroMemory(Shc, sizeof(HAWK_STREAM_HANDLE_CONTEXT));
    Shc->PathKey = *NormalizedPath;
}

VOID
HawkShcBindToScb(
    __inout PHAWK_STREAM_HANDLE_CONTEXT Shc,
    __in PHAWK_SCB Scb
    )
{
    if (Shc == NULL || Scb == NULL)
        return;

    Shc->PathKey = Scb->BucketLink.PathKey;
}

VOID
HawkCleanStreamHandleContext(
    __in PFLT_CONTEXT Context,
    __in FLT_CONTEXT_TYPE ContextType
    )
{
    PHAWK_STREAM_HANDLE_CONTEXT shc = (PHAWK_STREAM_HANDLE_CONTEXT)Context;

    if (ContextType != FLT_STREAMHANDLE_CONTEXT || shc == NULL)
        return;

    HawkShcClearShadowOpen(shc);
    HawkShcReleaseOwnedPathBuffer(shc);
    HawkShcResetNormalizedPath(shc);
}
