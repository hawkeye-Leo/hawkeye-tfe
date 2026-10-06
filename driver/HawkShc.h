#include "HawkeyeTfe.h"

VOID
HawkShcInitialize(
    __out PHAWK_STREAM_HANDLE_CONTEXT Shc,
    __in PCUNICODE_STRING NormalizedPath
    );

VOID
HawkShcBindToScb(
    __inout PHAWK_STREAM_HANDLE_CONTEXT Shc,
    __in PHAWK_SCB Scb
    );

VOID
HawkCleanStreamHandleContext(
    __in PFLT_CONTEXT Context,
    __in FLT_CONTEXT_TYPE ContextType
    );
