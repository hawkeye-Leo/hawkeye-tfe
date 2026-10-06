#include "HawkeyeTfe.h"

PHAWK_STREAM_HANDLE_CONTEXT
HawkRedirectResolveStreamContext(
    __in PFILE_OBJECT FileObject
    );

VOID
HawkRedirectIrpToShadowFileObject(
    __inout PFLT_CALLBACK_DATA Data,
    __in PHAWK_STREAM_HANDLE_CONTEXT Shc
    );
