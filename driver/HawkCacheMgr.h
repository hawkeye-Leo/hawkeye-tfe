#include "HawkeyeTfe.h"

BOOLEAN
HawkAcquireForLazyWrite(
    __in PVOID Context,
    __in BOOLEAN Wait
    );

BOOLEAN
HawkReleaseFromLazyWrite(
    __in PVOID Context
    );

BOOLEAN
HawkAcquireForReadAhead(
    __in PVOID Context,
    __in BOOLEAN Wait
    );

BOOLEAN
HawkReleaseFromReadAhead(
    __in PVOID Context
    );
