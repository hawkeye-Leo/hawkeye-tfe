#include "HawkeyeTfe.h"

VOID
HawkSyncPlaintextCache(
    __in PFILE_OBJECT FileObject,
    __in PHAWK_SCB Scb
    );

VOID
HawkPurgePlaintextCacheTail(
    __in PFILE_OBJECT FileObject,
    __in PHAWK_SCB Scb,
    __in LONGLONG NewEof
    );

VOID
HawkShrinkPlaintextScb(
    __in PFILE_OBJECT FileObject,
    __in PHAWK_SCB Scb,
    __in LONGLONG NewEof
    );

VOID
HawkSyncPlaintextCachesForScb(
    __in PHAWK_SCB Scb
    );

BOOLEAN
HawkIsChunkedRewriteFirstPiece(
    __in LONGLONG FileSize,
    __in ULONG StartVbo,
    __in ULONG ByteCount
    );

BOOLEAN
HawkShouldBypassCachedTruncateWrite(
    __in LONGLONG FileSize,
    __in ULONG StartVbo,
    __in ULONG ByteCount
    );

VOID
HawkPreparePlaintextCachedWrite(
    __in PFILE_OBJECT FileObject,
    __in PHAWK_SCB Scb,
    __inout PHAWK_STREAM_HANDLE_CONTEXT Shc,
    __in ULONG StartVbo,
    __in ULONG ByteCount
    );
