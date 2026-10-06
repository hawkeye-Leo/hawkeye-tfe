#include "HawkeyeTfe.h"

#define HAWK_LOCK_FCB(F) { \
    ExAcquireFastMutexUnsafe(F->FastMutex); \
}

#define HAWK_UNLOCK_FCB(F) { \
    ExReleaseFastMutexUnsafe(F->FastMutex); \
}

#define HAWK_LOCK_SCB(S) { \
    ExAcquireFastMutexUnsafe(&S->FastMutex); \
}

#define HAWK_UNLOCK_SCB(S) { \
    ExReleaseFastMutexUnsafe(&S->FastMutex); \
}

#define HAWK_SCB_FROM_HASH_ITEM(_Item) \
    CONTAINING_RECORD((_Item), HAWK_SCB, BucketLink)

PHAWK_SCB
HawkCreateScb(
    __in PFSRTL_ADVANCED_FCB_HEADER FcbHeader,
    __in PUNICODE_STRING NormalizedPath,
    __in PFILE_OBJECT FileObject
    );

BOOLEAN
HawkFindScb(
    __in PUNICODE_STRING NormalizedPath,
    __inout PHAWK_SCB *Scb
    );

VOID
HawkRenameScb(
    __in PUNICODE_STRING OldNormalizedPath,
    __in_opt PUNICODE_STRING NewNormalizedPath
    );

VOID
HawkIncrementScbHandles(
    __in PHAWK_SCB Scb
    );

VOID
HawkDecrementScbHandles(
    __in PHAWK_SCB Scb
    );

VOID
HawkReferenceScb(
    __in PHAWK_SCB Scb
    );

VOID
HawkDereferenceScb(
    __in PHAWK_SCB Scb,
    __in PHAWK_STREAM_HANDLE_CONTEXT Shc
    );

PHAWK_SCB
HawkResolvePlaintextScbFromFileObject(
    __in PFILE_OBJECT FileObject
    );
