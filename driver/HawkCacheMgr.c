#include "HawkeyeTfe.h"


/* Hawkeye TFE */
static BOOLEAN
HawkAcquireForLazyWritePagingResource(
    __in PHAWK_SCB Scb,
    __in BOOLEAN Wait
    )
{
    if (Scb->Header.PagingIoResource == NULL)
        return TRUE;

    return ExAcquireResourceSharedLite(Scb->Header.PagingIoResource, Wait);
}

static VOID
HawkAcquireForLazyWriteMarkCacheTopLevel(
    __in PHAWK_SCB Scb
    )
{
    if (PsGetCurrentThread() != NULL && IoGetTopLevelIrp() == NULL)
    {
        Scb->LazyWriterThread = PsGetCurrentThread();
        IoSetTopLevelIrp((PIRP)FSRTL_CACHE_TOP_LEVEL_IRP);
    }
}

/* Hawkeye TFE: LazyWrite */
BOOLEAN
HawkAcquireForLazyWrite(
    __in PVOID Context,
    __in BOOLEAN Wait
    )
{
    PHAWK_SCB scb = (PHAWK_SCB)Context;

    if (scb == NULL)
        return FALSE;

    if (!HawkAcquireForLazyWritePagingResource(scb, Wait))
        return FALSE;

    HawkAcquireForLazyWriteMarkCacheTopLevel(scb);
    return TRUE;
}

static VOID
HawkReleaseFromLazyWritePagingResource(
    __in PHAWK_SCB Scb
    )
{
    if (Scb->Header.PagingIoResource != NULL)
        ExReleaseResourceLite(Scb->Header.PagingIoResource);
}

static VOID
HawkReleaseFromLazyWriteClearCacheTopLevel(
    VOID
    )
{
    if (IoGetTopLevelIrp() == (PIRP)FSRTL_CACHE_TOP_LEVEL_IRP)
        IoSetTopLevelIrp(NULL);
}

VOID
HawkReleaseFromLazyWrite(
    __in PVOID Context
    )
{
    PHAWK_SCB scb = (PHAWK_SCB)Context;

    scb->LazyWriterThread = NULL;
    HawkReleaseFromLazyWritePagingResource(scb);
    HawkReleaseFromLazyWriteClearCacheTopLevel();
}

static BOOLEAN
HawkAcquireForReadAheadMainResource(
    __in PHAWK_SCB Scb,
    __in BOOLEAN Wait
    )
{
    return ExAcquireResourceSharedLite(Scb->Header.Resource, Wait);
}

static VOID
HawkAcquireForReadAheadMarkCacheTopLevel(
    VOID
    )
{
    IoSetTopLevelIrp((PIRP)FSRTL_CACHE_TOP_LEVEL_IRP);
}

/* Hawkeye TFE: ReadAhead */
BOOLEAN
HawkAcquireForReadAhead(
    __in PVOID Context,
    __in BOOLEAN Wait
    )
{
    PHAWK_SCB scb = (PHAWK_SCB)Context;
    BOOLEAN acquired;

    acquired = HawkAcquireForReadAheadMainResource(scb, Wait);
    if (IoGetTopLevelIrp() == NULL)
        HawkAcquireForReadAheadMarkCacheTopLevel();
    return acquired;
}

static VOID
HawkReleaseFromReadAheadMainResource(
    __in PHAWK_SCB Scb
    )
{
    ExReleaseResourceLite(Scb->Header.Resource);
}

VOID
HawkReleaseFromReadAhead(
    __in PVOID Context
    )
{
    PHAWK_SCB scb = (PHAWK_SCB)Context;

    if (IoGetTopLevelIrp() != (PIRP)FSRTL_CACHE_TOP_LEVEL_IRP)
        return;

    IoSetTopLevelIrp(NULL);
    HawkReleaseFromReadAheadMainResource(scb);
}
