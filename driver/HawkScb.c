#include "HawkeyeTfe.h"
#include "HawkScb.h"
#include "HawkShc.h"


/* Hawkeye TFE */
static ULONG
HawkHashPath(
    __in PCUNICODE_STRING Path
    )
{
    ULONG hash;
    ULONG i;
    PUCHAR bytes;
    ULONG byteCount;

    if (!Path || Path->Length < sizeof(WCHAR))
        return 0;

    if (!Path->Buffer)
        return 0;

    hash = 2166136261u;
    bytes = (PUCHAR)Path->Buffer;
    byteCount = Path->Length;
    for (i = 0; i < byteCount; ++i)
    {
        hash ^= bytes[i];
        hash *= 16777619u;
    }

    return hash % HAWK_SCB_HASH_BUCKETS;
}

static PHAWK_SCB_ITEM
HawkScbHashFindByPath(
    __in PCUNICODE_STRING Path,
    __out_opt PHAWK_SCB_ITEM *PrevEntry
    )
{
    ULONG bucketIndex;
    PHAWK_SCB_ITEM prev;
    PHAWK_SCB_ITEM entry;

    bucketIndex = HawkHashPath(Path);
    prev = NULL;
    entry = g_HawkScbTable.Buckets[bucketIndex];
    while (entry &&
           RtlCompareUnicodeString(&entry->PathKey, Path, FALSE) != 0)
    {
        prev = entry;
        entry = entry->NextInBucket;
    }

    if (PrevEntry)
        *PrevEntry = prev;

    return entry;
}

static VOID
HawkScbHashUnlinkEntry(
    __in ULONG BucketIndex,
    __in_opt PHAWK_SCB_ITEM PrevEntry,
    __in PHAWK_SCB_ITEM Entry
    )
{
    if (PrevEntry)
        PrevEntry->NextInBucket = Entry->NextInBucket;
    else
        g_HawkScbTable.Buckets[BucketIndex] = Entry->NextInBucket;
}

static VOID
HawkScbHashInsertEntry(
    __in ULONG BucketIndex,
    __in PHAWK_SCB_ITEM Entry
    )
{
    Entry->NextInBucket = g_HawkScbTable.Buckets[BucketIndex];
    g_HawkScbTable.Buckets[BucketIndex] = Entry;
}

static BOOLEAN
HawkScbHashUnlinkByPointer(
    __in PHAWK_SCB Scb
    )
{
    ULONG bucketIndex;
    PHAWK_SCB_ITEM prev;
    PHAWK_SCB_ITEM entry;

    bucketIndex = HawkHashPath(&Scb->BucketLink.PathKey);
    prev = NULL;
    entry = g_HawkScbTable.Buckets[bucketIndex];
    while (entry)
    {
        if (HAWK_SCB_FROM_HASH_ITEM(entry) == Scb)
        {
            HawkScbHashUnlinkEntry(bucketIndex, prev, entry);
            return TRUE;
        }
        prev = entry;
        entry = entry->NextInBucket;
    }

    return FALSE;
}

static VOID
HawkScbRebindStreamHandles(
    __in PHAWK_SCB Scb
    )
{
    PHAWK_STREAM_HANDLE_CONTEXT shc;

    for (shc = Scb->StreamChainHead; shc != NULL; shc = shc->ChainNext)
        HawkShcBindToScb(shc, Scb);
}

static VOID
HawkScbOrphanLocked(
    __in PHAWK_SCB Scb
    )
{
    Scb->BucketLink.PathKey.Length = 0;
    RtlZeroMemory(Scb->BucketLink.PathKey.Buffer, HAWK_FILE_NAME_LEN * sizeof(WCHAR));
    HawkScbHashInsertEntry(0, &Scb->BucketLink);
    HawkScbRebindStreamHandles(Scb);
}

static VOID
HawkScbOrphanByPathLocked(
    __in PCUNICODE_STRING Path
    )
{
    PHAWK_SCB_ITEM prevEntry;
    PHAWK_SCB_ITEM entry;
    ULONG bucketIndex;
    PHAWK_SCB scb;

    entry = HawkScbHashFindByPath(Path, &prevEntry);
    if (!entry)
        return;

    bucketIndex = HawkHashPath(Path);
    HawkScbHashUnlinkEntry(bucketIndex, prevEntry, entry);
    scb = HAWK_SCB_FROM_HASH_ITEM(entry);
    HawkScbOrphanLocked(scb);
}

static VOID
HawkScbRepathLocked(
    __in PHAWK_SCB Scb,
    __in PCUNICODE_STRING NewPath
    )
{
    ULONG bucketIndex;

    Scb->BucketLink.PathKey.Length = 0;
    RtlAppendUnicodeStringToString(&Scb->BucketLink.PathKey, (PUNICODE_STRING)NewPath);
    bucketIndex = HawkHashPath(NewPath);
    HawkScbHashInsertEntry(bucketIndex, &Scb->BucketLink);
    HawkScbRebindStreamHandles(Scb);
}

static VOID
HawkScbUnlinkStreamHandle(
    __in PHAWK_SCB Scb,
    __in PHAWK_STREAM_HANDLE_CONTEXT Shc
    )
{
    PHAWK_STREAM_HANDLE_CONTEXT *link;

    for (link = &Scb->StreamChainHead; *link != NULL; link = &(*link)->ChainNext)
    {
        if (*link == Shc)
        {
            *link = Shc->ChainNext;
            return;
        }
    }

}

static VOID
HawkDestroyScb(
    __in PHAWK_SCB Scb
    )
{
    FltUninitializeFileLock(&Scb->Lock.FileLock);
    FltUninitializeOplock(&Scb->Lock.Oplock);
    ExDeleteResourceLite(Scb->Header.Resource);
    ExDeleteResourceLite(Scb->Header.PagingIoResource);
    FsRtlTeardownPerStreamContexts(&Scb->Header);
    ExFreePoolWithTag(Scb, HAWK_POOL_TAG);
}

PHAWK_SCB
HawkCreateScb(
    __in PFSRTL_ADVANCED_FCB_HEADER FcbHeader,
    __in PUNICODE_STRING NormalizedPath,
    __in PFILE_OBJECT FileObject
    )
{
    PHAWK_SCB scb = NULL;
    NTSTATUS status;
    ULONG bucketIndex;

    UNREFERENCED_PARAMETER(FileObject);

    if (!NormalizedPath ||
         NormalizedPath->Length > HAWK_FILE_NAME_LEN * sizeof(WCHAR) ||
         (NormalizedPath->Length > 0 && NormalizedPath->Buffer == NULL))
    {
        return NULL;
    }

    KeEnterCriticalRegion();
    HAWK_LOCK_FCB(FcbHeader);
    scb = ExAllocatePoolWithTag(NonPagedPool, sizeof(HAWK_SCB), HAWK_POOL_TAG);
    if (!scb)
    {
        HAWK_UNLOCK_FCB(FcbHeader);
        KeLeaveCriticalRegion();
        return NULL;
    }

    RtlZeroMemory(scb, sizeof(HAWK_SCB));
    scb->Header.Resource = &scb->Resource;
    scb->Header.PagingIoResource = &scb->PagingIoResource;
    status = ExInitializeResourceLite(&scb->Resource);
    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(scb, HAWK_POOL_TAG);
        HAWK_UNLOCK_FCB(FcbHeader);
        KeLeaveCriticalRegion();
        return NULL;
    }

    status = ExInitializeResourceLite(&scb->PagingIoResource);
    if (!NT_SUCCESS(status))
    {
        ExDeleteResourceLite(&scb->Resource);
        ExFreePoolWithTag(scb, HAWK_POOL_TAG);
        HAWK_UNLOCK_FCB(FcbHeader);
        KeLeaveCriticalRegion();
        return NULL;
    }

    scb->Header.FastMutex = &scb->FastMutex;
    FltInitializeFileLock(&scb->Lock.FileLock);
    FltInitializeOplock(&scb->Lock.Oplock);
    scb->ObjectRefCount = 0;
    scb->StreamHandleCount = 0;
    ExInitializeFastMutex(&scb->FastMutex);
    FsRtlSetupAdvancedHeader(&scb->Header, &scb->FastMutex);
    scb->Header.NodeTypeCode = HAWK_SCB_TYPE_CODE;
    scb->Header.NodeByteSize = sizeof(HAWK_SCB);
    scb->Header.IsFastIoPossible = FastIoIsNotPossible;
    HAWK_UNLOCK_FCB(FcbHeader);

    scb->BucketLink.PathKey.Length = NormalizedPath->Length;
    scb->BucketLink.PathKey.MaximumLength = HAWK_FILE_NAME_LEN * sizeof(WCHAR);
    scb->BucketLink.PathKey.Buffer = scb->PathKeyStorage;
    RtlCopyMemory(scb->BucketLink.PathKey.Buffer, NormalizedPath->Buffer, NormalizedPath->Length);

    bucketIndex = HawkHashPath(NormalizedPath);
    ExAcquireResourceExclusiveLite(&g_HawkScbTable.Lock, TRUE);
    HawkScbHashInsertEntry(bucketIndex, &scb->BucketLink);
    ExReleaseResourceLite(&g_HawkScbTable.Lock);
    KeLeaveCriticalRegion();
    return scb;
}

/* Hawkeye TFE: Scb */
BOOLEAN
HawkFindScb(
    __in PUNICODE_STRING NormalizedPath,
    __inout PHAWK_SCB *Scb
    )
{
    PHAWK_SCB_ITEM entry;
    BOOLEAN found;

    if (!NormalizedPath || !NormalizedPath->Buffer || NormalizedPath->Length == 0)
        return FALSE;

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&g_HawkScbTable.Lock, TRUE);
    entry = HawkScbHashFindByPath(NormalizedPath, NULL);
    if (entry && Scb != NULL)
        *Scb = HAWK_SCB_FROM_HASH_ITEM(entry);
    found = (entry != NULL);
    ExReleaseResourceLite(&g_HawkScbTable.Lock);
    KeLeaveCriticalRegion();
    return found;
}

VOID
HawkRenameScb(
    __in PUNICODE_STRING OldNormalizedPath,
    __in_opt PUNICODE_STRING NewNormalizedPath
    )
{
    PHAWK_SCB_ITEM prevEntry;
    PHAWK_SCB_ITEM entry;
    ULONG bucketIndex;
    PHAWK_SCB scb;

    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&g_HawkScbTable.Lock, TRUE);

    entry = HawkScbHashFindByPath(OldNormalizedPath, &prevEntry);
    if (!entry)
        goto Done;

    bucketIndex = HawkHashPath(OldNormalizedPath);
    HawkScbHashUnlinkEntry(bucketIndex, prevEntry, entry);
    scb = HAWK_SCB_FROM_HASH_ITEM(entry);

    if (NewNormalizedPath != NULL)
    {
        HawkScbOrphanByPathLocked(NewNormalizedPath);
        HawkScbRepathLocked(scb, NewNormalizedPath);
    }
    else
    {
        HawkScbOrphanLocked(scb);
    }

Done:
    ExReleaseResourceLite(&g_HawkScbTable.Lock);
    KeLeaveCriticalRegion();
}

VOID
HawkIncrementScbHandles(
    __in PHAWK_SCB Scb
    )
{
    ExAcquireFastMutex(&Scb->FastMutex);
    Scb->StreamHandleCount += 1;
    ExReleaseFastMutex(&Scb->FastMutex);
}

VOID
HawkDecrementScbHandles(
    __in PHAWK_SCB Scb
    )
{
    ExAcquireFastMutex(&Scb->FastMutex);
    Scb->StreamHandleCount -= 1;
    ExReleaseFastMutex(&Scb->FastMutex);
}

VOID
HawkReferenceScb(
    __in PHAWK_SCB Scb
    )
{
    ExAcquireFastMutex(&Scb->FastMutex);
    Scb->ObjectRefCount += 1;
    ExReleaseFastMutex(&Scb->FastMutex);
}

VOID
HawkDereferenceScb(
    __in PHAWK_SCB Scb,
    __in PHAWK_STREAM_HANDLE_CONTEXT Shc
    )
{
    BOOLEAN destroyScb;

    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&g_HawkScbTable.Lock, TRUE);
    HAWK_LOCK_SCB(Scb);

    if (Scb->ObjectRefCount == 0)
    {
        DBG_PRINT("HawkeyeTfe!DereferenceScb: object reference count underflow");
        HAWK_UNLOCK_SCB(Scb);
        ExReleaseResourceLite(&g_HawkScbTable.Lock);
        KeLeaveCriticalRegion();
        return;
    }

    Scb->ObjectRefCount -= 1;
    HawkScbUnlinkStreamHandle(Scb, Shc);
    destroyScb = (Scb->ObjectRefCount == 0);
    HAWK_UNLOCK_SCB(Scb);

    if (destroyScb)
    {
        HawkScbHashUnlinkByPointer(Scb);
        HawkDestroyScb(Scb);
    }

    ExReleaseResourceLite(&g_HawkScbTable.Lock);
    KeLeaveCriticalRegion();
}

PHAWK_SCB
HawkResolvePlaintextScbFromFileObject(
    __in PFILE_OBJECT FileObject
    )
{
    PHAWK_SCB scb;

    if (FileObject == NULL || FileObject->Type != IO_TYPE_FILE)
        return NULL;

    scb = (PHAWK_SCB)FileObject->FsContext;
    if (scb == NULL || scb->Header.NodeTypeCode != HAWK_SCB_TYPE_CODE)
        return NULL;

    return scb;
}
