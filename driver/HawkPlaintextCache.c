#include "HawkeyeTfe.h"
#include "HawkPlaintextCache.h"


/* Hawkeye TFE */
static BOOLEAN
HawkPlaintextCacheIsMapped(
    __in PFILE_OBJECT FileObject
    )
{
    if (FileObject->PrivateCacheMap == NULL)
        return FALSE;
    if (FileObject->SectionObjectPointer == NULL)
        return FALSE;
    if (FileObject->SectionObjectPointer->SharedCacheMap == NULL)
        return FALSE;
    return TRUE;
}

VOID
HawkSyncPlaintextCache(
    __in PFILE_OBJECT FileObject,
    __in PHAWK_SCB Scb
    )
{
    if (FileObject == NULL || Scb == NULL)
        return;
    if (!HawkPlaintextCacheIsMapped(FileObject))
        return;

    CcSetFileSizes(FileObject, (PCC_FILE_SIZES)&Scb->Header.AllocationSize);
}

static BOOLEAN
HawkPlaintextCacheHasScbSharedMap(
    __in PHAWK_SCB Scb
    )
{
    return (Scb->SectionObjectPointers.SharedCacheMap != NULL);
}

static BOOLEAN
HawkPlaintextCacheHasFoSharedMap(
    __in PFILE_OBJECT FileObject
    )
{
    if (FileObject == NULL || FileObject->SectionObjectPointer == NULL)
        return FALSE;

    return (FileObject->SectionObjectPointer->SharedCacheMap != NULL);
}

static VOID
HawkPlaintextCachePurgeFromOffset(
    __in PSECTION_OBJECT_POINTERS SectionObjectPointer,
    __in LONGLONG NewEof
    )
{
    LARGE_INTEGER purgeOffset;

    purgeOffset.QuadPart = NewEof;
    CcPurgeCacheSection(SectionObjectPointer, &purgeOffset, 0, FALSE);
}

VOID
HawkPurgePlaintextCacheTail(
    __in PFILE_OBJECT FileObject,
    __in PHAWK_SCB Scb,
    __in LONGLONG NewEof
    )
{
    if (Scb == NULL || NewEof < 0)
        return;

    if (FileObject != NULL)
        HawkSyncPlaintextCache(FileObject, Scb);

    if (HawkPlaintextCacheHasScbSharedMap(Scb))
    {
        HawkPlaintextCachePurgeFromOffset(&Scb->SectionObjectPointers, NewEof);
        return;
    }

    if (HawkPlaintextCacheHasFoSharedMap(FileObject))
        HawkPlaintextCachePurgeFromOffset(FileObject->SectionObjectPointer, NewEof);
}

static VOID
HawkSyncPlaintextCacheForShc(
    __in PHAWK_STREAM_HANDLE_CONTEXT Shc,
    __in PHAWK_SCB Scb
    )
{
    if (Shc->PlaintextFileObject == NULL)
        return;

    HawkSyncPlaintextCache(Shc->PlaintextFileObject, Scb);
}

static VOID
HawkSyncPlaintextCachesForScbLocked(
    __in PHAWK_SCB Scb
    )
{
    PHAWK_STREAM_HANDLE_CONTEXT shc;

    for (shc = Scb->StreamChainHead; shc != NULL; shc = shc->ChainNext)
        HawkSyncPlaintextCacheForShc(shc, Scb);
}

/* Hawkeye TFE: PlaintextCache */
VOID
HawkSyncPlaintextCachesForScb(
    __in PHAWK_SCB Scb
    )
{
    if (Scb == NULL)
        return;

    ExAcquireFastMutex(&Scb->FastMutex);
    HawkSyncPlaintextCachesForScbLocked(Scb);
    ExReleaseFastMutex(&Scb->FastMutex);
}

static BOOLEAN
HawkShrinkPlaintextScbIsValidShrink(
    __in PHAWK_SCB Scb,
    __in LONGLONG NewEof
    )
{
    if (Scb == NULL || NewEof < 0)
        return FALSE;
    if (NewEof >= Scb->Header.FileSize.QuadPart)
        return FALSE;
    return TRUE;
}

static VOID
HawkShrinkPlaintextScbUpdateHeader(
    __inout PHAWK_SCB Scb,
    __in LONGLONG NewEof
    )
{
    Scb->Header.FileSize.QuadPart = NewEof;
    if (Scb->Header.ValidDataLength.QuadPart > NewEof)
        Scb->Header.ValidDataLength.QuadPart = NewEof;
    if (Scb->Header.AllocationSize.QuadPart < Scb->Header.FileSize.QuadPart)
        Scb->Header.AllocationSize.QuadPart = Scb->Header.FileSize.QuadPart;
}

static VOID
HawkShrinkPlaintextScbInvalidateCache(
    __in PFILE_OBJECT FileObject,
    __in PHAWK_SCB Scb,
    __in LONGLONG NewEof
    )
{

    if (HawkPlaintextCacheHasScbSharedMap(Scb))
        CcPurgeCacheSection(&Scb->SectionObjectPointers, NULL, 0, FALSE);
    else
        HawkPurgePlaintextCacheTail(FileObject, Scb, NewEof);
}

VOID
HawkShrinkPlaintextScb(
    __in PFILE_OBJECT FileObject,
    __in PHAWK_SCB Scb,
    __in LONGLONG NewEof
    )
{
    if (!HawkShrinkPlaintextScbIsValidShrink(Scb, NewEof))
        return;

    HawkShrinkPlaintextScbUpdateHeader(Scb, NewEof);
    HawkShrinkPlaintextScbInvalidateCache(FileObject, Scb, NewEof);
    HawkSyncPlaintextCachesForScb(Scb);
}

#define HAWK_CHUNKED_REWRITE_PIECE_BYTES 65536u
#define HAWK_CHUNKED_REWRITE_MIN_FILE_BYTES (HAWK_CHUNKED_REWRITE_PIECE_BYTES * 2)

static BOOLEAN
HawkIsPartialWriteAtFileOrigin(
    __in ULONG StartVbo,
    __in ULONG ByteCount,
    __in LONGLONG FileSize
    )
{
    if (StartVbo != 0)
        return FALSE;
    if (ByteCount >= FileSize)
        return FALSE;
    return TRUE;
}

static BOOLEAN
HawkIsNonEmptyPartialWriteAtFileOrigin(
    __in ULONG StartVbo,
    __in ULONG ByteCount,
    __in LONGLONG FileSize
    )
{
    if (ByteCount == 0)
        return FALSE;
    return HawkIsPartialWriteAtFileOrigin(StartVbo, ByteCount, FileSize);
}

static BOOLEAN
HawkIsChunkedRewriteFirstPieceSize(
    __in ULONG ByteCount,
    __in LONGLONG FileSize
    )
{

    if (ByteCount < HAWK_CHUNKED_REWRITE_PIECE_BYTES)
        return FALSE;
    if (FileSize <= (LONGLONG)ByteCount + HAWK_CHUNKED_REWRITE_PIECE_BYTES)
        return FALSE;
    return TRUE;
}

BOOLEAN
HawkIsChunkedRewriteFirstPiece(
    __in LONGLONG FileSize,
    __in ULONG StartVbo,
    __in ULONG ByteCount
    )
{
    if (!HawkIsPartialWriteAtFileOrigin(StartVbo, ByteCount, FileSize))
        return FALSE;
    if (FileSize <= HAWK_CHUNKED_REWRITE_MIN_FILE_BYTES)
        return FALSE;
    return HawkIsChunkedRewriteFirstPieceSize(ByteCount, FileSize);
}

BOOLEAN
HawkShouldBypassCachedTruncateWrite(
    __in LONGLONG FileSize,
    __in ULONG StartVbo,
    __in ULONG ByteCount
    )
{
    if (!HawkIsNonEmptyPartialWriteAtFileOrigin(StartVbo, ByteCount, FileSize))
        return FALSE;
    if (HawkIsChunkedRewriteFirstPiece(FileSize, StartVbo, ByteCount))
        return FALSE;
    return TRUE;
}

static VOID
HawkPreparePlaintextCachedWriteShrinkPath(
    __in PFILE_OBJECT FileObject,
    __in PHAWK_SCB Scb,
    __inout_opt PHAWK_STREAM_HANDLE_CONTEXT Shc,
    __in LONGLONG WriteEnd
    )
{
    HawkShrinkPlaintextScb(FileObject, Scb, WriteEnd);
    if (Shc != NULL)
        Shc->PlaintextValidLength = WriteEnd;
}

static VOID
HawkPreparePlaintextCachedWriteAdvanceValidLength(
    __inout PHAWK_STREAM_HANDLE_CONTEXT Shc,
    __in ULONG StartVbo,
    __in ULONG ByteCount,
    __in LONGLONG OldFileSize,
    __in LONGLONG WriteEnd
    )
{

    if (StartVbo == 0 && ByteCount > 0 &&
        !HawkIsChunkedRewriteFirstPiece(OldFileSize, StartVbo, ByteCount))
    {
        Shc->PlaintextValidLength = WriteEnd;
        return;
    }
    if (Shc->PlaintextValidLength == (LONGLONG)StartVbo)
        Shc->PlaintextValidLength = WriteEnd;
}

static VOID
HawkPreparePlaintextCachedWriteExtendPath(
    __inout_opt PHAWK_STREAM_HANDLE_CONTEXT Shc,
    __in ULONG StartVbo,
    __in ULONG ByteCount,
    __in LONGLONG OldFileSize,
    __in LONGLONG WriteEnd
    )
{

    if (Shc != NULL)
    {
        HawkPreparePlaintextCachedWriteAdvanceValidLength(
            Shc, StartVbo, ByteCount, OldFileSize, WriteEnd);
    }
}

VOID
HawkPreparePlaintextCachedWrite(
    __in PFILE_OBJECT FileObject,
    __in PHAWK_SCB Scb,
    __inout PHAWK_STREAM_HANDLE_CONTEXT Shc,
    __in ULONG StartVbo,
    __in ULONG ByteCount
    )
{
    LONGLONG writeEnd;
    LONGLONG oldFileSize;

    if (FileObject == NULL || Scb == NULL)
        return;

    writeEnd = (LONGLONG)StartVbo + ByteCount;
    oldFileSize = Scb->Header.FileSize.QuadPart;

    if (writeEnd < oldFileSize)
        HawkPreparePlaintextCachedWriteShrinkPath(FileObject, Scb, Shc, writeEnd);
    else
        HawkPreparePlaintextCachedWriteExtendPath(
            Shc, StartVbo, ByteCount, oldFileSize, writeEnd);
}
