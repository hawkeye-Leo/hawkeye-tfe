#ifndef HAWK_TFE_H
#define HAWK_TFE_H

/* Hawkeye TFE */
#define HAWKEYE_TFE_NAME L"Hawkeye TFE"
#define HAWKEYE_TFE_DRIVER L"HawkeyeTfe"
#define HAWKEYE_TFE_SYS L"HawkeyeTfe.sys"

#include <fltKernel.h>

#define HAWK_POOL_TAG           'kawH'
#define HAWK_VOL_CTX_TAG        'kawV'
#define HAWK_SHC_CTX_TAG        'kawS'
#define HAWK_SECTOR_SIZE 0x200
#define HAWK_FS_HEADER_SIZE 256
#define HAWK_FS_KEY_SIZE 256
#define HAWK_FS_ONDISK_PREFIX (HAWK_FS_HEADER_SIZE + HAWK_FS_KEY_SIZE)
#define HAWK_FS_MARK_SIZE 20
#define HAWK_SCB_HASH_BUCKETS 100

#define HAWK_SCB_TYPE_CODE ((CSHORT)0x4857)
#define HAWK_READ_AHEAD_GRANULARITY (0x10000)
#define HAWK_GRADUAL_ENCRYPT_CHUNK_SIZE (64 * 1024)
#define HAWK_ENCRYPT_TEMP_SUFFIX L".htfe-tmp"
#define HAWK_FILTER_DEVICE_NAME L"\\Device\\HawkeyeTfe"

#if DBG
#define DBG_PRINT(x, ...)   DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, x##"\n", ##__VA_ARGS__)
#else
#define DBG_PRINT(x, ...)
#endif

#define HAWK_FILE_NAME_LEN 300
#define HAWK_DEFAULT_PROTECT_PATH L"C:\\test_files"

typedef struct _HAWK_FILTER_DATA
{
    PFLT_FILTER Filter;
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING ProtectedRootPath;
} HAWK_FILTER_DATA, *PHAWK_FILTER_DATA;

#define HAWK_VOLUME_NAME_BYTES 32
#define HAWK_VOLUME_NAME_CHARS (HAWK_VOLUME_NAME_BYTES / sizeof(WCHAR))

typedef struct _HAWK_VOLUME_CONTEXT
{
    UNICODE_STRING VolumeName;
    WCHAR VolumeNameStorage[HAWK_VOLUME_NAME_CHARS];
    ULONG SectorSize;
} HAWK_VOLUME_CONTEXT, *PHAWK_VOLUME_CONTEXT;

typedef struct _HAWK_FLT_OBJECTS
{
    PVOID Filter;
    PVOID Volume;
    PVOID Instance;
} HAWK_FLT_OBJECTS, *PHAWK_FLT_OBJECTS;

typedef struct _HAWK_IRP_CONTEXT
{
    PIO_WORKITEM WorkItem;
    UCHAR MajorFunction;
    PFILE_OBJECT FileObject;
    PFLT_CALLBACK_DATA CallbackData;
    HAWK_FLT_OBJECTS RelatedObjects;
    PVOID * CompletionContext;
    ULONG Flags;
} HAWK_IRP_CONTEXT, *PHAWK_IRP_CONTEXT;

typedef struct _HAWK_PRE2POST_CONTEXT
{
    PHAWK_VOLUME_CONTEXT VolumeContext;
    PVOID HandoffPtr;
    PMDL HandoffMdl;
    PHAWK_IRP_CONTEXT IrpContext;
    PVOID BoundScb;
    ULONG CacheOffset;
    PVOID UserBuffer;
} HAWK_PRE2POST_CONTEXT, *PHAWK_PRE2POST_CONTEXT;

#define HAWK_IRP_CTX_FLAG_WAIT (0x00000002)
#define HAWK_IRP_CTX_FLAG_DEFERRED_WRITE (0x00000040)
#define HAWK_IRP_CTX_FLAG_IN_FSP (0x00000200)

PHAWK_IRP_CONTEXT
HawkCreateIrpContext(
    __in PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID * CompletionContext,
    __in BOOLEAN Wait
    );

VOID
HawkDeleteIrpContext(
    __in PHAWK_IRP_CONTEXT IrpContext
    );

typedef struct _HAWK_SCB HAWK_SCB, *PHAWK_SCB;

typedef struct _HAWK_STREAM_HANDLE_CONTEXT {
    struct _HAWK_STREAM_HANDLE_CONTEXT * ChainNext;
    PWCHAR PathStorage;
    UNICODE_STRING PathKey;
    HANDLE AliasHandle;
    PFILE_OBJECT ShadowFileObject;
    PFILE_OBJECT PlaintextFileObject;
    BOOLEAN IsProtectedOpen;
    BOOLEAN TruncatedOnOpen;
    BOOLEAN ZeroLengthCommitted;
    LONGLONG PlaintextValidLength;
} HAWK_STREAM_HANDLE_CONTEXT, *PHAWK_STREAM_HANDLE_CONTEXT;

typedef struct _HAWK_SCB_LOCK {
    FILE_LOCK FileLock;
    OPLOCK Oplock;
} HAWK_SCB_LOCK, *PHAWK_SCB_LOCK;

typedef struct _HAWK_SCB_ITEM {
    struct _HAWK_SCB_ITEM * NextInBucket;
    UNICODE_STRING PathKey;
} HAWK_SCB_ITEM, *PHAWK_SCB_ITEM;

struct _HAWK_SCB {
    FSRTL_ADVANCED_FCB_HEADER Header;
    ERESOURCE Resource;
    ERESOURCE PagingIoResource;
    HAWK_SCB_LOCK Lock;
    LONG ObjectRefCount;
    LONG StreamHandleCount;
    SECTION_OBJECT_POINTERS SectionObjectPointers;
    FAST_MUTEX FastMutex;
    PHAWK_STREAM_HANDLE_CONTEXT StreamChainHead;
    PVOID LazyWriterThread;
    HAWK_SCB_ITEM BucketLink;
    WCHAR PathKeyStorage[HAWK_FILE_NAME_LEN];
};

typedef struct _HAWK_SCB_QUEUE
{
    ERESOURCE Lock;
    PHAWK_SCB_ITEM Buckets[HAWK_SCB_HASH_BUCKETS];
} HAWK_SCB_QUEUE, *PHAWK_SCB_QUEUE;

typedef struct _HAWK_RENAME_PATHS
{
    UNICODE_STRING TargetPath;
    UNICODE_STRING TargetPathKey;
    WCHAR TargetPathBuffer[HAWK_FILE_NAME_LEN];
    WCHAR TargetPathKeyStorage[HAWK_FILE_NAME_LEN];
} HAWK_RENAME_PATHS, *PHAWK_RENAME_PATHS;

typedef struct _HAWK_CREATE_CONTEXT
{
    PFLT_CALLBACK_DATA CallbackData;
    PCFLT_RELATED_OBJECTS RelatedObjects;
    ULONG CreateOptions;
    ULONG CreateDisposition;
    ACCESS_MASK DesiredAccess;
    BOOLEAN IsProtectedOpen;
    BOOLEAN TargetExists;
    BOOLEAN TargetIsDirectory;
    BOOLEAN IsEncrypted;
    PHAWK_STREAM_HANDLE_CONTEXT StreamCtx;
    BOOLEAN StreamCtxAttached;
    UNICODE_STRING PathKey;
    OBJECT_ATTRIBUTES ObjectAttributes;
    BOOLEAN CriticalRegionActive;
    ULONG_PTR AliasOpenInfo;
    PFILE_OBJECT SavedRelatedFileObject;
    BOOLEAN RelatedOpenRedirected;
} HAWK_CREATE_CONTEXT, *PHAWK_CREATE_CONTEXT;

typedef struct _HAWK_ENCRYPT_SCRATCH {
    DECLSPEC_ALIGN(8) UCHAR RenameInfoStorage[sizeof(FILE_RENAME_INFORMATION) + HAWK_FILE_NAME_LEN * sizeof(WCHAR)];
    WCHAR TempPathBuffer[HAWK_FILE_NAME_LEN + 10 + 1];
} HAWK_ENCRYPT_SCRATCH, *PHAWK_ENCRYPT_SCRATCH;

extern HAWK_FILTER_DATA g_HawkFilter;
extern CACHE_MANAGER_CALLBACKS g_HawkCcCallbacks;
extern HAWK_SCB_QUEUE g_HawkScbTable;
extern NPAGED_LOOKASIDE_LIST g_HawkP2PLookaside;

#endif
