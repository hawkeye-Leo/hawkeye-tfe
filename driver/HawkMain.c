
#include "HawkeyeTfe.h"
#include "HawkSetup.h"
#include "HawkShc.h"
#include "HawkOperations.h"
#include "HawkCacheMgr.h"


/* Hawkeye TFE */
PHAWK_IRP_CONTEXT
HawkCreateIrpContext(
    __in PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID * CompletionContext,
    __in BOOLEAN Wait
    )
{
    PHAWK_IRP_CONTEXT irpContext = ExAllocatePoolWithTag(NonPagedPool, sizeof(HAWK_IRP_CONTEXT), HAWK_POOL_TAG);
    if (!irpContext)
        return NULL;
    RtlZeroMemory(irpContext, sizeof(HAWK_IRP_CONTEXT));
    irpContext->MajorFunction = Data->Iopb->MajorFunction;
    irpContext->FileObject = Data->Iopb->TargetFileObject;
    irpContext->CallbackData = Data;
    if (FltObjects->Filter)
        irpContext->RelatedObjects.Filter = FltObjects->Filter;
    if (FltObjects->Volume)
        irpContext->RelatedObjects.Volume = FltObjects->Volume;
    if (FltObjects->Instance)
        irpContext->RelatedObjects.Instance = FltObjects->Instance;
    irpContext->CompletionContext = CompletionContext;
    if (Wait)
        SetFlag(irpContext->Flags, HAWK_IRP_CTX_FLAG_WAIT);
    return irpContext;
}

VOID
HawkDeleteIrpContext(
    __in PHAWK_IRP_CONTEXT IrpContext
    )
{
    ExFreePoolWithTag(IrpContext, HAWK_POOL_TAG);
}

CONST FLT_CONTEXT_REGISTRATION g_HawkCtxRegistry[] = {
    { FLT_VOLUME_CONTEXT,
      0,
      HawkCleanupVolumeContext,
      sizeof(HAWK_VOLUME_CONTEXT),
      HAWK_VOL_CTX_TAG },

    { FLT_STREAMHANDLE_CONTEXT,
      0,
      HawkCleanStreamHandleContext,
      sizeof(HAWK_STREAM_HANDLE_CONTEXT),
      HAWK_SHC_CTX_TAG },

    { FLT_CONTEXT_END }
};
/* Hawkeye TFE: callbacks */

CONST FLT_OPERATION_REGISTRATION g_HawkCbRegistry[] = {
    { IRP_MJ_CREATE,
      0,
      HawkPreCreate,
      HawkPostCreate },

    { IRP_MJ_CREATE_NAMED_PIPE,
      0,
      HawkPreCreateNamedPipe,
      NULL },

    { IRP_MJ_CLOSE,
      0,
      HawkPreClose,
      HawkPostClose },

    { IRP_MJ_READ,
      0,
      HawkPreRead,
      HawkPostRead },

    { IRP_MJ_WRITE,
      0,
      HawkPreWrite,
      HawkPostWrite },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      HawkPreQueryInformation,
      HawkPostQueryInformation },

    { IRP_MJ_SET_INFORMATION,
      0,
      HawkPreSetInformation,
      HawkPostSetInformation },

    { IRP_MJ_QUERY_EA,
      0,
      HawkPreQueryEa,
      NULL },

    { IRP_MJ_SET_EA,
      0,
      HawkPreSetEa,
      NULL },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      HawkPreFlush,
      NULL },

    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      HawkPreQueryVolumeInformation,
      NULL },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      HawkPreSetVolumeInformation,
      NULL },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      HawkPreDirectoryControl,
      NULL },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      HawkPreFsControl,
      NULL },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      HawkPreDeviceControl,
      NULL },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      HawkPreInternalDeviceControl,
      NULL },

    { IRP_MJ_LOCK_CONTROL,
      0,
      HawkPreLockControl,
      HawkPostLockControl },

    { IRP_MJ_CLEANUP,
      0,
      HawkPreCleanup,
      HawkPostCleanup },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      HawkPreCreateMailslot,
      NULL },

    { IRP_MJ_QUERY_SECURITY,
      0,
      HawkPreQuerySecurity,
      NULL },

    { IRP_MJ_SET_SECURITY,
      0,
      HawkPreSetSecurity,
      NULL },

    { IRP_MJ_SYSTEM_CONTROL,
      0,
      HawkPreSystemControl,
      NULL },

    { IRP_MJ_QUERY_QUOTA,
      0,
      HawkPreQueryQuota,
      NULL },

    { IRP_MJ_SET_QUOTA,
      0,
      HawkPreSetQuota,
      NULL },

    { IRP_MJ_PNP,
      0,
      HawkPrePnp,
      NULL },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      HawkPreAcquireForSectionSynchronization,
      HawkPostAcquireForSectionSynchronization },

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
      HawkPreReleaseForSectionSynchronization,
      HawkPostReleaseForSectionSynchronization },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
      HawkPreAcquireForModWrite,
      HawkPostAcquireForModWrite },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
      HawkPreReleaseForModWrite,
      HawkPostReleaseForModWrite },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
      HawkPreAcquireForCcFlush,
      HawkPostAcquireForCcFlush },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
      HawkPreReleaseForCcFlush,
      HawkPostReleaseForCcFlush },

    { IRP_MJ_MDL_READ,
      0,
      HawkPreMdlRead,
      NULL },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      HawkPreMdlReadComplete,
      NULL },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      HawkPreMdlWrite,
      NULL },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      HawkPreMdlWriteComplete,
      NULL },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      HawkPreFastIoCheckPossible,
      NULL },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      HawkPreNetworkQueryOpen,
      HawkPostNetworkQueryOpen },

    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION g_HawkFilterDesc = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    g_HawkCtxRegistry,
    g_HawkCbRegistry,
    HawkFilterUnload,
    HawkInstanceSetup,
    HawkInstanceQueryTeardown,
    NULL,
    NULL,
    HawkGenerateFileName,
    HawkNormalizeNameComponent,
    NULL
};

HAWK_FILTER_DATA g_HawkFilter;
CACHE_MANAGER_CALLBACKS g_HawkCcCallbacks;
HAWK_SCB_QUEUE g_HawkScbTable;
NPAGED_LOOKASIDE_LIST g_HawkP2PLookaside;

static FLT_FILE_NAME_OPTIONS
HawkFileNameAdjustQueryOptions(
    __in FLT_FILE_NAME_OPTIONS NameOptions
    )
{
    ClearFlag(NameOptions, FLT_FILE_NAME_REQUEST_FROM_CURRENT_PROVIDER);
    if (FlagOn(NameOptions, FLT_FILE_NAME_NORMALIZED))
    {
        ClearFlag(NameOptions, FLT_FILE_NAME_NORMALIZED);
        SetFlag(NameOptions, FLT_FILE_NAME_OPENED);
    }
    return NameOptions;
}

static NTSTATUS
HawkFileNameQueryInformation(
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject,
    __in_opt PFLT_CALLBACK_DATA CallbackData,
    __in FLT_FILE_NAME_OPTIONS NameOptions,
    __deref_out PFLT_FILE_NAME_INFORMATION *FileNameInformation
    )
{
    PFILE_OBJECT savedTarget;
    NTSTATUS status;

    *FileNameInformation = NULL;
    if (FileObject == NULL || Instance == NULL)
        return STATUS_INVALID_PARAMETER;

    NameOptions = HawkFileNameAdjustQueryOptions(NameOptions);
    if (CallbackData != NULL)
    {
        savedTarget = CallbackData->Iopb->TargetFileObject;
        CallbackData->Iopb->TargetFileObject = FileObject;
        FltSetCallbackDataDirty(CallbackData);
        status = FltGetFileNameInformation(
            CallbackData,
            NameOptions,
            FileNameInformation);
        CallbackData->Iopb->TargetFileObject = savedTarget;
        FltClearCallbackDataDirty(CallbackData);
        return status;
    }

    return FltGetFileNameInformationUnsafe(
        FileObject,
        Instance,
        NameOptions,
        FileNameInformation);
}

static NTSTATUS
HawkFileNamePublishToNameControl(
    __in PFLT_FILE_NAME_INFORMATION FileNameInformation,
    __out PFLT_NAME_CONTROL NameControl
    )
{
    NTSTATUS status;

    if (FileNameInformation == NULL || NameControl == NULL)
        return STATUS_INVALID_PARAMETER;

    status = FltCheckAndGrowNameControl(
        NameControl,
        FileNameInformation->Name.Length);
    if (NT_SUCCESS(status))
        RtlCopyUnicodeString(&NameControl->Name, &FileNameInformation->Name);

    return status;
}

NTSTATUS
FLTAPI
HawkGenerateFileName(
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject,
    __in_opt PFLT_CALLBACK_DATA CallbackData,
    __in FLT_FILE_NAME_OPTIONS NameOptions,
    __out PBOOLEAN CacheFileNameInformation,
    __out PFLT_NAME_CONTROL FileName
    )
{
    PFLT_FILE_NAME_INFORMATION fileNameInformation = NULL;
    NTSTATUS status;

    if (CacheFileNameInformation == NULL || FileName == NULL)
        return STATUS_INVALID_PARAMETER;

    *CacheFileNameInformation = TRUE;

    FsRtlEnterFileSystem();
    status = HawkFileNameQueryInformation(
        Instance,
        FileObject,
        CallbackData,
        NameOptions,
        &fileNameInformation);
    if (!NT_SUCCESS(status) || fileNameInformation == NULL)
    {
        DBG_PRINT("HawkeyeTfe!GenerateFileName: FltGetFileNameInformation failed, status=0x%08X", status);
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    status = HawkFileNamePublishToNameControl(fileNameInformation, FileName);

Exit:
    if (fileNameInformation != NULL)
        FltReleaseFileNameInformation(fileNameInformation);
    FsRtlExitFileSystem();
    return status;
}

static ULONG
HawkFileNamePassthroughComponentBytes(
    __in PCUNICODE_STRING Component
    )
{
    return FIELD_OFFSET(FILE_NAMES_INFORMATION, FileName) + Component->Length;
}

static NTSTATUS
HawkFileNameWritePassthroughComponent(
    __out PFILE_NAMES_INFORMATION Dest,
    __in PCUNICODE_STRING Component
    )
{
    Dest->NextEntryOffset = 0;
    Dest->FileIndex = 0;
    Dest->FileNameLength = Component->Length;
    RtlCopyMemory(Dest->FileName, Component->Buffer, Component->Length);
    return STATUS_SUCCESS;
}

NTSTATUS
FLTAPI
HawkNormalizeNameComponent(
    __in PFLT_INSTANCE Instance,
    __in PCUNICODE_STRING ParentDirectory,
    __in USHORT DeviceNameLength,
    __in PCUNICODE_STRING Component,
    __out_bcount(ExpandComponentNameLength) PFILE_NAMES_INFORMATION ExpandComponentName,
    __in ULONG ExpandComponentNameLength,
    __in FLT_NORMALIZE_NAME_FLAGS Flags,
    __deref_out_opt PVOID *NormalizationContext
    )
{
    ULONG requiredBytes;

    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(ParentDirectory);
    UNREFERENCED_PARAMETER(DeviceNameLength);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(NormalizationContext);

    if (Component == NULL || ExpandComponentName == NULL)
        return STATUS_INVALID_PARAMETER;

    requiredBytes = HawkFileNamePassthroughComponentBytes(Component);
    if (ExpandComponentNameLength < requiredBytes)
        return STATUS_BUFFER_TOO_SMALL;

    return HawkFileNameWritePassthroughComponent(ExpandComponentName, Component);
}

typedef struct _HAWK_DRIVER_INIT_STATE
{
    BOOLEAN Pre2PostLookaside;
    BOOLEAN FilterRegistered;
    BOOLEAN DeviceObject;
    BOOLEAN ScbQueue;
} HAWK_DRIVER_INIT_STATE, *PHAWK_DRIVER_INIT_STATE;

static VOID
HawkDriverInitStateReset(
    __out PHAWK_DRIVER_INIT_STATE State
    )
{
    if (State == NULL)
        return;

    State->Pre2PostLookaside = FALSE;
    State->FilterRegistered = FALSE;
    State->DeviceObject = FALSE;
    State->ScbQueue = FALSE;
}

static VOID
HawkDriverEntryInitCcCallbacks(
    VOID
    )
{
    g_HawkCcCallbacks.AcquireForLazyWrite = &HawkAcquireForLazyWrite;
    g_HawkCcCallbacks.ReleaseFromLazyWrite = &HawkReleaseFromLazyWrite;
    g_HawkCcCallbacks.AcquireForReadAhead = &HawkAcquireForReadAhead;
    g_HawkCcCallbacks.ReleaseFromReadAhead = &HawkReleaseFromReadAhead;
}

static VOID
HawkDriverEntryInitPre2PostLookaside(
    VOID
    )
{
    ExInitializeNPagedLookasideList(
        &g_HawkP2PLookaside,
        NULL,
        NULL,
        0,
        sizeof(HAWK_PRE2POST_CONTEXT),
        HAWK_POOL_TAG,
        0);
}

static NTSTATUS
HawkDriverEntryCreateDevice(
    __in PDRIVER_OBJECT DriverObject
    )
{
    UNICODE_STRING deviceName;
    NTSTATUS status;

    if (DriverObject == NULL)
        return STATUS_INVALID_PARAMETER;

    RtlInitUnicodeString(&deviceName, HAWK_FILTER_DEVICE_NAME);
    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_HawkFilter.DeviceObject);
    if (status == STATUS_OBJECT_NAME_COLLISION)
    {
        DBG_PRINT("HawkeyeTfe!DriverEntry: control device name already in use; creating unnamed device");
        status = IoCreateDevice(
            DriverObject,
            0,
            NULL,
            FILE_DEVICE_UNKNOWN,
            0,
            FALSE,
            &g_HawkFilter.DeviceObject);
    }
    return status;
}

static NTSTATUS
HawkDriverEntryInitScbQueue(
    VOID
    )
{
    NTSTATUS status;
    ULONG i;

    status = ExInitializeResourceLite(&g_HawkScbTable.Lock);
    if (!NT_SUCCESS(status))
        return status;

    for (i = 0; i < HAWK_SCB_HASH_BUCKETS; ++i)
        g_HawkScbTable.Buckets[i] = NULL;

    return STATUS_SUCCESS;
}

static VOID
HawkDriverEntryRollback(
    __in PHAWK_DRIVER_INIT_STATE State
    )
{
    if (State == NULL)
        return;

    HawkFreeProtectPath();
    if (State->Pre2PostLookaside)
        ExDeleteNPagedLookasideList(&g_HawkP2PLookaside);
    if (State->DeviceObject)
        IoDeleteDevice(g_HawkFilter.DeviceObject);
    if (State->ScbQueue)
        ExDeleteResourceLite(&g_HawkScbTable.Lock);
    if (State->FilterRegistered)
        FltUnregisterFilter(g_HawkFilter.Filter);
}

/* Hawkeye TFE: DriverEntry */
NTSTATUS
DriverEntry(
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
    )
{
    HAWK_DRIVER_INIT_STATE initState;
    NTSTATUS status;

    HawkDriverInitStateReset(&initState);
    RtlZeroMemory(&g_HawkFilter, sizeof(HAWK_FILTER_DATA));

    status = HawkInitializeProtectPath();
    if (!NT_SUCCESS(status))
    {
        DBG_PRINT("HawkeyeTfe!DriverEntry: protected path initialization failed, status=0x%08X", status);
        goto Exit;
    }

    HawkDriverEntryInitCcCallbacks();
    HawkDriverEntryInitPre2PostLookaside();
    initState.Pre2PostLookaside = TRUE;

    status = FltRegisterFilter(
        DriverObject,
        &g_HawkFilterDesc,
        &g_HawkFilter.Filter);
    if (!NT_SUCCESS(status))
    {
        DBG_PRINT("HawkeyeTfe!DriverEntry: FltRegisterFilter failed, status=0x%08X", status);
        goto Exit;
    }
    initState.FilterRegistered = TRUE;

    status = HawkDriverEntryCreateDevice(DriverObject);
    if (!NT_SUCCESS(status))
    {
        DBG_PRINT("HawkeyeTfe!DriverEntry: IoCreateDevice failed, status=0x%08X", status);
        goto Exit;
    }
    initState.DeviceObject = TRUE;

    status = HawkDriverEntryInitScbQueue();
    if (!NT_SUCCESS(status))
    {
        DBG_PRINT("HawkeyeTfe!DriverEntry: SCB table initialization failed, status=0x%08X", status);
        goto Exit;
    }
    initState.ScbQueue = TRUE;

    status = FltStartFiltering(g_HawkFilter.Filter);
    if (!NT_SUCCESS(status))
    {
        DBG_PRINT("HawkeyeTfe!DriverEntry: FltStartFiltering failed, status=0x%08X", status);
        goto Exit;
    }

    DBG_PRINT("HawkeyeTfe!DriverEntry: driver loaded (build %s %s)", __DATE__, __TIME__);

Exit:
    if (!NT_SUCCESS(status))
    {
        DBG_PRINT("HawkeyeTfe!DriverEntry: initialization failed, status=0x%08X", status);
        HawkDriverEntryRollback(&initState);
    }

    return status;
}
