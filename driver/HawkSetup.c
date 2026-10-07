

#include "HawkeyeTfe.h"
#include "HawkSetup.h"
#include "HawkProtectPath.h"


/* Hawkeye TFE */
static __forceinline VOID
HawkProtectPathReset(
    __out PUNICODE_STRING Path
    )
{
    Path->Buffer = NULL;
    Path->Length = 0;
    Path->MaximumLength = 0;
}

static BOOLEAN
HawkProtectPathIsConfigured(
    VOID
    )
{
    PCUNICODE_STRING path = &g_HawkFilter.ProtectedRootPath;

    return (path->Buffer != NULL && path->Length > 0);
}

static VOID
HawkProtectPathReleaseOwnedBuffer(
    __inout PUNICODE_STRING Path
    )
{
    if (Path->Buffer != NULL)
    {
        ExFreePoolWithTag(Path->Buffer, HAWK_POOL_TAG);
        HawkProtectPathReset(Path);
    }
}

VOID
HawkFreeProtectPath(
    VOID
    )
{
    HawkProtectPathReleaseOwnedBuffer(&g_HawkFilter.ProtectedRootPath);
}

static VOID
HawkProtectPathStripTrailingSlash(
    __inout PUNICODE_STRING Path
    )
{
    USHORT chars;

    if (Path->Buffer == NULL || Path->Length == 0)
        return;

    chars = (USHORT)(Path->Length / sizeof(WCHAR));
    if (chars > 3 && Path->Buffer[chars - 1] == L'\\')
    {
        Path->Buffer[chars - 1] = L'\0';
        Path->Length = (USHORT)(Path->Length - sizeof(WCHAR));
    }
}

static NTSTATUS
HawkProtectPathAllocateCopy(
    __out PUNICODE_STRING Dest,
    __in PCUNICODE_STRING Source
    )
{
    USHORT bytes;

    HawkProtectPathReset(Dest);
    if (Source->Buffer == NULL || Source->Length == 0)
        return STATUS_INVALID_PARAMETER;

    bytes = (USHORT)(Source->Length + sizeof(WCHAR));
    Dest->Buffer = ExAllocatePoolWithTag(NonPagedPool, bytes, HAWK_POOL_TAG);
    if (Dest->Buffer == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlCopyMemory(Dest->Buffer, Source->Buffer, Source->Length);
    Dest->Buffer[Source->Length / sizeof(WCHAR)] = L'\0';
    Dest->Length = Source->Length;
    Dest->MaximumLength = bytes;
    return STATUS_SUCCESS;
}

static NTSTATUS
HawkProtectPathBuildNtObjectPath(
    __in PCUNICODE_STRING DosPath,
    __out PUNICODE_STRING NtPath,
    __out_bcount(BufferBytes) PWCHAR Buffer,
    __in USHORT BufferBytes
    )
{
    if (DosPath == NULL || DosPath->Buffer == NULL || DosPath->Length == 0)
        return STATUS_INVALID_PARAMETER;
    if (NtPath == NULL || Buffer == NULL || BufferBytes < sizeof(WCHAR))
        return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(Buffer, BufferBytes);
    NtPath->Buffer = Buffer;
    NtPath->Length = 0;
    NtPath->MaximumLength = BufferBytes;

    if (!HawkBuildNtCreatePath(NtPath, DosPath))
        return STATUS_NAME_TOO_LONG;

    return STATUS_SUCCESS;
}

static NTSTATUS
HawkProtectPathOpenOrCreateDirectory(
    __in PCUNICODE_STRING NtPath
    )
{
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE handle = NULL;
    NTSTATUS status;

    if (NtPath == NULL || NtPath->Buffer == NULL || NtPath->Length == 0)
        return STATUS_INVALID_PARAMETER;

    InitializeObjectAttributes(
        &oa,
        (PUNICODE_STRING)NtPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    status = ZwCreateFile(
        &handle,
        FILE_LIST_DIRECTORY | SYNCHRONIZE,
        &oa,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN_IF,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);
    if (handle != NULL)
        ZwClose(handle);

    return status;
}

static NTSTATUS
HawkProtectPathEnsureDirectory(
    VOID
    )
{
    WCHAR ntBuffer[HAWK_FILE_NAME_LEN];
    UNICODE_STRING ntPath;
    NTSTATUS status;

    if (!HawkProtectPathIsConfigured())
        return STATUS_INVALID_PARAMETER;

    status = HawkProtectPathBuildNtObjectPath(
        &g_HawkFilter.ProtectedRootPath,
        &ntPath,
        ntBuffer,
        sizeof(ntBuffer));
    if (!NT_SUCCESS(status))
        return status;

    status = HawkProtectPathOpenOrCreateDirectory(&ntPath);
    return status;
}

/* Hawkeye TFE: ProtectPath */
NTSTATUS
HawkInitializeProtectPath(
    VOID
    )
{
    UNICODE_STRING defaultPath;
    UNICODE_STRING ownedPath;
    NTSTATUS status;

    HawkFreeProtectPath();
    RtlInitUnicodeString(&defaultPath, HAWK_DEFAULT_PROTECT_PATH);

    status = HawkProtectPathAllocateCopy(&ownedPath, &defaultPath);
    if (!NT_SUCCESS(status))
        return status;

    HawkProtectPathStripTrailingSlash(&ownedPath);
    g_HawkFilter.ProtectedRootPath = ownedPath;

    status = HawkProtectPathEnsureDirectory();
    if (!NT_SUCCESS(status))
    {
        HawkFreeProtectPath();
        return status;
    }

    return STATUS_SUCCESS;
}

#define HAWK_VOLUME_PROPERTIES_BUFFER_SIZE (sizeof(FLT_VOLUME_PROPERTIES) + 512)

static VOID
HawkVolumeContextInitNameStorage(
    __inout PHAWK_VOLUME_CONTEXT Ctx
    )
{
    Ctx->VolumeName.Buffer = Ctx->VolumeNameStorage;
    Ctx->VolumeName.Length = 0;
    Ctx->VolumeName.MaximumLength = sizeof(Ctx->VolumeNameStorage);
}

static NTSTATUS
HawkVolumeContextSetName(
    __inout PHAWK_VOLUME_CONTEXT Ctx,
    __in PCUNICODE_STRING Name
    )
{
    if (Name == NULL || Name->Buffer == NULL)
        return STATUS_INVALID_PARAMETER;
    if (Name->Length + sizeof(WCHAR) > sizeof(Ctx->VolumeNameStorage))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(Ctx->VolumeNameStorage, Name->Buffer, Name->Length);
    Ctx->VolumeNameStorage[Name->Length / sizeof(WCHAR)] = L'\0';
    Ctx->VolumeName.Length = Name->Length;
    return STATUS_SUCCESS;
}

static NTSTATUS
HawkVolumeContextApplySectorSize(
    __in PFLT_VOLUME_PROPERTIES VolProp,
    __inout PHAWK_VOLUME_CONTEXT Ctx
    )
{
    ULONG sectorSize;

    if (VolProp == NULL || Ctx == NULL)
        return STATUS_INVALID_PARAMETER;

    sectorSize = VolProp->SectorSize ? VolProp->SectorSize : HAWK_SECTOR_SIZE;
    if (sectorSize != HAWK_SECTOR_SIZE)
    {
        DBG_PRINT(
            "HawkeyeTfe!InstanceSetup: unsupported volume sector size %lu (expected %lu)",
            sectorSize,
            (ULONG)HAWK_SECTOR_SIZE);
        return STATUS_NOT_SUPPORTED;
    }

    Ctx->SectorSize = HAWK_SECTOR_SIZE;
    return STATUS_SUCCESS;
}

static NTSTATUS
HawkVolumeContextTrySetNameFromDosVolume(
    __inout PHAWK_VOLUME_CONTEXT Ctx,
    __in PFLT_VOLUME Volume,
    __out PDEVICE_OBJECT *DiskDeviceObject
    )
{
    PDEVICE_OBJECT diskDevice = NULL;
    UNICODE_STRING dosName;
    NTSTATUS status;

    *DiskDeviceObject = NULL;
    RtlZeroMemory(&dosName, sizeof(dosName));

    status = FltGetDiskDeviceObject(Volume, &diskDevice);
    if (!NT_SUCCESS(status))
        return status;

    status = IoVolumeDeviceToDosName(diskDevice, &dosName);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(diskDevice);
        return status;
    }

    status = HawkVolumeContextSetName(Ctx, &dosName);
    ExFreePool(dosName.Buffer);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(diskDevice);
        return status;
    }

    status = HawkPrefixNtDosPathInPlace(&Ctx->VolumeName);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(diskDevice);
        return status;
    }

    *DiskDeviceObject = diskDevice;
    return STATUS_SUCCESS;
}

static PCUNICODE_STRING
HawkVolumeContextSelectFallbackDeviceName(
    __in PFLT_VOLUME_PROPERTIES VolProp
    )
{
    if (VolProp == NULL)
        return NULL;

    if (VolProp->RealDeviceName.Length > 0)
        return &VolProp->RealDeviceName;

    if (VolProp->FileSystemDeviceName.Length > 0)
        return &VolProp->FileSystemDeviceName;

    return NULL;
}

static NTSTATUS
HawkVolumeContextSetNameFromFallback(
    __inout PHAWK_VOLUME_CONTEXT Ctx,
    __in PCUNICODE_STRING DeviceName
    )
{
    NTSTATUS status;

    if (DeviceName == NULL || DeviceName->Buffer == NULL || DeviceName->Length == 0)
        return STATUS_INVALID_PARAMETER;

    if (DeviceName->Length + (2 * sizeof(WCHAR)) > sizeof(Ctx->VolumeNameStorage))
        return STATUS_BUFFER_TOO_SMALL;

    HawkVolumeContextInitNameStorage(Ctx);
    status = HawkVolumeContextSetName(Ctx, DeviceName);
    if (!NT_SUCCESS(status))
        return status;

    return RtlAppendUnicodeToString(&Ctx->VolumeName, L":");
}

static NTSTATUS
HawkVolumeContextResolveName(
    __inout PHAWK_VOLUME_CONTEXT Ctx,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PFLT_VOLUME_PROPERTIES VolProp,
    __out PDEVICE_OBJECT *DiskDeviceObject
    )
{
    PCUNICODE_STRING fallbackName;
    NTSTATUS status;

    *DiskDeviceObject = NULL;
    HawkVolumeContextInitNameStorage(Ctx);

    status = HawkVolumeContextTrySetNameFromDosVolume(
        Ctx,
        FltObjects->Volume,
        DiskDeviceObject);
    if (NT_SUCCESS(status))
        return STATUS_SUCCESS;

    fallbackName = HawkVolumeContextSelectFallbackDeviceName(VolProp);
    if (fallbackName == NULL)
        return STATUS_FLT_DO_NOT_ATTACH;

    return HawkVolumeContextSetNameFromFallback(Ctx, fallbackName);
}

static NTSTATUS
HawkVolumeContextPublish(
    __in PFLT_VOLUME Volume,
    __in PHAWK_VOLUME_CONTEXT Ctx
    )
{
    NTSTATUS status;

    status = FltSetVolumeContext(
        Volume,
        FLT_SET_CONTEXT_KEEP_IF_EXISTS,
        Ctx,
        NULL);
    if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED)
        return STATUS_SUCCESS;

    return status;
}

NTSTATUS
HawkInstanceSetup (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_SETUP_FLAGS Flags,
    __in DEVICE_TYPE VolumeDeviceType,
    __in FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
{
    PHAWK_VOLUME_CONTEXT ctx = NULL;
    PDEVICE_OBJECT diskDevice = NULL;
    UCHAR volPropBuffer[HAWK_VOLUME_PROPERTIES_BUFFER_SIZE];
    PFLT_VOLUME_PROPERTIES volProp = (PFLT_VOLUME_PROPERTIES)volPropBuffer;
    ULONG volPropLength = 0;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);

    status = FltAllocateContext(
        FltObjects->Filter,
        FLT_VOLUME_CONTEXT,
        sizeof(HAWK_VOLUME_CONTEXT),
        NonPagedPool,
        &ctx);
    if (!NT_SUCCESS(status))
        return status;

    status = FltGetVolumeProperties(
        FltObjects->Volume,
        volProp,
        sizeof(volPropBuffer),
        &volPropLength);
    if (!NT_SUCCESS(status))
        goto Cleanup;

    status = HawkVolumeContextApplySectorSize(volProp, ctx);
    if (!NT_SUCCESS(status))
        goto Cleanup;

    status = HawkVolumeContextResolveName(
        ctx,
        FltObjects,
        volProp,
        &diskDevice);
    if (!NT_SUCCESS(status))
        goto Cleanup;

    status = HawkVolumeContextPublish(FltObjects->Volume, ctx);

Cleanup:
    if (diskDevice != NULL)
        ObDereferenceObject(diskDevice);
    if (ctx != NULL)
        FltReleaseContext(ctx);

    return status;
}

NTSTATUS
HawkInstanceQueryTeardown (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

VOID
HawkCleanupVolumeContext(
    __in PFLT_CONTEXT Context,
    __in FLT_CONTEXT_TYPE ContextType
    )
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(ContextType);
}

static VOID
HawkFilterUnloadTeardownResources(
    VOID
    )
{
    ExDeleteResourceLite(&g_HawkScbTable.Lock);

    if (g_HawkFilter.DeviceObject != NULL)
    {
        IoDeleteDevice(g_HawkFilter.DeviceObject);
        g_HawkFilter.DeviceObject = NULL;
    }

    ExDeleteNPagedLookasideList(&g_HawkP2PLookaside);
    HawkFreeProtectPath();
}

/* Hawkeye TFE: Unload */
NTSTATUS
HawkFilterUnload (
    __in FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Flags);

    if (g_HawkFilter.Filter == NULL)
        return STATUS_SUCCESS;

    FltUnregisterFilter(g_HawkFilter.Filter);
    g_HawkFilter.Filter = NULL;

    HawkFilterUnloadTeardownResources();

    DBG_PRINT("HawkeyeTfe!DriverUnload: driver unloaded");
    return STATUS_SUCCESS;
}
