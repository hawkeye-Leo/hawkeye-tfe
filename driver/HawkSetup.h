#include "HawkeyeTfe.h"

NTSTATUS
HawkInitializeProtectPath(
    VOID
    );

VOID
HawkFreeProtectPath(
    VOID
    );

NTSTATUS
HawkInstanceSetup (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_SETUP_FLAGS Flags,
    __in DEVICE_TYPE VolumeDeviceType,
    __in FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

NTSTATUS
HawkInstanceQueryTeardown (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

VOID
HawkCleanupVolumeContext(
    __in PFLT_CONTEXT Context,
    __in FLT_CONTEXT_TYPE ContextType
    );

NTSTATUS
HawkFilterUnload (
    __in FLT_FILTER_UNLOAD_FLAGS Flags
    );
