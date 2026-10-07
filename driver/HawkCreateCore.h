#include "HawkeyeTfe.h"

NTSTATUS
HawkGetFilePathInCreate(
    __in PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __inout PUNICODE_STRING pNormalizedPath
    );

BOOLEAN
HawkBindPlaintextFileObject(
    __in PHAWK_STREAM_HANDLE_CONTEXT StreamHandleContext,
    __inout PFILE_OBJECT PlaintextFo
    );

BOOLEAN
HawkCreateFileHeader(
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PHAWK_STREAM_HANDLE_CONTEXT StreamHandleContext
    );

BOOLEAN
HawkIsEncryptedFile(
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PFILE_OBJECT FileObject
    );

BOOLEAN
HawkEncryptFileGradually(
    __in PFLT_INSTANCE FltInstance,
    __in PFLT_FILTER FltFilter,
    __in PFLT_VOLUME FltVolume,
    __in PFILE_OBJECT PlaintextShadowFo,
    __in PHAWK_STREAM_HANDLE_CONTEXT StreamHandleContext
    );
