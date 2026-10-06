#include "HawkeyeTfe.h"
#include "HawkScb.h"
#include "HawkShc.h"
#include "HawkCipher.h"
#include "HawkCreateCore.h"
#include "HawkProtectPath.h"


/* Hawkeye TFE */
static VOID
HawkFillExpectedFileMark(
    __in char* featureBuf
    );

static const UCHAR g_HawkOnDiskHeader[HAWK_FS_ONDISK_PREFIX] = {
    'P','o','w','e','r','e','d',' ','B','y',' ','H','a','w','k','e','y','e', 0, 0
};

typedef enum _HAWK_PATH_BUILD_RESULT
{
    HAWK_PATH_BUILD_NOT_APPLICABLE = 0,
    HAWK_PATH_BUILD_SUCCESS,
    HAWK_PATH_BUILD_BUFFER_TOO_SMALL
} HAWK_PATH_BUILD_RESULT;

static PUNICODE_STRING
HawkFoRelativeName(
    __in_opt PFILE_OBJECT FileObject
    )
{
    if (FileObject == NULL ||
         FileObject->FileName.Buffer == NULL ||
         FileObject->FileName.Length == 0)
    {
        return NULL;
    }
    return &FileObject->FileName;
}

static PUNICODE_STRING
HawkFoRelatedDirectoryName(
    __in_opt PFILE_OBJECT FileObject
    )
{
    PFILE_OBJECT relatedFo;

    if (FileObject == NULL)
        return NULL;

    relatedFo = FileObject->RelatedFileObject;
    if (relatedFo == NULL ||
         relatedFo->FileName.Buffer == NULL ||
         relatedFo->FileName.Length == 0)
    {
        return NULL;
    }
    return &relatedFo->FileName;
}

static HAWK_PATH_BUILD_RESULT
HawkTryBuildPathFromDrivenName(
    __inout PUNICODE_STRING NormalizedPath,
    __in_opt PCUNICODE_STRING Name,
    __in_opt PCUNICODE_STRING FinalRelativeName
    )
{
    WCHAR drive;
    UNICODE_STRING restAfterDrive;

    if (Name == NULL)
        return HAWK_PATH_BUILD_NOT_APPLICABLE;

    if (!HawkExtractDriveLetter(Name, &drive, &restAfterDrive))
        return HAWK_PATH_BUILD_NOT_APPLICABLE;

    NormalizedPath->Length = 0;
    if (!HawkBuildExactNtDosPath(
            NormalizedPath,
            drive,
            restAfterDrive.Length ? &restAfterDrive : NULL,
            FinalRelativeName))
    {
        return HAWK_PATH_BUILD_BUFFER_TOO_SMALL;
    }
    return HAWK_PATH_BUILD_SUCCESS;
}

static NTSTATUS
HawkFinalizeNormalizedPathStatus(
    __in PUNICODE_STRING NormalizedPath,
    __in NTSTATUS Status
    )
{
    if (NormalizedPath->Length == 0 && NT_SUCCESS(Status))
        return STATUS_OBJECT_PATH_NOT_FOUND;

    return Status;
}

static BOOLEAN
HawkPathBuildIsTerminal(
    __in HAWK_PATH_BUILD_RESULT Result,
    __out NTSTATUS *Status
    )
{
    switch (Result)
    {
    case HAWK_PATH_BUILD_SUCCESS:
        *Status = STATUS_SUCCESS;
        return TRUE;
    case HAWK_PATH_BUILD_BUFFER_TOO_SMALL:
        *Status = STATUS_BUFFER_TOO_SMALL;
        return TRUE;
    default:
        return FALSE;
    }
}

static NTSTATUS
HawkTryBuildPathFromVolume(
    __inout PUNICODE_STRING NormalizedPath,
    __in PHAWK_VOLUME_CONTEXT VolCtx,
    __in_opt PCUNICODE_STRING RelatedDirName,
    __in_opt PCUNICODE_STRING RelativeName
    )
{
    WCHAR drive;

    if (!HawkExtractDriveLetter(&VolCtx->VolumeName, &drive, NULL))
        return STATUS_OBJECT_PATH_NOT_FOUND;

    NormalizedPath->Length = 0;
    if (!HawkBuildExactNtDosPath(NormalizedPath, drive, RelatedDirName, RelativeName))
        return STATUS_BUFFER_TOO_SMALL;

    return STATUS_SUCCESS;
}

static NTSTATUS
HawkGetFilePathFromFileObject(
    __in PFILE_OBJECT FileObject,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __inout PUNICODE_STRING NormalizedPath
    )
{
    HAWK_PATH_BUILD_RESULT buildResult;
    PUNICODE_STRING relativeName;
    PUNICODE_STRING relatedDirName;
    PHAWK_VOLUME_CONTEXT volCtx;
    NTSTATUS status;

    NormalizedPath->Length = 0;
    if (FileObject == NULL)
        return STATUS_OBJECT_PATH_NOT_FOUND;

    relativeName = HawkFoRelativeName(FileObject);
    relatedDirName = HawkFoRelatedDirectoryName(FileObject);

    buildResult = HawkTryBuildPathFromDrivenName(NormalizedPath, relativeName, NULL);
    if (HawkPathBuildIsTerminal(buildResult, &status))
        return status;

    buildResult = HawkTryBuildPathFromDrivenName(
        NormalizedPath, relatedDirName, relativeName);
    if (HawkPathBuildIsTerminal(buildResult, &status))
        return status;

    status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, &volCtx);
    if (!NT_SUCCESS(status))
        return status;

    status = HawkTryBuildPathFromVolume(
        NormalizedPath, volCtx, relatedDirName, relativeName);
    FltReleaseContext(volCtx);
    return HawkFinalizeNormalizedPathStatus(NormalizedPath, status);
}

static NTSTATUS
HawkGetFilePathFromNameInformation(
    __in PFLT_CALLBACK_DATA Data,
    __inout PUNICODE_STRING NormalizedPath
    )
{
    PFLT_FILE_NAME_INFORMATION nameInfo;
    NTSTATUS status;

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status))
        return status;

    if (nameInfo->Name.Length > NormalizedPath->MaximumLength)
    {
        FltReleaseFileNameInformation(nameInfo);
        return STATUS_BUFFER_TOO_SMALL;
    }

    NormalizedPath->Length = 0;
    RtlCopyUnicodeString(NormalizedPath, &nameInfo->Name);
    FltReleaseFileNameInformation(nameInfo);

    status = HawkPrefixNtDosPathInPlace(NormalizedPath);
    if (!NT_SUCCESS(status))
        return status;

    return HawkFinalizeNormalizedPathStatus(NormalizedPath, STATUS_SUCCESS);
}

NTSTATUS
HawkGetFilePathInCreate(
    __in PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __inout PUNICODE_STRING NormalizedPath
    )
{
    NTSTATUS status;

    status = HawkGetFilePathFromFileObject(
        Data->Iopb->TargetFileObject, FltObjects, NormalizedPath);
    if (NT_SUCCESS(status) && NormalizedPath->Length > 0)
        return status;

    return HawkGetFilePathFromNameInformation(Data, NormalizedPath);
}

static LONGLONG
HawkPlaintextSizeFromShadow(
    __in LONGLONG ShadowSize
    )
{
    LONGLONG onDiskPrefix;

    onDiskPrefix = HAWK_FS_ONDISK_PREFIX;
    if (ShadowSize >= onDiskPrefix)
        return ShadowSize - onDiskPrefix;

    return 0;
}

static VOID
HawkBindInitScbPlaintextSizes(
    __inout PHAWK_SCB Scb,
    __in PFSRTL_ADVANCED_FCB_HEADER ShadowFcb
    )
{
    Scb->Header.AllocationSize.QuadPart = ShadowFcb->AllocationSize.QuadPart;
    Scb->Header.FileSize.QuadPart =
        HawkPlaintextSizeFromShadow(ShadowFcb->FileSize.QuadPart);
    Scb->Header.ValidDataLength.QuadPart =
        HawkPlaintextSizeFromShadow(ShadowFcb->ValidDataLength.QuadPart);
}

static PHAWK_SCB
HawkBindResolveScb(
    __in PHAWK_STREAM_HANDLE_CONTEXT Shc,
    __in PFSRTL_ADVANCED_FCB_HEADER ShadowFcb,
    __in PFILE_OBJECT ShadowFo,
    __out PBOOLEAN CreatedScb
    )
{
    PHAWK_SCB scb;

    *CreatedScb = FALSE;
    if (HawkFindScb(&Shc->PathKey, &scb))
        return scb;

    scb = HawkCreateScb(ShadowFcb, &Shc->PathKey, ShadowFo);
    if (scb != NULL)
        *CreatedScb = TRUE;

    return scb;
}

static VOID
HawkBindEnlistShcOnScb(
    __inout PHAWK_STREAM_HANDLE_CONTEXT Shc,
    __inout PHAWK_SCB Scb
    )
{
    HawkIncrementScbHandles(Scb);
    ExAcquireFastMutex(&Scb->FastMutex);
    Shc->ChainNext = Scb->StreamChainHead;
    Scb->StreamChainHead = Shc;
    ExReleaseFastMutex(&Scb->FastMutex);
    HawkReferenceScb(Scb);
    HawkShcBindToScb(Shc, Scb);
}

static VOID
HawkBindMirrorShadowFoToPlaintext(
    __inout PFILE_OBJECT PlaintextFo,
    __in PFILE_OBJECT ShadowFo,
    __in PHAWK_SCB Scb,
    __in PHAWK_STREAM_HANDLE_CONTEXT Shc
    )
{
    Shc->PlaintextFileObject = PlaintextFo;
    PlaintextFo->FsContext = Scb;
    PlaintextFo->FsContext2 = Shc;
    PlaintextFo->SectionObjectPointer = &Scb->SectionObjectPointers;
    PlaintextFo->Vpb = ShadowFo->Vpb;
    PlaintextFo->LockOperation = ShadowFo->LockOperation;
    PlaintextFo->DeletePending = ShadowFo->DeletePending;
    PlaintextFo->ReadAccess = ShadowFo->ReadAccess;
    PlaintextFo->WriteAccess = ShadowFo->WriteAccess;
    PlaintextFo->DeleteAccess = ShadowFo->DeleteAccess;
    PlaintextFo->SharedRead = ShadowFo->SharedRead;
    PlaintextFo->SharedWrite = ShadowFo->SharedWrite;
    PlaintextFo->SharedDelete = ShadowFo->SharedDelete;
    PlaintextFo->CurrentByteOffset = ShadowFo->CurrentByteOffset;
    PlaintextFo->Waiters = ShadowFo->Waiters;
    PlaintextFo->Busy = ShadowFo->Busy;
    PlaintextFo->Flags |= FO_CACHE_SUPPORTED;
    if (ShadowFo->Flags & FO_DELETE_ON_CLOSE)
        PlaintextFo->Flags |= FO_DELETE_ON_CLOSE;
    if (ShadowFo->Flags & FO_SYNCHRONOUS_IO)
        PlaintextFo->Flags |= FO_SYNCHRONOUS_IO;
}

/* Hawkeye TFE: CreateCore */
BOOLEAN
HawkBindPlaintextFileObject(
    __in PHAWK_STREAM_HANDLE_CONTEXT StreamHandleContext,
    __inout PFILE_OBJECT PlaintextFo
    )
{
    PHAWK_SCB scb;
    PFILE_OBJECT shadowFo;
    PFSRTL_ADVANCED_FCB_HEADER shadowFcb;
    BOOLEAN createdScb;

    shadowFo = StreamHandleContext->ShadowFileObject;
    shadowFcb = shadowFo->FsContext;

    scb = HawkBindResolveScb(StreamHandleContext, shadowFcb, shadowFo, &createdScb);
    if (scb == NULL)
        return FALSE;

    HawkBindEnlistShcOnScb(StreamHandleContext, scb);
    if (createdScb)
        HawkBindInitScbPlaintextSizes(scb, shadowFcb);

    HawkBindMirrorShadowFoToPlaintext(
        PlaintextFo, shadowFo, scb, StreamHandleContext);
    return TRUE;
}

static NTSTATUS
HawkWriteShadowOnDiskPrefix(
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT ShadowFo
    )
{
    LARGE_INTEGER byteOffset;

    byteOffset.QuadPart = 0;
    return FltWriteFile(
        Instance,
        ShadowFo,
        &byteOffset,
        HAWK_FS_ONDISK_PREFIX,
        (PVOID)g_HawkOnDiskHeader,
        FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED,
        NULL,
        NULL,
        NULL);
}

static NTSTATUS
HawkSetShadowEndOfFile(
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT ShadowFo,
    __in LONGLONG EndOfFile
    )
{
    FILE_END_OF_FILE_INFORMATION eofInfo;

    eofInfo.EndOfFile.QuadPart = EndOfFile;
    return FltSetInformationFile(
        Instance,
        ShadowFo,
        &eofInfo,
        sizeof(eofInfo),
        FileEndOfFileInformation);
}

BOOLEAN
HawkCreateFileHeader(
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PHAWK_STREAM_HANDLE_CONTEXT StreamHandleContext
    )
{
    PFILE_OBJECT shadowFo;
    NTSTATUS status;

    shadowFo = StreamHandleContext->ShadowFileObject;

    status = HawkWriteShadowOnDiskPrefix(FltObjects->Instance, shadowFo);
    if (!NT_SUCCESS(status))
        return FALSE;

    status = HawkSetShadowEndOfFile(
        FltObjects->Instance,
        shadowFo,
        HAWK_FS_ONDISK_PREFIX);
    return NT_SUCCESS(status);
}

typedef struct _HAWK_GRADUAL_ENCRYPT_WORKSPACE
{
    PHAWK_ENCRYPT_SCRATCH Scratch;
    PVOID Chunk;
} HAWK_GRADUAL_ENCRYPT_WORKSPACE, *PHAWK_GRADUAL_ENCRYPT_WORKSPACE;

static BOOLEAN
HawkGradualEncryptAllocWorkspace(
    __out PHAWK_GRADUAL_ENCRYPT_WORKSPACE Workspace
    )
{
    Workspace->Scratch = ExAllocatePoolWithTag(
        PagedPool, sizeof(HAWK_ENCRYPT_SCRATCH), HAWK_POOL_TAG);
    if (Workspace->Scratch == NULL)
        return FALSE;

    Workspace->Chunk = ExAllocatePoolWithTag(
        NonPagedPool, HAWK_GRADUAL_ENCRYPT_CHUNK_SIZE, HAWK_POOL_TAG);
    if (Workspace->Chunk == NULL)
    {
        ExFreePoolWithTag(Workspace->Scratch, HAWK_POOL_TAG);
        Workspace->Scratch = NULL;
        return FALSE;
    }

    return TRUE;
}

static VOID
HawkGradualEncryptFreeWorkspace(
    __inout PHAWK_GRADUAL_ENCRYPT_WORKSPACE Workspace
    )
{
    if (Workspace->Chunk != NULL)
    {
        ExFreePoolWithTag(Workspace->Chunk, HAWK_POOL_TAG);
        Workspace->Chunk = NULL;
    }
    if (Workspace->Scratch != NULL)
    {
        ExFreePoolWithTag(Workspace->Scratch, HAWK_POOL_TAG);
        Workspace->Scratch = NULL;
    }
}

static BOOLEAN
HawkGradualEncryptValidateRequest(
    __in PFLT_INSTANCE FltInstance,
    __in PFLT_FILTER FltFilter,
    __in PFLT_VOLUME FltVolume,
    __in PFILE_OBJECT PlaintextShadowFo,
    __in PHAWK_STREAM_HANDLE_CONTEXT Shc,
    __out PCUNICODE_STRING *NormalizedPath
    )
{
    PCUNICODE_STRING path;

    if (FltInstance == NULL || FltFilter == NULL || FltVolume == NULL ||
         PlaintextShadowFo == NULL || Shc == NULL ||
         Shc->AliasHandle == NULL || Shc->ShadowFileObject == NULL)
    {
        return FALSE;
    }

    path = &Shc->PathKey;
    if (path->Buffer == NULL || path->Length == 0 ||
         path->Length > HAWK_FILE_NAME_LEN * sizeof(WCHAR))
    {
        return FALSE;
    }

    *NormalizedPath = path;
    return TRUE;
}

static NTSTATUS
HawkGradualEncryptBuildTempPath(
    __in PHAWK_ENCRYPT_SCRATCH Scratch,
    __in PCUNICODE_STRING NormalizedPath,
    __out PUNICODE_STRING TempPath
    )
{
    TempPath->Buffer = Scratch->TempPathBuffer;
    TempPath->Length = 0;
    TempPath->MaximumLength = sizeof(Scratch->TempPathBuffer);
    RtlCopyUnicodeString(TempPath, NormalizedPath);
    return RtlAppendUnicodeToString(TempPath, HAWK_ENCRYPT_TEMP_SUFFIX);
}

static VOID
HawkGradualEncryptDeleteTempFile(
    __in PFLT_INSTANCE FltInstance,
    __in PFILE_OBJECT TempFo
    )
{
    FILE_DISPOSITION_INFORMATION dispositionInfo;

    dispositionInfo.DeleteFile = TRUE;
    FltSetInformationFile(
        FltInstance,
        TempFo,
        &dispositionInfo,
        sizeof(dispositionInfo),
        FileDispositionInformation);
}

static NTSTATUS
HawkGradualEncryptOpenTempShadow(
    __in PFLT_FILTER FltFilter,
    __in PFLT_INSTANCE FltInstance,
    __in PUNICODE_STRING TempPath,
    __in PLARGE_INTEGER AllocationSize,
    __out PHANDLE TempHandle,
    __out PFILE_OBJECT *TempFo
    )
{
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    *TempHandle = NULL;
    *TempFo = NULL;
    InitializeObjectAttributes(
        &objectAttributes,
        TempPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);
    status = FltCreateFile(
        FltFilter,
        FltInstance,
        TempHandle,
        GENERIC_READ | GENERIC_WRITE,
        &objectAttributes,
        &iosb,
        AllocationSize,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN_IF,
        FILE_NON_DIRECTORY_FILE,
        NULL,
        0,
        0);
    if (!NT_SUCCESS(status))
        return status;

    status = ObReferenceObjectByHandle(
        *TempHandle,
        GENERIC_READ | GENERIC_WRITE,
        *IoFileObjectType,
        KernelMode,
        TempFo,
        NULL);
    if (!NT_SUCCESS(status))
    {
        FltClose(*TempHandle);
        *TempHandle = NULL;
    }

    return status;
}

static NTSTATUS
HawkGradualEncryptCopyPlaintextToTemp(
    __in PFLT_INSTANCE FltInstance,
    __in PFILE_OBJECT PlaintextShadowFo,
    __in PFILE_OBJECT TempFo,
    __in PVOID Chunk,
    __in ULONG PlaintextSize
    )
{
    LARGE_INTEGER readOffset;
    LARGE_INTEGER writeOffset;
    NTSTATUS status;
    ULONG bytesRead;

    readOffset.QuadPart = 0;
    writeOffset.QuadPart = HAWK_FS_ONDISK_PREFIX;

    status = FltWriteFile(
        FltInstance,
        TempFo,
        &readOffset,
        HAWK_FS_ONDISK_PREFIX,
        (PVOID)g_HawkOnDiskHeader,
        0,
        NULL,
        NULL,
        NULL);
    if (!NT_SUCCESS(status))
        return status;

    readOffset.QuadPart = 0;
    while (readOffset.LowPart < PlaintextSize)
    {
        ULONG want = HAWK_GRADUAL_ENCRYPT_CHUNK_SIZE;

        if (want > PlaintextSize - readOffset.LowPart)
            want = PlaintextSize - readOffset.LowPart;

        bytesRead = 0;
        status = FltReadFile(
            FltInstance,
            PlaintextShadowFo,
            &readOffset,
            want,
            Chunk,
            FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
            &bytesRead,
            NULL,
            NULL);
        if (!NT_SUCCESS(status) || bytesRead == 0)
            return NT_SUCCESS(status) ? STATUS_UNEXPECTED_IO_ERROR : status;

        HawkXorEncrypt(
            Chunk,
            Chunk,
            readOffset.LowPart,
            bytesRead,
            (PCHAR)g_HawkCipherKey,
            32);
        readOffset.LowPart += bytesRead;

        status = FltWriteFile(
            FltInstance,
            TempFo,
            &writeOffset,
            bytesRead,
            Chunk,
            FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
            NULL,
            NULL,
            NULL);
        if (!NT_SUCCESS(status))
            return status;

        writeOffset.LowPart += bytesRead;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
HawkGradualEncryptReplaceOriginalWithTemp(
    __in PFLT_INSTANCE FltInstance,
    __in PHAWK_ENCRYPT_SCRATCH Scratch,
    __in PCUNICODE_STRING NormalizedPath,
    __inout PHAWK_STREAM_HANDLE_CONTEXT Shc,
    __in HANDLE TempHandle,
    __in PFILE_OBJECT TempFo
    )
{
    PFILE_RENAME_INFORMATION renameInfo;
    ULONG renameInfoLen;
    NTSTATUS status;

    renameInfoLen = (ULONG)(FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) +
                            NormalizedPath->Length);
    if (renameInfoLen > sizeof(Scratch->RenameInfoStorage))
        return STATUS_BUFFER_TOO_SMALL;

    FltClose(Shc->AliasHandle);
    ObDereferenceObject(Shc->ShadowFileObject);
    Shc->AliasHandle = NULL;
    Shc->ShadowFileObject = NULL;

    renameInfo = (PFILE_RENAME_INFORMATION)Scratch->RenameInfoStorage;
    RtlZeroMemory(renameInfo, renameInfoLen);
    renameInfo->ReplaceIfExists = TRUE;
    renameInfo->RootDirectory = NULL;
    renameInfo->FileNameLength = NormalizedPath->Length;
    RtlCopyMemory(renameInfo->FileName, NormalizedPath->Buffer, NormalizedPath->Length);

    status = FltSetInformationFile(
        FltInstance,
        TempFo,
        renameInfo,
        renameInfoLen,
        FileRenameInformation);
    if (!NT_SUCCESS(status))
        return status;

    Shc->AliasHandle = TempHandle;
    Shc->ShadowFileObject = TempFo;
    return STATUS_SUCCESS;
}

BOOLEAN
HawkEncryptFileGradually(
    __in PFLT_INSTANCE FltInstance,
    __in PFLT_FILTER FltFilter,
    __in PFLT_VOLUME FltVolume,
    __in PFILE_OBJECT PlaintextShadowFo,
    __in PHAWK_STREAM_HANDLE_CONTEXT StreamHandleContext
    )
{
    HAWK_GRADUAL_ENCRYPT_WORKSPACE workspace;
    PCUNICODE_STRING normalizedPath;
    PHAWK_VOLUME_CONTEXT volCtx;
    FILE_STANDARD_INFORMATION fileStdInfo;
    UNICODE_STRING tempPath;
    LARGE_INTEGER allocationSize;
    HANDLE tempHandle;
    PFILE_OBJECT tempFo;
    ULONG plaintextSize;
    NTSTATUS status;
    BOOLEAN tempHandleOpen;
    BOOLEAN tempFoReferenced;
    BOOLEAN success;

    RtlZeroMemory(&workspace, sizeof(workspace));
    tempHandle = NULL;
    tempFo = NULL;
    volCtx = NULL;
    tempHandleOpen = FALSE;
    tempFoReferenced = FALSE;
    success = FALSE;

    if (!HawkGradualEncryptValidateRequest(
            FltInstance,
            FltFilter,
            FltVolume,
            PlaintextShadowFo,
            StreamHandleContext,
            &normalizedPath))
    {
        return FALSE;
    }

    if (!HawkGradualEncryptAllocWorkspace(&workspace))
        return FALSE;

    status = FltQueryInformationFile(
        FltInstance,
        PlaintextShadowFo,
        &fileStdInfo,
        sizeof(FILE_STANDARD_INFORMATION),
        FileStandardInformation,
        NULL);
    if (!NT_SUCCESS(status))
        goto Exit;

    plaintextSize = fileStdInfo.EndOfFile.LowPart;

    status = FltGetVolumeContext(FltFilter, FltVolume, &volCtx);
    if (!NT_SUCCESS(status))
        goto Exit;

    allocationSize.QuadPart = (ULONG)ROUND_TO_SIZE(plaintextSize, volCtx->SectorSize);

    status = HawkGradualEncryptBuildTempPath(
        workspace.Scratch, normalizedPath, &tempPath);
    if (!NT_SUCCESS(status))
        goto Exit;

    status = HawkGradualEncryptOpenTempShadow(
        FltFilter,
        FltInstance,
        &tempPath,
        &allocationSize,
        &tempHandle,
        &tempFo);
    if (!NT_SUCCESS(status))
        goto Exit;

    tempHandleOpen = TRUE;
    tempFoReferenced = TRUE;

    status = HawkGradualEncryptCopyPlaintextToTemp(
        FltInstance,
        PlaintextShadowFo,
        tempFo,
        workspace.Chunk,
        plaintextSize);
    if (!NT_SUCCESS(status))
        goto Exit;

    status = HawkGradualEncryptReplaceOriginalWithTemp(
        FltInstance,
        workspace.Scratch,
        normalizedPath,
        StreamHandleContext,
        tempHandle,
        tempFo);
    if (!NT_SUCCESS(status))
        goto Exit;

    tempHandleOpen = FALSE;
    tempFoReferenced = FALSE;
    success = TRUE;

Exit:
    if (!success && tempFo != NULL)
        HawkGradualEncryptDeleteTempFile(FltInstance, tempFo);
    if (volCtx != NULL)
        FltReleaseContext(volCtx);
    if (tempFoReferenced)
        ObDereferenceObject(tempFo);
    if (tempHandleOpen)
        FltClose(tempHandle);
    HawkGradualEncryptFreeWorkspace(&workspace);
    return success;
}

static VOID
HawkFillExpectedFileMark(
    __out_bcount(HAWK_FS_MARK_SIZE) char* FeatureBuf
    )
{
    RtlCopyMemory(FeatureBuf, "Powered By Hawkeye", 18);
    FeatureBuf[18] = 0;
    FeatureBuf[19] = 0;
}

BOOLEAN
HawkIsEncryptedFile(
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PFILE_OBJECT FileObject
    )
{
    LARGE_INTEGER byteOffset;
    IO_STATUS_BLOCK iosb;
    char onDiskMark[HAWK_FS_MARK_SIZE] = {0};
    char expectedMark[HAWK_FS_MARK_SIZE] = { 0 };

    if (!FileObject->ReadAccess)
        return FALSE;

    byteOffset.QuadPart = 0;
    iosb.Information = 0;
    iosb.Status = FltReadFile(
        FltObjects->Instance,
        FileObject,
        &byteOffset,
        HAWK_FS_MARK_SIZE,
        onDiskMark,
        FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
        (PULONG)&iosb.Information,
        NULL,
        NULL);
    if (!NT_SUCCESS(iosb.Status) || iosb.Information < HAWK_FS_MARK_SIZE)
        return FALSE;

    HawkFillExpectedFileMark(expectedMark);
    return (RtlCompareMemory(onDiskMark, expectedMark, HAWK_FS_MARK_SIZE) == HAWK_FS_MARK_SIZE);
}
