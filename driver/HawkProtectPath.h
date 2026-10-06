#include "HawkeyeTfe.h"

BOOLEAN
HawkPathIsNtObjectName(
    __in PCUNICODE_STRING Name
    );

BOOLEAN
HawkPathIsDosDrive(
    __in PCUNICODE_STRING Name
    );

BOOLEAN
HawkBuildNtCreatePath(
    __inout PUNICODE_STRING Dest,
    __in PCUNICODE_STRING Src
    );

BOOLEAN
HawkExtractDriveLetter(
    __in PCUNICODE_STRING Name,
    __out PWCHAR Drive,
    __out_opt PUNICODE_STRING RestAfterDrive
    );

BOOLEAN
HawkBuildExactNtDosPath(
    __inout PUNICODE_STRING Dest,
    __in WCHAR Drive,
    __in_opt PCUNICODE_STRING Rel1,
    __in_opt PCUNICODE_STRING Rel2
    );

NTSTATUS
HawkPrefixNtDosPathInPlace(
    __inout PUNICODE_STRING Path
    );

BOOLEAN
HawkIsProtectedTxtFile(
    __in PUNICODE_STRING fileName
    );

BOOLEAN
HawkResolveRenameTarget(
    __in PFILE_RENAME_INFORMATION Info,
    __in PUNICODE_STRING CurrentPath,
    __out PUNICODE_STRING TargetOut
    );
