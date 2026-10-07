#include "HawkeyeTfe.h"
#include "HawkProtectPath.h"


/* Hawkeye TFE */
#define HAWK_NT_DOS_PREFIX_CHARS     4
#define HAWK_DOS_DEVICES_PREFIX_CHARS 12

static BOOLEAN
HawkHasPrefixI(
    __in PCUNICODE_STRING Name,
    __in PCWSTR Prefix
    )
{
    UNICODE_STRING prefix;

    if (!Name || !Name->Buffer || !Prefix)
        return FALSE;
    RtlInitUnicodeString(&prefix, Prefix);
    return RtlPrefixUnicodeString(&prefix, Name, TRUE);
}

static VOID
HawkSkipNtDosPrefix(
    __in PCUNICODE_STRING In,
    __out PUNICODE_STRING Out
    )
{
    if (!In || !Out)
        return;

    *Out = *In;
    if (!In->Buffer)
        return;

    if (HawkHasPrefixI(In, L"\\??\\"))
    {
        Out->Buffer = In->Buffer + HAWK_NT_DOS_PREFIX_CHARS;
        Out->Length = (USHORT)(In->Length - HAWK_NT_DOS_PREFIX_CHARS * sizeof(WCHAR));
        Out->MaximumLength = (USHORT)(In->MaximumLength - HAWK_NT_DOS_PREFIX_CHARS * sizeof(WCHAR));
        return;
    }

    if (HawkHasPrefixI(In, L"\\DosDevices\\"))
    {
        Out->Buffer = In->Buffer + HAWK_DOS_DEVICES_PREFIX_CHARS;
        Out->Length = (USHORT)(In->Length - HAWK_DOS_DEVICES_PREFIX_CHARS * sizeof(WCHAR));
        Out->MaximumLength = (USHORT)(In->MaximumLength - HAWK_DOS_DEVICES_PREFIX_CHARS * sizeof(WCHAR));
    }
}

static BOOLEAN
HawkIsDriveLetter(
    __in WCHAR Ch
    )
{
    return (BOOLEAN)((Ch >= L'A' && Ch <= L'Z') || (Ch >= L'a' && Ch <= L'z'));
}

static BOOLEAN
HawkAppendCleanRelative(
    __inout PUNICODE_STRING Dest,
    __in PCUNICODE_STRING Src
    )
{
    USHORT i;
    USHORT charCount;

    if (!Dest || !Dest->Buffer || !Src || !Src->Buffer || Src->Length == 0)
        return TRUE;

    charCount = (USHORT)(Src->Length / sizeof(WCHAR));
    for (i = 0; i < charCount; ++i)
    {
        WCHAR ch = Src->Buffer[i];

        if (ch == L'/')
            ch = L'\\';
        if (ch == L' ' || ch == L'\t' || ch == L'\0' || ch == L'\r' || ch == L'\n')
            continue;
        if (ch == L'\\' && Dest->Length >= sizeof(WCHAR) &&
             Dest->Buffer[(Dest->Length / sizeof(WCHAR)) - 1] == L'\\')
            continue;
        if ((ULONG)Dest->Length + sizeof(WCHAR) > Dest->MaximumLength)
            return FALSE;

        Dest->Buffer[Dest->Length / sizeof(WCHAR)] = ch;
        Dest->Length = (USHORT)(Dest->Length + sizeof(WCHAR));
    }

    return TRUE;
}

static BOOLEAN
HawkIsTxtExtension(
    __in PCUNICODE_STRING FileName
    )
{
    USHORT charCount;
    USHORT i;
    USHORT lastSlash;
    USHORT lastDot;
    WCHAR ext0;
    WCHAR ext1;
    WCHAR ext2;

    if (!FileName || !FileName->Buffer || FileName->Length < 4 * sizeof(WCHAR))
        return FALSE;

    charCount = (USHORT)(FileName->Length / sizeof(WCHAR));
    lastSlash = charCount;
    lastDot = charCount;

    for (i = charCount; i > 0; --i)
    {
        WCHAR ch = FileName->Buffer[i - 1];

        if (ch == L'\\' || ch == L'/')
        {
            lastSlash = (USHORT)(i - 1);
            break;
        }
        if (ch == L'.' && lastDot == charCount)
            lastDot = (USHORT)(i - 1);
    }

    if (lastDot == charCount || lastDot <= lastSlash || (charCount - lastDot - 1) != 3)
        return FALSE;

    ext0 = FileName->Buffer[lastDot + 1];
    ext1 = FileName->Buffer[lastDot + 2];
    ext2 = FileName->Buffer[lastDot + 3];
    if (ext0 >= L'A' && ext0 <= L'Z') ext0 = (WCHAR)(ext0 - L'A' + L'a');
    if (ext1 >= L'A' && ext1 <= L'Z') ext1 = (WCHAR)(ext1 - L'A' + L'a');
    if (ext2 >= L'A' && ext2 <= L'Z') ext2 = (WCHAR)(ext2 - L'A' + L'a');

    return (BOOLEAN)(ext0 == L't' && ext1 == L'x' && ext2 == L't');
}

static BOOLEAN
HawkPathHasDotDotComponent(
    __in PCUNICODE_STRING Path
    )
{
    USHORT i;
    USHORT charCount;

    if (!Path || !Path->Buffer)
        return FALSE;

    charCount = (USHORT)(Path->Length / sizeof(WCHAR));
    for (i = 0; i + 1 < charCount; ++i)
    {
        if (Path->Buffer[i] != L'.' || Path->Buffer[i + 1] != L'.')
            continue;

        {
            WCHAR prev = (i == 0) ? L'\\' : Path->Buffer[i - 1];
            WCHAR next = (i + 2 >= charCount) ? L'\\' : Path->Buffer[i + 2];

            if ((prev == L'\\' || prev == L'/') &&
                 (next == L'\\' || next == L'/' || i + 2 >= charCount))
            {
                return TRUE;
            }
        }
    }

    return FALSE;
}

static BOOLEAN
HawkIsUnderProtectPath(
    __in PCUNICODE_STRING FileName
    )
{
    UNICODE_STRING file;
    UNICODE_STRING prefix;
    BOOLEAN prefixEndsWithSlash;

    if (!g_HawkFilter.ProtectedRootPath.Buffer || g_HawkFilter.ProtectedRootPath.Length == 0)
        return FALSE;

    HawkSkipNtDosPrefix(FileName, &file);
    HawkSkipNtDosPrefix(&g_HawkFilter.ProtectedRootPath, &prefix);

    if (HawkPathHasDotDotComponent(&file))
        return FALSE;
    if (!file.Buffer || !prefix.Buffer || file.Length < prefix.Length)
        return FALSE;
    if (!RtlPrefixUnicodeString(&prefix, &file, TRUE))
        return FALSE;
    if (file.Length == prefix.Length)
        return TRUE;

    prefixEndsWithSlash =
        (prefix.Length >= sizeof(WCHAR)) &&
        (prefix.Buffer[(prefix.Length / sizeof(WCHAR)) - 1] == L'\\');

    if (prefixEndsWithSlash)
        return TRUE;

    return (BOOLEAN)(file.Buffer[prefix.Length / sizeof(WCHAR)] == L'\\');
}

BOOLEAN
HawkPathIsNtObjectName(
    __in PCUNICODE_STRING Name
    )
{
    return HawkHasPrefixI(Name, L"\\??\\") ||
           HawkHasPrefixI(Name, L"\\DosDevices\\") ||
           HawkHasPrefixI(Name, L"\\Device\\");
}

BOOLEAN
HawkPathIsDosDrive(
    __in PCUNICODE_STRING Name
    )
{
    if (!Name || !Name->Buffer || Name->Length < 2 * sizeof(WCHAR))
        return FALSE;

    return HawkIsDriveLetter(Name->Buffer[0]) && Name->Buffer[1] == L':';
}

BOOLEAN
HawkExtractDriveLetter(
    __in PCUNICODE_STRING Name,
    __out PWCHAR Drive,
    __out_opt PUNICODE_STRING RestAfterDrive
    )
{
    UNICODE_STRING stripped;

    if (Drive)
        *Drive = 0;
    if (RestAfterDrive)
    {
        RestAfterDrive->Length = 0;
        RestAfterDrive->MaximumLength = 0;
        RestAfterDrive->Buffer = NULL;
    }
    if (!Name || !Drive)
        return FALSE;

    HawkSkipNtDosPrefix(Name, &stripped);
    if (stripped.Length < 2 * sizeof(WCHAR) || !stripped.Buffer)
        return FALSE;
    if (!HawkIsDriveLetter(stripped.Buffer[0]) || stripped.Buffer[1] != L':')
        return FALSE;

    *Drive = stripped.Buffer[0];
    if (RestAfterDrive && stripped.Length > 2 * sizeof(WCHAR))
    {
        RestAfterDrive->Buffer = stripped.Buffer + 2;
        RestAfterDrive->Length = (USHORT)(stripped.Length - 2 * sizeof(WCHAR));
        RestAfterDrive->MaximumLength = RestAfterDrive->Length;
    }

    return TRUE;
}

BOOLEAN
HawkBuildExactNtDosPath(
    __inout PUNICODE_STRING Dest,
    __in WCHAR Drive,
    __in_opt PCUNICODE_STRING Rel1,
    __in_opt PCUNICODE_STRING Rel2
    )
{
    PWCHAR buffer;

    if (!Dest || !Dest->Buffer || Dest->MaximumLength < 7 * sizeof(WCHAR))
        return FALSE;
    if (!HawkIsDriveLetter(Drive))
        return FALSE;

    buffer = Dest->Buffer;
    buffer[0] = L'\\';
    buffer[1] = L'?';
    buffer[2] = L'?';
    buffer[3] = L'\\';
    buffer[4] = Drive;
    buffer[5] = L':';
    buffer[6] = L'\\';
    Dest->Length = 7 * sizeof(WCHAR);

    if (Rel1 && !HawkAppendCleanRelative(Dest, Rel1))
        return FALSE;
    if (Rel2 && !HawkAppendCleanRelative(Dest, Rel2))
        return FALSE;

    return TRUE;
}

BOOLEAN
HawkBuildNtCreatePath(
    __inout PUNICODE_STRING Dest,
    __in PCUNICODE_STRING Src
    )
{
    WCHAR drive;
    UNICODE_STRING rest;

    if (!HawkExtractDriveLetter(Src, &drive, &rest))
        return FALSE;

    return HawkBuildExactNtDosPath(Dest, drive, rest.Length ? &rest : NULL, NULL);
}

NTSTATUS
HawkPrefixNtDosPathInPlace(
    __inout PUNICODE_STRING Path
    )
{
    if (!Path || !Path->Buffer || Path->Length == 0)
        return STATUS_INVALID_PARAMETER;
    if (HawkPathIsNtObjectName(Path))
        return STATUS_SUCCESS;
    if (!HawkPathIsDosDrive(Path))
        return STATUS_SUCCESS;
    if (Path->MaximumLength < Path->Length + HAWK_NT_DOS_PREFIX_CHARS * sizeof(WCHAR))
        return STATUS_BUFFER_TOO_SMALL;

    RtlMoveMemory(
        Path->Buffer + HAWK_NT_DOS_PREFIX_CHARS,
        Path->Buffer,
        Path->Length);
    Path->Buffer[0] = L'\\';
    Path->Buffer[1] = L'?';
    Path->Buffer[2] = L'?';
    Path->Buffer[3] = L'\\';
    Path->Length = (USHORT)(Path->Length + HAWK_NT_DOS_PREFIX_CHARS * sizeof(WCHAR));
    return STATUS_SUCCESS;
}

/* Hawkeye TFE: ProtectPath */
BOOLEAN
HawkIsProtectedTxtFile(
    __in PUNICODE_STRING FileName
    )
{
    if (!FileName || !FileName->Buffer || FileName->Length == 0)
        return FALSE;
    if (!HawkIsTxtExtension(FileName))
        return FALSE;

    return HawkIsUnderProtectPath(FileName);
}

static BOOLEAN
HawkPathLooksAbsolute(
    __in PCUNICODE_STRING Name
    )
{
    UNICODE_STRING stripped;

    if (!Name || !Name->Buffer || Name->Length < 2 * sizeof(WCHAR))
        return FALSE;

    if (HawkPathIsDosDrive(Name))
        return TRUE;

    HawkSkipNtDosPrefix(Name, &stripped);
    return HawkPathIsDosDrive(&stripped);
}

BOOLEAN
HawkResolveRenameTarget(
    __in PFILE_RENAME_INFORMATION Info,
    __in PUNICODE_STRING CurrentPath,
    __out PUNICODE_STRING TargetOut
    )
{
    UNICODE_STRING source;
    UNICODE_STRING current;
    USHORT charCount;
    USHORT i;

    if (!Info || !Info->FileNameLength || !CurrentPath || !CurrentPath->Buffer ||
         !TargetOut || !TargetOut->Buffer)
    {
        return FALSE;
    }
    if (Info->RootDirectory != NULL)
        return FALSE;

    source.Buffer = Info->FileName;
    source.Length = (USHORT)Info->FileNameLength;
    source.MaximumLength = source.Length;
    TargetOut->Length = 0;

    HawkSkipNtDosPrefix(CurrentPath, &current);
    if (HawkPathLooksAbsolute(&source))
    {
        UNICODE_STRING stripped;

        HawkSkipNtDosPrefix(&source, &stripped);
        if (stripped.Length > TargetOut->MaximumLength)
            return FALSE;

        RtlCopyUnicodeString(TargetOut, &stripped);
        return (BOOLEAN)(TargetOut->Length > 0);
    }

    charCount = (USHORT)(current.Length / sizeof(WCHAR));
    for (i = charCount; i > 0; --i)
    {
        if (current.Buffer[i - 1] == L'\\' || current.Buffer[i - 1] == L'/')
            break;
    }
    if (i == 0)
        return FALSE;

    {
        UNICODE_STRING dir = current;
        UNICODE_STRING leaf = source;

        dir.Length = (USHORT)(i * sizeof(WCHAR));
        dir.MaximumLength = dir.Length;

        if (leaf.Length >= sizeof(WCHAR) &&
             (leaf.Buffer[0] == L'\\' || leaf.Buffer[0] == L'/'))
        {
            leaf.Buffer += 1;
            leaf.Length = (USHORT)(leaf.Length - sizeof(WCHAR));
            leaf.MaximumLength = leaf.Length;
        }

        if ((ULONG)dir.Length + (ULONG)leaf.Length > TargetOut->MaximumLength)
            return FALSE;

        RtlCopyUnicodeString(TargetOut, &dir);
        RtlAppendUnicodeStringToString(TargetOut, &leaf);
        return (BOOLEAN)(TargetOut->Length > 0);
    }
}
