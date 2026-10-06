param(
    [Parameter(Mandatory = $true)]
    [string] $SysPath
)

$ErrorActionPreference = "Continue"
$Subject = "CN=HawkeyeTfe Test"

if (-not (Test-Path -LiteralPath $SysPath)) {
    Write-Host "ERROR: File not found: $SysPath"
    exit 1
}

function Find-SignTool {
    $kitBin = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
    if (Test-Path $kitBin) {
        $found = Get-ChildItem -Path $kitBin -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Directory.Name -eq "x64" } |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Invoke-Native {
    param([string]$FilePath, [string[]]$Arguments)
    $argLine = ($Arguments | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
    }) -join ' '
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = $argLine
    $psi.UseShellExecute = $false
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.WaitForExit()
    return $p.ExitCode
}

$signTool = Find-SignTool
if (-not $signTool) {
    Write-Host "ERROR: signtool.exe not found. Install Windows 10 SDK / WDK."
    exit 1
}
Write-Host "signtool: $signTool"

$cert = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq $Subject -and $_.HasPrivateKey } |
    Select-Object -First 1

if (-not $cert) {
    Write-Host "Creating test code-signing certificate..."
    try {
        $cert = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject $Subject `
            -CertStoreLocation Cert:\CurrentUser\My `
            -HashAlgorithm SHA256 `
            -KeyExportPolicy Exportable `
            -NotAfter (Get-Date).AddYears(5)
    }
    catch {
        Write-Host "ERROR: New-SelfSignedCertificate failed: $_"
        exit 1
    }
}

$outDir = Split-Path -Parent $SysPath
$cerPath = Join-Path $outDir "HawkeyeTfe_Test.cer"
try {
    Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null
    Write-Host "Exported cert: $cerPath"
}
catch {
    Write-Host "WARNING: could not export .cer: $_"
}

$signExit = Invoke-Native $signTool @("sign", "/fd", "SHA256", "/a", "/sha1", $cert.Thumbprint, $SysPath)
if ($signExit -ne 0) {
    Write-Host "ERROR: signtool sign failed ($signExit)"
    exit $signExit
}

Write-Host "Signed: $SysPath"
Write-Host "On the test VM (admin), import the .cer once:"
Write-Host "  certutil -addstore root `"$cerPath`""
Write-Host "  certutil -addstore TrustedPublisher `"$cerPath`""
exit 0
