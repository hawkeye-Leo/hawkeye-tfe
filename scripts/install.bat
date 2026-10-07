@echo off
setlocal
net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

set "SYS=%~dp0HawkeyeTfe.sys"
set "DEST=%SystemRoot%\System32\drivers\HawkeyeTfe.sys"

if not exist "%SYS%" (
    echo sys not found: %SYS%
    pause
    exit /b 1
)

copy /Y "%SYS%" "%DEST%"
if errorlevel 1 (
    echo copy failed. Stop the driver first if it is running.
    pause
    exit /b 1
)

sc query HawkeyeTfe >nul 2>&1
if errorlevel 1 (
    sc create HawkeyeTfe type= filesys start= demand error= normal binPath= \SystemRoot\System32\drivers\HawkeyeTfe.sys group= "FSFilter Encryption" depend= FltMgr DisplayName= HawkeyeTfe
) else (
    sc config HawkeyeTfe type= filesys start= demand error= normal binPath= \SystemRoot\System32\drivers\HawkeyeTfe.sys group= "FSFilter Encryption" depend= FltMgr DisplayName= HawkeyeTfe
)
if errorlevel 1 (
    pause
    exit /b 1
)

reg add "HKLM\SYSTEM\CurrentControlSet\Services\HawkeyeTfe\Instances" /v DefaultInstance /t REG_SZ /d "HawkeyeTfe Instance" /f >nul
if errorlevel 1 goto regfail
reg add "HKLM\SYSTEM\CurrentControlSet\Services\HawkeyeTfe\Instances\HawkeyeTfe Instance" /v Altitude /t REG_SZ /d 407800 /f >nul
if errorlevel 1 goto regfail
reg add "HKLM\SYSTEM\CurrentControlSet\Services\HawkeyeTfe\Instances\HawkeyeTfe Instance" /v Flags /t REG_DWORD /d 0 /f >nul
if errorlevel 1 goto regfail

echo installed HawkeyeTfe
pause
exit /b 0

:regfail
echo registry write failed
pause
exit /b 1
