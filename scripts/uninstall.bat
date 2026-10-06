@echo off
setlocal
net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

set "DEST=%SystemRoot%\System32\drivers\HawkeyeTfe.sys"

sc query HawkeyeTfe >nul 2>&1
if not errorlevel 1 (
    sc stop HawkeyeTfe >nul 2>&1
    sc delete HawkeyeTfe
    if errorlevel 1 (
        echo failed to delete service HawkeyeTfe
        pause
        exit /b 1
    )
)

if exist "%DEST%" (
    del /F /Q "%DEST%"
    if errorlevel 1 (
        echo failed to delete %DEST%
        echo ensure the driver is stopped, then retry
        pause
        exit /b 1
    )
)

echo uninstalled HawkeyeTfe
pause
exit /b 0
