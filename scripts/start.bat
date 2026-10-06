@echo off
setlocal
net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

sc start HawkeyeTfe
set ERR=%ERRORLEVEL%
echo.
pause
exit /b %ERR%
