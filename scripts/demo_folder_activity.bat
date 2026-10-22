@echo off
setlocal
title RansomShield Random Folder Activity Demo

echo RansomShield random folder activity demo
echo This creates a new, uniquely named test folder. It does not edit your existing files.
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0demo_folder_activity.ps1" %*
if errorlevel 1 (
    echo.
    echo The demo stopped because of an error. Read the message above.
)
echo.
pause
endlocal
