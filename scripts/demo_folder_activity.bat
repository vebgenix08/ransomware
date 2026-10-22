@echo off
setlocal
title RansomShield Six-Step Activity Demo

echo RansomShield six-step folder activity demo
echo It changes files only inside a new, uniquely named test folder.
echo The six steps are: create, modify a few, modify more, create again, delete some, and mixed activity.
echo Keep the server-folder monitor running while you follow the prompts.
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0demo_folder_activity.ps1" %*
if errorlevel 1 (
    echo.
    echo The demo stopped because of an error. Read the message above.
)
echo.
pause
endlocal
