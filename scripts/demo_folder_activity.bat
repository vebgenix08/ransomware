@echo off
setlocal EnableExtensions

rem Safe RansomShield demo: operates only on newly created files in a unique folder.
for /f %%i in ('powershell -NoProfile -Command "[guid]::NewGuid().ToString('N')"') do set "RUN_ID=%%i"
if not defined RUN_ID (
    echo Could not create a unique demo folder name.
    pause
    exit /b 1
)

set "DEMO_DIR=%USERPROFILE%\Documents\RansomShield-Demo-%RUN_ID%"
mkdir "%DEMO_DIR%" 2>nul
if errorlevel 1 (
    echo Could not create demo folder: "%DEMO_DIR%"
    pause
    exit /b 1
)

echo.
echo RansomShield safe folder activity demo
echo Demo folder: "%DEMO_DIR%"
echo.
echo In the app, open Monitor Files and choose this demo folder.
echo Start monitoring, then return here and press any key.
pause >nul

echo Creating 10 demo text files...
for /l %%n in (1,1,10) do (
    >"%DEMO_DIR%\RansomShield-demo-%%n.txt" echo Demo file %%n created for RansomShield folder monitoring.
)
echo 10 files created. Check the app, then press any key to modify them.
pause >nul

echo Modifying the 10 demo text files...
for /l %%n in (1,1,10) do (
    >>"%DEMO_DIR%\RansomShield-demo-%%n.txt" echo Demo file %%n modified.
)
echo 10 files modified. Check the app, then press any key to delete these demo files.
pause >nul

echo Deleting only the 10 files created by this script...
for /l %%n in (1,1,10) do del /q "%DEMO_DIR%\RansomShield-demo-%%n.txt" 2>nul
echo Demo complete. The uniquely named demo folder remains empty:
echo "%DEMO_DIR%"
echo You can remove that empty folder yourself if you no longer need it.
pause
endlocal
