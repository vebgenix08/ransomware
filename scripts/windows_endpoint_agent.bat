@echo off
setlocal
title RansomShield Windows Endpoint Agent

set "PROJECT_ROOT=%~dp0.."
if exist "%PROJECT_ROOT%\.venv\Scripts\python.exe" (
    "%PROJECT_ROOT%\.venv\Scripts\python.exe" "%~dp0windows_endpoint_agent.py" %*
) else (
    py -3 "%~dp0windows_endpoint_agent.py" %*
)
set "AGENT_EXIT=%ERRORLEVEL%"
if not "%AGENT_EXIT%"=="0" (
    echo.
    echo The endpoint agent stopped with an error. Read the message above.
)
echo.
pause
exit /b %AGENT_EXIT%
