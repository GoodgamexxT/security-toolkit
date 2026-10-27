@echo off
chcp 65001 >nul
title Access Log Analyzer
cd /d "%~dp0"

rem ---- locate Python: prefer the "py" launcher, fall back to python ----
set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY (
    where python >nul 2>nul && set "PY=python"
)
if not defined PY goto :nopython

rem ---- run (GUI when no args; CLI export when --html/--csv/--json given) ----
%PY% log_analyzer_gui.py %*
if errorlevel 1 (
    echo.
    echo   [!] Exited with an error - see the messages above.
    pause
)
exit /b 0

:nopython
echo.
echo   [!] Python was not found on this machine.
echo       Install Python 3.9+ from https://www.python.org/downloads/
echo       and tick "Add python.exe to PATH" during setup.
echo.
pause
exit /b 1
