@echo off
setlocal

:: ============================================================
::  PC Security Check - Launcher
::  Double-click this file - window will STAY OPEN
::  Right-click -> Run as administrator  (recommended)
:: ============================================================

:: Keep window open even if script has errors
if /i not "%~1"=="RUN" (
    start "PC Security Check" cmd /k "%~f0" RUN
    exit /b
)

title PC Security Check
color 0A
mode con: cols=110 lines=45
cd /d "%~dp0"

echo.
echo  Starting PC Security Check...
echo  Please wait, this may take 1-2 minutes.
echo.

:: Run the PowerShell check script
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0PC-Security-Check.ps1"

if errorlevel 1 (
    echo.
    echo  [ERROR] Scan failed. Make sure PC-Security-Check.ps1 is in the same folder.
    echo          Both files must be in the same folder:
    echo          %~dp0
)

echo.
echo  ============================================================
echo   DONE - Press any key to close this window
echo  ============================================================
pause >nul
