@echo off
setlocal
title PC Security Check
color 0A
mode con: cols=110 lines=45
cd /d "%~dp0"

echo.
echo  ============================================================
echo   PC SECURITY CHECK  [v5]
echo  ============================================================
echo.
echo  Folder: %~dp0
echo.

if not exist "%~dp0PC-Security-Check.ps1" (
    echo  ERROR: PC-Security-Check.ps1 not found!
    echo  Both files must be in the same folder as this bat file.
    echo  %~dp0
    echo.
    pause
    exit /b 1
)

findstr /C:"SCRIPT_VERSION=v5" "%~dp0PC-Security-Check.ps1" >nul
if errorlevel 1 (
    echo  ERROR: Your PC-Security-Check.ps1 is OLD or wrong version!
    echo  You must copy BOTH v5 files together into this folder:
    echo  %~dp0
    echo.
    pause
    exit /b 1
)

set "PCSEC_DIR=%~dp0"
del /f /q "%TEMP%\PC-Security-Check-run.ps1" 2>nul

echo  Report will be saved HERE: %~dp0
echo  Starting scan... please wait 1-2 minutes.
echo.

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0PC-Security-Check.ps1" -ScriptDir "%~dp0"
set "SCAN_EXIT=%ERRORLEVEL%"

echo.
echo  ============================================================
if "%SCAN_EXIT%"=="0" (
    echo   SUCCESS - Scan completed
) else (
    echo   Finished with code %SCAN_EXIT%
)
echo.
echo   Files saved in this folder:
echo   - PC-Security-Check-report-*.txt   ^(full log^)
echo   - PC-Security-Check-SUMMARY.txt    ^(attention list^)
echo.
echo   Press any key to close this window
echo  ============================================================
pause >nul
exit /b %SCAN_EXIT%
