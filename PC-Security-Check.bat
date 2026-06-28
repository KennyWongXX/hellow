@echo off
setlocal
title PC Security Check
color 0A
mode con: cols=110 lines=45
cd /d "%~dp0"

set "REPORT=%~dp0PC-Security-Check-report.txt"
set "SUMMARY=%~dp0PC-Security-Check-SUMMARY.txt"

echo.
echo  ============================================================
echo   PC SECURITY CHECK  [v8]
echo  ============================================================
echo.
echo  Folder: %~dp0
echo  Report: %REPORT%
echo  Summary: %SUMMARY%
echo.

if not exist "%~dp0PC-Security-Check.ps1" (
    echo  ERROR: PC-Security-Check.ps1 not found!
    pause
    exit /b 1
)

findstr /C:"SCRIPT_VERSION=v8" "%~dp0PC-Security-Check.ps1" >nul
if errorlevel 1 (
    echo  ERROR: Need v8 ps1 file! Line 1 must say SCRIPT_VERSION=v8
    pause
    exit /b 1
)

echo  Testing write access...
echo test> "%~dp0_PC-Security-Check-write-test.txt" 2>nul
if not exist "%~dp0_PC-Security-Check-write-test.txt" (
    echo  ERROR: Cannot write files to this folder!
    echo  Try moving both files to Desktop and run from there.
    pause
    exit /b 1
)
del "%~dp0_PC-Security-Check-write-test.txt" 2>nul
echo  [OK] Folder is writable.
echo.

set "PCSEC_DIR=%~dp0"
echo  Starting scan... please wait 1-2 minutes.
echo.

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0PC-Security-Check.ps1" -ScriptDir "%~dp0" -ReportPath "%REPORT%" -SummaryPath "%SUMMARY%"
set "SCAN_EXIT=%ERRORLEVEL%"

echo.
echo  ============================================================
echo   CHECKING OUTPUT FILES...
echo  ============================================================
echo.

if exist "%REPORT%" (
    echo  [OK] Report created:
    echo       %REPORT%
    for %%A in ("%REPORT%") do echo       Size: %%~zA bytes
) else (
    echo  [MISSING] Report NOT created:
    echo       %REPORT%
)

echo.

if exist "%SUMMARY%" (
    echo  [OK] Summary created:
    echo       %SUMMARY%
    echo.
    echo  --- SUMMARY contents ---
    type "%SUMMARY%"
    echo  --- end summary ---
) else (
    echo  [MISSING] Summary NOT created:
    echo       %SUMMARY%
)

echo.
echo  ============================================================
if "%SCAN_EXIT%"=="0" (
    echo   SUCCESS - Scan completed
) else (
    echo   Finished with code %SCAN_EXIT%
)
echo.
echo   Opening folder: %~dp0
echo   Press any key to close
echo  ============================================================
start "" explorer.exe "%~dp0"
pause >nul
exit /b %SCAN_EXIT%
