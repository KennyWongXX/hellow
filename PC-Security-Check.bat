@echo off
setlocal
title PC Security Check
color 0A
mode con: cols=110 lines=45
cd /d "%~dp0"

echo.
echo  ============================================================
echo   PC SECURITY CHECK  [v7]
echo  ============================================================
echo.
echo  Bat folder: %~dp0
echo.

if not exist "%~dp0PC-Security-Check.ps1" (
    echo  ERROR: PC-Security-Check.ps1 not found!
    pause
    exit /b 1
)

findstr /C:"SCRIPT_VERSION=v7" "%~dp0PC-Security-Check.ps1" >nul
if errorlevel 1 (
    echo  ERROR: Your PC-Security-Check.ps1 is OLD! Need v7.
    pause
    exit /b 1
)

set "PCSEC_DIR=%~dp0"
set "WORK_DIR=%TEMP%\PC-Security-Check"
if not exist "%WORK_DIR%" mkdir "%WORK_DIR%" 2>nul

del /f /q "%TEMP%\PC-Security-Check-run.ps1" 2>nul

echo  Starting scan... please wait 1-2 minutes.
echo.

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0PC-Security-Check.ps1" -ScriptDir "%~dp0"
set "SCAN_EXIT=%ERRORLEVEL%"

echo.
echo  Copying report files to bat folder...
if exist "%WORK_DIR%\*.txt" (
    copy /Y "%WORK_DIR%\*.txt" "%~dp0\" >nul 2>&1
    if errorlevel 1 (
        echo  [WARN] Could not copy to Downloads - files remain in:
        echo  %WORK_DIR%
    ) else (
        echo  [OK] Files copied to:
        echo  %~dp0
    )
) else (
    echo  [WARN] No report files found in:
    echo  %WORK_DIR%
)

echo.
echo  ============================================================
if "%SCAN_EXIT%"=="0" (
    echo   SUCCESS - Scan completed
) else (
    echo   Finished with code %SCAN_EXIT%
)
echo.
echo   CHECK THESE LOCATIONS FOR YOUR FILES:
echo.
echo   1^) %~dp0
echo   2^) %WORK_DIR%
echo.
echo   Look for:
echo   - PC-Security-Check-report-*.txt
echo   - PC-Security-Check-SUMMARY.txt
echo   - PC-Security-Check-FILES-HERE.txt
echo.
echo   File Explorer should have opened automatically.
echo   Press any key to close this window
echo  ============================================================
pause >nul
exit /b %SCAN_EXIT%
