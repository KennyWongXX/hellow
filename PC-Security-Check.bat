@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion

:: ============================================================
::  PC Security Check Tool
::  Checks for remote-access apps, suspicious activity, cameras
::
::  HOW TO USE:
::    1. Save this file as PC-Security-Check.bat
::    2. Right-click -> Run as administrator  (recommended)
::    3. Read the results shown in this window
::    4. Full report is also saved to your TEMP folder
:: ============================================================

title PC Security Check
color 0A
mode con: cols=110 lines=45

set "REPORT=%TEMP%\PC-Security-Check-%DATE:/=-%_%TIME::=-%.txt"
set "REPORT=%REPORT: =_%"
set "WARN=0"

:: Start logging everything to report file
powershell -NoProfile -Command "Start-Transcript -Path '%REPORT%' -Force -Append" >nul 2>&1

echo.
echo  ============================================================
echo   PC SECURITY CHECK  ^|  PC 安全檢查
echo   %DATE% %TIME%
echo  ============================================================
echo.
echo  Report file / 報告檔案:
echo  %REPORT%
echo.

:: --- Admin check ---
net session >nul 2>&1
if %errorlevel%==0 (
    echo  [OK] Running as Administrator / 以系統管理員身分執行
    set "IS_ADMIN=1"
) else (
    echo  [!] Not running as Administrator / 未以系統管理員執行
    echo      Right-click -^> Run as administrator / 右鍵 -^> 以系統管理員身分執行
    set "IS_ADMIN=0"
    set /a WARN+=1
)
echo.

:: ============================================================
:: 1. REMOTE ACCESS SOFTWARE (installed)
:: ============================================================
call :Section "1. REMOTE ACCESS SOFTWARE (Installed) / 遠端控制軟體"

set "REMOTE_LIST=TeamViewer AnyDesk RustDesk Splashtop LogMeIn VNC TightVNC UltraVNC RealVNC Chrome Remote Desktop Quick Assist RemotePC ConnectWise ScreenConnect Ammyy Admin Supremo DWAgent MeshCentral Radmin GoToAssist UltraViewer AeroAdmin Parsec"

echo  Scanning installed programs / 掃描已安裝程式...
echo.
powershell -NoProfile -Command ^
  "$names = '%REMOTE_LIST%'.Split(' '); " ^
  "$apps = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object DisplayName; " ^
  "$found = @(); foreach ($n in $names) { $m = $apps | Where-Object { $_.DisplayName -match $n }; if ($m) { $found += $m } }; " ^
  "if ($found.Count -eq 0) { Write-Host '  [OK] No common remote-access programs found.' -ForegroundColor Green; Write-Host '  [OK] 未發現常見遠端控制軟體。' -ForegroundColor Green } " ^
  "else { Write-Host '  [!!] REMOTE ACCESS SOFTWARE FOUND / 發現遠端控制軟體:' -ForegroundColor Red; $found | Select-Object DisplayName, Publisher, InstallDate -Unique | Format-Table -AutoSize | Out-String | Write-Host }"

echo.
echo  Checking install folders / 檢查常見安裝資料夾...
set "FOLDER_FOUND=0"
for %%F in (
    "%ProgramFiles%\TeamViewer"
    "%ProgramFiles(x86)%\TeamViewer"
    "%ProgramFiles%\AnyDesk"
    "%ProgramFiles(x86)%\AnyDesk"
    "%ProgramFiles%\RustDesk"
    "%LocalAppData%\RustDesk"
    "%ProgramFiles%\RealVNC"
    "%ProgramFiles(x86)%\RealVNC"
    "%ProgramFiles%\TightVNC"
    "%ProgramFiles(x86)%\TightVNC"
    "%ProgramFiles%\Splashtop"
    "%ProgramFiles(x86)%\Splashtop"
) do (
    if exist "%%~F" (
        echo   [!!] Folder exists / 資料夾存在: %%~F
        set "FOLDER_FOUND=1"
        set /a WARN+=1
    )
)
if "!FOLDER_FOUND!"=="0" echo   [OK] No suspicious folders in common paths.
echo.

:: ============================================================
:: 2. RUNNING PROCESSES
:: ============================================================
call :Section "2. RUNNING PROCESSES / 執行中的程序"

echo  Remote-access and suspicious processes / 遠端控制與可疑程序:
echo.
set "PROC_FOUND=0"
for %%P in (
    TeamViewer.exe TeamViewer_Service.exe AnyDesk.exe rustdesk.exe
    vncviewer.exe vncserver.exe winvnc.exe tvnserver.exe
    chrome_remote_desktop_host.exe msra.exe QuickAssist.exe
    splashtop.exe LogMeIn.exe ammyy.exe dwagent.exe
    MeshAgent.exe ScreenConnect.ClientService.exe
    nc.exe ncat.exe netcat.exe mstsc.exe
) do (
    tasklist /FI "IMAGENAME eq %%P" 2>nul | find /I "%%P" >nul
    if !errorlevel! equ 0 (
        echo   [!!] RUNNING / 執行中: %%P
        tasklist /FI "IMAGENAME eq %%P" /FO LIST 2>nul | findstr /I "PID Session"
        set "PROC_FOUND=1"
        set /a WARN+=1
    )
)
if "!PROC_FOUND!"=="0" echo   [OK] No known remote-access processes running.
echo.

:: ============================================================
:: 3. NETWORK - LISTENING PORTS
:: ============================================================
call :Section "3. NETWORK - LISTENING PORTS / 監聽中的連接埠"

echo  Incoming connections / 可接受外部連線的埠:
echo  (Risky: 22=SSH, 3389=RDP, 5900=VNC, 5938=TeamViewer, 7070=AnyDesk)
echo.
netstat -ano | findstr "LISTENING"
echo.
echo  --- Risky ports check / 高風險埠檢查 ---
set "PORT_FOUND=0"
for %%P in (22 3389 5900 5938 6568 7070 21116 47984 48000) do (
    netstat -ano | findstr /C:":%%P " | findstr "LISTENING" >nul 2>&1
    if !errorlevel! equ 0 (
        echo   [!!] Port %%P is LISTENING / 埠 %%P 正在監聽
        for /f "tokens=5" %%A in ('netstat -ano ^| findstr /C:":%%P " ^| findstr "LISTENING"') do (
            echo        PID: %%A
            tasklist /FI "PID eq %%A" /FO LIST 2>nul | findstr /I "Image Name"
        )
        set "PORT_FOUND=1"
        set /a WARN+=1
    )
)
if "!PORT_FOUND!"=="0" echo   [OK] No common remote-access ports listening.
echo.

:: ============================================================
:: 4. ACTIVE CONNECTIONS
:: ============================================================
call :Section "4. ACTIVE CONNECTIONS / 目前連線"

echo  Established connections / 已建立的連線:
echo.
netstat -ano | findstr "ESTABLISHED"
echo.

:: ============================================================
:: 5. STARTUP PROGRAMS
:: ============================================================
call :Section "5. STARTUP PROGRAMS / 開機自動啟動"

echo  --- Startup folder (User) / 使用者啟動資料夾 ---
dir /B "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
if errorlevel 1 echo   (empty)
echo.
echo  --- Startup folder (All Users) / 所有使用者 ---
dir /B "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
if errorlevel 1 echo   (empty)
echo.
echo  --- Registry Run (HKCU) ---
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" 2>nul
echo.
echo  --- Registry Run (HKLM) ---
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" 2>nul
echo.

:: ============================================================
:: 6. SCHEDULED TASKS
:: ============================================================
call :Section "6. SCHEDULED TASKS / 排程工作"

echo  Tasks matching remote-access keywords:
schtasks /Query /FO LIST 2>nul | findstr /I /B "TaskName:" | findstr /I "TeamViewer AnyDesk RustDesk VNC Remote Splashtop LogMeIn Agent Update"
if errorlevel 1 echo   [OK] No obvious remote-access tasks found.
echo.

:: ============================================================
:: 7. CAMERAS ON THIS PC
:: ============================================================
call :Section "7. CAMERAS ON THIS PC / 電腦連接的攝影機"

echo  Camera / webcam devices / 攝影機裝置:
echo.
powershell -NoProfile -Command ^
  "$cams = @(Get-PnpDevice -Class Camera -ErrorAction SilentlyContinue); " ^
  "if ($cams.Count -eq 0) { $cams = @(Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -match 'camera|webcam|video|uvc|integrated|imaging' }) }; " ^
  "if ($cams.Count -gt 0) { Write-Host '  [INFO] Camera devices found / 發現攝影機:' -ForegroundColor Yellow; $cams | Select-Object Status, Class, FriendlyName | Format-Table -AutoSize | Out-String | Write-Host; $bad = $cams | Where-Object { $_.Status -ne 'OK' -and $_.Status -ne 'Unknown' }; if ($bad) { Write-Host '  [!] Some devices have unusual status.' -ForegroundColor Red } } " ^
  "else { Write-Host '  [OK] No camera devices detected on this PC.' -ForegroundColor Green; Write-Host '  [OK] 此電腦未偵測到攝影機。' -ForegroundColor Green }"
echo.

:: ============================================================
:: 8. CAMERA PERMISSIONS
:: ============================================================
call :Section "8. CAMERA PERMISSIONS / 攝影機權限"

echo  Apps allowed to use camera / 允許使用攝影機的 App:
echo.
powershell -NoProfile -Command ^
  "$base = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam'; " ^
  "$count = 0; if (Test-Path $base) { Get-ChildItem $base -ErrorAction SilentlyContinue | ForEach-Object { $v = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue; if ($v.Value -eq 'Allow') { Write-Host ('  [ALLOW] ' + $_.PSChildName) -ForegroundColor Yellow; $script:count++ } } }; " ^
  "if ($count -eq 0) { Write-Host '  [INFO] No apps with explicit Allow found (or using system default).' }"
echo.

:: ============================================================
:: 9. CAMERA APPS RUNNING NOW
:: ============================================================
call :Section "9. CAMERA APPS RUNNING NOW / 正在使用攝影機的 App"

powershell -NoProfile -Command ^
  "$keywords = 'camera','webcam','zoom','teams','skype','obs','meet','discord','line','wechat'; " ^
  "$found = $false; Get-Process -ErrorAction SilentlyContinue | ForEach-Object { foreach ($k in $keywords) { if ($_.ProcessName -match $k -or $_.MainWindowTitle -match $k) { Write-Host ('  [INFO] Possible camera app: ' + $_.ProcessName + ' | ' + $_.MainWindowTitle) -ForegroundColor Yellow; $script:found = $true; break } } }; " ^
  "if (-not $found) { Write-Host '  [OK] No obvious camera apps running.' -ForegroundColor Green }; " ^
  "Write-Host ''; Write-Host '  Tip: If camera light is ON but nothing listed, run Malwarebytes scan.' -ForegroundColor Cyan; " ^
  "Write-Host '  提示: 若攝影機指示燈亮但沒有 App，請用防毒軟體掃描。' -ForegroundColor Cyan"
echo.

:: ============================================================
:: 10. NETWORK / HIDDEN CAMERA TIPS
:: ============================================================
call :Section "10. NETWORK INFO / 網路資訊 (針孔攝影機排查)"

echo  Your IP / 本機 IP:
ipconfig | findstr /I "IPv4"
echo.
echo  Router / 路由器 (check connected devices here / 在此查看所有連線裝置):
for /f "tokens=3" %%G in ('route print 2^>nul ^| findstr /I "0.0.0.0" ^| findstr /V "On-link"') do (
    echo   http://%%G
)
echo.
echo  Local network devices (ARP) / 區域網路裝置:
arp -a
echo.
echo  [TIP] Hidden pinhole cameras / 針孔攝影機 usually connect to Wi-Fi,
echo        NOT to your PC. Check router for unknown devices like:
echo        IPCAM, CamHi, V380, Hikvision, Dahua, Generic
echo        針孔攝影機通常連 Wi-Fi，不連電腦。請到路由器查看未知裝置。
echo.

:: ============================================================
:: 11. WINDOWS DEFENDER
:: ============================================================
call :Section "11. WINDOWS DEFENDER / 防毒狀態"

powershell -NoProfile -Command ^
  "try { $s = Get-MpComputerStatus; Write-Host ('  Antivirus enabled    : ' + $s.AntivirusEnabled); Write-Host ('  Real-time protection : ' + $s.RealTimeProtectionEnabled); Write-Host ('  Last quick scan      : ' + $s.QuickScanStartTime); Write-Host ('  Last full scan       : ' + $s.FullScanStartTime); if (-not $s.RealTimeProtectionEnabled) { Write-Host '  [!!] Real-time protection is OFF!' -ForegroundColor Red } else { Write-Host '  [OK] Real-time protection is ON.' -ForegroundColor Green } } catch { Write-Host '  [?] Could not read Defender status (may need Admin).' -ForegroundColor Yellow }"
echo.

:: ============================================================
:: 12. RECENTLY INSTALLED PROGRAMS (last 30 days)
:: ============================================================
call :Section "12. RECENTLY INSTALLED PROGRAMS / 近期安裝的程式"

powershell -NoProfile -Command ^
  "$cutoff = (Get-Date).AddDays(-30); " ^
  "$apps = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and $_.InstallDate }; " ^
  "$recent = $apps | ForEach-Object { $d = $null; if ($_.InstallDate -match '^(\d{4})(\d{2})(\d{2})') { $d = Get-Date -Year $matches[1] -Month $matches[2] -Day $matches[3] }; if ($d -and $d -gt $cutoff) { [PSCustomObject]@{ Name=$_.DisplayName; Installed=$d.ToString('yyyy-MM-dd'); Publisher=$_.Publisher } } } | Sort-Object Installed -Descending; " ^
  "if ($recent) { $recent | Select-Object -First 15 | Format-Table -AutoSize | Out-String | Write-Host } else { Write-Host '  [INFO] No install dates found in last 30 days.' }"
echo.

:: ============================================================
:: SUMMARY
:: ============================================================
call :Section "SUMMARY / 總結"

if "!WARN!"=="0" (
    color 0A
    echo   [OK] No major red flags detected / 未發現明顯異常
    echo.
    echo   Note: This scan is NOT 100%% guarantee of safety.
    echo   注意: 此掃描無法 100%% 保證安全。
    echo.
    echo   For hidden room cameras / 針孔攝影機:
    echo   - Log into your router and check all connected devices
    echo   - 登入路由器，檢查所有連線裝置
) else (
    color 0C
    echo   [!!] WARNING: !WARN! possible issue(s) found / 發現 !WARN! 個可能問題
    echo.
    echo   Review all [!!] items above carefully.
    echo   請仔細查看上方標記 [!!] 的項目。
    echo.
    echo   If you did NOT install remote software yourself:
    echo   1. Disconnect internet / 斷開網路
    echo   2. Run Windows Defender full scan / 完整掃描
    echo   3. Download Malwarebytes: https://www.malwarebytes.com
    echo   4. Change important passwords from another device
)

:: Stop transcript
powershell -NoProfile -Command "Stop-Transcript" >nul 2>&1

echo.
echo  ============================================================
echo   Report saved / 報告已儲存:
echo   %REPORT%
echo  ============================================================
echo.
echo  Press any key to exit / 按任意鍵結束...
pause >nul
exit /b 0

:: ============================================================
:Section
echo.
echo  ============================================================
echo   %~1
echo  ============================================================
echo.
exit /b 0
