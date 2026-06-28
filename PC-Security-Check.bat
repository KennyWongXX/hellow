@echo off
setlocal
title PC Security Check
color 0A
mode con: cols=110 lines=45
cd /d "%~dp0"

echo.
echo  ============================================================
echo   PC SECURITY CHECK
echo  ============================================================
echo.
echo  Starting scan... please wait 1-2 minutes.
echo.

set "RUNPS1=%TEMP%\PC-Security-Check-run.ps1"

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "try { $bat='%~f0'; $lines=[System.IO.File]::ReadAllLines($bat); $s=-1; $e=$lines.Length; for($i=0;$i -lt $lines.Length;$i++){ $t=$lines[$i].Trim(); if($t -eq '<<SCRIPT>>'){ $s=$i+1 }; if($t -eq '<<END>>'){ $e=$i; break } }; if($s -lt 0){ throw 'Script not found inside bat file' }; $script=($lines[$s..($e-1)] -join [Environment]::NewLine); [System.IO.File]::WriteAllText('%RUNPS1%',$script,[System.Text.UTF8Encoding]::new($false)); & '%RUNPS1%' } catch { Write-Host ''; Write-Host ' ERROR:' $_.Exception.Message -ForegroundColor Red; Write-Host ''; exit 1 }"

echo.
echo  ============================================================
echo   DONE - Press any key to close this window
echo  ============================================================
pause >nul
exit /b 0

<<SCRIPT>>
# PC Security Check - PowerShell script
# Called by PC-Security-Check.bat

$ErrorActionPreference = 'SilentlyContinue'
$WarnCount = 0

$ReportDir = $env:TEMP
$ReportFile = Join-Path $ReportDir ("PC-Security-Check-{0:yyyyMMdd-HHmmss}.txt" -f (Get-Date))

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host "   $Title" -ForegroundColor Cyan
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Ok   { param([string]$Msg) Write-Host "  [OK]   $Msg" -ForegroundColor Green }
function Write-Warn { param([string]$Msg) Write-Host "  [!!]   $Msg" -ForegroundColor Red; $script:WarnCount++ }
function Write-Info { param([string]$Msg) Write-Host "  [INFO] $Msg" -ForegroundColor Yellow }

Start-Transcript -Path $ReportFile -Force | Out-Null

Write-Host ""
Write-Host "  ============================================================" -ForegroundColor Green
Write-Host "   PC SECURITY CHECK" -ForegroundColor Green
Write-Host "   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Green
Write-Host "  ============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Report file: $ReportFile"
Write-Host ""

# Admin check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Ok "Running as Administrator"
} else {
    Write-Warn "Not running as Administrator - some checks may be limited"
    Write-Host "       Tip: Right-click bat file -> Run as administrator"
}

# 1. Remote access software
Write-Section "1. REMOTE ACCESS SOFTWARE - Installed"

$remoteKeywords = @(
    'TeamViewer','AnyDesk','RustDesk','Splashtop','LogMeIn','VNC','TightVNC',
    'UltraVNC','RealVNC','Chrome Remote','Quick Assist','RemotePC','ConnectWise',
    'ScreenConnect','Ammyy','Supremo','DWAgent','MeshCentral','Radmin',
    'GoToAssist','UltraViewer','AeroAdmin','Parsec'
)

$regPaths = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

$apps = foreach ($path in $regPaths) {
    Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName }
}

$foundApps = @()
foreach ($kw in $remoteKeywords) {
    $foundApps += $apps | Where-Object { $_.DisplayName -match $kw }
}

$foundApps = $foundApps | Select-Object DisplayName, Publisher, InstallDate -Unique

if ($foundApps) {
    Write-Warn "Remote access software found:"
    $foundApps | Format-Table -AutoSize | Out-String | Write-Host
} else {
    Write-Ok "No common remote-access programs found in registry"
}

$folders = @(
    "$env:ProgramFiles\TeamViewer",
    "${env:ProgramFiles(x86)}\TeamViewer",
    "$env:ProgramFiles\AnyDesk",
    "${env:ProgramFiles(x86)}\AnyDesk",
    "$env:ProgramFiles\RustDesk",
    "$env:LOCALAPPDATA\RustDesk",
    "$env:ProgramFiles\RealVNC",
    "${env:ProgramFiles(x86)}\RealVNC"
)

Write-Host "  Checking install folders..."
foreach ($folder in $folders) {
    if (Test-Path $folder) {
        Write-Warn "Folder exists: $folder"
    }
}

# 2. Running processes
Write-Section "2. RUNNING PROCESSES - Remote / Suspicious"

$procNames = @(
    'TeamViewer','AnyDesk','rustdesk','vncviewer','vncserver','winvnc','tvnserver',
    'chrome_remote_desktop_host','msra','QuickAssist','splashtop','LogMeIn',
    'ammyy','dwagent','MeshAgent','ScreenConnect','nc','ncat','netcat'
)

$procFound = $false
foreach ($name in $procNames) {
    $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
    if ($procs) {
        $procFound = $true
        foreach ($p in $procs) {
            Write-Warn "RUNNING: $($p.ProcessName)  PID=$($p.Id)"
        }
    }
}
if (-not $procFound) { Write-Ok "No known remote-access processes running" }

# 3. Listening ports
Write-Section "3. NETWORK - Listening Ports"

Write-Host "  Risky ports: 22=SSH, 3389=RDP, 5900=VNC, 5938=TeamViewer, 7070=AnyDesk"
Write-Host ""
Write-Host "  All LISTENING ports:"
netstat -ano | Select-String "LISTENING" | ForEach-Object { Write-Host "  $_" }

$riskyPorts = @(22, 3389, 5900, 5938, 6568, 7070, 21116)
$portFound = $false
foreach ($port in $riskyPorts) {
    $matches = netstat -ano | Select-String ":$port\s" | Select-String "LISTENING"
    if ($matches) {
        $portFound = $true
        Write-Warn "Port $port is LISTENING:"
        $matches | ForEach-Object { Write-Host "    $_" }
    }
}
if (-not $portFound) { Write-Ok "No common remote-access ports listening" }

# 4. Active connections
Write-Section "4. ACTIVE CONNECTIONS"

$conns = netstat -ano | Select-String "ESTABLISHED"
if ($conns) {
    $conns | ForEach-Object { Write-Host "  $_" }
} else {
    Write-Info "No established connections right now"
}

# 5. Startup programs
Write-Section "5. STARTUP PROGRAMS"

Write-Host "  --- Startup folder (User) ---"
$userStartup = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
if (Test-Path $userStartup) {
    Get-ChildItem $userStartup | ForEach-Object { Write-Host "  $($_.Name)" }
} else {
    Write-Host "  [empty]"
}

Write-Host ""
Write-Host "  --- Startup folder (All Users) ---"
$allStartup = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
if (Test-Path $allStartup) {
    Get-ChildItem $allStartup | ForEach-Object { Write-Host "  $($_.Name)" }
} else {
    Write-Host "  [empty]"
}

Write-Host ""
Write-Host "  --- Registry Run HKCU ---"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" 2>$null

Write-Host ""
Write-Host "  --- Registry Run HKLM ---"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" 2>$null

# 6. Scheduled tasks
Write-Section "6. SCHEDULED TASKS"

$taskOutput = schtasks /Query /FO LIST 2>$null
$taskHits = $taskOutput | Select-String -Pattern "TeamViewer|AnyDesk|RustDesk|VNC|Remote|Splashtop|LogMeIn"
if ($taskHits) {
    $taskHits | ForEach-Object { Write-Info $_.Line.Trim() }
} else {
    Write-Ok "No obvious remote-access tasks found"
}

# 7. Cameras
Write-Section "7. CAMERAS ON THIS PC"

$cams = @(Get-PnpDevice -Class Camera -ErrorAction SilentlyContinue)
if ($cams.Count -eq 0) {
    $cams = @(Get-PnpDevice -ErrorAction SilentlyContinue |
        Where-Object { $_.FriendlyName -match 'camera|webcam|video|uvc|integrated|imaging' })
}

if ($cams.Count -gt 0) {
    Write-Info "Camera devices found:"
    $cams | Select-Object Status, Class, FriendlyName | Format-Table -AutoSize | Out-String | Write-Host
} else {
    Write-Ok "No camera devices detected on this PC"
}

# 8. Camera permissions
Write-Section "8. CAMERA PERMISSIONS"

$camBase = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam'
$allowCount = 0
if (Test-Path $camBase) {
    Get-ChildItem $camBase -ErrorAction SilentlyContinue | ForEach-Object {
        $v = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($v.Value -eq 'Allow') {
            Write-Info "ALLOW: $($_.PSChildName)"
            $allowCount++
        }
    }
}
if ($allowCount -eq 0) {
    Write-Info "No apps with explicit Allow found"
}

# 9. Camera apps running
Write-Section "9. CAMERA APPS RUNNING NOW"

$keywords = 'camera','webcam','zoom','teams','skype','obs','meet','discord','line','wechat'
$camAppFound = $false
Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    foreach ($kw in $keywords) {
        if ($_.ProcessName -match $kw -or $_.MainWindowTitle -match $kw) {
            Write-Info "Possible camera app: $($_.ProcessName) | $($_.MainWindowTitle)"
            $camAppFound = $true
            break
        }
    }
}
if (-not $camAppFound) { Write-Ok "No obvious camera apps running" }
Write-Host ""
Write-Host "  Tip: If camera light is ON but nothing listed, run a malware scan." -ForegroundColor Cyan

# 10. Network info
Write-Section "10. NETWORK INFO - Pinhole Camera Check"

Write-Host "  Your IP addresses:"
ipconfig | Select-String "IPv4" | ForEach-Object { Write-Host "  $_" }

Write-Host ""
Write-Host "  Router address - open in browser to see ALL connected devices:"
$gateway = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Sort-Object RouteMetric | Select-Object -First 1).NextHop
if ($gateway) { Write-Host "  http://$gateway" -ForegroundColor Yellow }

Write-Host ""
Write-Host "  Local network devices (ARP):"
arp -a

Write-Host ""
Write-Host "  [TIP] Hidden pinhole cameras connect to Wi-Fi, NOT your PC." -ForegroundColor Cyan
Write-Host "        Check router for unknown devices: IPCAM, CamHi, V380, Hikvision" -ForegroundColor Cyan

# 11. Windows Defender
Write-Section "11. WINDOWS DEFENDER"

try {
    $s = Get-MpComputerStatus
    Write-Host "  Antivirus enabled    : $($s.AntivirusEnabled)"
    Write-Host "  Real-time protection : $($s.RealTimeProtectionEnabled)"
    Write-Host "  Last quick scan      : $($s.QuickScanStartTime)"
    Write-Host "  Last full scan       : $($s.FullScanStartTime)"
    if ($s.RealTimeProtectionEnabled) {
        Write-Ok "Real-time protection is ON"
    } else {
        Write-Warn "Real-time protection is OFF"
    }
} catch {
    Write-Info "Could not read Defender status - try Run as administrator"
}

# 12. Recently installed
Write-Section "12. RECENTLY INSTALLED PROGRAMS - Last 30 days"

$cutoff = (Get-Date).AddDays(-30)
$recent = $apps | ForEach-Object {
    if ($_.InstallDate -match '^(\d{4})(\d{2})(\d{2})') {
        $d = Get-Date -Year $matches[1] -Month $matches[2] -Day $matches[3]
        if ($d -gt $cutoff) {
            [PSCustomObject]@{
                Name      = $_.DisplayName
                Installed = $d.ToString('yyyy-MM-dd')
                Publisher = $_.Publisher
            }
        }
    }
} | Sort-Object Installed -Descending

if ($recent) {
    $recent | Select-Object -First 15 | Format-Table -AutoSize | Out-String | Write-Host
} else {
    Write-Info "No install dates found in last 30 days"
}

# Summary
Write-Section "SUMMARY"

if ($WarnCount -eq 0) {
    Write-Host "  [OK] No major red flags detected" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Note: This scan does NOT guarantee 100% safety."
    Write-Host "  For hidden room cameras: log into your router and check connected devices."
} else {
    Write-Host "  [!!] WARNING: $WarnCount possible issue(s) found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Review all [!!] items above."
    Write-Host "  If you did NOT install remote software yourself:"
    Write-Host "  1. Disconnect internet"
    Write-Host "  2. Run Windows Defender full scan"
    Write-Host "  3. Download Malwarebytes: https://www.malwarebytes.com"
    Write-Host "  4. Change passwords from another device"
}

Stop-Transcript | Out-Null

Write-Host ""
Write-Host "  ============================================================" -ForegroundColor Green
Write-Host "   Report saved: $ReportFile" -ForegroundColor Green
Write-Host "  ============================================================" -ForegroundColor Green


Write-Host ''
Write-Host '  Scan finished successfully.' -ForegroundColor Green

<<END>>
