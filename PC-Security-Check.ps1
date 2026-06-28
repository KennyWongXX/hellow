# SCRIPT_VERSION=v6
param(
    [string]$ScriptDir = ''
)

$ErrorActionPreference = 'SilentlyContinue'
$WarnCount = 0
$apps = @()

if (-not $ScriptDir -and $env:PCSEC_DIR) {
    $ScriptDir = $env:PCSEC_DIR
}
if (-not $ScriptDir -and $MyInvocation.MyCommand.Path) {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if (-not $ScriptDir) {
    $ScriptDir = (Get-Location).Path
}

$ScriptFolder = $ScriptDir.TrimEnd('\')
$ReportFile = Join-Path $ScriptFolder ("PC-Security-Check-report-{0:yyyyMMdd-HHmmss}.txt" -f (Get-Date))
$AttentionItems = New-Object System.Collections.Generic.List[string]

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host "   $Title" -ForegroundColor Cyan
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Add-Attention {
    param(
        [string]$Category,
        [string]$Detail
    )
    if ([string]::IsNullOrWhiteSpace($Detail)) { return }
    $entry = "[$Category] $Detail"
    $script:AttentionItems.Add($entry) | Out-Null
}

function Write-Ok   { param([string]$Msg) Write-Host "  [OK]   $Msg" -ForegroundColor Green }

function Write-Warn {
    param(
        [string]$Msg,
        [string]$Category = 'Warning'
    )
    Write-Host "  [!!]   $Msg" -ForegroundColor Red
    Add-Attention -Category $Category -Detail $Msg
    $script:WarnCount++
}

function Write-Info {
    param(
        [string]$Msg,
        [string]$Category = '',
        [switch]$Attention
    )
    Write-Host "  [INFO] $Msg" -ForegroundColor Yellow
    if ($Attention -and $Category) {
        Add-Attention -Category $Category -Detail $Msg
    }
}

function Invoke-Check {
    param(
        [string]$Name,
        [scriptblock]$Action
    )
    Write-Section $Name
    try {
        & $Action
    } catch {
        Write-Warn "Check failed: $($_.Exception.Message)" -Category $Name
    }
}

function Show-AttentionSummary {
    Write-Host ""
    Write-Host "  ############################################################" -ForegroundColor Red
    Write-Host "   SUMMARY - ITEMS YOU NEED TO PAY ATTENTION TO" -ForegroundColor Red
    Write-Host "  ############################################################" -ForegroundColor Red
    Write-Host ""

    if ($AttentionItems.Count -eq 0) {
        Write-Host "  [OK] No major red flags detected." -ForegroundColor Green
        Write-Host "  Nothing urgent found. Still check your router for unknown devices." -ForegroundColor Green
    } else {
        Write-Host "  Found $($AttentionItems.Count) item(s) that need your attention:" -ForegroundColor Red
        Write-Host ""
        $num = 1
        foreach ($item in $AttentionItems) {
            Write-Host "    $num. $item" -ForegroundColor Yellow
            $num++
        }
        Write-Host ""
        Write-Host "  What to do if you did NOT install/expect these:" -ForegroundColor Red
        Write-Host "    1. Disconnect internet"
        Write-Host "    2. Run Windows Defender full scan"
        Write-Host "    3. Download Malwarebytes: https://www.malwarebytes.com"
        Write-Host "    4. Change passwords from another device"
        Write-Host "    5. For pinhole cameras: check router for unknown Wi-Fi devices"
    }

    Write-Host ""
    Write-Host "  Note: This scan does NOT guarantee 100% safety." -ForegroundColor Cyan
}

function Get-InstalledAppsSafe {
    $roots = @(
        @{ Hive = [Microsoft.Win32.Registry]::LocalMachine; Path = 'Software\Microsoft\Windows\CurrentVersion\Uninstall' },
        @{ Hive = [Microsoft.Win32.Registry]::LocalMachine; Path = 'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' },
        @{ Hive = [Microsoft.Win32.Registry]::CurrentUser;  Path = 'Software\Microsoft\Windows\CurrentVersion\Uninstall' }
    )

    $results = New-Object System.Collections.Generic.List[Object]

    foreach ($root in $roots) {
        $parentKey = $null
        try {
            $parentKey = $root.Hive.OpenSubKey($root.Path)
            if (-not $parentKey) { continue }

            foreach ($subName in $parentKey.GetSubKeyNames()) {
                $subKey = $null
                try {
                    $subKey = $parentKey.OpenSubKey($subName)
                    if (-not $subKey) { continue }

                    $displayName = $subKey.GetValue('DisplayName')
                    if (-not $displayName) { continue }

                    $results.Add([PSCustomObject]@{
                        DisplayName = [string]$displayName
                        Publisher   = [string]($subKey.GetValue('Publisher'))
                        InstallDate = [string]($subKey.GetValue('InstallDate'))
                    }) | Out-Null
                } catch {
                    continue
                } finally {
                    if ($subKey) { $subKey.Close() }
                }
            }
        } catch {
            continue
        } finally {
            if ($parentKey) { $parentKey.Close() }
        }
    }

    return ,$results.ToArray()
}

try { Start-Transcript -Path $ReportFile -Force | Out-Null } catch { }

Write-Host ""
Write-Host "  ============================================================" -ForegroundColor Green
Write-Host "   PC SECURITY CHECK  [v6]" -ForegroundColor Green
Write-Host "   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Green
Write-Host "  ============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Script folder : $ScriptFolder"
Write-Host "  Report file   : $ReportFile"
Write-Host ""

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Ok "Running as Administrator"
} else {
    Write-Warn "Not running as Administrator - some checks may be limited" -Category 'Admin'
    Write-Host "       Tip: Right-click bat file -> Run as administrator"
}

Invoke-Check "1. REMOTE ACCESS SOFTWARE - Installed" {
    $remoteKeywords = @(
        'TeamViewer','AnyDesk','RustDesk','Splashtop','LogMeIn','VNC','TightVNC',
        'UltraVNC','RealVNC','Chrome Remote','Quick Assist','RemotePC','ConnectWise',
        'ScreenConnect','Ammyy','Supremo','DWAgent','MeshCentral','Radmin',
        'GoToAssist','UltraViewer','AeroAdmin','Parsec'
    )

    $script:apps = @(Get-InstalledAppsSafe)

    $foundApps = New-Object System.Collections.Generic.List[Object]
    foreach ($app in $script:apps) {
        foreach ($kw in $remoteKeywords) {
            if ($app.DisplayName -match $kw) {
                $foundApps.Add($app) | Out-Null
                break
            }
        }
    }

    $unique = @($foundApps | Sort-Object DisplayName -Unique)
    if ($unique.Count -gt 0) {
        Write-Host "  [!!]   Remote access software found:" -ForegroundColor Red
        foreach ($app in $unique) {
            $detail = $app.DisplayName
            if ($app.Publisher) { $detail += " | Publisher: $($app.Publisher)" }
            Add-Attention -Category 'Remote Software' -Detail $detail
            Write-Host "         - $detail" -ForegroundColor Red
        }
        $script:WarnCount++
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
        if (Test-Path -LiteralPath $folder) {
            Write-Warn "Install folder exists: $folder" -Category 'Remote Software'
        }
    }
}

Invoke-Check "2. RUNNING PROCESSES - Remote / Suspicious" {
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
                Write-Warn "Process RUNNING: $($p.ProcessName) (PID $($p.Id))" -Category 'Running Process'
            }
        }
    }
    if (-not $procFound) { Write-Ok "No known remote-access processes running" }
}

Invoke-Check "3. NETWORK - Listening Ports" {
    Write-Host "  Risky ports: 22=SSH, 3389=RDP, 5900=VNC, 5938=TeamViewer, 7070=AnyDesk"
    Write-Host ""
    Write-Host "  All LISTENING ports:"
    netstat -ano | Select-String "LISTENING" | ForEach-Object { Write-Host "  $_" }

    $riskyPorts = @(22, 3389, 5900, 5938, 6568, 7070, 21116)
    $portFound = $false
    foreach ($port in $riskyPorts) {
        $portHits = @(netstat -ano | Select-String ":$port\s" | Select-String "LISTENING")
        if ($portHits.Count -gt 0) {
            $portFound = $true
            foreach ($hit in $portHits) {
                Write-Warn "Risky port $port is LISTENING - $hit" -Category 'Network Port'
            }
        }
    }
    if (-not $portFound) { Write-Ok "No common remote-access ports listening" }
}

Invoke-Check "4. ACTIVE CONNECTIONS" {
    $conns = @(netstat -ano | Select-String "ESTABLISHED")
    if ($conns.Count -gt 0) {
        $conns | ForEach-Object { Write-Host "  $_" }
    } else {
        Write-Info "No established connections right now"
    }
}

Invoke-Check "5. STARTUP PROGRAMS" {
    Write-Host "  --- Startup folder (User) ---"
    $userStartup = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    if (Test-Path -LiteralPath $userStartup) {
        Get-ChildItem -LiteralPath $userStartup | ForEach-Object { Write-Host "  $($_.Name)" }
    } else {
        Write-Host "  [empty]"
    }

    Write-Host ""
    Write-Host "  --- Startup folder (All Users) ---"
    $allStartup = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    if (Test-Path -LiteralPath $allStartup) {
        Get-ChildItem -LiteralPath $allStartup | ForEach-Object { Write-Host "  $($_.Name)" }
    } else {
        Write-Host "  [empty]"
    }

    Write-Host ""
    Write-Host "  --- Registry Run HKCU ---"
    cmd /c 'reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" 2>nul'

    Write-Host ""
    Write-Host "  --- Registry Run HKLM ---"
    cmd /c 'reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" 2>nul'
}

Invoke-Check "6. SCHEDULED TASKS" {
    $taskOutput = @(schtasks /Query /FO LIST 2>$null)
    $taskHits = @($taskOutput | Select-String -Pattern "TeamViewer|AnyDesk|RustDesk|VNC|Remote|Splashtop|LogMeIn")
    if ($taskHits.Count -gt 0) {
        foreach ($hit in $taskHits) {
            $line = $hit.Line.Trim()
            Write-Info $line -Category 'Scheduled Task' -Attention
        }
    } else {
        Write-Ok "No obvious remote-access tasks found"
    }
}

Invoke-Check "7. CAMERAS ON THIS PC" {
    $cams = @(Get-PnpDevice -Class Camera -ErrorAction SilentlyContinue)
    if ($cams.Count -eq 0) {
        $cams = @(Get-PnpDevice -ErrorAction SilentlyContinue |
            Where-Object { $_.FriendlyName -match 'camera|webcam|video|uvc|integrated|imaging' })
    }

    if ($cams.Count -gt 0) {
        Write-Host "  [INFO] Camera devices found on this PC:" -ForegroundColor Yellow
        foreach ($cam in $cams) {
            $detail = "$($cam.FriendlyName) | Status: $($cam.Status)"
            Add-Attention -Category 'Camera' -Detail $detail
            Write-Host "         - $detail" -ForegroundColor Yellow
        }
    } else {
        Write-Ok "No camera devices detected on this PC"
    }
}

Invoke-Check "8. CAMERA PERMISSIONS" {
    $camBase = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam'
    $allowCount = 0
    if (Test-Path -LiteralPath $camBase) {
        Get-ChildItem -LiteralPath $camBase -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(
                    'Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\' + $_.PSChildName)
                if ($key) {
                    $val = [string]$key.GetValue('Value')
                    $key.Close()
                    if ($val -eq 'Allow') {
                        $detail = "App allowed to use camera: $($_.PSChildName)"
                        Add-Attention -Category 'Camera Permission' -Detail $detail
                        Write-Host "  [INFO] $detail" -ForegroundColor Yellow
                        $allowCount++
                    }
                }
            } catch {
                continue
            }
        }
    }
    if ($allowCount -eq 0) {
        Write-Info "No apps with explicit camera Allow found"
    }
}

Invoke-Check "9. CAMERA APPS RUNNING NOW" {
    $keywords = @('camera','webcam','zoom','teams','skype','obs','meet','discord','line','wechat')
    $camAppFound = $false
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        foreach ($kw in $keywords) {
            if ($_.ProcessName -match $kw -or $_.MainWindowTitle -match $kw) {
                $detail = "$($_.ProcessName) | $($_.MainWindowTitle)"
                Add-Attention -Category 'Camera In Use' -Detail $detail
                Write-Host "  [INFO] Camera app running now: $detail" -ForegroundColor Yellow
                $camAppFound = $true
                break
            }
        }
    }
    if (-not $camAppFound) { Write-Ok "No obvious camera apps running" }
    Write-Host ""
    Write-Host "  Tip: If camera light is ON but nothing listed, run a malware scan." -ForegroundColor Cyan
}

Invoke-Check "10. NETWORK INFO - Pinhole Camera Check" {
    Write-Host "  Your IP addresses:"
    ipconfig | Select-String "IPv4" | ForEach-Object { Write-Host "  $_" }

    Write-Host ""
    Write-Host "  Router address - open in browser to see ALL connected devices:"
    $gateway = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Sort-Object RouteMetric | Select-Object -First 1).NextHop
    if ($gateway) {
        Write-Host "  http://$gateway" -ForegroundColor Yellow
        Add-Attention -Category 'Pinhole Camera Check' -Detail "Check router at http://$gateway for unknown Wi-Fi devices (IPCAM, CamHi, V380)"
    }

    Write-Host ""
    Write-Host "  Local network devices (ARP):"
    cmd /c arp -a

    Write-Host ""
    Write-Host "  [TIP] Hidden pinhole cameras connect to Wi-Fi, NOT your PC." -ForegroundColor Cyan
    Write-Host "        Check router for unknown devices: IPCAM, CamHi, V380, Hikvision" -ForegroundColor Cyan
}

Invoke-Check "11. WINDOWS DEFENDER" {
    $s = Get-MpComputerStatus -ErrorAction Stop
    Write-Host "  Antivirus enabled    : $($s.AntivirusEnabled)"
    Write-Host "  Real-time protection : $($s.RealTimeProtectionEnabled)"
    Write-Host "  Last quick scan      : $($s.QuickScanStartTime)"
    Write-Host "  Last full scan       : $($s.FullScanStartTime)"
    if ($s.RealTimeProtectionEnabled) {
        Write-Ok "Real-time protection is ON"
    } else {
        Write-Warn "Real-time protection is OFF" -Category 'Windows Defender'
    }
    if (-not $s.AntivirusEnabled) {
        Write-Warn "Antivirus is disabled" -Category 'Windows Defender'
    }
}

Invoke-Check "12. RECENTLY INSTALLED PROGRAMS - Last 30 days" {
    $cutoff = (Get-Date).AddDays(-30)
    $recentList = New-Object System.Collections.Generic.List[Object]

    foreach ($app in $apps) {
        $dateText = [string]$app.InstallDate
        if ($dateText -match '^(\d{4})(\d{2})(\d{2})$') {
            $year = [int]$Matches[1]
            $month = [int]$Matches[2]
            $day = [int]$Matches[3]
            $d = Get-Date -Year $year -Month $month -Day $day
            if ($d -gt $cutoff) {
                $recentList.Add([PSCustomObject]@{
                    Name      = $app.DisplayName
                    Installed = $d.ToString('yyyy-MM-dd')
                    Publisher = $app.Publisher
                }) | Out-Null
            }
        }
    }

    $recent = @($recentList | Sort-Object Installed -Descending)
    if ($recent.Count -gt 0) {
        Write-Host "  [INFO] Recently installed programs:" -ForegroundColor Yellow
        foreach ($item in ($recent | Select-Object -First 15)) {
            $detail = "$($item.Name) | Installed: $($item.Installed)"
            Add-Attention -Category 'Recent Install' -Detail $detail
            Write-Host "         - $detail" -ForegroundColor Yellow
        }
    } else {
        Write-Info "No install dates found in last 30 days"
    }
}

Show-AttentionSummary

try { Stop-Transcript | Out-Null } catch { }

$summaryFile = Join-Path $ScriptFolder "PC-Security-Check-SUMMARY.txt"
$summaryLines = New-Object System.Collections.Generic.List[string]
$summaryLines.Add("PC Security Check Summary - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')") | Out-Null
$summaryLines.Add("Report file: $ReportFile") | Out-Null
$summaryLines.Add("") | Out-Null

if ($AttentionItems.Count -eq 0) {
    $summaryLines.Add("No items need immediate attention.") | Out-Null
} else {
    $summaryLines.Add("Items you need to pay attention to ($($AttentionItems.Count)):") | Out-Null
    $num = 1
    foreach ($item in $AttentionItems) {
        $summaryLines.Add("$num. $item") | Out-Null
        $num++
    }
}

try {
    [System.IO.File]::WriteAllLines($summaryFile, $summaryLines.ToArray())
} catch { }

$pathInfoFile = Join-Path $ScriptFolder "PC-Security-Check-FILES-HERE.txt"
$pathInfo = @(
    "PC Security Check - file locations"
    "Scan time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    ""
    "Folder:"
    $ScriptFolder
    ""
    "Full report:"
    $ReportFile
    ""
    "Summary list:"
    $summaryFile
)
try {
    [System.IO.File]::WriteAllLines($pathInfoFile, $pathInfo)
} catch { }

Write-Host ""
Write-Host "  ############################################################" -ForegroundColor Green
Write-Host "   FILES SAVED HERE:" -ForegroundColor Green
Write-Host "  ############################################################" -ForegroundColor Green
Write-Host ""
Write-Host "  $ScriptFolder" -ForegroundColor Yellow
Write-Host ""
Write-Host "  1) $ReportFile" -ForegroundColor Yellow
Write-Host "  2) $summaryFile" -ForegroundColor Yellow
Write-Host "  3) $pathInfoFile" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Opening this folder in File Explorer now..." -ForegroundColor Cyan
Write-Host "  ############################################################" -ForegroundColor Green

try { Start-Process explorer.exe -ArgumentList $ScriptFolder } catch { }

Show-AttentionSummary
