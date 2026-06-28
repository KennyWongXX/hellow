# SCRIPT_VERSION=v8
param(
    [string]$ScriptDir = '',
    [string]$ReportPath = '',
    [string]$SummaryPath = ''
)

$ErrorActionPreference = 'SilentlyContinue'
$WarnCount = 0
$apps = @()
$LogLines = New-Object System.Collections.Generic.List[string]
$AttentionItems = New-Object System.Collections.Generic.List[string]

if (-not $ScriptDir -and $env:PCSEC_DIR) { $ScriptDir = $env:PCSEC_DIR }
if (-not $ScriptDir -and $MyInvocation.MyCommand.Path) {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if (-not $ScriptDir) { $ScriptDir = (Get-Location).Path }

$ScriptFolder = $ScriptDir.TrimEnd('\')
if (-not $ReportPath) { $ReportPath = Join-Path $ScriptFolder 'PC-Security-Check-report.txt' }
if (-not $SummaryPath) { $SummaryPath = Join-Path $ScriptFolder 'PC-Security-Check-SUMMARY.txt' }

function Log-Line {
    param([string]$Msg)
    Write-Host $Msg
    $script:LogLines.Add($Msg) | Out-Null
}

function Write-Section {
    param([string]$Title)
    Log-Line ""
    Log-Line "  ============================================================"
    Log-Line "   $Title"
    Log-Line "  ============================================================"
    Log-Line ""
}

function Add-Attention {
    param([string]$Category, [string]$Detail)
    if ([string]::IsNullOrWhiteSpace($Detail)) { return }
    $script:AttentionItems.Add("[$Category] $Detail") | Out-Null
}

function Write-Ok {
    param([string]$Msg)
    Log-Line "  [OK]   $Msg"
}

function Write-Warn {
    param([string]$Msg, [string]$Category = 'Warning')
    Log-Line "  [!!]   $Msg"
    Add-Attention -Category $Category -Detail $Msg
    $script:WarnCount++
}

function Write-Info {
    param([string]$Msg, [string]$Category = '', [switch]$Attention)
    Log-Line "  [INFO] $Msg"
    if ($Attention -and $Category) { Add-Attention -Category $Category -Detail $Msg }
}

function Invoke-Check {
    param([string]$Name, [scriptblock]$Action)
    Write-Section $Name
    try { & $Action } catch { Write-Warn "Check failed: $($_.Exception.Message)" -Category $Name }
}

function Save-TextFile {
    param([string]$Path, [string[]]$Lines)
    try {
        $dir = Split-Path $Path -Parent
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        [System.IO.File]::WriteAllLines($Path, $Lines, [System.Text.UTF8Encoding]::new($false))
        Log-Line "  [SAVED] $Path"
        return $true
    } catch {
        Log-Line "  [ERROR] Failed to save: $Path"
        Log-Line "          $($_.Exception.Message)"
        return $false
    }
}

function Show-AttentionSummary {
    Log-Line ""
    Log-Line "  ############################################################"
    Log-Line "   SUMMARY - ITEMS YOU NEED TO PAY ATTENTION TO"
    Log-Line "  ############################################################"
    Log-Line ""
    if ($AttentionItems.Count -eq 0) {
        Log-Line "  [OK] No major red flags detected."
    } else {
        Log-Line "  Found $($AttentionItems.Count) item(s) that need your attention:"
        Log-Line ""
        $num = 1
        foreach ($item in $AttentionItems) {
            Log-Line "    $num. $item"
            $num++
        }
    }
    Log-Line ""
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
                } catch { continue } finally { if ($subKey) { $subKey.Close() } }
            }
        } catch { continue } finally { if ($parentKey) { $parentKey.Close() } }
    }
    return ,$results.ToArray()
}

Log-Line ""
Log-Line "  ============================================================"
Log-Line "   PC SECURITY CHECK  [v8]"
Log-Line "   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Log-Line "  ============================================================"
Log-Line ""
Log-Line "  Report will save to: $ReportPath"
Log-Line "  Summary will save to: $SummaryPath"
Log-Line ""

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) { Write-Ok "Running as Administrator" }
else { Write-Warn "Not running as Administrator - some checks may be limited" -Category 'Admin' }

Invoke-Check "1. REMOTE ACCESS SOFTWARE - Installed" {
    $remoteKeywords = @('TeamViewer','AnyDesk','RustDesk','Splashtop','LogMeIn','VNC','TightVNC','UltraVNC','RealVNC','Chrome Remote','Quick Assist','RemotePC','ConnectWise','ScreenConnect','Ammyy','Supremo','DWAgent','MeshCentral','Radmin','GoToAssist','UltraViewer','AeroAdmin','Parsec')
    $script:apps = @(Get-InstalledAppsSafe)
    $foundApps = New-Object System.Collections.Generic.List[Object]
    foreach ($app in $script:apps) {
        foreach ($kw in $remoteKeywords) {
            if ($app.DisplayName -match $kw) { $foundApps.Add($app) | Out-Null; break }
        }
    }
    $unique = @($foundApps | Sort-Object DisplayName -Unique)
    if ($unique.Count -gt 0) {
        Log-Line "  [!!]   Remote access software found:"
        foreach ($app in $unique) {
            $detail = $app.DisplayName
            if ($app.Publisher) { $detail += " | Publisher: $($app.Publisher)" }
            Add-Attention -Category 'Remote Software' -Detail $detail
            Log-Line "         - $detail"
        }
        $script:WarnCount++
    } else { Write-Ok "No common remote-access programs found in registry" }

    foreach ($folder in @("$env:ProgramFiles\TeamViewer","${env:ProgramFiles(x86)}\TeamViewer","$env:ProgramFiles\AnyDesk","${env:ProgramFiles(x86)}\AnyDesk","$env:ProgramFiles\RustDesk","$env:LOCALAPPDATA\RustDesk")) {
        if (Test-Path -LiteralPath $folder) { Write-Warn "Install folder exists: $folder" -Category 'Remote Software' }
    }
}

Invoke-Check "2. RUNNING PROCESSES - Remote / Suspicious" {
    $procFound = $false
    foreach ($name in @('TeamViewer','AnyDesk','rustdesk','vncviewer','vncserver','winvnc','tvnserver','chrome_remote_desktop_host','msra','QuickAssist','splashtop','LogMeIn','ammyy','dwagent','MeshAgent','ScreenConnect','nc','ncat','netcat')) {
        $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
        if ($procs) {
            $procFound = $true
            foreach ($p in $procs) { Write-Warn "Process RUNNING: $($p.ProcessName) (PID $($p.Id))" -Category 'Running Process' }
        }
    }
    if (-not $procFound) { Write-Ok "No known remote-access processes running" }
}

Invoke-Check "3. NETWORK - Listening Ports" {
    Log-Line "  Risky ports: 22=SSH, 3389=RDP, 5900=VNC, 5938=TeamViewer, 7070=AnyDesk"
    Log-Line ""
    foreach ($line in (netstat -ano | Select-String "LISTENING")) { Log-Line "  $line" }
    $portFound = $false
    foreach ($port in @(22, 3389, 5900, 5938, 6568, 7070, 21116)) {
        foreach ($hit in @(netstat -ano | Select-String ":$port\s" | Select-String "LISTENING")) {
            $portFound = $true
            Write-Warn "Risky port $port is LISTENING - $hit" -Category 'Network Port'
        }
    }
    if (-not $portFound) { Write-Ok "No common remote-access ports listening" }
}

Invoke-Check "4. ACTIVE CONNECTIONS" {
    $conns = @(netstat -ano | Select-String "ESTABLISHED")
    if ($conns.Count -gt 0) { foreach ($c in $conns) { Log-Line "  $c" } }
    else { Write-Info "No established connections right now" }
}

Invoke-Check "5. STARTUP PROGRAMS" {
    Log-Line "  --- Startup folder (User) ---"
    $userStartup = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    if (Test-Path -LiteralPath $userStartup) { Get-ChildItem -LiteralPath $userStartup | ForEach-Object { Log-Line "  $($_.Name)" } }
    else { Log-Line "  [empty]" }
    Log-Line ""
    Log-Line "  --- Registry Run HKCU ---"
    foreach ($line in (cmd /c 'reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" 2>nul')) { Log-Line "  $line" }
    Log-Line ""
    Log-Line "  --- Registry Run HKLM ---"
    foreach ($line in (cmd /c 'reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" 2>nul')) { Log-Line "  $line" }
}

Invoke-Check "6. SCHEDULED TASKS" {
    $taskHits = @(schtasks /Query /FO LIST 2>$null | Select-String -Pattern "TeamViewer|AnyDesk|RustDesk|VNC|Remote|Splashtop|LogMeIn")
    if ($taskHits.Count -gt 0) { foreach ($hit in $taskHits) { Write-Info $hit.Line.Trim() -Category 'Scheduled Task' -Attention } }
    else { Write-Ok "No obvious remote-access tasks found" }
}

Invoke-Check "7. CAMERAS ON THIS PC" {
    $cams = @(Get-PnpDevice -Class Camera -ErrorAction SilentlyContinue)
    if ($cams.Count -eq 0) {
        $cams = @(Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -match 'camera|webcam|video|uvc|integrated|imaging' })
    }
    if ($cams.Count -gt 0) {
        Log-Line "  [INFO] Camera devices found:"
        foreach ($cam in $cams) {
            $detail = "$($cam.FriendlyName) | Status: $($cam.Status)"
            Add-Attention -Category 'Camera' -Detail $detail
            Log-Line "         - $detail"
        }
    } else { Write-Ok "No camera devices detected on this PC" }
}

Invoke-Check "8. CAMERA PERMISSIONS" {
    $camBase = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam'
    $allowCount = 0
    if (Test-Path -LiteralPath $camBase) {
        Get-ChildItem -LiteralPath $camBase -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\' + $_.PSChildName)
                if ($key) {
                    $val = [string]$key.GetValue('Value')
                    $key.Close()
                    if ($val -eq 'Allow') {
                        Add-Attention -Category 'Camera Permission' -Detail "App allowed: $($_.PSChildName)"
                        Log-Line "  [INFO] App allowed to use camera: $($_.PSChildName)"
                        $allowCount++
                    }
                }
            } catch { continue }
        }
    }
    if ($allowCount -eq 0) { Write-Info "No apps with explicit camera Allow found" }
}

Invoke-Check "9. CAMERA APPS RUNNING NOW" {
    $script:camAppFound = $false
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        foreach ($kw in @('camera','webcam','zoom','teams','skype','obs','meet','discord','line','wechat')) {
            if ($_.ProcessName -match $kw -or $_.MainWindowTitle -match $kw) {
                $detail = "$($_.ProcessName) | $($_.MainWindowTitle)"
                Add-Attention -Category 'Camera In Use' -Detail $detail
                Log-Line "  [INFO] Camera app running now: $detail"
                $script:camAppFound = $true
                break
            }
        }
    }
    if (-not $script:camAppFound) { Write-Ok "No obvious camera apps running" }
}

Invoke-Check "10. NETWORK INFO - Pinhole Camera Check" {
    foreach ($line in (ipconfig | Select-String "IPv4")) { Log-Line "  $line" }
    $gateway = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).NextHop
    if ($gateway) {
        Log-Line "  Router: http://$gateway"
        Add-Attention -Category 'Pinhole Camera Check' -Detail "Check router at http://$gateway for unknown Wi-Fi devices"
    }
    Log-Line ""
    foreach ($line in (cmd /c arp -a)) { Log-Line "  $line" }
}

Invoke-Check "11. WINDOWS DEFENDER" {
    try {
        $s = Get-MpComputerStatus -ErrorAction Stop
        Log-Line "  Antivirus enabled    : $($s.AntivirusEnabled)"
        Log-Line "  Real-time protection : $($s.RealTimeProtectionEnabled)"
        if ($s.RealTimeProtectionEnabled) { Write-Ok "Real-time protection is ON" }
        else { Write-Warn "Real-time protection is OFF" -Category 'Windows Defender' }
    } catch { Write-Info "Could not read Defender status" }
}

Invoke-Check "12. RECENTLY INSTALLED PROGRAMS - Last 30 days" {
    $cutoff = (Get-Date).AddDays(-30)
    $recentList = New-Object System.Collections.Generic.List[Object]
    foreach ($app in $apps) {
        $dateText = [string]$app.InstallDate
        if ($dateText -match '^(\d{4})(\d{2})(\d{2})$') {
            $d = Get-Date -Year ([int]$Matches[1]) -Month ([int]$Matches[2]) -Day ([int]$Matches[3])
            if ($d -gt $cutoff) {
                $recentList.Add([PSCustomObject]@{ Name = $app.DisplayName; Installed = $d.ToString('yyyy-MM-dd') }) | Out-Null
            }
        }
    }
    $recent = @($recentList | Sort-Object Installed -Descending)
    if ($recent.Count -gt 0) {
        Log-Line "  [INFO] Recently installed programs:"
        foreach ($item in ($recent | Select-Object -First 15)) {
            $detail = "$($item.Name) | Installed: $($item.Installed)"
            Add-Attention -Category 'Recent Install' -Detail $detail
            Log-Line "         - $detail"
        }
    } else { Write-Info "No install dates found in last 30 days" }
}

Show-AttentionSummary

$summaryLines = New-Object System.Collections.Generic.List[string]
$summaryLines.Add("PC Security Check Summary - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')") | Out-Null
$summaryLines.Add("Folder: $ScriptFolder") | Out-Null
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
$summaryLines.Add("") | Out-Null
$summaryLines.Add("Full report: $ReportPath") | Out-Null

$reportOk = Save-TextFile -Path $ReportPath -Lines $LogLines.ToArray()
$summaryOk = Save-TextFile -Path $SummaryPath -Lines $summaryLines.ToArray()

Log-Line ""
Log-Line "  ############################################################"
if ($reportOk -and $summaryOk) {
    Log-Line "   SUCCESS - Files saved:"
} else {
    Log-Line "   WARNING - Some files could not be saved:"
}
Log-Line "   $ReportPath"
Log-Line "   $SummaryPath"
Log-Line "  ############################################################"

if (-not $reportOk -or -not $summaryOk) { exit 2 }
exit 0
