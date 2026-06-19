<#PSScriptInfo
.VERSION 0.8.13
.GUID fd499ba1-8ce6-4512-877e-9dede49777f5
.AUTHOR SysAdminDoc
.DESCRIPTION Per-adapter IP lockdown for Windows via registry ACL deny ACEs. WPF GUI and headless CLI.
.COPYRIGHT (c) 2026 SysAdminDoc. All rights reserved.
.TAGS networking adapter lock registry ACL IP security PACS
.LICENSEURI https://github.com/SysAdminDoc/AdapterLock/blob/master/LICENSE
.PROJECTURI https://github.com/SysAdminDoc/AdapterLock
.RELEASENOTES Adds compact read-only status mode and GUI report export/open action.
#>

<#
.SYNOPSIS
    Per-adapter IP lockdown via registry ACL deny ACEs.

.DESCRIPTION
    Locks a specific NIC's TCP/IP configuration at the registry ACL level so that
    ncpa.cpl, netsh, Set-NetIPAddress, and DHCP reassignment all fail with access
    denied on that interface -- even for local administrators -- while every other
    adapter stays fully editable.

    Works by adding a Deny ACE for Authenticated Users (S-1-5-11) on SetValue,
    CreateSubKey, Delete, and WriteKey on the adapter's Tcpip, Tcpip6, and NetBT
    interface registry keys. Admins retain WRITE_DAC so the tool can always unlock.

    Run without parameters for the WPF GUI. Use -Lock/-Unlock with -Silent for
    headless deployment via Intune, SCCM, or GPO startup scripts.

.PARAMETER Lock
    Lock the specified adapter (deny IP config writes).

.PARAMETER Unlock
    Unlock the specified adapter (remove deny ACEs).

.PARAMETER Adapter
    Target adapter by display name (e.g. "Ethernet", "PACS Link").

.PARAMETER Mac
    Target adapter by MAC address. Separators (colons, hyphens) are normalised automatically.

.PARAMETER Guid
    Target adapter by interface GUID (e.g. "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}").

.PARAMETER Silent
    Suppress the GUI and run in CLI mode. Required for headless deployment.

.PARAMETER DryRun
    Preview which registry keys would be modified without writing any ACL changes.

.PARAMETER Compact
    Launch a compact read-only status window for monitoring lock state, exporting reports, and opening logs.

.PARAMETER ListAdapters
    List visible and hidden adapters with stable identifiers and lock state for CLI discovery.

.PARAMETER LoadPolicy
    Path to a JSON policy file to load and enforce. Entries with State=locked are applied; partial entries are skipped with a warning.

.PARAMETER RestoreBackup
    Restore the latest saved SDDL backup for the adapter specified by -Guid, or an exact backup selected with -BackupFile.

.PARAMETER ListBackups
    List saved SDDL backups. Use -Guid to filter to one adapter.

.PARAMETER BackupFile
    Exact SDDL backup file to restore with -RestoreBackup. May be a full path or a file name under the AdapterLock backup directory.

.PARAMETER InstallTask
    Register a scheduled task that re-applies the lock policy at system startup.

.PARAMETER UninstallTask
    Remove the AdapterLock scheduled enforcement task.

.PARAMETER PolicyFile
    Path to the policy file used by -InstallTask. Defaults to %ProgramData%\AdapterLock\policy.json.

.PARAMETER VerifyLocks
    Check all locked adapters (or policy targets) for ACL drift and report status.

.PARAMETER Remediate
    When used with -VerifyLocks, automatically re-apply deny ACEs on adapters with drift.

.PARAMETER Query
    Query lock state of adapters on one or more remote machines via Invoke-Command.

.PARAMETER ComputerName
    One or more remote computer names to query. Used with -Query.

.PARAMETER InstallWatcher
    Install permanent WMI event subscriptions that log registry tree changes on Tcpip, Tcpip6, and NetBT interface keys (EventId 1002).

.PARAMETER UninstallWatcher
    Remove the AdapterLock WMI drift watcher.

.PARAMETER Report
    Generate an HTML fleet report of lock state across remote hosts (use with -ComputerName).

.PARAMETER OutputFile
    Path for the HTML report file. Defaults to adapterlock-report-{timestamp}.html in the current directory.

.PARAMETER OutputFormat
    Output format for -Query or -Report. Query defaults to Table; Report defaults to Html. Json and Csv are machine-readable.

.EXAMPLE
    .\AdapterLock.ps1
    Launch the WPF GUI for interactive lock/unlock.

.EXAMPLE
    .\AdapterLock.ps1 -Compact
    Launch a compact read-only status window.

.EXAMPLE
    .\AdapterLock.ps1 -Lock -Adapter "Ethernet" -Silent
    Lock the adapter named "Ethernet" in headless mode.

.EXAMPLE
    .\AdapterLock.ps1 -Unlock -Mac "AA:BB:CC:DD:EE:FF" -Silent
    Unlock the adapter with the given MAC address.

.EXAMPLE
    .\AdapterLock.ps1 -Lock -Adapter "Ethernet" -Silent -DryRun
    Preview which registry keys would be locked without making changes.

.EXAMPLE
    .\AdapterLock.ps1 -ListAdapters -OutputFormat Json -Silent
    List visible and hidden adapters with identifiers for scripting.

.EXAMPLE
    .\AdapterLock.ps1 -LoadPolicy C:\policy.json -Silent
    Load and enforce a JSON policy file.

.EXAMPLE
    .\AdapterLock.ps1 -RestoreBackup -Guid "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}" -Silent
    Restore the latest SDDL backup for the specified adapter.

.LINK
    https://github.com/SysAdminDoc/AdapterLock
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [switch]$Lock,
    [switch]$Unlock,
    [string]$Adapter,
    [string]$Mac,
    [string]$Guid,
    [switch]$Silent,
    [switch]$DryRun,
    [switch]$Compact,
    [switch]$ListAdapters,
    [string]$LoadPolicy,
    [switch]$RestoreBackup,
    [switch]$ListBackups,
    [string]$BackupFile,
    [switch]$InstallTask,
    [switch]$UninstallTask,
    [string]$PolicyFile,
    [switch]$VerifyLocks,
    [switch]$Remediate,
    [switch]$Query,
    [string[]]$ComputerName,
    [switch]$InstallWatcher,
    [switch]$UninstallWatcher,
    [switch]$Report,
    [string]$OutputFile,
    [ValidateSet('Table','Json','Csv','Html')]
    [string]$OutputFormat
)


$script:IsCli    = $Silent.IsPresent -or $Lock.IsPresent -or $Unlock.IsPresent -or $ListAdapters.IsPresent -or $LoadPolicy -or $RestoreBackup.IsPresent -or $ListBackups.IsPresent -or $InstallTask.IsPresent -or $UninstallTask.IsPresent -or $VerifyLocks.IsPresent -or $Query.IsPresent -or $InstallWatcher.IsPresent -or $UninstallWatcher.IsPresent -or $Report.IsPresent
$script:IsDryRun = $DryRun.IsPresent -or $WhatIfPreference
$script:RootCmdlet = $PSCmdlet
$script:IsCompactMode = $Compact.IsPresent


#region Self-elevate + hide console
$ErrorActionPreference = 'Stop'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-ProcessArgument {
    param([object]$Value)
    $text = [string]$Value
    return '"' + ($text -replace '"', '\"') + '"'
}

function Add-ForwardedParameterArgument {
    param(
        [System.Collections.Generic.List[string]]$Arguments,
        [string]$Name,
        [object]$Value
    )

    if ($Value -is [System.Management.Automation.SwitchParameter]) {
        if ($Value.IsPresent) { $Arguments.Add("-$Name") }
        return
    }
    if ($null -eq $Value) { return }

    $Arguments.Add("-$Name")
    if ($Value -is [System.Array] -and $Value -isnot [string]) {
        foreach ($item in $Value) {
            $Arguments.Add((ConvertTo-ProcessArgument -Value $item))
        }
        return
    }
    $Arguments.Add((ConvertTo-ProcessArgument -Value $Value))
}

if (-not (Test-Admin)) {
    $psi          = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = (Get-Process -Id $PID).Path
    $psi.Verb     = 'runas'
    $psi.WindowStyle = if ($script:IsCli) { 'Normal' } else { 'Hidden' }

    $fwd = [System.Collections.Generic.List[string]]::new()
    $fwd.AddRange([string[]]@('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`""))
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        Add-ForwardedParameterArgument -Arguments $fwd -Name $kv.Key -Value $kv.Value
    }
    $psi.Arguments = $fwd -join ' '
    try {
        [void][System.Diagnostics.Process]::Start($psi)
    } catch {
        throw "Elevation launch failed: $($_.Exception.Message)"
    }
    exit
}

if (-not ([System.Management.Automation.PSTypeName]'AdapterLock.Win32Console').Type) {
    Add-Type -Name Win32Console -Namespace AdapterLock -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
public static extern System.IntPtr GetConsoleWindow();
[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern bool ShowWindow(System.IntPtr hWnd, int nCmdShow);
'@
}
if (-not $script:IsCli) {
    $hwnd = [AdapterLock.Win32Console]::GetConsoleWindow()
    if ($hwnd -ne [IntPtr]::Zero) { [void][AdapterLock.Win32Console]::ShowWindow($hwnd, 0) }
}
#endregion

if (-not $script:IsCli) {
    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName PresentationCore
    Add-Type -AssemblyName WindowsBase
    Add-Type -AssemblyName System.Windows.Forms
}

$script:Version   = '0.8.13'
$script:LogPath   = Join-Path $env:APPDATA   'AdapterLock\adapterlock.log'
$script:BackupDir = Join-Path $env:ProgramData 'AdapterLock\Backups'
$null = New-Item -ItemType Directory -Force -Path (Split-Path $script:LogPath) -ErrorAction SilentlyContinue
$null = New-Item -ItemType Directory -Force -Path $script:BackupDir             -ErrorAction SilentlyContinue

#region Core lock/unlock logic
function Write-AppLog {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
    if ($script:IsCli) {
        if ($Level -eq 'ERROR' -or $Level -eq 'WARN') { Write-Warning $Message }
        else { Write-Information $line -InformationAction Continue }
    }
    if ($script:LogBox) {
        $script:LogBox.Dispatcher.Invoke([action]{
            $script:LogBox.AppendText($line + "`r`n")
            $script:LogBox.ScrollToEnd()
        })
    }
}

function Initialize-EventSource {
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists('AdapterLock')) {
            [System.Diagnostics.EventLog]::CreateEventSource('AdapterLock', 'Application')
        }
    } catch {
        Write-AppLog "Event source initialization failed: $($_.Exception.Message)" 'WARN'
    }
}

function Write-EvtLog {
    param([string]$Message, [string]$EntryType = 'Information')
    try {
        Write-EventLog -LogName Application -Source AdapterLock `
            -EventId 1001 -EntryType $EntryType -Message $Message -ErrorAction SilentlyContinue
    } catch {
        Write-AppLog "Event log write failed: $($_.Exception.Message)" 'WARN'
    }
}

function Test-ShouldProcessChange {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [string]$Target,
        [string]$Action
    )
    if (-not $script:IsCli -or -not $script:RootCmdlet) { return $true }
    return [bool]$script:RootCmdlet.ShouldProcess($Target, $Action)
}

function Get-NicType {
    param($A)
    $desc = [string]$A.InterfaceDescription
    if ($A.ifIndex -eq 1)    { return 'Loop' }
    if ($A.PhysicalMediaType -eq '802.11' -or $desc -match 'Wi-?Fi|Wireless|WLAN|802\.11') { return 'WiFi' }
    if ($desc -match 'Virtual|VMware|VirtualBox|Hyper-V|vEthernet|vSwitch|VPN|TAP')        { return 'Virt' }
    if ($desc -match 'WAN Miniport|L2TP|PPTP|PPPoE|Tunnel|6to4|Teredo|ISATAP')             { return 'Tunl' }
    return 'Phys'
}

function Get-NicTypeGlyph {
    param([string]$Type)
    # Segoe MDL2 Assets glyphs
    $glyphs = @{
        'Phys'  = [char]0xE7F8   # PhysicalNetwork
        'WiFi'  = [char]0xE702   # WiFi
        'Virt'  = [char]0xE721   # VirtualMachine
        'Tunl'  = [char]0xE784   # VPN
        'Loop'  = [char]0xE81D   # LoopArrow
    }
    if ($glyphs.ContainsKey($Type)) { return $glyphs[$Type] }
    return $Type
}

function Get-RegistryLastWrite {
    param([string]$Path)
    if (-not ([System.Management.Automation.PSTypeName]'AdapterLock.RegistryUtil').Type) {
        Add-Type -Namespace AdapterLock -Name RegistryUtil -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
private static extern long RegOpenKeyEx(System.IntPtr hKey, string lpSubKey, int ulOptions, int samDesired, out System.IntPtr phkResult);
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
private static extern long RegQueryInfoKey(System.IntPtr hKey, System.Text.StringBuilder lpClass, ref uint lpcClass,
    IntPtr lpReserved, out uint lpcSubKeys, out uint lpcMaxSubKeyLen, out uint lpcMaxClassLen, out uint lpcValues,
    out uint lpcMaxValueNameLen, out uint lpcMaxValueLen, out uint lpcSecurityDescriptor,
    out System.Runtime.InteropServices.ComTypes.FILETIME lpftLastWriteTime);
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
private static extern long RegCloseKey(System.IntPtr hKey);
private const long HKEY_LOCAL_MACHINE = 0x80000002L;
private const int KEY_READ = 0x20019;
public static System.DateTime GetKeyLastWrite(string path) {
    System.IntPtr hKey = System.IntPtr.Zero;
    try {
        if (RegOpenKeyEx(new System.IntPtr(HKEY_LOCAL_MACHINE), path, 0, KEY_READ, out hKey) != 0) return System.DateTime.MinValue;
        System.Runtime.InteropServices.ComTypes.FILETIME ft = new System.Runtime.InteropServices.ComTypes.FILETIME();
        uint c = 0, mc = 0, cl = 0, v = 0, mvn = 0, mvl = 0, sec = 0;
        if (RegQueryInfoKey(hKey, null, ref c, System.IntPtr.Zero, out var sub, out var msub, out var mcl, out var vals, out mvn, out mvl, out sec, out ft) != 0)
            return System.DateTime.MinValue;
        long hft = ((long)ft.dwHighDateTime << 32) | (uint)ft.dwLowDateTime;
        return hft > 0 ? System.DateTime.FromFileTime(hft) : System.DateTime.MinValue;
    } finally { if (hKey != System.IntPtr.Zero) RegCloseKey(hKey); }
}
'@
    }
    try {
        $subPath = $Path -replace '^HKLM:\\', ''
        $dt = [AdapterLock.RegistryUtil]::GetKeyLastWrite($subPath)
        if ($dt -ne [DateTime]::MinValue) { return $dt }
        return $null
    } catch {
        return $null
    }
}

function ConvertTo-ReportHtml {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertTo-PolicyGuid {
    param([string]$Value)
    if (-not $Value) { return '' }
    $trimmed = $Value.Trim()
    if ($trimmed -notmatch '^\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?$') {
        return $null
    }
    return '{' + ($trimmed.Trim('{}').ToLowerInvariant()) + '}'
}

function ConvertTo-PolicyMac {
    param([string]$Value)
    if (-not $Value) { return '' }
    $norm = ($Value -replace '[:\-\s\.]', '').ToUpperInvariant()
    if ($norm -notmatch '^[0-9A-F]{12}$') { return $null }
    return ($norm -replace '(.{2})(?=.)', '$1-')
}

function Get-PolicyIdentifierKey {
    param($Adapter)
    $keys = New-Object System.Collections.Generic.List[string]
    if ($Adapter.Name) { $keys.Add("name:$(([string]$Adapter.Name).ToLowerInvariant())") }
    if ($Adapter.MAC)  { $keys.Add("mac:$(([string]$Adapter.MAC).ToUpperInvariant())") }
    if ($Adapter.GUID) { $keys.Add("guid:$(([string]$Adapter.GUID).ToLowerInvariant())") }
    return $keys
}

function Export-LockPolicy {
    param([string]$Path)
    $policy = @{
        Version = $script:Version
        Timestamp = (Get-Date -Format 'o')
        Adapters = @()
    }
    try {
        Get-AdapterRow | ForEach-Object {
            if ($_.IsLocked) {
                $policy.Adapters += @{
                    Name = $_.Name
                    MAC = $_.MAC
                    GUID = $_.Guid
                    State = if ($_.LockBadge -eq 'LOCKED') { 'locked' } else { 'partial' }
                }
            }
        }
    } catch {
        Write-AppLog "Policy export scan failed: $($_.Exception.Message)" 'WARN'
    }
    $policy | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $Path -Encoding UTF8
    Write-AppLog "Policy exported: $Path ($($policy.Adapters.Count) adapters)" 'OK'
}

function Import-LockPolicy {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-AppLog "Policy file not found: $Path" 'ERROR'
        return @()
    }
    try {
        $policy = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-AppLog "Policy parse failed: $($_.Exception.Message)" 'ERROR'
        return @()
    }

    if (-not $policy.Version) {
        Write-AppLog "Policy validation failed: missing 'Version' field" 'ERROR'
        return @()
    }
    if ($null -eq $policy.Adapters -or $policy.Adapters -isnot [System.Array]) {
        Write-AppLog "Policy validation failed: 'Adapters' must be an array" 'ERROR'
        return @()
    }
    $valid = @()
    $seen = @{}
    for ($i = 0; $i -lt $policy.Adapters.Count; $i++) {
        $a = $policy.Adapters[$i]
        $hasId = [bool]$a.Name -or [bool]$a.MAC -or [bool]$a.GUID
        if (-not $hasId) {
            Write-AppLog "Policy validation failed: Adapters[$i] has no Name, MAC, or GUID" 'ERROR'
            return @()
        }

        $state = if ($a.State) { ([string]$a.State).Trim().ToLowerInvariant() } else { 'locked' }
        if ($state -notin @('locked', 'partial')) {
            Write-AppLog "Policy validation failed: Adapters[$i] has invalid State '$($a.State)'" 'ERROR'
            return @()
        }

        $guid = ''
        if ($a.GUID) {
            $guid = ConvertTo-PolicyGuid -Value ([string]$a.GUID)
            if ($null -eq $guid) {
                Write-AppLog "Policy validation failed: Adapters[$i] has invalid GUID '$($a.GUID)'" 'ERROR'
                return @()
            }
        }

        $mac = ''
        if ($a.MAC) {
            $mac = ConvertTo-PolicyMac -Value ([string]$a.MAC)
            if ($null -eq $mac) {
                Write-AppLog "Policy validation failed: Adapters[$i] has invalid MAC '$($a.MAC)'" 'ERROR'
                return @()
            }
        }

        $normalized = [pscustomobject]@{
            Name  = if ($a.Name) { [string]$a.Name } else { '' }
            MAC   = $mac
            GUID  = $guid
            State = $state
        }

        foreach ($key in (Get-PolicyIdentifierKey -Adapter $normalized)) {
            if ($seen.ContainsKey($key)) {
                Write-AppLog "Policy validation failed: duplicate adapter identifier '$key'" 'ERROR'
                return @()
            }
            $seen[$key] = $true
        }

        $valid += $normalized
    }
    Write-AppLog "Policy loaded: $Path ($($valid.Count) adapters)" 'OK'
    return $valid
}

function Get-LockPolicySummary {
    param([object[]]$Results)
    $applied = @($Results | Where-Object { $_.Status -eq 'Applied' }).Count
    $dryRun  = @($Results | Where-Object { $_.Status -eq 'DryRun' }).Count
    $skipped = @($Results | Where-Object { $_.Status -eq 'SkippedPartial' }).Count
    $missing = @($Results | Where-Object { $_.Status -eq 'NotFound' }).Count
    $failed  = @($Results | Where-Object { $_.Status -eq 'Failed' }).Count
    return "Policy summary: $applied applied, $dryRun dry-run, $skipped partial skipped, $missing missing, $failed failed"
}

function Invoke-LockPolicy {
    param(
        [object[]]$Policy,
        [switch]$Preview
    )

    $results = @()
    foreach ($p in $Policy) {
        $targetText = if ($p.Name) { $p.Name } elseif ($p.MAC) { $p.MAC } else { $p.GUID }
        if ($p.State -eq 'partial') {
            Write-AppLog "Policy skipped partial target: $targetText. Change State to 'locked' to enforce it." 'WARN'
            $results += [pscustomobject]@{
                Target = $targetText
                Adapter = ''
                GUID = $p.GUID
                State = $p.State
                Status = 'SkippedPartial'
            }
            continue
        }

        $adapter = Find-AdapterByIdentifier -ByName $p.Name -ByMac $p.MAC -ByGuid $p.GUID
        if (-not $adapter) {
            Write-AppLog "Policy target not found: $($p.Name) / $($p.MAC) / $($p.GUID)" 'WARN'
            $results += [pscustomobject]@{
                Target = $targetText
                Adapter = ''
                GUID = $p.GUID
                State = $p.State
                Status = 'NotFound'
            }
            continue
        }

        $ok = Lock-Adapter -Guid $adapter.InterfaceGuid -Name $adapter.Name -Preview:($Preview -or $script:IsDryRun)
        $status = if ($Preview -or $script:IsDryRun) {
            'DryRun'
        } elseif ($ok) {
            'Applied'
        } else {
            'Failed'
        }
        if ($status -eq 'Applied') {
            Write-AppLog "Policy enforced: $($adapter.Name)" 'OK'
        } elseif ($status -eq 'Failed') {
            Write-AppLog "Policy enforcement failed: $($adapter.Name)" 'ERROR'
        }

        $results += [pscustomobject]@{
            Target = $targetText
            Adapter = $adapter.Name
            GUID = $adapter.InterfaceGuid
            State = $p.State
            Status = $status
        }
    }
    Write-AppLog (Get-LockPolicySummary -Results $results) 'INFO'
    return $results
}

function Install-EnforcementTask {
    param([string]$PolicyPath = '')
    $taskName = 'AdapterLock-Enforce'
    $scriptPath = $PSCommandPath
    if (-not $PolicyPath) {
        $PolicyPath = Join-Path $env:ProgramData 'AdapterLock\policy.json'
    }
    if (-not (Test-Path -LiteralPath $PolicyPath)) {
        Write-AppLog "Enforcement task not installed: policy file not found at $PolicyPath" 'ERROR'
        return $false
    }
    $policy = @(Import-LockPolicy -Path $PolicyPath)
    if ($policy.Count -eq 0) {
        Write-AppLog "Enforcement task not installed: policy file is empty or invalid at $PolicyPath" 'ERROR'
        return $false
    }

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -LoadPolicy `"$PolicyPath`" -Silent"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId SYSTEM -RunLevel Highest
    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    } catch {
        Write-AppLog "Existing task cleanup failed: $($_.Exception.Message)" 'WARN'
    }
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force -ErrorAction Stop | Out-Null
    Write-AppLog "Enforcement task installed: $taskName (runs at startup with $($policy.Count) policy target(s))" 'OK'
    Write-EvtLog "Enforcement task installed on $env:COMPUTERNAME"
    return $true
}

function Uninstall-EnforcementTask {
    $taskName = 'AdapterLock-Enforce'
    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
        Write-AppLog "Enforcement task removed: $taskName" 'OK'
        Write-EvtLog "Enforcement task removed on $env:COMPUTERNAME"
    } catch {
        Write-AppLog "Task removal failed: $($_.Exception.Message)" 'WARN'
    }
}


function Get-WmiWatcherDefinition {
    return @(
        [pscustomobject]@{
            Name = 'AdapterLock_RegistryFilter_Tcpip'
            Label = 'Tcpip'
            RootPath = 'SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces'
        }
        [pscustomobject]@{
            Name = 'AdapterLock_RegistryFilter_Tcpip6'
            Label = 'Tcpip6'
            RootPath = 'SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces'
        }
        [pscustomobject]@{
            Name = 'AdapterLock_RegistryFilter_NetBT'
            Label = 'NetBT'
            RootPath = 'SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces'
        }
    )
}

function Get-WmiWatcherFilterName {
    $names = @('AdapterLock_RegistryFilter')
    $names += @(Get-WmiWatcherDefinition | Select-Object -ExpandProperty Name)
    return $names
}

function Install-WmiWatcher {
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '', Justification='Permanent WMI event subscriptions require these legacy subscription classes on Windows PowerShell 5.1.')]
    param()

    $wmiNs = 'root\subscription'
    $consumerName = 'AdapterLock_LogConsumer'
    $definitions = @(Get-WmiWatcherDefinition)

    foreach ($filterName in (Get-WmiWatcherFilterName)) {
        try {
            Get-WmiObject -Namespace $wmiNs -Class __FilterToConsumerBinding -Filter "Filter = ""__EventFilter.Name='$filterName'""" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
        } catch {
            Write-AppLog "Existing WMI binding cleanup skipped for $filterName`: $($_.Exception.Message)" 'INFO'
        }
        try {
            Get-WmiObject -Namespace $wmiNs -Class __EventFilter -Filter "Name='$filterName'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
        } catch {
            Write-AppLog "Existing WMI filter cleanup skipped for $filterName`: $($_.Exception.Message)" 'INFO'
        }
    }

    try {
        Get-WmiObject -Namespace $wmiNs -Class NTEventLogEventConsumer -Filter "Name='$consumerName'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
    } catch {
        Write-AppLog "Existing WMI consumer cleanup skipped: $($_.Exception.Message)" 'INFO'
    }

    $consumer = Set-WmiInstance -Namespace $wmiNs -Class NTEventLogEventConsumer -Arguments @{
        Name = $consumerName
        SourceName = 'AdapterLock'
        EventID = [uint32]1002
        EventType = [uint32]2
        Category = [uint16]0
        NumberOfInsertionStrings = [uint32]1
        InsertionStringTemplates = @('AdapterLock drift: registry tree change detected on %RootPath%')
    } -ErrorAction Stop

    foreach ($definition in $definitions) {
        $wql = "SELECT * FROM RegistryTreeChangeEvent WHERE Hive='HKEY_LOCAL_MACHINE' AND RootPath='$($definition.RootPath)'"
        $filter = Set-WmiInstance -Namespace $wmiNs -Class __EventFilter -Arguments @{
            Name = $definition.Name
            EventNamespace = 'root\default'
            QueryLanguage = 'WQL'
            Query = $wql
        } -ErrorAction Stop

        Set-WmiInstance -Namespace $wmiNs -Class __FilterToConsumerBinding -Arguments @{
            Filter = $filter
            Consumer = $consumer
        } -ErrorAction Stop | Out-Null
    }

    Write-AppLog "WMI watcher installed: $($definitions.Count) registry tree filters -> $consumerName (EventId 1002)" 'OK'
    Write-EvtLog "WMI drift watcher installed on $env:COMPUTERNAME"
}

function Uninstall-WmiWatcher {
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '', Justification='Permanent WMI event subscriptions require these legacy subscription classes on Windows PowerShell 5.1.')]
    param()

    $wmiNs = 'root\subscription'
    $consumerName = 'AdapterLock_LogConsumer'
    $removed = 0

    foreach ($filterName in (Get-WmiWatcherFilterName)) {
        try {
            Get-WmiObject -Namespace $wmiNs -Class __FilterToConsumerBinding -Filter "Filter = ""__EventFilter.Name='$filterName'""" -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
            $removed++
        } catch {
            Write-AppLog "WMI binding removal skipped for $filterName`: $($_.Exception.Message)" 'INFO'
        }
        try {
            Get-WmiObject -Namespace $wmiNs -Class __EventFilter -Filter "Name='$filterName'" -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
            $removed++
        } catch {
            Write-AppLog "WMI filter removal skipped for $filterName`: $($_.Exception.Message)" 'INFO'
        }
    }
    try {
        Get-WmiObject -Namespace $wmiNs -Class NTEventLogEventConsumer -Filter "Name='$consumerName'" -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
        $removed++
    } catch {
        Write-AppLog "WMI consumer removal skipped: $($_.Exception.Message)" 'INFO'
    }

    if ($removed -gt 0) {
        Write-AppLog "WMI watcher removed ($removed component(s))" 'OK'
        Write-EvtLog "WMI drift watcher removed from $env:COMPUTERNAME"
    } else {
        Write-AppLog 'No WMI watcher components found' 'INFO'
    }
}

function Get-InterfaceKeyPath {
    param([string]$Guid)
    return @(
        "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid"
        "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$Guid"
        "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$Guid"
    )
}

function Get-AdapterDhcpState {
    param([string]$Guid)
    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid"
    if (-not (Test-Path -LiteralPath $path)) {
        return [pscustomobject]@{
            Mode = 'Unknown'
            IsDhcp = $false
            Detail = 'IPv4 interface registry key not found'
        }
    }
    try {
        $value = Get-ItemPropertyValue -LiteralPath $path -Name EnableDHCP -ErrorAction Stop
        if ([int]$value -eq 1) {
            return [pscustomobject]@{
                Mode = 'DHCP'
                IsDhcp = $true
                Detail = 'EnableDHCP=1'
            }
        }
        return [pscustomobject]@{
            Mode = 'Static'
            IsDhcp = $false
            Detail = 'EnableDHCP=0'
        }
    } catch {
        return [pscustomobject]@{
            Mode = 'Unknown'
            IsDhcp = $false
            Detail = "EnableDHCP unreadable: $($_.Exception.Message)"
        }
    }
}

function Get-BackupKeyTag {
    param([string]$Path)
    $keyTag = ($Path -split '\\')[-1]
    if ($Path -like '*\Tcpip6\Parameters\Interfaces\*') { return "Tcpip6.$keyTag" }
    if ($Path -like '*\NetBT\Parameters\Interfaces\*') { return "NetBT.$keyTag" }
    return "Tcpip.$keyTag"
}

function Save-AdapterSddl {
    param([string]$Guid, [string]$Name)
    $ts       = Get-Date -Format 'yyyyMMdd-HHmmss'
    $safeGuid = $Guid -replace '[{}]', ''
    foreach ($p in (Get-InterfaceKeyPath -Guid $Guid)) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        try {
            $sddl    = (Get-Acl -LiteralPath $p -ErrorAction Stop).Sddl
            $keyTag  = Get-BackupKeyTag -Path $p
            $outFile = Join-Path $script:BackupDir "$safeGuid.$keyTag.$ts.sddl"
            Set-Content -LiteralPath $outFile -Value $sddl -Encoding UTF8 -ErrorAction Stop
        } catch {
            Write-AppLog "SDDL backup failed for $p : $($_.Exception.Message)" 'WARN'
        }
    }
    Write-AppLog "SDDL snapshot saved: $Name ($Guid)" 'INFO'
}

function ConvertFrom-AdapterBackupFile {
    param([System.IO.FileInfo]$File)
    if (-not $File -or $File.Extension -ne '.sddl') { return $null }

    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($File.Name)
    $parts = $baseName -split '\.'
    if ($parts.Count -lt 3) { return $null }

    $safeGuid = $parts[0]
    $timestamp = $parts[$parts.Count - 1]
    $keyTag = ($parts[1..($parts.Count - 2)] -join '.')
    $stack = if ($keyTag -like 'Tcpip6.*') {
        'Tcpip6'
    } elseif ($keyTag -like 'NetBT.*') {
        'NetBT'
    } else {
        'Tcpip'
    }

    return [pscustomobject]@{
        Guid = "{$safeGuid}"
        SafeGuid = $safeGuid
        Stack = $stack
        KeyTag = $keyTag
        Timestamp = $timestamp
        LastWriteTime = $File.LastWriteTime
        FileName = $File.Name
        Path = $File.FullName
        Length = $File.Length
    }
}

function Resolve-BackupFile {
    param([string]$Path)
    if (-not $Path) { return $null }
    $candidate = if ([System.IO.Path]::IsPathRooted($Path)) {
        $Path
    } else {
        Join-Path $script:BackupDir $Path
    }
    try {
        return Get-Item -LiteralPath $candidate -ErrorAction Stop
    } catch {
        Write-AppLog "Backup file not found: $Path" 'ERROR'
        return $null
    }
}

function Get-AdapterBackupRecord {
    param(
        [string]$Guid = '',
        [string]$BackupFile = ''
    )

    if ($BackupFile) {
        $file = Resolve-BackupFile -Path $BackupFile
        if (-not $file) { return @() }
        $record = ConvertFrom-AdapterBackupFile -File $file
        if ($record) { return @($record) }
        Write-AppLog "Backup file has an unrecognized name: $($file.Name)" 'ERROR'
        return @()
    }

    $filter = '*.sddl'
    if ($Guid) {
        $safeGuid = $Guid -replace '[{}]', ''
        $filter = "$safeGuid.*.sddl"
    }
    $records = @()
    Get-ChildItem -LiteralPath $script:BackupDir -Filter $filter -File -ErrorAction SilentlyContinue | ForEach-Object {
        $record = ConvertFrom-AdapterBackupFile -File $_
        if ($record) { $records += $record }
    }
    return $records | Sort-Object Guid, Stack, LastWriteTime -Descending
}

function Get-BackupRestorePath {
    param(
        [string]$Guid,
        $Backup
    )
    switch ($Backup.Stack) {
        'Tcpip6' { return "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$Guid" }
        'NetBT'  { return "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$Guid" }
        default  { return "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid" }
    }
}

function Invoke-SddlRestore {
    param(
        [string]$RegistryPath,
        [string]$BackupPath
    )
    if (-not (Test-Path -LiteralPath $RegistryPath)) {
        Write-AppLog "Restore skipped missing key: $RegistryPath" 'WARN'
        return $false
    }
    try {
        $sddl = (Get-Content -LiteralPath $BackupPath -Raw -ErrorAction Stop).Trim()
        $acl = Get-Acl -LiteralPath $RegistryPath -ErrorAction Stop
        $acl.SetSecurityDescriptorSddlForm($sddl)
        Set-Acl -LiteralPath $RegistryPath -AclObject $acl -ErrorAction Stop
        Write-AppLog "Restored SDDL for $RegistryPath from $(Split-Path $BackupPath -Leaf)" 'OK'
        return $true
    } catch {
        Write-AppLog "SDDL restore failed for $RegistryPath : $($_.Exception.Message)" 'ERROR'
        return $false
    }
}

function Restore-AdapterSddl {
    param([string]$Guid, [string]$Name = '', [string]$BackupFile = '')
    $safeGuid = $Guid -replace '[{}]', ''
    $displayName = if ($Name) { $Name } else { $Guid }
    $restored = 0

    if ($BackupFile) {
        $backup = @(Get-AdapterBackupRecord -BackupFile $BackupFile | Select-Object -First 1)
        if ($backup.Count -eq 0) {
            Write-AppLog "No SDDL backup restored for $displayName ($Guid): exact backup not found" 'ERROR'
            return $false
        }
        if ($backup[0].SafeGuid -and $backup[0].SafeGuid -ne $safeGuid) {
            Write-AppLog "Backup GUID mismatch: $($backup[0].Guid) does not match $Guid" 'ERROR'
            return $false
        }
        $targetPath = Get-BackupRestorePath -Guid $Guid -Backup $backup[0]
        if (Invoke-SddlRestore -RegistryPath $targetPath -BackupPath $backup[0].Path) {
            $restored = 1
        }
        if ($restored -gt 0) {
            Write-AppLog "RESTORED $displayName ($Guid) from exact backup $($backup[0].FileName)" 'OK'
            Write-EvtLog "RESTORED adapter ACL exact backup: $displayName ($Guid) on $env:COMPUTERNAME by $env:USERNAME"
            return $true
        }
        Write-AppLog "No SDDL backups restored for $displayName ($Guid)" 'ERROR'
        return $false
    }

    foreach ($p in (Get-InterfaceKeyPath -Guid $Guid)) {
        $keyTag = Get-BackupKeyTag -Path $p
        $legacyKeyTag = ($p -split '\\')[-1]
        $backup = Get-ChildItem -LiteralPath $script:BackupDir -Filter "$safeGuid.$keyTag.*.sddl" -File -ErrorAction SilentlyContinue |
                  Sort-Object LastWriteTime -Descending |
                  Select-Object -First 1

        if (-not $backup) {
            $backup = Get-ChildItem -LiteralPath $script:BackupDir -Filter "$safeGuid.$legacyKeyTag.*.sddl" -File -ErrorAction SilentlyContinue |
                      Sort-Object LastWriteTime -Descending |
                      Select-Object -First 1
        }

        if (-not $backup) {
            Write-AppLog "No SDDL backup found for $p" 'WARN'
            continue
        }

        if (Invoke-SddlRestore -RegistryPath $p -BackupPath $backup.FullName) {
            $restored++
        }
    }

    if ($restored -gt 0) {
        Write-AppLog "RESTORED $displayName ($Guid) - $restored key(s) restored from backup" 'OK'
        Write-EvtLog "RESTORED adapter ACL backup: $displayName ($Guid) on $env:COMPUTERNAME by $env:USERNAME"
        return $true
    }
    Write-AppLog "No SDDL backups restored for $displayName ($Guid)" 'ERROR'
    return $false
}

function Get-AdapterLockState {
    param([string]$Guid)

    $stackDefinitions = @(
        [pscustomobject]@{
            Name = 'IPv4'
            Key = 'V4'
            Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid"
            Required = $true
        }
        [pscustomobject]@{
            Name = 'IPv6'
            Key = 'V6'
            Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$Guid"
            Required = $false
        }
        [pscustomobject]@{
            Name = 'NetBT'
            Key = 'NetBT'
            Path = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$Guid"
            Required = $false
        }
    )

    $isDeny = {
        param([string]$Path)
        try {
            $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
            return [bool]($acl.Access | Where-Object {
                $_.AccessControlType -eq 'Deny' -and
                $_.IdentityReference.Value -match 'Authenticated Users|Everyone|BUILTIN\\Users'
            })
        } catch { return $false }
    }

    $stacks = foreach ($definition in $stackDefinitions) {
        $exists = [bool](Test-Path -LiteralPath $definition.Path -ErrorAction SilentlyContinue)
        $locked = if ($exists) { [bool](& $isDeny $definition.Path) } else { $false }
        [pscustomobject]@{
            Name = $definition.Name
            Key = $definition.Key
            Path = $definition.Path
            Required = $definition.Required
            Exists = $exists
            Locked = $locked
        }
    }

    $v4 = $stacks | Where-Object { $_.Key -eq 'V4' } | Select-Object -First 1
    $v6 = $stacks | Where-Object { $_.Key -eq 'V6' } | Select-Object -First 1
    $netBt = $stacks | Where-Object { $_.Key -eq 'NetBT' } | Select-Object -First 1
    $hasAnyLock = [bool]($stacks | Where-Object { $_.Locked } | Select-Object -First 1)
    $fullyLocked = [bool]$v4.Locked -and ([bool]$v6.Locked -or -not [bool]$v6.Exists) -and ([bool]$netBt.Locked -or -not [bool]$netBt.Exists)
    $badge = if ($fullyLocked) { 'LOCKED' } elseif ($hasAnyLock) { 'PARTIAL' } else { 'Unlocked' }

    $lockedParts = New-Object System.Collections.Generic.List[string]
    $openParts = New-Object System.Collections.Generic.List[string]
    foreach ($stack in $stacks) {
        if ($stack.Locked) {
            $lockedParts.Add($stack.Name)
        } elseif ($stack.Exists -or $stack.Required) {
            $openParts.Add($stack.Name)
        }
    }
    $detailText = if ($lockedParts.Count -eq 0) {
        'No AdapterLock deny ACEs'
    } else {
        $text = "Locked: $($lockedParts -join ' + ')"
        if ($openParts.Count -gt 0) {
            $text += "; Open: $($openParts -join ' + ')"
        }
        $text
    }

    return [pscustomobject]@{
        GUID = $Guid
        LockBadge = $badge
        LockDetail = $detailText
        IsFullyLocked = $fullyLocked
        IsPartial = ($badge -eq 'PARTIAL')
        HasAnyLock = $hasAnyLock
        Stacks = @($stacks)
        V4Locked = [bool]$v4.Locked
        V4Exists = [bool]$v4.Exists
        V6Locked = [bool]$v6.Locked
        V6Exists = [bool]$v6.Exists
        NetBTLocked = [bool]$netBt.Locked
        NetBTExists = [bool]$netBt.Exists
    }
}

function Test-AdapterLockedDetailed {
    param([string]$Guid)
    return Get-AdapterLockState -Guid $Guid
}

function Get-LockBadgeFromDetail {
    param($Detail)
    if ($Detail.PSObject.Properties['LockBadge']) { return $Detail.LockBadge }
    $v4Ready = [bool]$Detail.V4Locked
    $v6Ready = [bool]$Detail.V6Locked -or -not [bool]$Detail.V6Exists
    $netBtReady = [bool]$Detail.NetBTLocked -or -not [bool]$Detail.NetBTExists
    if ($v4Ready -and $v6Ready -and $netBtReady) { return 'LOCKED' }
    if ($Detail.V4Locked -or $Detail.V6Locked -or $Detail.NetBTLocked) { return 'PARTIAL' }
    return 'Unlocked'
}

function Get-LockDetailText {
    param($Detail)
    if ($Detail.PSObject.Properties['LockDetail']) { return $Detail.LockDetail }
    $locked = New-Object System.Collections.Generic.List[string]
    $open = New-Object System.Collections.Generic.List[string]

    if ($Detail.V4Locked) { $locked.Add('IPv4') }
    else { $open.Add('IPv4') }

    if ($Detail.V6Locked) { $locked.Add('IPv6') }
    elseif ($Detail.V6Exists) { $open.Add('IPv6') }

    if ($Detail.NetBTLocked) { $locked.Add('NetBT') }
    elseif ($Detail.NetBTExists) { $open.Add('NetBT') }

    if ($locked.Count -eq 0) { return 'No AdapterLock deny ACEs' }

    $detailText = "Locked: $($locked -join ' + ')"
    if ($open.Count -gt 0) {
        $detailText += "; Open: $($open -join ' + ')"
    }
    return $detailText
}

function Test-AdapterLocked {
    param([string]$Guid)
    $d = Test-AdapterLockedDetailed -Guid $Guid
    if ($d.PSObject.Properties['HasAnyLock']) { return [bool]$d.HasAnyLock }
    return ($d.V4Locked -or $d.V6Locked -or $d.NetBTLocked)
}

function Lock-Adapter {
    param([string]$Guid, [string]$Name, [switch]$Preview)
    $paths = Get-InterfaceKeyPath -Guid $Guid
    $dhcpState = Get-AdapterDhcpState -Guid $Guid
    if ($dhcpState.IsDhcp) {
        Write-AppLog "DHCP warning: $Name ($Guid) has EnableDHCP=1; locking can block DHCP lease registry updates." 'WARN'
    }

    if ($Preview -or $script:IsDryRun) {
        if ($WhatIfPreference) {
            [void](Test-ShouldProcessChange -Target "$Name ($Guid)" -Action 'Apply AdapterLock deny ACEs')
        }
        Write-AppLog "DRY-RUN Lock $Name ($Guid) - Deny ACE would be applied to:" 'INFO'
        foreach ($p in $paths) {
            Write-AppLog ("  {0} [exists={1}]" -f $p, (Test-Path -LiteralPath $p)) 'INFO'
        }
        return $true
    }

    if (-not (Test-ShouldProcessChange -Target "$Name ($Guid)" -Action 'Apply AdapterLock deny ACEs')) {
        Write-AppLog "Skipped lock for $Name ($Guid) by ShouldProcess" 'INFO'
        return $true
    }

    Save-AdapterSddl -Guid $Guid -Name $Name
    $changed = 0
    foreach ($p in $paths) {
        if (-not (Test-Path -LiteralPath $p)) {
            Write-AppLog "Skip missing key: $p" 'WARN'
            continue
        }
        try {
            $acl    = Get-Acl -LiteralPath $p
            $sid    = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-11')
            $rights = [System.Security.AccessControl.RegistryRights]'SetValue, CreateSubKey, Delete, WriteKey'
            $rule   = New-Object System.Security.AccessControl.RegistryAccessRule(
                $sid, $rights, 'ContainerInherit', 'None', 'Deny'
            )
            $acl.AddAccessRule($rule)
            Set-Acl -LiteralPath $p -AclObject $acl
            $changed++
        } catch {
            Write-AppLog "Lock failed on $p : $($_.Exception.Message)" 'ERROR'
        }
    }
    if ($changed -gt 0) {
        Write-AppLog "LOCKED $Name ($Guid) - $changed key(s) ACL'd" 'OK'
        Write-EvtLog "LOCKED adapter: $Name ($Guid) on $env:COMPUTERNAME by $env:USERNAME"
        return $true
    }
    return $false
}

function Unlock-Adapter {
    param([string]$Guid, [string]$Name, [switch]$Preview)
    $paths = Get-InterfaceKeyPath -Guid $Guid

    if ($Preview -or $script:IsDryRun) {
        if ($WhatIfPreference) {
            [void](Test-ShouldProcessChange -Target "$Name ($Guid)" -Action 'Remove AdapterLock deny ACEs')
        }
        Write-AppLog "DRY-RUN Unlock $Name ($Guid) - Deny ACEs would be removed from:" 'INFO'
        foreach ($p in $paths) {
            Write-AppLog ("  {0} [exists={1}]" -f $p, (Test-Path -LiteralPath $p)) 'INFO'
        }
        return $true
    }

    if (-not (Test-ShouldProcessChange -Target "$Name ($Guid)" -Action 'Remove AdapterLock deny ACEs')) {
        Write-AppLog "Skipped unlock for $Name ($Guid) by ShouldProcess" 'INFO'
        return $true
    }

    Save-AdapterSddl -Guid $Guid -Name $Name
    $changed = 0
    foreach ($p in $paths) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        try {
            $acl      = Get-Acl -LiteralPath $p
            $toRemove = @($acl.Access | Where-Object {
                $_.AccessControlType -eq 'Deny' -and
                $_.IdentityReference.Value -match 'Authenticated Users|Everyone|BUILTIN\\Users'
            })
            if ($toRemove.Count -eq 0) { continue }
            foreach ($r in $toRemove) { [void]$acl.RemoveAccessRule($r) }
            Set-Acl -LiteralPath $p -AclObject $acl
            $changed++
        } catch {
            Write-AppLog "Unlock failed on $p : $($_.Exception.Message)" 'ERROR'
        }
    }
    if ($changed -gt 0) {
        Write-AppLog "UNLOCKED $Name ($Guid) - $changed key(s) restored" 'OK'
        Write-EvtLog "UNLOCKED adapter: $Name ($Guid) on $env:COMPUTERNAME by $env:USERNAME"
        return $true
    }
    Write-AppLog "$Name was not locked" 'INFO'
    return $false
}

function Test-LockIntegrity {
    param([switch]$Fix)
    $policyPath = Join-Path $env:ProgramData 'AdapterLock\policy.json'
    if (-not (Test-Path -LiteralPath $policyPath)) {
        Write-AppLog 'No policy file found; verifying all currently-locked adapters' 'INFO'
        $targets = @()
        try {
            $adapters = Get-NetAdapter -IncludeHidden:$false -ErrorAction Stop
        } catch {
            Write-AppLog "Get-NetAdapter failed: $($_.Exception.Message)" 'ERROR'
            return @()
        }
        foreach ($a in $adapters) {
            if (Test-AdapterLocked -Guid $a.InterfaceGuid) {
                $targets += [pscustomobject]@{ Name = $a.Name; GUID = $a.InterfaceGuid }
            }
        }
    } else {
        $targets = @(Import-LockPolicy -Path $policyPath)
        if ($targets.Count -eq 0) {
            Write-AppLog 'Policy file is empty or invalid' 'WARN'
            return @()
        }
    }

    $results = @()
    foreach ($t in $targets) {
        if ($t.State -eq 'partial') {
            $targetName = if ($t.Name) { $t.Name } else { $t.GUID }
            Write-AppLog "Skipping partial policy target during integrity check: $targetName" 'WARN'
            continue
        }
        $adapter = Find-AdapterByIdentifier -ByName $t.Name -ByMac $t.MAC -ByGuid $t.GUID
        if (-not $adapter) {
            $targetName = if ($t.Name) { $t.Name } elseif ($t.MAC) { $t.MAC } else { $t.GUID }
            Write-AppLog "Policy target not found during integrity check: $targetName" 'WARN'
            $results += [pscustomobject]@{
                Adapter        = $targetName
                GUID           = $t.GUID
                Status         = 'DRIFT'
                OriginalStatus = 'DRIFT'
                Remediated     = $false
                V4             = $false
                V6             = $false
                NetBT          = $false
                Detail         = 'Policy target not found'
            }
            continue
        }
        $guid = $adapter.InterfaceGuid
        $name = $adapter.Name
        $detail = Test-AdapterLockedDetailed -Guid $guid
        $actual = (Get-LockBadgeFromDetail -Detail $detail) -eq 'LOCKED'
        $status = if ($actual) { 'OK' } else { 'DRIFT' }
        $originalStatus = $status
        $remediated = $false

        if ($status -eq 'DRIFT') {
            Write-AppLog "DRIFT detected: $name ($guid) - V4=$($detail.V4Locked) V6=$($detail.V6Locked) NetBT=$($detail.NetBTLocked)" 'WARN'
            Write-EvtLog "Lock drift detected: $name ($guid) on $env:COMPUTERNAME" 'Warning'
            if ($Fix) {
                Write-AppLog "Remediating drift for $name ($guid)" 'INFO'
                $remediated = [bool](Lock-Adapter -Guid $guid -Name $name)
                $detail = Test-AdapterLockedDetailed -Guid $guid
                $actual = (Get-LockBadgeFromDetail -Detail $detail) -eq 'LOCKED'
                $status = if ($actual) { 'OK' } else { 'DRIFT' }
                if ($status -eq 'OK') {
                    Write-AppLog "Remediation verified: $name ($guid) is locked" 'OK'
                } else {
                    Write-AppLog "Remediation incomplete: $name ($guid) still has drift" 'ERROR'
                }
            }
        } else {
            Write-AppLog "OK: $name ($guid) - all applicable locks intact" 'INFO'
        }

        $results += [pscustomobject]@{
            Adapter        = $name
            GUID           = $guid
            Status         = $status
            OriginalStatus = $originalStatus
            Remediated     = $remediated
            V4             = $detail.V4Locked
            V6             = $detail.V6Locked
            NetBT          = $detail.NetBTLocked
            Detail         = Get-LockDetailText -Detail $detail
        }
    }
    return $results
}

function Invoke-RemoteLockQuery {
    param([string[]]$Targets)

    $lockStateFunction = ${function:Get-AdapterLockState}.ToString()
    $queryBlock = {
        param([string]$LockStateFunction)
        . ([scriptblock]::Create("function Get-AdapterLockState {`n$LockStateFunction`n}"))

        $results = @()
        try {
            $adapters = Get-NetAdapter -IncludeHidden:$false -ErrorAction Stop
        } catch {
            return @([pscustomobject]@{
                Computer = $env:COMPUTERNAME
                Adapter  = 'ERROR'
                GUID     = ''
                Locked   = $false
                Detail   = $_.Exception.Message
                Mode     = ''
            })
        }
        foreach ($a in $adapters) {
            $guid = $a.InterfaceGuid
            $v4 = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid"
            $lockState = Get-AdapterLockState -Guid $guid

            $mode = 'Unknown'
            try {
                $dhcp = Get-ItemPropertyValue -LiteralPath $v4 -Name EnableDHCP -ErrorAction Stop
                $mode = if ([int]$dhcp -eq 1) { 'DHCP' } else { 'Static' }
            } catch {
                $mode = 'Unknown'
            }

            $results += [pscustomobject]@{
                Computer = $env:COMPUTERNAME
                Adapter  = $a.Name
                GUID     = $guid
                Locked   = $lockState.LockBadge
                Detail   = $lockState.LockDetail
                Mode     = $mode
            }
        }
        return $results
    }

    Write-AppLog "Querying $($Targets.Count) remote host(s)..." 'INFO'
    $results = @()
    foreach ($target in $Targets) {
        try {
            $raw = Invoke-Command -ComputerName $target -ScriptBlock $queryBlock -ArgumentList $lockStateFunction -ErrorAction Stop
            $results += @($raw | Select-Object Computer, Adapter, GUID, Locked, Detail, Mode)
        } catch {
            Write-AppLog "Remote query failed for $target`: $($_.Exception.Message)" 'ERROR'
        }
    }
    return $results | Select-Object Computer, Adapter, GUID, Locked, Detail, Mode
}

function Select-LockOutputRecord {
    param([object[]]$Data)
    return $Data | Select-Object Computer, Adapter, GUID, Locked, Detail, Mode
}

function Export-LockData {
    param(
        [object[]]$Data,
        [ValidateSet('Table','Json','Csv')]
        [string]$Format = 'Table',
        [string]$OutputFile = ''
    )

    $records = @(Select-LockOutputRecord -Data $Data)
    switch ($Format) {
        'Json' {
            $content = $records | ConvertTo-Json -Depth 4
            if ($OutputFile) {
                Set-Content -LiteralPath $OutputFile -Value $content -Encoding UTF8 -ErrorAction Stop
                Write-AppLog "JSON output written: $OutputFile ($($records.Count) rows)" 'OK'
            } else {
                Write-Output $content
            }
        }
        'Csv' {
            if ($OutputFile) {
                $records | Export-Csv -LiteralPath $OutputFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
                Write-AppLog "CSV output written: $OutputFile ($($records.Count) rows)" 'OK'
            } else {
                $records | ConvertTo-Csv -NoTypeInformation
            }
        }
        'Table' {
            $records | Format-Table -AutoSize
        }
    }
}

function Get-DefaultOutputFile {
    param(
        [string]$Format,
        [string]$Prefix = 'adapterlock-report'
    )
    $ext = switch ($Format) {
        'Json' { 'json' }
        'Csv'  { 'csv' }
        default { 'html' }
    }
    return Join-Path (Get-Location) "$Prefix-$(Get-Date -Format 'yyyyMMdd-HHmmss').$ext"
}

function Export-LockReport {
    param([string]$OutputFile, [object[]]$Data)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $hosts = ($Data | Select-Object -ExpandProperty Computer -Unique).Count
    $locked = ($Data | Where-Object { $_.Locked -eq 'LOCKED' }).Count
    $partial = ($Data | Where-Object { $_.Locked -eq 'PARTIAL' }).Count
    $unlocked = ($Data | Where-Object { $_.Locked -eq 'Unlocked' }).Count

    $tableRows = foreach ($r in ($Data | Sort-Object Computer, Adapter)) {
        $color = switch ($r.Locked) {
            'LOCKED'   { '#f38ba8' }
            'PARTIAL'  { '#f9e2af' }
            'Unlocked' { '#a6e3a1' }
            default    { '#cdd6f4' }
        }
        $computer = ConvertTo-ReportHtml $r.Computer
        $adapter = ConvertTo-ReportHtml $r.Adapter
        $guid = ConvertTo-ReportHtml $r.GUID
        $mode = ConvertTo-ReportHtml $r.Mode
        $lockedState = ConvertTo-ReportHtml $r.Locked
        $detail = ConvertTo-ReportHtml $r.Detail
        "        <tr><td>$computer</td><td>$adapter</td><td>$guid</td><td>$mode</td><td style=`"color:$color;font-weight:bold`">$lockedState</td><td>$detail</td></tr>"
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>AdapterLock Fleet Report</title>
<style>
body{background:#1e1e2e;color:#cdd6f4;font-family:'Segoe UI',sans-serif;margin:2em}
h1{color:#cba6f7}
.summary{margin:1em 0;color:#a6adc8}
table{border-collapse:collapse;width:100%}
th{background:#11111b;color:#cba6f7;text-align:left;padding:10px 12px;border-bottom:2px solid #45475a}
td{padding:8px 12px;border-bottom:1px solid #313244}
tr:hover{background:#313244}
.footer{margin-top:2em;color:#585b70;font-size:0.85em}
</style>
</head>
<body>
<h1>AdapterLock Fleet Report</h1>
<div class="summary">Generated $ts | $hosts host(s) | $locked locked | $partial partial | $unlocked unlocked</div>
<table>
    <thead><tr><th>Host</th><th>Adapter</th><th>GUID</th><th>Mode</th><th>Lock State</th><th>Detail</th></tr></thead>
    <tbody>
$($tableRows -join "`n")
    </tbody>
</table>
<div class="footer">AdapterLock v$($script:Version)</div>
</body>
</html>
"@
    Set-Content -LiteralPath $OutputFile -Value $html -Encoding UTF8 -ErrorAction Stop
    Write-AppLog "Fleet report written: $OutputFile ($($Data.Count) rows)" 'OK'
}

function Get-AdapterRow {
    param([switch]$ShowHidden)
    $rows = New-Object System.Collections.ObjectModel.ObservableCollection[object]
    try {
        $adapters = Get-NetAdapter -IncludeHidden:$ShowHidden -ErrorAction Stop | Sort-Object ifIndex
    } catch {
        $script:LastAdapterScanError = $_.Exception.Message
        Write-AppLog "Get-NetAdapter failed: $script:LastAdapterScanError" 'ERROR'
        return $rows
    }

    $connectedGuids = @{}
    if ($ShowHidden) {
        Get-NetAdapter -IncludeHidden:$false -ErrorAction SilentlyContinue | ForEach-Object {
            $connectedGuids[$_.InterfaceGuid] = $true
        }
    }

    foreach ($a in $adapters) {
        $guid = $a.InterfaceGuid
        $isHidden = $ShowHidden -and -not $connectedGuids.ContainsKey($guid)
        $ipv4 = (Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                 Where-Object { $_.IPAddress -notlike '169.254.*' } |
                 Select-Object -First 1 -ExpandProperty IPAddress) -as [string]
        if (-not $ipv4) { $ipv4 = '-' }

        $lastChanged = Get-RegistryLastWrite -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid"
        $dhcpState = Get-AdapterDhcpState -Guid $guid
        $detail = Test-AdapterLockedDetailed -Guid $guid
        $badge = Get-LockBadgeFromDetail -Detail $detail
        $lockDetail = Get-LockDetailText -Detail $detail

        $displayName = if ($isHidden) { "$($a.Name) (hidden)" } else { $a.Name }
        $displayStatus = if ($isHidden) { 'Hidden' } else { [string]$a.Status }
        $rows.Add([pscustomobject]@{
            NicType    = Get-NicType -A $a
            NicTypeGlyph = Get-NicTypeGlyph -Type (Get-NicType -A $a)
            Name       = $displayName
            Description = $a.InterfaceDescription
            MAC        = $a.MacAddress
            IPv4       = $ipv4
            ConfigMode = $dhcpState.Mode
            ConfigDetail = $dhcpState.Detail
            IsDhcp     = $dhcpState.IsDhcp
            Status     = $displayStatus
            LastChanged = if ($lastChanged) { $lastChanged.ToString('yyyy-MM-dd HH:mm') } else { '-' }
            LockBadge  = $badge
            LockDetail = $lockDetail
            Guid       = $guid
            IsLocked   = ($badge -ne 'Unlocked')
            IsHidden   = $isHidden
        }) | Out-Null
    }
    return $rows
}

function Get-AdapterInventory {
    $records = @()
    try {
        $adapters = @(Get-NetAdapter -IncludeHidden:$true -ErrorAction Stop | Sort-Object ifIndex)
    } catch {
        Write-AppLog "Get-NetAdapter failed: $($_.Exception.Message)" 'ERROR'
        return @()
    }

    $visibleGuids = @{}
    Get-NetAdapter -IncludeHidden:$false -ErrorAction SilentlyContinue | ForEach-Object {
        $visibleGuids[$_.InterfaceGuid] = $true
    }

    foreach ($adapter in $adapters) {
        $guid = [string]$adapter.InterfaceGuid
        $hidden = -not $visibleGuids.ContainsKey($guid)
        $dhcpState = Get-AdapterDhcpState -Guid $guid
        $lockState = Get-AdapterLockState -Guid $guid
        $records += [pscustomobject]@{
            Computer = $env:COMPUTERNAME
            Name = [string]$adapter.Name
            Description = [string]$adapter.InterfaceDescription
            MAC = [string]$adapter.MacAddress
            GUID = $guid
            IfIndex = $adapter.ifIndex
            Status = [string]$adapter.Status
            Visibility = if ($hidden) { 'Hidden' } else { 'Visible' }
            Hidden = [bool]$hidden
            Mode = $dhcpState.Mode
            LockState = $lockState.LockBadge
            Detail = $lockState.LockDetail
        }
    }
    return $records
}

function Select-AdapterInventoryRecord {
    param([object[]]$Data)
    return $Data | Select-Object Computer, Name, Description, MAC, GUID, IfIndex, Status, Visibility, Hidden, Mode, LockState, Detail
}

function Export-AdapterInventoryData {
    param(
        [object[]]$Data,
        [ValidateSet('Table','Json','Csv')]
        [string]$Format = 'Table',
        [string]$OutputFile = ''
    )

    $records = @(Select-AdapterInventoryRecord -Data $Data)
    switch ($Format) {
        'Json' {
            $content = $records | ConvertTo-Json -Depth 4
            if ($OutputFile) {
                Set-Content -LiteralPath $OutputFile -Value $content -Encoding UTF8 -ErrorAction Stop
                Write-AppLog "Adapter inventory JSON written: $OutputFile ($($records.Count) rows)" 'OK'
            } else {
                Write-Output $content
            }
        }
        'Csv' {
            if ($OutputFile) {
                $records | Export-Csv -LiteralPath $OutputFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
                Write-AppLog "Adapter inventory CSV written: $OutputFile ($($records.Count) rows)" 'OK'
            } else {
                $records | ConvertTo-Csv -NoTypeInformation
            }
        }
        default {
            if ($OutputFile) {
                $records |
                    Format-Table Computer, Name, MAC, GUID, Status, Visibility, Mode, LockState -AutoSize |
                    Out-String |
                    Set-Content -LiteralPath $OutputFile -Encoding UTF8 -ErrorAction Stop
                Write-AppLog "Adapter inventory table written: $OutputFile ($($records.Count) rows)" 'OK'
            } else {
                $records | Format-Table Computer, Name, MAC, GUID, Status, Visibility, Mode, LockState -AutoSize
            }
        }
    }
}

function Get-StringDistance {
    param([string]$Left, [string]$Right)
    if ($null -eq $Left) { $Left = '' }
    if ($null -eq $Right) { $Right = '' }
    $leftLength = $Left.Length
    $rightLength = $Right.Length
    if ($leftLength -eq 0) { return $rightLength }
    if ($rightLength -eq 0) { return $leftLength }

    $matrix = New-Object 'int[,]' ($leftLength + 1), ($rightLength + 1)
    for ($i = 0; $i -le $leftLength; $i++) { $matrix[$i,0] = $i }
    for ($j = 0; $j -le $rightLength; $j++) { $matrix[0,$j] = $j }

    for ($i = 1; $i -le $leftLength; $i++) {
        for ($j = 1; $j -le $rightLength; $j++) {
            $cost = if ($Left[($i - 1)] -eq $Right[($j - 1)]) { 0 } else { 1 }
            $delete = $matrix[($i - 1),$j] + 1
            $insert = $matrix[$i,($j - 1)] + 1
            $replace = $matrix[($i - 1),($j - 1)] + $cost
            $matrix[$i,$j] = [Math]::Min([Math]::Min($delete, $insert), $replace)
        }
    }
    return $matrix[$leftLength,$rightLength]
}

function Format-AdapterCandidate {
    param($Adapter)
    return "{0} | MAC={1} | GUID={2} | Status={3}" -f $Adapter.Name, $Adapter.MacAddress, $Adapter.InterfaceGuid, $Adapter.Status
}

function Get-AdapterMatchCandidate {
    param(
        [object[]]$Adapters,
        [string]$Query,
        [int]$Max = 5
    )
    if (-not $Query) { return @($Adapters | Select-Object -First $Max) }

    $needle = $Query.ToLowerInvariant()
    $needleMac = $Query -replace '[:\-\s]', ''
    $ranked = foreach ($adapter in $Adapters) {
        $name = ([string]$adapter.Name).ToLowerInvariant()
        $description = ([string]$adapter.InterfaceDescription).ToLowerInvariant()
        $mac = ([string]$adapter.MacAddress) -replace '[:\-\s]', ''
        $guidText = ([string]$adapter.InterfaceGuid).ToLowerInvariant()
        $distance = Get-StringDistance -Left $needle -Right $name
        if ($description.Contains($needle)) { $distance = [Math]::Min($distance, 2) }
        if ($name.Contains($needle)) { $distance = [Math]::Min($distance, 1) }
        if ($needleMac -and $mac.Contains($needleMac)) { $distance = [Math]::Min($distance, 1) }
        if ($guidText.Contains($needle)) { $distance = [Math]::Min($distance, 1) }
        [pscustomobject]@{
            Adapter = $adapter
            Score = $distance
        }
    }
    return @($ranked | Sort-Object Score, @{ Expression = { $_.Adapter.Name } } | Select-Object -First $Max | ForEach-Object { $_.Adapter })
}

function Write-AdapterMatchCandidate {
    param(
        [object[]]$Adapters,
        [string]$Query
    )
    $candidates = @(Get-AdapterMatchCandidate -Adapters $Adapters -Query $Query)
    if ($candidates.Count -eq 0) { return }
    Write-AppLog 'Closest visible adapter candidates:' 'WARN'
    foreach ($candidate in $candidates) {
        Write-AppLog ("  " + (Format-AdapterCandidate -Adapter $candidate)) 'WARN'
    }
}

function Find-AdapterByIdentifier {
    param([string]$ByName, [string]$ByMac, [string]$ByGuid)
    try { $adapters = Get-NetAdapter -IncludeHidden:$false -ErrorAction Stop }
    catch {
        Write-AppLog "Get-NetAdapter failed: $($_.Exception.Message)" 'ERROR'
        return $null
    }

    if ($ByName) {
        $resolvedAdapters = @($adapters | Where-Object { $_.Name -eq $ByName })
        if ($resolvedAdapters.Count -eq 1) { return $resolvedAdapters[0] }
        if ($resolvedAdapters.Count -gt 1) {
            Write-AppLog "Adapter name '$ByName' is ambiguous. Use -Guid or -Mac to choose one adapter." 'ERROR'
            foreach ($resolvedAdapter in $resolvedAdapters) {
                Write-AppLog ("  " + (Format-AdapterCandidate -Adapter $resolvedAdapter)) 'WARN'
            }
            return $null
        }
        Write-AppLog "No visible adapter named '$ByName'." 'ERROR'
        Write-AdapterMatchCandidate -Adapters $adapters -Query $ByName
        return $null
    }

    if ($ByMac) {
        $normIn = $ByMac -replace '[:\-\s]', ''
        if (-not $normIn) {
            Write-AppLog 'MAC address is empty after normalization.' 'ERROR'
            return $null
        }
        $resolvedAdapters = @($adapters | Where-Object { (($_.MacAddress -replace '[:\-\s]', '') -ieq $normIn) })
        if ($resolvedAdapters.Count -eq 1) { return $resolvedAdapters[0] }
        if ($resolvedAdapters.Count -gt 1) {
            Write-AppLog "MAC '$ByMac' matched multiple visible adapters. Use -Guid to choose one adapter." 'ERROR'
            foreach ($resolvedAdapter in $resolvedAdapters) {
                Write-AppLog ("  " + (Format-AdapterCandidate -Adapter $resolvedAdapter)) 'WARN'
            }
            return $null
        }
        Write-AppLog "No visible adapter with MAC '$ByMac'." 'ERROR'
        Write-AdapterMatchCandidate -Adapters $adapters -Query $ByMac
        return $null
    }

    if ($ByGuid) {
        $resolvedAdapters = @($adapters | Where-Object { $_.InterfaceGuid -eq $ByGuid })
        if ($resolvedAdapters.Count -eq 1) { return $resolvedAdapters[0] }
        if ($resolvedAdapters.Count -gt 1) {
            Write-AppLog "GUID '$ByGuid' matched multiple visible adapters; refusing to choose automatically." 'ERROR'
            foreach ($resolvedAdapter in $resolvedAdapters) {
                Write-AppLog ("  " + (Format-AdapterCandidate -Adapter $resolvedAdapter)) 'WARN'
            }
            return $null
        }
        Write-AppLog "No visible adapter with GUID '$ByGuid'." 'ERROR'
        Write-AdapterMatchCandidate -Adapters $adapters -Query $ByGuid
        return $null
    }

    return $null
}
#endregion

#region CLI / silent mode
if ($script:IsCli) {
    Initialize-EventSource

    if ($InstallTask) {
        Write-AppLog "AdapterLock v$($script:Version) installing enforcement task"
        if (-not (Test-ShouldProcessChange -Target 'scheduled task AdapterLock-Enforce' -Action 'Install enforcement task')) {
            exit 0
        }
        $ok = Install-EnforcementTask -PolicyPath $PolicyFile
        if ($ok) { exit 0 } else { exit 1 }
    }
    if ($UninstallTask) {
        Write-AppLog "AdapterLock v$($script:Version) uninstalling enforcement task"
        if (-not (Test-ShouldProcessChange -Target 'scheduled task AdapterLock-Enforce' -Action 'Uninstall enforcement task')) {
            exit 0
        }
        Uninstall-EnforcementTask
        exit 0
    }
    if ($InstallWatcher) {
        Write-AppLog "AdapterLock v$($script:Version) installing WMI drift watcher"
        if (-not (Test-ShouldProcessChange -Target 'WMI AdapterLock drift watcher' -Action 'Install permanent WMI event subscriptions')) {
            exit 0
        }
        try {
            Install-WmiWatcher
            exit 0
        } catch {
            Write-AppLog "WMI watcher install failed: $($_.Exception.Message)" 'ERROR'
            exit 1
        }
    }
    if ($UninstallWatcher) {
        Write-AppLog "AdapterLock v$($script:Version) removing WMI drift watcher"
        if (-not (Test-ShouldProcessChange -Target 'WMI AdapterLock drift watcher' -Action 'Remove permanent WMI event subscriptions')) {
            exit 0
        }
        Uninstall-WmiWatcher
        exit 0
    }
    if ($ListAdapters) {
        $format = if ($OutputFormat) { $OutputFormat } else { 'Table' }
        if ($format -eq 'Html') {
            Write-AppLog 'Use -Report for Html output; -ListAdapters supports Table, Json, and Csv' 'ERROR'
            exit 2
        }
        Write-AppLog "AdapterLock v$($script:Version) listing adapters"
        $records = @(Get-AdapterInventory)
        if ($records.Count -eq 0) { exit 1 }
        Export-AdapterInventoryData -Data $records -Format $format -OutputFile $OutputFile
        exit 0
    }
    if ($ListBackups) {
        Write-AppLog "AdapterLock v$($script:Version) listing SDDL backups"
        $backups = @(Get-AdapterBackupRecord -Guid $Guid)
        if ($backups.Count -eq 0) {
            Write-AppLog 'No SDDL backups found' 'WARN'
            exit 1
        }
        $backups | Select-Object Guid, Stack, Timestamp, LastWriteTime, FileName, Path | Format-Table -AutoSize
        exit 0
    }
    if ($RestoreBackup) {
        Write-AppLog "AdapterLock v$($script:Version) restoring latest SDDL backup"
        if (-not $Guid -and $BackupFile) {
            $backupRecord = @(Get-AdapterBackupRecord -BackupFile $BackupFile | Select-Object -First 1)
            if ($backupRecord.Count -gt 0) { $Guid = $backupRecord[0].Guid }
        }
        if (-not $Guid) {
            Write-AppLog 'Specify -Guid <guid> with -RestoreBackup' 'ERROR'
            exit 2
        }
        $target = Find-AdapterByIdentifier -ByGuid $Guid
        $name = if ($target) { $target.Name } else { $Guid }
        if (-not (Test-ShouldProcessChange -Target "$name ($Guid)" -Action 'Restore adapter registry ACL backup')) {
            exit 0
        }
        $ok = Restore-AdapterSddl -Guid $Guid -Name $name -BackupFile $BackupFile
        if ($ok) { exit 0 } else { exit 1 }
    }
    if ($LoadPolicy) {
        Write-AppLog "AdapterLock v$($script:Version) loading policy: $LoadPolicy"
        $policy = Import-LockPolicy -Path $LoadPolicy
        if ($policy.Count -eq 0) { exit 1 }
        $policyResults = @(Invoke-LockPolicy -Policy $policy -Preview:$script:IsDryRun)
        $failures = @($policyResults | Where-Object { $_.Status -in @('NotFound', 'Failed') })
        if ($failures.Count -gt 0) { exit 1 }
        exit 0
    }
    if ($VerifyLocks) {
        Write-AppLog "AdapterLock v$($script:Version) verifying lock integrity"
        $results = Test-LockIntegrity -Fix:$Remediate
        $originalDrift = @($results | Where-Object { $_.OriginalStatus -eq 'DRIFT' -or ($null -eq $_.OriginalStatus -and $_.Status -eq 'DRIFT') })
        $remainingDrift = @($results | Where-Object { $_.Status -eq 'DRIFT' })
        if ($remainingDrift.Count -gt 0) {
            Write-AppLog "$($remainingDrift.Count) adapter(s) still have lock drift" 'WARN'
            exit 1
        }
        if ($Remediate -and $originalDrift.Count -gt 0) {
            Write-AppLog "Remediated and verified $($originalDrift.Count) adapter(s) with drift" 'OK'
        }
        Write-AppLog "All locks intact ($($results.Count) adapter(s) verified)" 'OK'
        exit 0
    }
    if ($Query) {
        if (-not $ComputerName -or $ComputerName.Count -eq 0) {
            Write-AppLog 'Specify -ComputerName with -Query' 'ERROR'
            exit 2
        }
        $format = if ($OutputFormat) { $OutputFormat } else { 'Table' }
        if ($format -eq 'Html') {
            Write-AppLog 'Use -Report for Html output; -Query supports Table, Json, and Csv' 'ERROR'
            exit 2
        }
        Write-AppLog "AdapterLock v$($script:Version) querying remote hosts"
        $results = Invoke-RemoteLockQuery -Targets $ComputerName
        if ($results.Count -eq 0) { exit 1 }
        Export-LockData -Data $results -Format $format -OutputFile $OutputFile
        exit 0
    }
    if ($Report) {
        if (-not $ComputerName -or $ComputerName.Count -eq 0) {
            Write-AppLog 'Specify -ComputerName with -Report' 'ERROR'
            exit 2
        }
        $format = if ($OutputFormat) { $OutputFormat } else { 'Html' }
        if ($format -eq 'Table') {
            Write-AppLog 'Use -Query for Table output; -Report supports Html, Json, and Csv' 'ERROR'
            exit 2
        }
        if (-not $OutputFile) {
            $OutputFile = Get-DefaultOutputFile -Format $format
        }
        Write-AppLog "AdapterLock v$($script:Version) generating fleet report"
        $results = Invoke-RemoteLockQuery -Targets $ComputerName
        if ($results.Count -eq 0) { exit 1 }
        if ($format -eq 'Html') {
            Export-LockReport -OutputFile $OutputFile -Data $results
        } else {
            Export-LockData -Data $results -Format $format -OutputFile $OutputFile
        }
        exit 0
    }

    Write-AppLog "AdapterLock v$($script:Version) CLI started. Lock=$($Lock.IsPresent) Unlock=$($Unlock.IsPresent) DryRun=$($script:IsDryRun)"

    if (-not ($Lock -or $Unlock)) {
        Write-AppLog 'Specify -Lock or -Unlock' 'ERROR'
        exit 2
    }
    if (-not ($Adapter -or $Mac -or $Guid)) {
        Write-AppLog 'Specify adapter with -Adapter <name>, -Mac <mac>, or -Guid <guid>' 'ERROR'
        exit 2
    }

    $target = Find-AdapterByIdentifier -ByName $Adapter -ByMac $Mac -ByGuid $Guid
    if (-not $target) {
        Write-AppLog 'No adapter found matching the specified identifier' 'ERROR'
        exit 1
    }

    Write-AppLog "Target: $($target.Name) ($($target.InterfaceGuid))"
    $ok = if ($Lock) {
        Lock-Adapter   -Guid $target.InterfaceGuid -Name $target.Name -Preview:$script:IsDryRun
    } else {
        Unlock-Adapter -Guid $target.InterfaceGuid -Name $target.Name -Preview:$script:IsDryRun
    }
    if ($ok) { exit 0 } else { exit 1 }
}
#endregion

#region XAML - Catppuccin Mocha dark theme
[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="AdapterLock" Width="1180" Height="760" MinWidth="980" MinHeight="720"
        WindowStartupLocation="CenterScreen"
        Background="#FF1E1E2E" Foreground="#FFCDD6F4"
        FontFamily="Segoe UI" FontSize="13"
        UseLayoutRounding="True" SnapsToDevicePixels="True">
    <Window.Resources>
        <SolidColorBrush x:Key="Base"     Color="#FF1E1E2E"/>
        <SolidColorBrush x:Key="Mantle"   Color="#FF181825"/>
        <SolidColorBrush x:Key="Crust"    Color="#FF11111B"/>
        <SolidColorBrush x:Key="Surface0" Color="#FF313244"/>
        <SolidColorBrush x:Key="Surface1" Color="#FF45475A"/>
        <SolidColorBrush x:Key="Surface2" Color="#FF585B70"/>
        <SolidColorBrush x:Key="Text"     Color="#FFCDD6F4"/>
        <SolidColorBrush x:Key="Subtext"  Color="#FFA6ADC8"/>
        <SolidColorBrush x:Key="Mauve"    Color="#FFCBA6F7"/>
        <SolidColorBrush x:Key="Green"    Color="#FFA6E3A1"/>
        <SolidColorBrush x:Key="Red"      Color="#FFF38BA8"/>
        <SolidColorBrush x:Key="Yellow"   Color="#FFF9E2AF"/>
        <SolidColorBrush x:Key="Blue"     Color="#FF89B4FA"/>
        <SolidColorBrush x:Key="Lavender" Color="#FFB4BEFE"/>
        <SolidColorBrush x:Key="Overlay"  Color="#FF6C7086"/>
        <SolidColorBrush x:Key="Card"     Color="#CC181825"/>
        <SolidColorBrush x:Key="SoftBlue" Color="#26374A67"/>
        <SolidColorBrush x:Key="SoftGreen" Color="#2434552E"/>
        <SolidColorBrush x:Key="SoftRed" Color="#2A5C2F3D"/>
        <SolidColorBrush x:Key="SoftYellow" Color="#2A5C512D"/>

        <Style x:Key="ControlFocusVisual">
            <Setter Property="Control.Template">
                <Setter.Value>
                    <ControlTemplate>
                        <Rectangle Stroke="{StaticResource Blue}" StrokeThickness="2"
                                   RadiusX="6" RadiusY="6" Margin="2"/>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="MetricLabel" TargetType="TextBlock">
            <Setter Property="Foreground" Value="{StaticResource Subtext}"/>
            <Setter Property="FontSize" Value="11"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
        </Style>

        <Style x:Key="MetricValue" TargetType="TextBlock">
            <Setter Property="Foreground" Value="{StaticResource Text}"/>
            <Setter Property="FontSize" Value="18"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Margin" Value="0,2,0,0"/>
        </Style>

        <Style x:Key="TrustBadge" TargetType="Border">
            <Setter Property="Background" Value="{StaticResource Crust}"/>
            <Setter Property="BorderBrush" Value="{StaticResource Surface1}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="CornerRadius" Value="6"/>
            <Setter Property="Padding" Value="9,5"/>
            <Setter Property="Margin" Value="0,8,8,0"/>
        </Style>

        <Style TargetType="Button">
            <Setter Property="Background" Value="{StaticResource Surface0}"/>
            <Setter Property="Foreground" Value="{StaticResource Text}"/>
            <Setter Property="BorderBrush" Value="{StaticResource Surface2}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="14,8"/>
            <Setter Property="MinHeight" Value="36"/>
            <Setter Property="MinWidth" Value="96"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="FocusVisualStyle" Value="{StaticResource ControlFocusVisual}"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="bd" Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="7">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"
                                              Margin="{TemplateBinding Padding}"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="bd" Property="Background" Value="#FF3A3B4D"/>
                                <Setter TargetName="bd" Property="BorderBrush" Value="{StaticResource Blue}"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="bd" Property="Background" Value="#FF45475A"/>
                            </Trigger>
                            <Trigger Property="IsKeyboardFocused" Value="True">
                                <Setter TargetName="bd" Property="BorderBrush" Value="{StaticResource Blue}"/>
                                <Setter TargetName="bd" Property="BorderThickness" Value="2"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Opacity" Value="0.45"/>
                                <Setter Property="Cursor" Value="Arrow"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="PrimaryButtonStyle" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
            <Setter Property="Background" Value="{StaticResource Mauve}"/>
            <Setter Property="Foreground" Value="{StaticResource Crust}"/>
            <Setter Property="BorderBrush" Value="{StaticResource Mauve}"/>
        </Style>

        <Style x:Key="QuietButtonStyle" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
            <Setter Property="Background" Value="{StaticResource Mantle}"/>
            <Setter Property="BorderBrush" Value="{StaticResource Surface1}"/>
        </Style>

        <Style TargetType="{x:Type DataGrid}">
            <Setter Property="Background" Value="{StaticResource Crust}"/>
            <Setter Property="Foreground" Value="{StaticResource Text}"/>
            <Setter Property="BorderBrush" Value="{StaticResource Surface1}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="GridLinesVisibility" Value="Horizontal"/>
            <Setter Property="HorizontalGridLinesBrush" Value="{StaticResource Surface0}"/>
            <Setter Property="RowBackground" Value="#FF181825"/>
            <Setter Property="AlternatingRowBackground" Value="#FF1B1B2A"/>
            <Setter Property="HeadersVisibility" Value="Column"/>
            <Setter Property="AutoGenerateColumns" Value="False"/>
            <Setter Property="CanUserAddRows" Value="False"/>
            <Setter Property="CanUserDeleteRows" Value="False"/>
            <Setter Property="IsReadOnly" Value="True"/>
            <Setter Property="SelectionMode" Value="Extended"/>
            <Setter Property="SelectionUnit" Value="FullRow"/>
            <Setter Property="RowHeaderWidth" Value="0"/>
            <Setter Property="MinRowHeight" Value="36"/>
            <Setter Property="EnableRowVirtualization" Value="True"/>
            <Setter Property="EnableColumnVirtualization" Value="True"/>
            <Setter Property="ScrollViewer.CanContentScroll" Value="True"/>
        </Style>
        <Style TargetType="{x:Type DataGridColumnHeader}">
            <Setter Property="Background" Value="{StaticResource Crust}"/>
            <Setter Property="Foreground" Value="{StaticResource Lavender}"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Padding" Value="10,9"/>
            <Setter Property="BorderBrush" Value="{StaticResource Surface1}"/>
            <Setter Property="BorderThickness" Value="0,0,1,1"/>
        </Style>
        <Style TargetType="{x:Type DataGridRow}">
            <Setter Property="Foreground" Value="{StaticResource Text}"/>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="{StaticResource Surface0}"/>
                </Trigger>
                <Trigger Property="IsSelected" Value="True">
                    <Setter Property="Background" Value="#FF34364A"/>
                    <Setter Property="Foreground" Value="{StaticResource Text}"/>
                </Trigger>
            </Style.Triggers>
        </Style>
        <Style TargetType="{x:Type DataGridCell}">
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="10,6"/>
            <Setter Property="FocusVisualStyle" Value="{StaticResource ControlFocusVisual}"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="DataGridCell">
                        <Border Background="{TemplateBinding Background}" Padding="{TemplateBinding Padding}">
                            <ContentPresenter VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="GridCellText" TargetType="TextBlock">
            <Setter Property="TextTrimming" Value="CharacterEllipsis"/>
            <Setter Property="VerticalAlignment" Value="Center"/>
        </Style>

        <Style TargetType="{x:Type TextBox}">
            <Setter Property="Background" Value="{StaticResource Crust}"/>
            <Setter Property="Foreground" Value="{StaticResource Text}"/>
            <Setter Property="BorderBrush" Value="{StaticResource Surface1}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="10,7"/>
            <Setter Property="FontFamily" Value="Consolas"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="CaretBrush" Value="{StaticResource Blue}"/>
            <Setter Property="SelectionBrush" Value="{StaticResource Surface2}"/>
            <Setter Property="FocusVisualStyle" Value="{StaticResource ControlFocusVisual}"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="{x:Type TextBox}">
                        <Border x:Name="bd" Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="7" Padding="{TemplateBinding Padding}">
                            <ScrollViewer x:Name="PART_ContentHost"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsKeyboardFocusWithin" Value="True">
                                <Setter TargetName="bd" Property="BorderBrush" Value="{StaticResource Blue}"/>
                                <Setter TargetName="bd" Property="BorderThickness" Value="2"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Opacity" Value="0.45"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style TargetType="ScrollBar">
            <Setter Property="Background" Value="{StaticResource Mantle}"/>
            <Setter Property="Foreground" Value="{StaticResource Surface2}"/>
            <Setter Property="Width" Value="10"/>
        </Style>
    </Window.Resources>

    <Grid Margin="20">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="182"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Header -->
        <Border Grid.Row="0" Background="{StaticResource Card}" BorderBrush="{StaticResource Surface1}"
                BorderThickness="1" CornerRadius="10" Padding="18,16" Margin="0,0,0,14">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <StackPanel Grid.Column="0">
                    <StackPanel Orientation="Horizontal">
                        <TextBlock Text="AdapterLock" FontSize="26" FontWeight="SemiBold" Foreground="{StaticResource Text}"/>
                        <TextBlock x:Name="VersionText" Text=" v0.8.13" FontSize="13" Foreground="{StaticResource Subtext}" VerticalAlignment="Bottom" Margin="6,0,0,5"/>
                    </StackPanel>
                    <TextBlock x:Name="HeaderDescription" Margin="0,6,24,0"
                               Text="Protect static NIC configuration with adapter-specific registry ACL enforcement. Select adapters, review state, and apply lock policies without changing unrelated interfaces."
                               Foreground="{StaticResource Subtext}" FontSize="14" TextWrapping="Wrap" MaxWidth="720"/>
                    <WrapPanel x:Name="TrustBadgePanel" Margin="0,2,0,0">
                        <Border Style="{StaticResource TrustBadge}">
                            <TextBlock Text="ACL-level enforcement" Foreground="{StaticResource Subtext}" FontSize="12"/>
                        </Border>
                        <Border Style="{StaticResource TrustBadge}">
                            <TextBlock Text="SDDL backups before writes" Foreground="{StaticResource Subtext}" FontSize="12"/>
                        </Border>
                        <Border Style="{StaticResource TrustBadge}">
                            <TextBlock Text="Event log audit trail" Foreground="{StaticResource Subtext}" FontSize="12"/>
                        </Border>
                        <Border Style="{StaticResource TrustBadge}">
                            <TextBlock Text="No reboot required" Foreground="{StaticResource Subtext}" FontSize="12"/>
                        </Border>
                    </WrapPanel>
                </StackPanel>
                <WrapPanel Grid.Column="1" HorizontalAlignment="Right" VerticalAlignment="Center" MaxWidth="430">
                    <Border Background="{StaticResource Crust}" BorderBrush="{StaticResource Surface1}" BorderThickness="1" CornerRadius="8" Padding="12,10" Margin="8,0,0,8" MinWidth="92">
                        <StackPanel>
                            <TextBlock Text="ADAPTERS" Style="{StaticResource MetricLabel}"/>
                            <TextBlock x:Name="AdapterCountText" Text="-" Style="{StaticResource MetricValue}"/>
                        </StackPanel>
                    </Border>
                    <Border Background="{StaticResource SoftGreen}" BorderBrush="#66479A45" BorderThickness="1" CornerRadius="8" Padding="12,10" Margin="8,0,0,8" MinWidth="92">
                        <StackPanel>
                            <TextBlock Text="LOCKED" Style="{StaticResource MetricLabel}"/>
                            <TextBlock x:Name="LockedCountText" Text="-" Foreground="{StaticResource Green}" FontSize="18" FontWeight="SemiBold" Margin="0,2,0,0"/>
                        </StackPanel>
                    </Border>
                    <Border Background="{StaticResource SoftYellow}" BorderBrush="#665B4F2A" BorderThickness="1" CornerRadius="8" Padding="12,10" Margin="8,0,0,8" MinWidth="92">
                        <StackPanel>
                            <TextBlock Text="PARTIAL" Style="{StaticResource MetricLabel}"/>
                            <TextBlock x:Name="PartialCountText" Text="-" Foreground="{StaticResource Yellow}" FontSize="18" FontWeight="SemiBold" Margin="0,2,0,0"/>
                        </StackPanel>
                    </Border>
                    <Border Background="{StaticResource Crust}" BorderBrush="{StaticResource Surface1}" BorderThickness="1" CornerRadius="8" Padding="12,10" Margin="8,0,0,8" MinWidth="92">
                        <StackPanel>
                            <TextBlock Text="HIDDEN" Style="{StaticResource MetricLabel}"/>
                            <TextBlock x:Name="HiddenCountText" Text="-" Style="{StaticResource MetricValue}"/>
                        </StackPanel>
                    </Border>
                </WrapPanel>
            </Grid>
        </Border>

        <!-- Search and summary -->
        <Grid Grid.Row="1" Margin="0,0,0,10">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <TextBox Grid.Column="0" x:Name="FilterBox"
                     FontFamily="Segoe UI" FontSize="13"
                     Text="Search adapters..." Foreground="{StaticResource Overlay}"
                     ToolTip="Search adapter name, description, MAC, IPv4, or GUID"
                     AutomationProperties.Name="Adapter search"/>
            <TextBlock x:Name="FilterCountText" Grid.Column="1" Text="No adapters loaded"
                       Foreground="{StaticResource Subtext}" VerticalAlignment="Center"
                       Margin="12,0,0,0"/>
        </Grid>

        <!-- Adapter grid -->
        <Grid Grid.Row="2">
            <DataGrid x:Name="AdapterGrid" AutomationProperties.Name="Network adapters">
                <DataGrid.Columns>
                    <DataGridTemplateColumn Header="Type" Width="54">
                        <DataGridTemplateColumn.CellTemplate>
                            <DataTemplate>
                                <TextBlock Text="{Binding NicTypeGlyph}" FontFamily="Segoe MDL2 Assets" FontSize="15"
                                           HorizontalAlignment="Center" VerticalAlignment="Center"
                                           ToolTip="{Binding NicType}" AutomationProperties.Name="{Binding NicType}"/>
                            </DataTemplate>
                        </DataGridTemplateColumn.CellTemplate>
                    </DataGridTemplateColumn>
                    <DataGridTextColumn Header="Name"        Binding="{Binding Name}"         Width="140" ElementStyle="{StaticResource GridCellText}"/>
                    <DataGridTextColumn Header="Description" Binding="{Binding Description}"  Width="230" ElementStyle="{StaticResource GridCellText}"/>
                    <DataGridTextColumn Header="MAC"         Binding="{Binding MAC}"          Width="138" ElementStyle="{StaticResource GridCellText}"/>
                    <DataGridTextColumn Header="IPv4"        Binding="{Binding IPv4}"         Width="124" ElementStyle="{StaticResource GridCellText}"/>
                    <DataGridTextColumn Header="Mode"        Binding="{Binding ConfigMode}"   Width="74"  ElementStyle="{StaticResource GridCellText}"/>
                    <DataGridTextColumn Header="Status"      Binding="{Binding Status}"       Width="76"  ElementStyle="{StaticResource GridCellText}"/>
                    <DataGridTextColumn Header="Changed"     Binding="{Binding LastChanged}"  Width="128" ElementStyle="{StaticResource GridCellText}"/>
                    <DataGridTemplateColumn Header="Lock" Width="116">
                        <DataGridTemplateColumn.CellTemplate>
                            <DataTemplate>
                                <Border CornerRadius="5" Padding="8,4" HorizontalAlignment="Left"
                                        BorderThickness="1" ToolTip="{Binding LockDetail}">
                                    <Border.Style>
                                        <Style TargetType="Border">
                                            <Setter Property="Background" Value="{StaticResource SoftGreen}"/>
                                            <Setter Property="BorderBrush" Value="#88479A45"/>
                                            <Style.Triggers>
                                                <DataTrigger Binding="{Binding LockBadge}" Value="LOCKED">
                                                    <Setter Property="Background" Value="{StaticResource SoftRed}"/>
                                                    <Setter Property="BorderBrush" Value="#88944655"/>
                                                </DataTrigger>
                                                <DataTrigger Binding="{Binding LockBadge}" Value="PARTIAL">
                                                    <Setter Property="Background" Value="{StaticResource SoftYellow}"/>
                                                    <Setter Property="BorderBrush" Value="#88805F20"/>
                                                </DataTrigger>
                                            </Style.Triggers>
                                        </Style>
                                    </Border.Style>
                                    <TextBlock Text="{Binding LockBadge}" FontWeight="SemiBold" FontSize="11">
                                        <TextBlock.Style>
                                            <Style TargetType="TextBlock">
                                                <Setter Property="Foreground" Value="{StaticResource Green}"/>
                                                <Style.Triggers>
                                                    <DataTrigger Binding="{Binding LockBadge}" Value="LOCKED">
                                                        <Setter Property="Foreground" Value="{StaticResource Red}"/>
                                                    </DataTrigger>
                                                    <DataTrigger Binding="{Binding LockBadge}" Value="PARTIAL">
                                                        <Setter Property="Foreground" Value="{StaticResource Yellow}"/>
                                                    </DataTrigger>
                                                </Style.Triggers>
                                            </Style>
                                        </TextBlock.Style>
                                    </TextBlock>
                                </Border>
                            </DataTemplate>
                        </DataGridTemplateColumn.CellTemplate>
                    </DataGridTemplateColumn>
                </DataGrid.Columns>
            </DataGrid>

            <Border x:Name="EmptyStatePanel" Visibility="Collapsed" Background="#F011111B"
                    BorderBrush="{StaticResource Surface1}" BorderThickness="1" CornerRadius="8">
                <StackPanel HorizontalAlignment="Center" VerticalAlignment="Center" Width="460">
                    <TextBlock x:Name="EmptyStateTitle" Text="Scanning adapters"
                               Foreground="{StaticResource Text}" FontSize="18" FontWeight="SemiBold"
                               TextAlignment="Center"/>
                    <TextBlock x:Name="EmptyStateBody" Text="AdapterLock is reading network adapter state."
                               Foreground="{StaticResource Subtext}" FontSize="13" Margin="0,8,0,0"
                               TextAlignment="Center" TextWrapping="Wrap"/>
                    <TextBlock x:Name="EmptyStateHint" Text="Status and details will appear here when the scan completes."
                               Foreground="{StaticResource Overlay}" FontSize="12" Margin="0,8,0,0"
                               TextAlignment="Center" TextWrapping="Wrap"/>
                </StackPanel>
            </Border>
        </Grid>

        <!-- Button row -->
        <Grid Grid.Row="3" Margin="0,12,0,12">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <StackPanel Grid.Column="0" Orientation="Horizontal">
                <Button x:Name="LockBtn" Content="Lock Selected" Style="{StaticResource PrimaryButtonStyle}" Margin="0,0,8,0" IsEnabled="False"
                        ToolTip="Apply AdapterLock deny ACEs to selected adapters"/>
                <Button x:Name="UnlockBtn" Content="Unlock Selected" Margin="0,0,8,0" IsEnabled="False"
                        ToolTip="Remove AdapterLock deny ACEs from selected adapters"/>
                <Button x:Name="RefreshBtn" Content="Refresh" Style="{StaticResource QuietButtonStyle}" Margin="0,0,8,0"
                        ToolTip="Rescan adapter and registry lock state"/>
            </StackPanel>
            <TextBlock x:Name="SelectionSummaryText" Grid.Column="1"
                       Text="No adapters selected."
                       Foreground="{StaticResource Subtext}" VerticalAlignment="Center"
                       Margin="4,0,12,0" TextTrimming="CharacterEllipsis"
                       Visibility="Collapsed"/>
            <WrapPanel Grid.Column="2" HorizontalAlignment="Right">
                <Button x:Name="SavePolicyBtn" Content="Export Policy" Style="{StaticResource QuietButtonStyle}" Margin="0,0,8,0"
                        ToolTip="Save current locked adapters as a JSON policy"/>
                <Button x:Name="LoadPolicyBtn" Content="Apply Policy" Style="{StaticResource QuietButtonStyle}" Margin="0,0,8,0"
                        ToolTip="Load a JSON policy and lock matching adapters"/>
                <Button x:Name="OpenNcpaBtn" Content="Connections" Style="{StaticResource QuietButtonStyle}" Margin="0,0,8,0"
                        ToolTip="Open Windows network connections"/>
                <Button x:Name="OpenLogBtn" Content="Logs" Style="{StaticResource QuietButtonStyle}" Margin="0,0,8,0"
                        ToolTip="Open the AdapterLock log folder"/>
                <Button x:Name="ReportBtn" Content="Report" Style="{StaticResource QuietButtonStyle}" Margin="0,0,8,0"
                        ToolTip="Export and open an HTML report for the currently visible adapters"/>
                <Button x:Name="ToggleHiddenBtn" Content="Show Hidden" Style="{StaticResource QuietButtonStyle}"
                        ToolTip="Show unplugged and hidden adapters"/>
            </WrapPanel>
        </Grid>

        <!-- Log -->
        <Grid Grid.Row="4">
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
            </Grid.RowDefinitions>
            <Grid Grid.Row="0" Margin="0,0,0,6">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <TextBlock Text="Activity log" Foreground="{StaticResource Text}" FontSize="13" FontWeight="SemiBold"/>
                <TextBlock Grid.Column="1" Text="Backups and registry ACL changes are logged here"
                           Foreground="{StaticResource Surface2}" FontSize="12"/>
            </Grid>
            <TextBox Grid.Row="1" x:Name="LogBox" IsReadOnly="True"
                     VerticalScrollBarVisibility="Auto"
                     HorizontalScrollBarVisibility="Auto"
                     TextWrapping="NoWrap"
                     AutomationProperties.Name="Activity log"/>
        </Grid>

        <!-- Status bar -->
        <Border Grid.Row="5" Margin="0,10,0,0" Background="{StaticResource Mantle}"
                BorderBrush="{StaticResource Surface1}" BorderThickness="1" CornerRadius="7" Padding="10,7">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <TextBlock x:Name="StatusText" Grid.Column="0" Text="Ready." Foreground="{StaticResource Subtext}" TextTrimming="CharacterEllipsis"/>
                <TextBlock x:Name="LastDriftText" Grid.Column="1" Text="No drift events recorded"
                           Foreground="{StaticResource Surface2}" FontSize="12" Margin="12,0,0,0"/>
            </Grid>
        </Border>
    </Grid>
</Window>
'@
#endregion

#region Build window
$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

$script:AdapterGrid = $window.FindName('AdapterGrid')
$script:LogBox      = $window.FindName('LogBox')
$script:StatusText  = $window.FindName('StatusText')
$script:VersionText = $window.FindName('VersionText')
$script:FilterBox   = $window.FindName('FilterBox')
$script:FilterCountText = $window.FindName('FilterCountText')
$script:HeaderDescription = $window.FindName('HeaderDescription')
$script:TrustBadgePanel = $window.FindName('TrustBadgePanel')
$script:SelectionSummaryText = $window.FindName('SelectionSummaryText')
$script:LastDriftText = $window.FindName('LastDriftText')
$script:EmptyStatePanel = $window.FindName('EmptyStatePanel')
$script:EmptyStateTitle = $window.FindName('EmptyStateTitle')
$script:EmptyStateBody = $window.FindName('EmptyStateBody')
$script:EmptyStateHint = $window.FindName('EmptyStateHint')
$script:AdapterCountText = $window.FindName('AdapterCountText')
$script:LockedCountText = $window.FindName('LockedCountText')
$script:PartialCountText = $window.FindName('PartialCountText')
$script:HiddenCountText = $window.FindName('HiddenCountText')
$script:SkipActionConfirm = $false
$script:AllRows     = $null
$script:SearchPlaceholder = 'Search adapters...'
$script:LastAdapterScanError = $null
$script:UiBusy = $false
$script:PendingStatusText = ''

$LockBtn     = $window.FindName('LockBtn')
$UnlockBtn   = $window.FindName('UnlockBtn')
$RefreshBtn  = $window.FindName('RefreshBtn')
$SavePolicyBtn = $window.FindName('SavePolicyBtn')
$LoadPolicyBtn = $window.FindName('LoadPolicyBtn')
$OpenNcpaBtn = $window.FindName('OpenNcpaBtn')
$OpenLogBtn       = $window.FindName('OpenLogBtn')
$ReportBtn        = $window.FindName('ReportBtn')
$ToggleHiddenBtn  = $window.FindName('ToggleHiddenBtn')
$script:ShowHidden = $false

$script:VersionText.Text = " v$($script:Version)"

function Get-CurrentFilterTerm {
    if (-not $script:FilterBox) { return '' }
    $text = [string]$script:FilterBox.Text
    if ($text -eq $script:SearchPlaceholder) { return '' }
    return $text.Trim()
}

function Show-EmptyState {
    param(
        [string]$Title,
        [string]$Body,
        [string]$Hint = '',
        [switch]$Visible
    )
    if (-not $script:EmptyStatePanel) { return }
    $script:EmptyStateTitle.Text = $Title
    $script:EmptyStateBody.Text = $Body
    $script:EmptyStateHint.Text = $Hint
    $script:EmptyStateHint.Visibility = if ($Hint) { 'Visible' } else { 'Collapsed' }
    $script:EmptyStatePanel.Visibility = if ($Visible) { 'Visible' } else { 'Collapsed' }
}

function Get-LastDriftSummary {
    param([int]$PartialCount = 0)
    if ($PartialCount -gt 0) {
        return "Partial locks visible: $PartialCount"
    }
    try {
        if (Test-Path -LiteralPath $script:LogPath) {
            $line = Get-Content -LiteralPath $script:LogPath -Tail 200 -ErrorAction Stop |
                Where-Object { $_ -match 'DRIFT|drift' } |
                Select-Object -Last 1
            if ($line) {
                $message = ($line -replace '^\[[^\]]+\]\s+\[[^\]]+\]\s+', '').Trim()
                if ($message.Length -gt 72) { $message = $message.Substring(0, 69) + '...' }
                return "Last drift: $message"
            }
        }
    } catch {
        return 'Last drift: unavailable'
    }
    return 'No drift events recorded'
}

function ConvertTo-LocalReportRecord {
    param([object[]]$Rows)
    foreach ($row in @($Rows)) {
        [pscustomobject]@{
            Computer = $env:COMPUTERNAME
            Adapter = $row.Name
            GUID = $row.Guid
            Locked = $row.LockBadge
            Detail = $row.LockDetail
            Mode = $row.ConfigMode
        }
    }
}

function Show-SummaryState {
    $rows = @($script:AllRows)
    $locked = @($rows | Where-Object { $_.LockBadge -eq 'LOCKED' }).Count
    $partial = @($rows | Where-Object { $_.LockBadge -eq 'PARTIAL' }).Count
    $hidden = @($rows | Where-Object { $_.IsHidden }).Count
    $script:AdapterCountText.Text = [string]$rows.Count
    $script:LockedCountText.Text = [string]$locked
    $script:PartialCountText.Text = [string]$partial
    $script:HiddenCountText.Text = [string]$hidden
    if ($script:LastDriftText) {
        $script:LastDriftText.Text = Get-LastDriftSummary -PartialCount $partial
    }
}

function Show-SelectionState {
    if (-not $script:AdapterGrid) { return }
    if ($script:SelectionSummaryText) {
        $script:SelectionSummaryText.Visibility = if ($script:IsCompactMode) { 'Visible' } else { 'Collapsed' }
    }
    if ($script:UiBusy) {
        $LockBtn.IsEnabled = $false
        $UnlockBtn.IsEnabled = $false
        if ($script:SelectionSummaryText) { $script:SelectionSummaryText.Text = 'Working...' }
        return
    }
    $count = @($script:AdapterGrid.SelectedItems).Count
    $hasSelection = $count -gt 0
    $LockBtn.IsEnabled = $hasSelection -and -not $script:IsCompactMode
    $UnlockBtn.IsEnabled = $hasSelection -and -not $script:IsCompactMode
    if ($hasSelection) {
        if ($count -eq 1) {
            $row = $script:AdapterGrid.SelectedItem
            $script:SelectionSummaryText.Text = "$($row.Name): $($row.LockBadge)"
            $script:SelectionSummaryText.ToolTip = $row.LockDetail
        } else {
            $script:SelectionSummaryText.Text = "$count selected."
            $script:SelectionSummaryText.ToolTip = ''
        }
    } else {
        $script:SelectionSummaryText.Text = if ($script:IsCompactMode) {
            'Read-only status mode. Select an adapter to inspect lock details.'
        } else {
            'No adapters selected.'
        }
        $script:SelectionSummaryText.ToolTip = ''
    }
}

# --- Context menu (built in code; avoids XAML x:Name scoping issues) ---
function Get-CMBrush {
    param([string]$Hex)
    $c = [System.Windows.Media.ColorConverter]::ConvertFromString($Hex)
    return New-Object System.Windows.Media.SolidColorBrush $c
}
function Get-CMMenuItem {
    param([string]$Header)
    $mi = New-Object System.Windows.Controls.MenuItem
    $mi.Header     = $Header
    $mi.Foreground = Get-CMBrush '#FFCDD6F4'
    $mi.Background = Get-CMBrush '#FF181825'
    $mi.Padding    = [System.Windows.Thickness]::new(12,8,18,8)
    $mi.FontSize   = 13
    $mi.MinHeight  = 34
    return $mi
}

function Show-AdapterDecisionDialog {
    param(
        [string]$Title,
        [string]$Heading,
        [string]$Body,
        [string]$Detail = '',
        [string]$ConfirmText = 'Continue',
        [ValidateSet('Default','Warning','Danger')][string]$Tone = 'Default',
        [switch]$AllowSessionSkip
    )

    $accentHex = switch ($Tone) {
        'Warning' { '#FFF9E2AF' }
        'Danger'  { '#FFF38BA8' }
        default   { '#FFCBA6F7' }
    }

    $dialog = New-Object System.Windows.Window
    $dialog.Title = $Title
    $dialog.Width = 540
    $dialog.SizeToContent = 'Height'
    $dialog.ResizeMode = 'NoResize'
    $dialog.WindowStartupLocation = 'CenterOwner'
    $dialog.Owner = $window
    $dialog.Background = Get-CMBrush '#FF1E1E2E'
    $dialog.Foreground = Get-CMBrush '#FFCDD6F4'
    $dialog.FontFamily = 'Segoe UI'
    $dialog.FontSize = 13
    $dialog.ShowInTaskbar = $false
    $dialog.Tag = $false
    [void]$dialog.Resources.MergedDictionaries.Add($window.Resources)

    $outer = New-Object System.Windows.Controls.Border
    $outer.Background = Get-CMBrush '#FF181825'
    $outer.BorderBrush = Get-CMBrush '#FF45475A'
    $outer.BorderThickness = [System.Windows.Thickness]::new(1)
    $outer.CornerRadius = [System.Windows.CornerRadius]::new(10)
    $outer.Padding = [System.Windows.Thickness]::new(18)

    $panel = New-Object System.Windows.Controls.StackPanel

    $headingRow = New-Object System.Windows.Controls.Grid
    $headingRow.Margin = [System.Windows.Thickness]::new(0,0,0,14)
    $headingRow.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{ Width = [System.Windows.GridLength]::Auto })) | Out-Null
    $headingRow.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{ Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star) })) | Out-Null

    $accent = New-Object System.Windows.Controls.Border
    $accent.Width = 4
    $accent.MinHeight = 52
    $accent.CornerRadius = [System.Windows.CornerRadius]::new(4)
    $accent.Background = Get-CMBrush $accentHex
    $accent.Margin = [System.Windows.Thickness]::new(0,0,12,0)
    [System.Windows.Controls.Grid]::SetColumn($accent, 0)
    $headingRow.Children.Add($accent) | Out-Null

    $copyStack = New-Object System.Windows.Controls.StackPanel
    [System.Windows.Controls.Grid]::SetColumn($copyStack, 1)

    $headingText = New-Object System.Windows.Controls.TextBlock
    $headingText.Text = $Heading
    $headingText.Foreground = Get-CMBrush '#FFCDD6F4'
    $headingText.FontSize = 18
    $headingText.FontWeight = 'SemiBold'
    $headingText.TextWrapping = 'Wrap'
    $copyStack.Children.Add($headingText) | Out-Null

    $text = New-Object System.Windows.Controls.TextBlock
    $text.Text = $Body
    $text.TextWrapping = 'Wrap'
    $text.Foreground = Get-CMBrush '#FFA6ADC8'
    $text.Margin = [System.Windows.Thickness]::new(0,6,0,0)
    $copyStack.Children.Add($text) | Out-Null

    if ($Detail) {
        $detailText = New-Object System.Windows.Controls.TextBlock
        $detailText.Text = $Detail
        $detailText.TextWrapping = 'Wrap'
        $detailText.Foreground = Get-CMBrush '#FFBAC2DE'
        $detailText.Margin = [System.Windows.Thickness]::new(0,8,0,0)
        $copyStack.Children.Add($detailText) | Out-Null
    }

    $headingRow.Children.Add($copyStack) | Out-Null
    $panel.Children.Add($headingRow) | Out-Null

    $remember = $null
    if ($AllowSessionSkip) {
        $remember = New-Object System.Windows.Controls.CheckBox
        $remember.Content = "Don't ask again this session"
        $remember.Foreground = Get-CMBrush '#FFA6ADC8'
        $remember.Margin = [System.Windows.Thickness]::new(0,0,0,18)
        $panel.Children.Add($remember) | Out-Null
    }

    $buttons = New-Object System.Windows.Controls.StackPanel
    $buttons.Orientation = 'Horizontal'
    $buttons.HorizontalAlignment = 'Right'

    $confirmBtn = New-Object System.Windows.Controls.Button
    $confirmBtn.Content = $ConfirmText
    $confirmBtn.MinWidth = 118
    $confirmBtn.Margin = [System.Windows.Thickness]::new(0,0,8,0)
    $confirmBtn.Background = Get-CMBrush $accentHex
    $confirmBtn.Foreground = Get-CMBrush '#FF11111B'
    $confirmBtn.BorderBrush = Get-CMBrush $accentHex
    $confirmBtn.IsDefault = $true

    $cancelBtn = New-Object System.Windows.Controls.Button
    $cancelBtn.Content = 'Cancel'
    $cancelBtn.MinWidth = 92
    $cancelBtn.IsCancel = $true

    $confirmBtn.Add_Click({
        if ($remember) { $script:SkipActionConfirm = [bool]$remember.IsChecked }
        $dialog.Tag = $true
        $dialog.Close()
    })
    $cancelBtn.Add_Click({
        $dialog.Tag = $false
        $dialog.Close()
    })

    $buttons.Children.Add($confirmBtn) | Out-Null
    $buttons.Children.Add($cancelBtn) | Out-Null
    $panel.Children.Add($buttons) | Out-Null
    $outer.Child = $panel
    $dialog.Content = $outer

    [void]$dialog.ShowDialog()
    return [bool]$dialog.Tag
}

function Show-AdapterActionDialog {
    param([ValidateSet('Lock','Unlock')][string]$Action, $Row)
    $isDhcpLock = ($Action -eq 'Lock' -and $Row.IsDhcp)
    if ($script:SkipActionConfirm -and -not $isDhcpLock) { return $true }

    if ($Action -eq 'Lock') {
        $detail = if ($isDhcpLock) {
            'This adapter is DHCP-configured. Locking it can prevent lease updates from writing registry values, so confirm the address is intentionally fixed before continuing.'
        } else {
            'A current SDDL backup is saved before AdapterLock writes deny ACEs.'
        }
        return Show-AdapterDecisionDialog `
            -Title 'Lock adapter' `
            -Heading "Lock $($Row.Name)?" `
            -Body 'AdapterLock will deny IP configuration writes on the selected adapter while leaving other adapters editable.' `
            -Detail $detail `
            -ConfirmText 'Lock adapter' `
            -Tone $(if ($isDhcpLock) { 'Warning' } else { 'Default' }) `
            -AllowSessionSkip:(!$isDhcpLock)
    }

    return Show-AdapterDecisionDialog `
        -Title 'Unlock adapter' `
        -Heading "Unlock $($Row.Name)?" `
        -Body 'AdapterLock will remove its deny ACEs so Windows tools can change this adapter again.' `
        -Detail 'Existing IP settings are not changed.' `
        -ConfirmText 'Unlock adapter' `
        -AllowSessionSkip
}

function Confirm-AdapterOperation {
    param([ValidateSet('Lock','Unlock','Restore')][string]$Action, $Row)

    if ($Action -eq 'Lock') {
        return (Show-AdapterActionDialog -Action 'Lock' -Row $Row)
    }
    if ($Action -eq 'Unlock') {
        return (Show-AdapterActionDialog -Action 'Unlock' -Row $Row)
    }

    return Show-AdapterDecisionDialog `
        -Title 'Restore adapter ACL backup' `
        -Heading "Restore latest SDDL backup for $($Row.Name)?" `
        -Body 'This replaces the current ACLs on AdapterLock registry keys with the most recent saved backup.' `
        -Detail 'Use this only when an adapter needs to return to a known previous registry ACL state.' `
        -ConfirmText 'Restore backup' `
        -Tone 'Warning'
}

function Show-BackupSelectionDialog {
    param($Row)

    $backups = @(Get-AdapterBackupRecord -Guid $Row.Guid)
    if ($backups.Count -eq 0) {
        $script:StatusText.Text = "No SDDL backups found for $($Row.Name)."
        Write-AppLog "No SDDL backups found for $($Row.Name) ($($Row.Guid))" 'WARN'
        return $null
    }

    $dlg = New-Object System.Windows.Window
    $dlg.Title = 'Restore adapter ACL backup'
    $dlg.Owner = $window
    $dlg.WindowStartupLocation = 'CenterOwner'
    $dlg.ResizeMode = 'NoResize'
    $dlg.SizeToContent = 'WidthAndHeight'
    $dlg.Background = Get-CMBrush '#FF1E1E2E'
    $dlg.Foreground = Get-CMBrush '#FFCDD6F4'
    $dlg.FontFamily = 'Segoe UI'

    $panel = New-Object System.Windows.Controls.StackPanel
    $panel.Margin = [System.Windows.Thickness]::new(22)
    $panel.Width = 720

    $heading = New-Object System.Windows.Controls.TextBlock
    $heading.Text = "Choose backup for $($Row.Name)"
    $heading.FontSize = 18
    $heading.FontWeight = 'SemiBold'
    $heading.Foreground = Get-CMBrush '#FFCDD6F4'
    $heading.Margin = [System.Windows.Thickness]::new(0,0,0,6)
    $panel.Children.Add($heading) | Out-Null

    $body = New-Object System.Windows.Controls.TextBlock
    $body.Text = 'Restore applies the selected SDDL file to its matching registry stack key.'
    $body.TextWrapping = 'Wrap'
    $body.Foreground = Get-CMBrush '#FFA6ADC8'
    $body.Margin = [System.Windows.Thickness]::new(0,0,0,14)
    $panel.Children.Add($body) | Out-Null

    $grid = New-Object System.Windows.Controls.DataGrid
    $grid.AutoGenerateColumns = $false
    $grid.IsReadOnly = $true
    $grid.SelectionMode = 'Single'
    $grid.HeadersVisibility = 'Column'
    $grid.MinHeight = 220
    $grid.MaxHeight = 280
    $grid.Background = Get-CMBrush '#FF11111B'
    $grid.Foreground = Get-CMBrush '#FFCDD6F4'
    $grid.RowBackground = Get-CMBrush '#FF181825'
    $grid.AlternatingRowBackground = Get-CMBrush '#FF1E1E2E'
    $grid.GridLinesVisibility = 'None'
    $grid.BorderBrush = Get-CMBrush '#FF45475A'
    $grid.BorderThickness = [System.Windows.Thickness]::new(1)
    $grid.Margin = [System.Windows.Thickness]::new(0,0,0,16)

    foreach ($columnSpec in @(
        @{ Header = 'Stack'; Binding = 'Stack'; Width = 82 },
        @{ Header = 'Timestamp'; Binding = 'Timestamp'; Width = 142 },
        @{ Header = 'Saved'; Binding = 'LastWriteTime'; Width = 170 },
        @{ Header = 'File'; Binding = 'FileName'; Width = 300 }
    )) {
        $col = New-Object System.Windows.Controls.DataGridTextColumn
        $col.Header = $columnSpec.Header
        $col.Binding = New-Object System.Windows.Data.Binding($columnSpec.Binding)
        $col.Width = $columnSpec.Width
        $grid.Columns.Add($col) | Out-Null
    }

    $grid.ItemsSource = $backups
    $grid.SelectedIndex = 0
    $panel.Children.Add($grid) | Out-Null

    $buttons = New-Object System.Windows.Controls.StackPanel
    $buttons.Orientation = 'Horizontal'
    $buttons.HorizontalAlignment = 'Right'

    $cancel = New-Object System.Windows.Controls.Button
    $cancel.Content = 'Cancel'
    $cancel.MinWidth = 96
    $cancel.Padding = [System.Windows.Thickness]::new(14,8,14,8)
    $cancel.Margin = [System.Windows.Thickness]::new(0,0,8,0)

    $restore = New-Object System.Windows.Controls.Button
    $restore.Content = 'Restore selected'
    $restore.MinWidth = 132
    $restore.Padding = [System.Windows.Thickness]::new(14,8,14,8)

    $dlg.Tag = $null
    $cancel.Add_Click({ $dlg.DialogResult = $false; $dlg.Close() })
    $restore.Add_Click({
        if ($grid.SelectedItem) {
            $dlg.Tag = $grid.SelectedItem.Path
            $dlg.DialogResult = $true
            $dlg.Close()
        }
    })

    $buttons.Children.Add($cancel) | Out-Null
    $buttons.Children.Add($restore) | Out-Null
    $panel.Children.Add($buttons) | Out-Null
    $dlg.Content = $panel

    [void]$dlg.ShowDialog()
    return [string]$dlg.Tag
}

$ctxMenu = New-Object System.Windows.Controls.ContextMenu
$ctxMenu.Background      = Get-CMBrush '#FF181825'
$ctxMenu.Foreground      = Get-CMBrush '#FFCDD6F4'
$ctxMenu.BorderBrush     = Get-CMBrush '#FF45475A'
$ctxMenu.BorderThickness = [System.Windows.Thickness]::new(1)

$ctxLock     = Get-CMMenuItem 'Lock'
$ctxUnlock   = Get-CMMenuItem 'Unlock'
$ctxRestore  = Get-CMMenuItem 'Restore from Backup'
$ctxNcpa     = Get-CMMenuItem 'Open in ncpa.cpl'
$ctxCopyMac  = Get-CMMenuItem 'Copy MAC'
$ctxCopyGuid = Get-CMMenuItem 'Copy GUID'

[void]$ctxMenu.Items.Add($ctxLock)
[void]$ctxMenu.Items.Add($ctxUnlock)
[void]$ctxMenu.Items.Add($ctxRestore)
[void]$ctxMenu.Items.Add((New-Object System.Windows.Controls.Separator))
[void]$ctxMenu.Items.Add($ctxNcpa)
[void]$ctxMenu.Items.Add((New-Object System.Windows.Controls.Separator))
[void]$ctxMenu.Items.Add($ctxCopyMac)
[void]$ctxMenu.Items.Add($ctxCopyGuid)

$script:AdapterGrid.ContextMenu = $ctxMenu

# Track which row was right-clicked so the menu operates on the correct item
$script:RightClickedRow = $null

$script:AdapterGrid.Add_PreviewMouseRightButtonDown({
    param($grid, $e)
    $null = $grid
    $script:RightClickedRow = $null
    try {
        $dep = $e.OriginalSource -as [System.Windows.DependencyObject]
        while ($dep -and $dep -isnot [System.Windows.Controls.DataGridRow]) {
            $dep = [System.Windows.Media.VisualTreeHelper]::GetParent($dep)
        }
        if ($dep -is [System.Windows.Controls.DataGridRow]) {
            $dep.IsSelected             = $true
            $script:RightClickedRow     = $dep.Item
        }
    } catch {
        Write-AppLog "Context menu row detection failed: $($_.Exception.Message)" 'WARN'
    }
})

$ctxMenu.Add_Opening({
    param($menu, $e)
    $null = $menu
    if (-not $script:RightClickedRow) { $e.Handled = $true }
    else {
        $ctxLock.IsEnabled = ($script:RightClickedRow.LockBadge -ne 'LOCKED')
        $ctxUnlock.IsEnabled = ($script:RightClickedRow.LockBadge -ne 'Unlocked')
    }
})

$ctxLock.Add_Click({
    $row = $script:RightClickedRow
    if ($row -and (Confirm-AdapterOperation -Action 'Lock' -Row $row)) {
        Invoke-AdapterOperationWorker -Action 'Lock' -Rows @($row)
    }
})
$ctxUnlock.Add_Click({
    $row = $script:RightClickedRow
    if ($row -and (Confirm-AdapterOperation -Action 'Unlock' -Row $row)) {
        Invoke-AdapterOperationWorker -Action 'Unlock' -Rows @($row)
    }
})
$ctxRestore.Add_Click({
    $row = $script:RightClickedRow
    if ($row) {
        $backupPath = Show-BackupSelectionDialog -Row $row
        if ($backupPath) {
            Invoke-AdapterOperationWorker -Action 'Restore' -Rows @([pscustomobject]@{
                Name = $row.Name
                Guid = $row.Guid
                BackupFile = $backupPath
            })
        }
    }
})
$ctxNcpa.Add_Click({
    try { Start-Process 'ncpa.cpl' } catch { Write-AppLog "ncpa open failed: $($_.Exception.Message)" 'ERROR' }
})
$ctxCopyMac.Add_Click({
    $row = $script:RightClickedRow
    if ($row) {
        [System.Windows.Clipboard]::SetText($row.MAC)
        $script:StatusText.Text = "Copied MAC: $($row.MAC)"
    }
})
$ctxCopyGuid.Add_Click({
    $row = $script:RightClickedRow
    if ($row) {
        [System.Windows.Clipboard]::SetText($row.Guid)
        $script:StatusText.Text = "Copied GUID: $($row.Guid)"
    }
})

function ConvertTo-WorkerLiteral {
    param([string]$Value)
    if ($null -eq $Value) { return "''" }
    return "'" + ($Value -replace "'", "''") + "'"
}

function Get-UiWorkerScript {
    param([scriptblock]$Work)

    $functionNames = @(
        'Write-AppLog',
        'Write-EvtLog',
        'Test-ShouldProcessChange',
        'Get-NicType',
        'Get-NicTypeGlyph',
        'Get-RegistryLastWrite',
        'ConvertTo-ReportHtml',
        'ConvertTo-PolicyGuid',
        'ConvertTo-PolicyMac',
        'Get-PolicyIdentifierKey',
        'Export-LockPolicy',
        'Import-LockPolicy',
        'Get-LockPolicySummary',
        'Invoke-LockPolicy',
        'Get-InterfaceKeyPath',
        'Get-AdapterDhcpState',
        'Get-BackupKeyTag',
        'Save-AdapterSddl',
        'ConvertFrom-AdapterBackupFile',
        'Resolve-BackupFile',
        'Get-AdapterBackupRecord',
        'Get-BackupRestorePath',
        'Invoke-SddlRestore',
        'Restore-AdapterSddl',
        'Get-AdapterLockState',
        'Test-AdapterLockedDetailed',
        'Get-LockBadgeFromDetail',
        'Get-LockDetailText',
        'Test-AdapterLocked',
        'Lock-Adapter',
        'Unlock-Adapter',
        'Get-AdapterRow',
        'Get-StringDistance',
        'Format-AdapterCandidate',
        'Get-AdapterMatchCandidate',
        'Write-AdapterMatchCandidate',
        'Find-AdapterByIdentifier'
    )

    $functionSource = foreach ($name in $functionNames) {
        $cmd = Get-Command -Name $name -CommandType Function -ErrorAction Stop
        "function $name {`r`n$($cmd.Definition)`r`n}"
    }

    $bootstrap = @"
`$ErrorActionPreference = 'Stop'
`$script:IsCli = `$false
`$script:IsDryRun = `$false
`$script:Version = $(ConvertTo-WorkerLiteral $script:Version)
`$script:LogPath = $(ConvertTo-WorkerLiteral $script:LogPath)
`$script:BackupDir = $(ConvertTo-WorkerLiteral $script:BackupDir)
`$script:LastAdapterScanError = `$null
"@

    return @"
param(`$WorkerArgument)
$bootstrap
$($functionSource -join "`r`n")
$($Work.ToString())
"@
}

function Show-UiBusyState {
    param(
        [bool]$Busy,
        [string]$Message = ''
    )

    $script:UiBusy = $Busy
    if ($Message) { $script:StatusText.Text = $Message }
    $RefreshBtn.IsEnabled = -not $Busy
    $SavePolicyBtn.IsEnabled = -not $Busy
    $LoadPolicyBtn.IsEnabled = -not $Busy
    $ToggleHiddenBtn.IsEnabled = -not $Busy
    $OpenNcpaBtn.IsEnabled = -not $Busy
    $OpenLogBtn.IsEnabled = -not $Busy
    $ReportBtn.IsEnabled = -not $Busy
    if ($script:AdapterGrid) { $script:AdapterGrid.IsEnabled = -not $Busy }
    if ($Busy) {
        $LockBtn.IsEnabled = $false
        $UnlockBtn.IsEnabled = $false
        $ctxLock.IsEnabled = $false
        $ctxUnlock.IsEnabled = $false
        $ctxRestore.IsEnabled = $false
        $window.Cursor = [System.Windows.Input.Cursors]::Wait
    } else {
        $ctxRestore.IsEnabled = $true
        $window.Cursor = $null
        Show-SelectionState
    }
}

function Invoke-UiWorker {
    param(
        [string]$Name,
        [string]$Status,
        [scriptblock]$Work,
        [object]$Argument,
        [scriptblock]$OnSuccess
    )

    if ($script:UiBusy) {
        $script:StatusText.Text = 'Another AdapterLock operation is already running.'
        return
    }

    $successHandler = $OnSuccess
    Show-UiBusyState -Busy $true -Message $Status
    $ps = [PowerShell]::Create()
    try {
        [void]$ps.AddScript((Get-UiWorkerScript -Work $Work)).AddArgument($Argument)
        $async = $ps.BeginInvoke()
    } catch {
        $ps.Dispose()
        Show-UiBusyState -Busy $false
        Write-AppLog "$Name failed to start: $($_.Exception.Message)" 'ERROR'
        $script:StatusText.Text = "$Name failed to start. See the activity log."
        return
    }

    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(150)
    $timer.Add_Tick({
        if (-not $async.IsCompleted) { return }
        $timer.Stop()
        try {
            $raw = @($ps.EndInvoke($async))
            if ($ps.Streams.Error.Count -gt 0) {
                throw $ps.Streams.Error[0].Exception
            }
            $result = if ($raw.Count -eq 1) { $raw[0] } else { $raw }
            Show-UiBusyState -Busy $false
            if ($successHandler) { & $successHandler $result }
        } catch {
            Show-UiBusyState -Busy $false
            Write-AppLog "$Name failed: $($_.Exception.Message)" 'ERROR'
            $script:StatusText.Text = "$Name failed. See the activity log."
        } finally {
            $ps.Dispose()
        }
    })
    $timer.Start()
}

function Show-AdapterGridResult {
    param($Result)

    $rows = New-Object System.Collections.ObjectModel.ObservableCollection[object]
    foreach ($row in @($Result.Rows)) {
        $rows.Add($row) | Out-Null
    }
    $script:AllRows = $rows
    $script:LastAdapterScanError = [string]$Result.Error
    Show-SummaryState
    Show-AdapterFilter
    $locked  = @($script:AllRows | Where-Object { $_.LockBadge -eq 'LOCKED' }).Count
    $partial = @($script:AllRows | Where-Object { $_.LockBadge -eq 'PARTIAL' }).Count
    $msg     = "Loaded $($script:AllRows.Count) adapter(s). $locked locked"
    if ($partial -gt 0) { $msg += " ($partial partial)" }
    if ($script:LastAdapterScanError) { $msg = 'Adapter scan failed. See the activity log for details' }
    if ($script:PendingStatusText) {
        $msg = $script:PendingStatusText
        $script:PendingStatusText = ''
    }
    $script:StatusText.Text = $msg + '.'
    Write-AppLog "Refresh: $($script:AllRows.Count) adapters, $locked locked, $partial partial"
}

function Invoke-AdapterOperationWorker {
    param(
        [ValidateSet('Lock','Unlock','Restore')][string]$Action,
        [object[]]$Rows
    )

    $items = @($Rows | ForEach-Object {
        [pscustomobject]@{
            Name = $_.Name
            Guid = $_.Guid
            BackupFile = $_.BackupFile
        }
    })
    if ($items.Count -eq 0) { return }

    Invoke-UiWorker `
        -Name "$Action adapter" `
        -Status "$Action operation running..." `
        -Argument ([pscustomobject]@{ Action = $Action; Rows = $items }) `
        -Work {
            $results = @()
            foreach ($row in @($WorkerArgument.Rows)) {
                $ok = switch ($WorkerArgument.Action) {
                    'Lock'    { Lock-Adapter -Guid $row.Guid -Name $row.Name }
                    'Unlock'  { Unlock-Adapter -Guid $row.Guid -Name $row.Name }
                    'Restore' { Restore-AdapterSddl -Guid $row.Guid -Name $row.Name -BackupFile $row.BackupFile }
                }
                $results += [pscustomobject]@{
                    Name = $row.Name
                    Guid = $row.Guid
                    Action = $WorkerArgument.Action
                    Success = [bool]$ok
                }
            }
            [pscustomobject]@{ Results = $results }
        } `
        -OnSuccess {
            param($Result)
            $results = @($Result.Results)
            $okCount = @($results | Where-Object { $_.Success }).Count
            $failCount = $results.Count - $okCount
            $script:PendingStatusText = "$Action complete: $okCount succeeded, $failCount failed"
            Show-AdapterGrid
        }
}

function Invoke-PolicyApplyWorker {
    param([string]$Path)

    Invoke-UiWorker `
        -Name 'Apply policy' `
        -Status 'Applying policy...' `
        -Argument ([pscustomobject]@{ Path = $Path }) `
        -Work {
            $policy = @(Import-LockPolicy -Path $WorkerArgument.Path)
            if ($policy.Count -eq 0) {
                [pscustomobject]@{ Success = $false; Summary = 'Failed to load policy'; Results = @() }
                return
            }
            $policyResults = @(Invoke-LockPolicy -Policy $policy)
            [pscustomobject]@{
                Success = $true
                Summary = (Get-LockPolicySummary -Results $policyResults)
                Results = $policyResults
            }
        } `
        -OnSuccess {
            param($Result)
            $script:PendingStatusText = $Result.Summary
            Show-AdapterGrid
        }
}

# --- Grid helpers ---
function Show-AdapterGrid {
    $script:StatusText.Text = 'Scanning adapters...'
    Show-EmptyState -Title 'Scanning adapters' -Body 'AdapterLock is reading network adapter state and registry ACLs.' -Hint 'This usually completes in a few seconds.' -Visible
    Invoke-UiWorker `
        -Name 'Refresh adapters' `
        -Status 'Scanning adapters...' `
        -Argument ([pscustomobject]@{ ShowHidden = [bool]$script:ShowHidden }) `
        -Work {
            $script:LastAdapterScanError = $null
            $rows = @(Get-AdapterRow -ShowHidden:([bool]$WorkerArgument.ShowHidden))
            [pscustomobject]@{
                Rows = $rows
                Error = $script:LastAdapterScanError
            }
        } `
        -OnSuccess {
            param($Result)
            Show-AdapterGridResult -Result $Result
        }
}

function Show-AdapterFilter {
    $term = Get-CurrentFilterTerm
    $total = @($script:AllRows).Count
    $filtered = New-Object System.Collections.ObjectModel.ObservableCollection[object]
    foreach ($r in @($script:AllRows)) {
        if (-not $term) {
            $filtered.Add($r) | Out-Null
            continue
        }
        foreach ($value in @($r.Name, $r.Description, $r.MAC, $r.IPv4, $r.Guid, $r.Status, $r.ConfigMode, $r.LockBadge)) {
            if (([string]$value).IndexOf($term, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $filtered.Add($r) | Out-Null
                break
            }
        }
    }
    $script:AdapterGrid.ItemsSource = $filtered
    if ($term) {
        $script:FilterCountText.Text = "Showing $($filtered.Count) of $total"
    } else {
        $script:FilterCountText.Text = "$total adapter(s)"
    }

    if ($script:LastAdapterScanError) {
        Show-EmptyState -Title 'Adapter scan failed' `
            -Body $script:LastAdapterScanError `
            -Hint 'Run from an elevated PowerShell session and check that Get-NetAdapter is available.' `
            -Visible
    } elseif ($filtered.Count -eq 0 -and $term) {
        Show-EmptyState -Title 'No adapters match this search' `
            -Body "No visible adapter matches `"$term`"." `
            -Hint 'Search by name, description, MAC, IPv4, status, mode, lock state, or GUID.' `
            -Visible
    } elseif ($filtered.Count -eq 0) {
        Show-EmptyState -Title 'No adapters found' `
            -Body 'AdapterLock did not find any visible network adapters.' `
            -Hint 'Use Show Hidden to include unplugged or hidden adapters.' `
            -Visible
    } else {
        Show-EmptyState -Title '' -Body '' -Visible:$false
    }
    Show-SelectionState
}

function Export-VisibleAdapterReport {
    param([string]$OutputFile)
    $visibleRows = @($script:AdapterGrid.ItemsSource)
    if ($visibleRows.Count -eq 0) {
        $script:StatusText.Text = 'No visible adapters to report.'
        return $false
    }
    $records = @(ConvertTo-LocalReportRecord -Rows $visibleRows)
    Export-LockReport -OutputFile $OutputFile -Data $records
    Write-AppLog "Visible adapter report exported: $OutputFile ($($records.Count) rows)" 'OK'
    return $true
}

function Show-CompactUiMode {
    if (-not $script:IsCompactMode) { return }

    $window.Title = 'AdapterLock Status'
    $window.Width = 760
    $window.Height = 620
    $window.MinWidth = 720
    $window.MinHeight = 560

    if ($script:HeaderDescription) {
        $script:HeaderDescription.Text = 'Read-only enforcement status for adapter lock posture, drift visibility, logs, and reports.'
        $script:HeaderDescription.MaxWidth = 520
    }
    if ($script:TrustBadgePanel) {
        $script:TrustBadgePanel.Visibility = 'Collapsed'
    }

    foreach ($control in @($LockBtn, $UnlockBtn, $SavePolicyBtn, $LoadPolicyBtn)) {
        if ($control) { $control.Visibility = 'Collapsed' }
    }
    foreach ($item in @($ctxLock, $ctxUnlock, $ctxRestore)) {
        if ($item) { $item.Visibility = 'Collapsed' }
    }

    foreach ($column in @($script:AdapterGrid.Columns)) {
        if ($column.Header -in @('Description','MAC','Changed')) {
            $column.Visibility = 'Collapsed'
        }
    }

    $rootGrid = $window.Content -as [System.Windows.Controls.Grid]
    if ($rootGrid -and $rootGrid.RowDefinitions.Count -gt 4) {
        $rootGrid.RowDefinitions[4].Height = [System.Windows.GridLength]::new(0)
    }

    $script:AdapterGrid.SelectionMode = 'Single'
    $script:StatusText.Text = 'Compact read-only status mode. Refresh, report, logs, and connections are available.'
    if ($script:LastDriftText) { $script:LastDriftText.Text = Get-LastDriftSummary }
}

function Invoke-SelectedAdapterAction {
    param([ValidateSet('Lock','Unlock')][string]$Action)
    $sel = @($script:AdapterGrid.SelectedItems)
    if ($sel.Count -eq 0) {
        $script:StatusText.Text = 'Select one or more adapters first.'
        return
    }
    $confirmed = @()
    foreach ($row in $sel) {
        if (-not (Confirm-AdapterOperation -Action $Action -Row $row)) {
            Write-AppLog "$Action cancelled for $($row.Name) ($($row.Guid))" 'INFO'
            continue
        }
        $confirmed += $row
    }
    if ($confirmed.Count -eq 0) {
        $script:StatusText.Text = 'No adapter changes were selected.'
        return
    }
    Invoke-AdapterOperationWorker -Action $Action -Rows $confirmed
}

$LockBtn.Add_Click({     Invoke-SelectedAdapterAction -Action 'Lock' })
$UnlockBtn.Add_Click({   Invoke-SelectedAdapterAction -Action 'Unlock' })
$RefreshBtn.Add_Click({  Show-AdapterGrid })
$script:AdapterGrid.Add_SelectionChanged({ Show-SelectionState })
$script:FilterBox.Text = $script:SearchPlaceholder
$script:FilterBox.Foreground = Get-CMBrush '#FF585B70'
$script:FilterBox.Add_GotFocus({
    if ($script:FilterBox.Text -eq $script:SearchPlaceholder) {
        $script:FilterBox.Text = ''
        $script:FilterBox.Foreground = Get-CMBrush '#FFCDD6F4'
    }
})
$script:FilterBox.Add_LostFocus({
    if (-not $script:FilterBox.Text.Trim()) {
        $script:FilterBox.Text = $script:SearchPlaceholder
        $script:FilterBox.Foreground = Get-CMBrush '#FF585B70'
    }
})
$script:FilterBox.Add_TextChanged({
    if ($script:FilterBox.Text -ne $script:SearchPlaceholder) { Show-AdapterFilter }
})
$SavePolicyBtn.Add_Click({
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = 'JSON files (*.json)|*.json'
    $dlg.InitialDirectory = $env:ProgramData
    $dlg.FileName = 'adapter-policy.json'
    if ($dlg.ShowDialog() -eq 'OK') {
        Export-LockPolicy -Path $dlg.FileName
        $script:StatusText.Text = "Policy exported: $(Split-Path $dlg.FileName -Leaf)"
    }
})
$LoadPolicyBtn.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = 'JSON files (*.json)|*.json'
    $dlg.InitialDirectory = $env:ProgramData
    if ($dlg.ShowDialog() -eq 'OK') {
        Invoke-PolicyApplyWorker -Path $dlg.FileName
    }
})
$OpenNcpaBtn.Add_Click({ try { Start-Process 'ncpa.cpl' } catch { Write-AppLog "ncpa open failed: $($_.Exception.Message)" 'ERROR' } })
$OpenLogBtn.Add_Click({  try { Start-Process (Split-Path $script:LogPath) } catch { Write-AppLog "log folder open failed: $($_.Exception.Message)" 'ERROR' } })
$ReportBtn.Add_Click({
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = 'HTML report (*.html)|*.html'
    $dlg.InitialDirectory = [Environment]::GetFolderPath('MyDocuments')
    $dlg.FileName = "adapterlock-report-$((Get-Date).ToString('yyyyMMdd-HHmmss')).html"
    if ($dlg.ShowDialog() -eq 'OK') {
        if (Export-VisibleAdapterReport -OutputFile $dlg.FileName) {
            $script:StatusText.Text = "Report exported: $(Split-Path $dlg.FileName -Leaf)"
            try { Start-Process $dlg.FileName } catch { Write-AppLog "report open failed: $($_.Exception.Message)" 'WARN' }
        }
    }
})
$ToggleHiddenBtn.Add_Click({
    $script:ShowHidden = -not $script:ShowHidden
    $ToggleHiddenBtn.Content = if ($script:ShowHidden) { 'Hide Hidden' } else { 'Show Hidden' }
    $ToggleHiddenBtn.ToolTip = if ($script:ShowHidden) { 'Return to visible adapters only' } else { 'Show unplugged and hidden adapters' }
    Show-AdapterGrid
})
Show-CompactUiMode
Show-SelectionState

$window.Add_Loaded({
    Initialize-EventSource
    Write-AppLog "AdapterLock v$($script:Version) started"
    Show-AdapterGrid
})

[void]$window.ShowDialog()
#endregion
