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

.PARAMETER LoadPolicy
    Path to a JSON policy file to load and enforce. Each adapter in the policy is locked.

.PARAMETER RestoreBackup
    Restore the latest saved SDDL backup for the adapter specified by -Guid.

.PARAMETER InstallTask
    Register a scheduled task that re-applies the lock policy at system startup.

.PARAMETER UninstallTask
    Remove the AdapterLock scheduled enforcement task.

.PARAMETER PolicyFile
    Path to the policy file used by -InstallTask. Defaults to %ProgramData%\AdapterLock\policy.json.

.EXAMPLE
    .\AdapterLock.ps1
    Launch the WPF GUI for interactive lock/unlock.

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
    .\AdapterLock.ps1 -LoadPolicy C:\policy.json -Silent
    Load and enforce a JSON policy file.

.EXAMPLE
    .\AdapterLock.ps1 -RestoreBackup -Guid "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}" -Silent
    Restore the latest SDDL backup for the specified adapter.

.LINK
    https://github.com/SysAdminDoc/AdapterLock
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$Lock,
    [switch]$Unlock,
    [string]$Adapter,
    [string]$Mac,
    [string]$Guid,
    [switch]$Silent,
    [switch]$DryRun,
    [string]$LoadPolicy,
    [switch]$RestoreBackup,
    [switch]$InstallTask,
    [switch]$UninstallTask,
    [string]$PolicyFile
)


$script:IsCli    = $Silent.IsPresent -or $Lock.IsPresent -or $Unlock.IsPresent -or $LoadPolicy -or $RestoreBackup.IsPresent -or $InstallTask.IsPresent -or $UninstallTask.IsPresent
$script:IsDryRun = $DryRun.IsPresent


#region Self-elevate + hide console
$ErrorActionPreference = 'Stop'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    $psi          = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = (Get-Process -Id $PID).Path
    $psi.Verb     = 'runas'
    $psi.WindowStyle = if ($script:IsCli) { 'Normal' } else { 'Hidden' }

    $fwd = [System.Collections.Generic.List[string]]::new()
    $fwd.AddRange([string[]]@('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`""))
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Value -is [System.Management.Automation.SwitchParameter]) {
            if ($kv.Value.IsPresent) { $fwd.Add("-$($kv.Key)") }
        } else {
            $fwd.Add("-$($kv.Key)"); $fwd.Add("`"$($kv.Value)`"")
        }
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

$script:Version   = '0.6.0'
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
    for ($i = 0; $i -lt $policy.Adapters.Count; $i++) {
        $a = $policy.Adapters[$i]
        $hasId = [bool]$a.Name -or [bool]$a.MAC -or [bool]$a.GUID
        if (-not $hasId) {
            Write-AppLog "Policy validation failed: Adapters[$i] has no Name, MAC, or GUID" 'ERROR'
            return @()
        }
        $valid += $a
    }
    Write-AppLog "Policy loaded: $Path ($($valid.Count) adapters)" 'OK'
    return $valid
}

function Install-EnforcementTask {
    param([string]$PolicyPath = '')
    $taskName = 'AdapterLock-Enforce'
    $scriptPath = $PSCommandPath
    if (-not $PolicyPath) {
        $PolicyPath = Join-Path $env:ProgramData 'AdapterLock\policy.json'
    }
    $action = if ($PolicyPath -and (Test-Path -LiteralPath $PolicyPath)) {
        New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -LoadPolicy `"$PolicyPath`" -Silent"
    } else {
        New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -DryRun -Silent"
    }
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId SYSTEM -RunLevel Highest
    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    } catch {
        Write-AppLog "Existing task cleanup failed: $($_.Exception.Message)" 'WARN'
    }
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force -ErrorAction Stop | Out-Null
    Write-AppLog "Enforcement task installed: $taskName (runs at startup)" 'OK'
    Write-EvtLog "Enforcement task installed on $env:COMPUTERNAME"
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

function Restore-AdapterSddl {
    param([string]$Guid, [string]$Name = '')
    $safeGuid = $Guid -replace '[{}]', ''
    $displayName = if ($Name) { $Name } else { $Guid }
    $restored = 0

    foreach ($p in (Get-InterfaceKeyPath -Guid $Guid)) {
        if (-not (Test-Path -LiteralPath $p)) {
            Write-AppLog "Restore skipped missing key: $p" 'WARN'
            continue
        }

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

        try {
            $sddl = (Get-Content -LiteralPath $backup.FullName -Raw -ErrorAction Stop).Trim()
            $acl = Get-Acl -LiteralPath $p -ErrorAction Stop
            $acl.SetSecurityDescriptorSddlForm($sddl)
            Set-Acl -LiteralPath $p -AclObject $acl -ErrorAction Stop
            $restored++
            Write-AppLog "Restored SDDL for $p from $($backup.Name)" 'OK'
        } catch {
            Write-AppLog "SDDL restore failed for $p : $($_.Exception.Message)" 'ERROR'
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

function Test-AdapterLockedDetailed {
    param([string]$Guid)
    $v4 = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid"
    $v6 = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$Guid"
    $nb = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$Guid"

    $isDeny = {
        param([string]$path)
        if (-not (Test-Path -LiteralPath $path)) { return $false }
        try {
            $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
            return [bool]($acl.Access | Where-Object {
                $_.AccessControlType -eq 'Deny' -and
                $_.IdentityReference.Value -match 'Authenticated Users|Everyone|BUILTIN\\Users'
            })
        } catch { return $false }
    }
    return [pscustomobject]@{
        V4Locked    = (& $isDeny $v4)
        V6Locked    = (& $isDeny $v6)
        V6Exists    = (Test-Path -LiteralPath $v6)
        NetBTLocked = (& $isDeny $nb)
    }
}

function Test-AdapterLocked {
    param([string]$Guid)
    $d = Test-AdapterLockedDetailed -Guid $Guid
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
        Write-AppLog "DRY-RUN Lock $Name ($Guid) - Deny ACE would be applied to:" 'INFO'
        foreach ($p in $paths) {
            Write-AppLog ("  {0} [exists={1}]" -f $p, (Test-Path -LiteralPath $p)) 'INFO'
        }
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
        Write-AppLog "DRY-RUN Unlock $Name ($Guid) - Deny ACEs would be removed from:" 'INFO'
        foreach ($p in $paths) {
            Write-AppLog ("  {0} [exists={1}]" -f $p, (Test-Path -LiteralPath $p)) 'INFO'
        }
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

function Get-AdapterRow {
    $rows = New-Object System.Collections.ObjectModel.ObservableCollection[object]
    try {
        $adapters = Get-NetAdapter -IncludeHidden:$false -ErrorAction Stop | Sort-Object ifIndex
    } catch {
        Write-AppLog "Get-NetAdapter failed: $($_.Exception.Message)" 'ERROR'
        return $rows
    }
    foreach ($a in $adapters) {
        $guid = $a.InterfaceGuid
        $ipv4 = (Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                 Where-Object { $_.IPAddress -notlike '169.254.*' } |
                 Select-Object -First 1 -ExpandProperty IPAddress) -as [string]
        if (-not $ipv4) { $ipv4 = '-' }

        $lastChanged = Get-RegistryLastWrite -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid"
        $dhcpState = Get-AdapterDhcpState -Guid $guid
        $detail = Test-AdapterLockedDetailed -Guid $guid
        $badge  = if     ($detail.V4Locked -and ($detail.V6Locked -or -not $detail.V6Exists)) { 'LOCKED'   }
                  elseif ($detail.V4Locked -or $detail.V6Locked -or $detail.NetBTLocked)       { 'PARTIAL'  }
                  else                                                                          { 'Unlocked' }
        $lockDetail = if     ($detail.V4Locked -and $detail.V6Locked)    { 'v4 + v6' }
                      elseif ($detail.V4Locked -and -not $detail.V6Exists) { 'v4 (no v6 key)' }
                      elseif ($detail.V4Locked)                           { 'v4 only (!)' }
                      elseif ($detail.V6Locked)                           { 'v6 only (!)' }
                      else                                                { '-' }

        $rows.Add([pscustomobject]@{
            NicType    = Get-NicType -A $a
            NicTypeGlyph = Get-NicTypeGlyph -Type (Get-NicType -A $a)
            Name       = $a.Name
            Description = $a.InterfaceDescription
            MAC        = $a.MacAddress
            IPv4       = $ipv4
            ConfigMode = $dhcpState.Mode
            ConfigDetail = $dhcpState.Detail
            IsDhcp     = $dhcpState.IsDhcp
            Status     = $a.Status
            LastChanged = if ($lastChanged) { $lastChanged.ToString('yyyy-MM-dd HH:mm') } else { '-' }
            LockBadge  = $badge
            LockDetail = $lockDetail
            Guid       = $guid
            IsLocked   = ($badge -ne 'Unlocked')
        }) | Out-Null
    }
    return $rows
}

function Find-AdapterByIdentifier {
    param([string]$ByName, [string]$ByMac, [string]$ByGuid)
    try { $adapters = Get-NetAdapter -IncludeHidden:$false -ErrorAction Stop }
    catch {
        Write-AppLog "Get-NetAdapter failed: $($_.Exception.Message)" 'ERROR'
        return $null
    }
    foreach ($a in $adapters) {
        if ($ByName -and $a.Name -eq $ByName) { return $a }
        if ($ByMac) {
            $normIn = $ByMac          -replace '[:\-\s]', ''
            $normA  = $a.MacAddress   -replace '[:\-\s]', ''
            if ($normA -ieq $normIn) { return $a }
        }
        if ($ByGuid -and $a.InterfaceGuid -eq $ByGuid) { return $a }
    }
    return $null
}
#endregion

#region CLI / silent mode
if ($script:IsCli) {
    Initialize-EventSource

    if ($InstallTask) {
        Write-AppLog "AdapterLock v$($script:Version) installing enforcement task"
        Install-EnforcementTask -PolicyPath $PolicyFile
        exit 0
    }
    if ($UninstallTask) {
        Write-AppLog "AdapterLock v$($script:Version) uninstalling enforcement task"
        Uninstall-EnforcementTask
        exit 0
    }
    if ($RestoreBackup) {
        Write-AppLog "AdapterLock v$($script:Version) restoring latest SDDL backup"
        if (-not $Guid) {
            Write-AppLog 'Specify -Guid <guid> with -RestoreBackup' 'ERROR'
            exit 2
        }
        $target = Find-AdapterByIdentifier -ByGuid $Guid
        $name = if ($target) { $target.Name } else { $Guid }
        $ok = Restore-AdapterSddl -Guid $Guid -Name $name
        if ($ok) { exit 0 } else { exit 1 }
    }
    if ($LoadPolicy) {
        Write-AppLog "AdapterLock v$($script:Version) loading policy: $LoadPolicy"
        $policy = Import-LockPolicy -Path $LoadPolicy
        if ($policy.Count -eq 0) { exit 1 }
        foreach ($p in $policy) {
            $adapter = Find-AdapterByIdentifier -ByName $p.Name -ByMac $p.MAC -ByGuid $p.GUID
            if ($adapter) {
                Lock-Adapter -Guid $adapter.InterfaceGuid -Name $adapter.Name
                Write-AppLog "Policy enforced: $($adapter.Name)"
            } else {
                Write-AppLog "Policy target not found: $($p.Name) / $($p.MAC)" 'WARN'
            }
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
        Lock-Adapter   -Guid $target.InterfaceGuid -Name $target.Name -Preview:$DryRun
    } else {
        Unlock-Adapter -Guid $target.InterfaceGuid -Name $target.Name -Preview:$DryRun
    }
    if ($ok) { exit 0 } else { exit 1 }
}
#endregion

#region XAML - Catppuccin Mocha dark theme
[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="AdapterLock" Width="1100" Height="700"
        WindowStartupLocation="CenterScreen"
        Background="#FF1E1E2E" Foreground="#FFCDD6F4"
        FontFamily="Segoe UI" FontSize="13">
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

        <Style TargetType="Button">
            <Setter Property="Background" Value="{StaticResource Surface0}"/>
            <Setter Property="Foreground" Value="{StaticResource Text}"/>
            <Setter Property="BorderBrush" Value="{StaticResource Surface2}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="14,7"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="bd" Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="6">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"
                                              Margin="{TemplateBinding Padding}"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="bd" Property="Background" Value="{StaticResource Surface1}"/>
                                <Setter TargetName="bd" Property="BorderBrush" Value="{StaticResource Mauve}"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="bd" Property="Background" Value="{StaticResource Surface2}"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Opacity" Value="0.45"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style TargetType="{x:Type DataGrid}">
            <Setter Property="Background" Value="{StaticResource Mantle}"/>
            <Setter Property="Foreground" Value="{StaticResource Text}"/>
            <Setter Property="BorderBrush" Value="{StaticResource Surface1}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="GridLinesVisibility" Value="Horizontal"/>
            <Setter Property="HorizontalGridLinesBrush" Value="{StaticResource Surface0}"/>
            <Setter Property="RowBackground" Value="{StaticResource Mantle}"/>
            <Setter Property="AlternatingRowBackground" Value="#FF1B1B28"/>
            <Setter Property="HeadersVisibility" Value="Column"/>
            <Setter Property="AutoGenerateColumns" Value="False"/>
            <Setter Property="CanUserAddRows" Value="False"/>
            <Setter Property="CanUserDeleteRows" Value="False"/>
            <Setter Property="IsReadOnly" Value="True"/>
            <Setter Property="SelectionMode" Value="Extended"/>
            <Setter Property="SelectionUnit" Value="FullRow"/>
        </Style>
        <Style TargetType="{x:Type DataGridColumnHeader}">
            <Setter Property="Background" Value="{StaticResource Crust}"/>
            <Setter Property="Foreground" Value="{StaticResource Mauve}"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Padding" Value="10,7"/>
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
                    <Setter Property="Background" Value="{StaticResource Surface1}"/>
                    <Setter Property="Foreground" Value="{StaticResource Text}"/>
                </Trigger>
            </Style.Triggers>
        </Style>
        <Style TargetType="{x:Type DataGridCell}">
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="8,5"/>
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

        <Style TargetType="TextBox">
            <Setter Property="Background" Value="{StaticResource Crust}"/>
            <Setter Property="Foreground" Value="{StaticResource Text}"/>
            <Setter Property="BorderBrush" Value="{StaticResource Surface1}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="8"/>
            <Setter Property="FontFamily" Value="Consolas"/>
            <Setter Property="FontSize" Value="12"/>
        </Style>

        <Style TargetType="ScrollBar">
            <Setter Property="Background" Value="{StaticResource Mantle}"/>
            <Setter Property="Foreground" Value="{StaticResource Surface2}"/>
            <Setter Property="Width" Value="10"/>
        </Style>
    </Window.Resources>

    <Grid Margin="16">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="170"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Header -->
        <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="0,0,0,4">
            <TextBlock Text="AdapterLock" FontSize="22" FontWeight="Bold" Foreground="{StaticResource Mauve}"/>
            <TextBlock x:Name="VersionText" Text=" v0.6.0" FontSize="13" Foreground="{StaticResource Subtext}" VerticalAlignment="Bottom" Margin="4,0,0,4"/>
        </StackPanel>
        <TextBlock Grid.Row="1" Margin="0,0,0,12"
                   Text="Per-adapter IP lockdown via registry ACL. Locks Tcpip\Interfaces\{GUID} so ncpa.cpl, netsh, and Set-NetIPAddress all fail - even for local admins. Right-click a row for more options."
                   Foreground="{StaticResource Subtext}" TextWrapping="Wrap"/>

        <!-- Adapter grid -->
        <DataGrid Grid.Row="2" x:Name="AdapterGrid">
            <DataGrid.Columns>
                <DataGridTemplateColumn Header="Type" Width="50">
                    <DataGridTemplateColumn.CellTemplate>
                        <DataTemplate>
                            <TextBlock Text="{Binding NicTypeGlyph}" FontFamily="Segoe MDL2 Assets" FontSize="14" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </DataTemplate>
                    </DataGridTemplateColumn.CellTemplate>
                </DataGridTemplateColumn>
                <DataGridTextColumn Header="Name"        Binding="{Binding Name}"         Width="130"/>
                <DataGridTextColumn Header="Description" Binding="{Binding Description}"  Width="*"/>
                <DataGridTextColumn Header="MAC"         Binding="{Binding MAC}"          Width="140"/>
                <DataGridTextColumn Header="IPv4"        Binding="{Binding IPv4}"         Width="130"/>
                <DataGridTextColumn Header="Mode"        Binding="{Binding ConfigMode}"   Width="80"/>
                <DataGridTextColumn Header="Status"      Binding="{Binding Status}"       Width="80"/>
                <DataGridTextColumn Header="Changed"     Binding="{Binding LastChanged}"  Width="140"/>
                <DataGridTemplateColumn Header="Lock" Width="110">
                    <DataGridTemplateColumn.CellTemplate>
                        <DataTemplate>
                            <Border CornerRadius="4" Padding="8,3" HorizontalAlignment="Left"
                                    ToolTip="{Binding LockDetail}">
                                <Border.Style>
                                    <Style TargetType="Border">
                                        <Setter Property="Background" Value="#FFA6E3A1"/>
                                        <Style.Triggers>
                                            <DataTrigger Binding="{Binding LockBadge}" Value="LOCKED">
                                                <Setter Property="Background" Value="#FFF38BA8"/>
                                            </DataTrigger>
                                            <DataTrigger Binding="{Binding LockBadge}" Value="PARTIAL">
                                                <Setter Property="Background" Value="#FFF9E2AF"/>
                                            </DataTrigger>
                                        </Style.Triggers>
                                    </Style>
                                </Border.Style>
                                <TextBlock Text="{Binding LockBadge}" Foreground="#FF11111B" FontWeight="Bold" FontSize="11"/>
                            </Border>
                        </DataTemplate>
                    </DataGridTemplateColumn.CellTemplate>
                </DataGridTemplateColumn>
            </DataGrid.Columns>
        </DataGrid>

        <!-- Button row -->
        <StackPanel Grid.Row="3" Orientation="Horizontal" Margin="0,12,0,12">
            <Button x:Name="LockBtn"     Content="Lock Selected"   Margin="0,0,8,0"/>
            <Button x:Name="UnlockBtn"   Content="Unlock Selected" Margin="0,0,8,0"/>
            <Button x:Name="RefreshBtn"  Content="Refresh"         Margin="0,0,8,0"/>
            <Button x:Name="SavePolicyBtn" Content="Save Policy"    Margin="0,0,8,0"/>
            <Button x:Name="LoadPolicyBtn" Content="Load Policy"    Margin="0,0,8,0"/>
            <Button x:Name="OpenNcpaBtn" Content="Open ncpa.cpl"   Margin="0,0,8,0"/>
            <Button x:Name="OpenLogBtn"  Content="Open Log Folder"/>
        </StackPanel>

        <!-- Log -->
        <TextBox Grid.Row="4" x:Name="LogBox" IsReadOnly="True"
                 VerticalScrollBarVisibility="Auto"
                 HorizontalScrollBarVisibility="Auto"
                 TextWrapping="NoWrap"/>

        <!-- Status bar -->
        <Grid Grid.Row="5" Margin="0,8,0,0">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <TextBlock x:Name="StatusText" Grid.Column="0" Text="Ready." Foreground="{StaticResource Subtext}"/>
            <TextBlock Grid.Column="1" Text="Run as Administrator | Changes take effect immediately"
                       Foreground="{StaticResource Surface2}" FontStyle="Italic"/>
        </Grid>
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
$script:SkipActionConfirm = $false

$LockBtn     = $window.FindName('LockBtn')
$UnlockBtn   = $window.FindName('UnlockBtn')
$RefreshBtn  = $window.FindName('RefreshBtn')
$SavePolicyBtn = $window.FindName('SavePolicyBtn')
$LoadPolicyBtn = $window.FindName('LoadPolicyBtn')
$OpenNcpaBtn = $window.FindName('OpenNcpaBtn')
$OpenLogBtn  = $window.FindName('OpenLogBtn')

$script:VersionText.Text = " v$($script:Version)"

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
    return $mi
}

function Show-AdapterActionDialog {
    param([ValidateSet('Lock','Unlock')][string]$Action, $Row)
    if ($script:SkipActionConfirm) { return $true }

    $verb = if ($Action -eq 'Lock') { 'Lock' } else { 'Unlock' }
    $message = if ($Action -eq 'Lock') {
        "Lock adapter $($Row.Name)?`r`n`r`nThis will deny all IP configuration changes."
    } else {
        "Unlock adapter $($Row.Name)?`r`n`r`nThis will remove AdapterLock deny ACEs and allow IP configuration changes."
    }

    $dialog = New-Object System.Windows.Window
    $dialog.Title = "$verb adapter"
    $dialog.Width = 460
    $dialog.Height = 230
    $dialog.ResizeMode = 'NoResize'
    $dialog.WindowStartupLocation = 'CenterOwner'
    $dialog.Owner = $window
    $dialog.Background = Get-CMBrush '#FF1E1E2E'
    $dialog.Foreground = Get-CMBrush '#FFCDD6F4'
    $dialog.FontFamily = 'Segoe UI'
    $dialog.FontSize = 13
    $dialog.Tag = $false

    $panel = New-Object System.Windows.Controls.StackPanel
    $panel.Margin = [System.Windows.Thickness]::new(18)

    $text = New-Object System.Windows.Controls.TextBlock
    $text.Text = $message
    $text.TextWrapping = 'Wrap'
    $text.Margin = [System.Windows.Thickness]::new(0,0,0,14)
    $panel.Children.Add($text) | Out-Null

    $remember = New-Object System.Windows.Controls.CheckBox
    $remember.Content = "Don't ask again this session"
    $remember.Foreground = Get-CMBrush '#FFA6ADC8'
    $remember.Margin = [System.Windows.Thickness]::new(0,0,0,18)
    $panel.Children.Add($remember) | Out-Null

    $buttons = New-Object System.Windows.Controls.StackPanel
    $buttons.Orientation = 'Horizontal'
    $buttons.HorizontalAlignment = 'Right'

    $confirmBtn = New-Object System.Windows.Controls.Button
    $confirmBtn.Content = $verb
    $confirmBtn.MinWidth = 92
    $confirmBtn.Margin = [System.Windows.Thickness]::new(0,0,8,0)

    $cancelBtn = New-Object System.Windows.Controls.Button
    $cancelBtn.Content = 'Cancel'
    $cancelBtn.MinWidth = 92

    $confirmBtn.Add_Click({
        $script:SkipActionConfirm = [bool]$remember.IsChecked
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
    $dialog.Content = $panel

    [void]$dialog.ShowDialog()
    return [bool]$dialog.Tag
}

function Confirm-DhcpLock {
    param($Row)
    if (-not $Row.IsDhcp) { return $true }

    $message = "Adapter $($Row.Name) is DHCP-configured (EnableDHCP=1). Locking it can prevent DHCP lease updates and may break connectivity.`r`n`r`nContinue?"
    $result = [System.Windows.MessageBox]::Show(
        $window,
        $message,
        'DHCP adapter warning',
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Warning
    )
    return ($result -eq [System.Windows.MessageBoxResult]::Yes)
}

function Confirm-AdapterOperation {
    param([ValidateSet('Lock','Unlock','Restore')][string]$Action, $Row)

    if ($Action -eq 'Lock') {
        if (-not (Confirm-DhcpLock -Row $Row)) { return $false }
        return (Show-AdapterActionDialog -Action 'Lock' -Row $Row)
    }
    if ($Action -eq 'Unlock') {
        return (Show-AdapterActionDialog -Action 'Unlock' -Row $Row)
    }

    $message = "Restore latest SDDL backup for adapter $($Row.Name)?`r`n`r`nThis will replace the current ACLs on AdapterLock registry keys."
    $result = [System.Windows.MessageBox]::Show(
        $window,
        $message,
        'Restore adapter ACL backup',
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Warning
    )
    return ($result -eq [System.Windows.MessageBoxResult]::Yes)
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
})

$ctxLock.Add_Click({
    $row = $script:RightClickedRow
    if ($row -and (Confirm-AdapterOperation -Action 'Lock' -Row $row)) {
        [void](Lock-Adapter -Guid $row.Guid -Name $row.Name)
        Show-AdapterGrid
    }
})
$ctxUnlock.Add_Click({
    $row = $script:RightClickedRow
    if ($row -and (Confirm-AdapterOperation -Action 'Unlock' -Row $row)) {
        [void](Unlock-Adapter -Guid $row.Guid -Name $row.Name)
        Show-AdapterGrid
    }
})
$ctxRestore.Add_Click({
    $row = $script:RightClickedRow
    if ($row -and (Confirm-AdapterOperation -Action 'Restore' -Row $row)) {
        [void](Restore-AdapterSddl -Guid $row.Guid -Name $row.Name)
        Show-AdapterGrid
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

# --- Grid helpers ---
function Show-AdapterGrid {
    $script:StatusText.Text = 'Scanning adapters...'
    $rows = Get-AdapterRow
    $script:AdapterGrid.ItemsSource = $rows
    $locked  = ($rows | Where-Object { $_.IsLocked }).Count
    $partial = ($rows | Where-Object { $_.LockBadge -eq 'PARTIAL' }).Count
    $msg     = "Loaded $($rows.Count) adapter(s). $locked locked"
    if ($partial -gt 0) { $msg += " ($partial partial)" }
    $script:StatusText.Text = $msg + '.'
    Write-AppLog "Refresh: $($rows.Count) adapters, $locked locked, $partial partial"
}

function Invoke-SelectedAdapterAction {
    param([ValidateSet('Lock','Unlock')][string]$Action)
    $sel = @($script:AdapterGrid.SelectedItems)
    if ($sel.Count -eq 0) {
        $script:StatusText.Text = 'No adapter selected.'
        return
    }
    foreach ($row in $sel) {
        if (-not (Confirm-AdapterOperation -Action $Action -Row $row)) {
            Write-AppLog "$Action cancelled for $($row.Name) ($($row.Guid))" 'INFO'
            continue
        }
        if ($Action -eq 'Lock') {
            [void](Lock-Adapter   -Guid $row.Guid -Name $row.Name)
        } else {
            [void](Unlock-Adapter -Guid $row.Guid -Name $row.Name)
        }
    }
    Show-AdapterGrid
}

$LockBtn.Add_Click({     Invoke-SelectedAdapterAction -Action 'Lock' })
$UnlockBtn.Add_Click({   Invoke-SelectedAdapterAction -Action 'Unlock' })
$RefreshBtn.Add_Click({  Show-AdapterGrid })
$SavePolicyBtn.Add_Click({
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = 'JSON files (*.json)|*.json'
    $dlg.InitialDirectory = $env:ProgramData
    $dlg.FileName = 'adapter-policy.json'
    if ($dlg.ShowDialog() -eq 'OK') {
        Export-LockPolicy -Path $dlg.FileName
        $script:StatusText.Text = "Policy saved: $(Split-Path $dlg.FileName -Leaf)"
    }
})
$LoadPolicyBtn.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = 'JSON files (*.json)|*.json'
    $dlg.InitialDirectory = $env:ProgramData
    if ($dlg.ShowDialog() -eq 'OK') {
        $policy = Import-LockPolicy -Path $dlg.FileName
        if ($policy.Count -gt 0) {
            foreach ($p in $policy) {
                $a = Find-AdapterByIdentifier -ByName $p.Name -ByMac $p.MAC -ByGuid $p.GUID
                if ($a) { [void](Lock-Adapter -Guid $a.InterfaceGuid -Name $a.Name) }
            }
            Show-AdapterGrid
            $script:StatusText.Text = "Policy loaded: $($policy.Count) adapter(s)"
        } else {
            $script:StatusText.Text = 'Failed to load policy.'
        }
    }
})
$OpenNcpaBtn.Add_Click({ try { Start-Process 'ncpa.cpl' } catch { Write-AppLog "ncpa open failed: $($_.Exception.Message)" 'ERROR' } })
$OpenLogBtn.Add_Click({  try { Start-Process (Split-Path $script:LogPath) } catch { Write-AppLog "log folder open failed: $($_.Exception.Message)" 'ERROR' } })

$window.Add_Loaded({
    Initialize-EventSource
    Write-AppLog "AdapterLock v$($script:Version) started"
    Show-AdapterGrid
})

[void]$window.ShowDialog()
#endregion
