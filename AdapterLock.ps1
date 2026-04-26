#Requires -Version 5.1
# AdapterLock v0.2.0
# Per-adapter IP lockdown via registry ACL on Tcpip\Parameters\Interfaces\{GUID}
# Blocks ncpa.cpl / netsh / Set-NetIPAddress from modifying the selected NIC,
# even for local administrators. Unlock restores normal ACLs.
#
# GUI mode  : .\AdapterLock.ps1
# CLI mode  : .\AdapterLock.ps1 -Lock   [-Adapter <name>|-Mac <mac>|-Guid <guid>] [-Silent] [-DryRun]
#             .\AdapterLock.ps1 -Unlock [-Adapter <name>|-Mac <mac>|-Guid <guid>] [-Silent] [-DryRun]

[CmdletBinding()]
param(
    [switch]$Lock,
    [switch]$Unlock,
    [string]$Adapter,
    [string]$Mac,
    [string]$Guid,
    [switch]$Silent,
    [switch]$DryRun
)

$script:IsCli    = $Silent.IsPresent -or (($Lock.IsPresent -or $Unlock.IsPresent) -and ($Adapter -or $Mac -or $Guid))
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
    try { [void][System.Diagnostics.Process]::Start($psi) } catch { }
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
}

$script:Version   = '0.2.0'
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
        else { Write-Host $line }
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
    } catch { }
}

function Write-EvtLog {
    param([string]$Message, [string]$EntryType = 'Information')
    try {
        Write-EventLog -LogName Application -Source AdapterLock `
            -EventId 1001 -EntryType $EntryType -Message $Message -ErrorAction SilentlyContinue
    } catch { }
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

function Get-InterfaceKeyPaths {
    param([string]$Guid)
    return @(
        "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid"
        "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$Guid"
        "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$Guid"
    )
}

function Save-AdapterSddl {
    param([string]$Guid, [string]$Name)
    $ts       = Get-Date -Format 'yyyyMMdd-HHmmss'
    $safeGuid = $Guid -replace '[{}]', ''
    foreach ($p in (Get-InterfaceKeyPaths -Guid $Guid)) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        try {
            $sddl    = (Get-Acl -LiteralPath $p -ErrorAction Stop).Sddl
            $keyTag  = ($p -split '\\')[-1]
            $outFile = Join-Path $script:BackupDir "$safeGuid.$keyTag.$ts.sddl"
            Set-Content -LiteralPath $outFile -Value $sddl -Encoding UTF8 -ErrorAction Stop
        } catch {
            Write-AppLog "SDDL backup failed for $p : $($_.Exception.Message)" 'WARN'
        }
    }
    Write-AppLog "SDDL snapshot saved: $Name ($Guid)" 'INFO'
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
    $paths = Get-InterfaceKeyPaths -Guid $Guid

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
    $paths = Get-InterfaceKeyPaths -Guid $Guid

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

function Get-AdapterRows {
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
            Name       = $a.Name
            Description = $a.InterfaceDescription
            MAC        = $a.MacAddress
            IPv4       = $ipv4
            Status     = $a.Status
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
    exit (if ($ok) { 0 } else { 1 })
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
            <TextBlock x:Name="VersionText" Text=" v0.2.0" FontSize="13" Foreground="{StaticResource Subtext}" VerticalAlignment="Bottom" Margin="4,0,0,4"/>
        </StackPanel>
        <TextBlock Grid.Row="1" Margin="0,0,0,12"
                   Text="Per-adapter IP lockdown via registry ACL. Locks Tcpip\Interfaces\{GUID} so ncpa.cpl, netsh, and Set-NetIPAddress all fail - even for local admins. Right-click a row for more options."
                   Foreground="{StaticResource Subtext}" TextWrapping="Wrap"/>

        <!-- Adapter grid -->
        <DataGrid Grid.Row="2" x:Name="AdapterGrid">
            <DataGrid.Columns>
                <DataGridTextColumn Header="Type"        Binding="{Binding NicType}"      Width="55"/>
                <DataGridTextColumn Header="Name"        Binding="{Binding Name}"         Width="130"/>
                <DataGridTextColumn Header="Description" Binding="{Binding Description}"  Width="*"/>
                <DataGridTextColumn Header="MAC"         Binding="{Binding MAC}"          Width="140"/>
                <DataGridTextColumn Header="IPv4"        Binding="{Binding IPv4}"         Width="130"/>
                <DataGridTextColumn Header="Status"      Binding="{Binding Status}"       Width="80"/>
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

$LockBtn     = $window.FindName('LockBtn')
$UnlockBtn   = $window.FindName('UnlockBtn')
$RefreshBtn  = $window.FindName('RefreshBtn')
$OpenNcpaBtn = $window.FindName('OpenNcpaBtn')
$OpenLogBtn  = $window.FindName('OpenLogBtn')

$script:VersionText.Text = " v$($script:Version)"

# --- Context menu (built in code; avoids XAML x:Name scoping issues) ---
function New-CMBrush {
    param([string]$Hex)
    $c = [System.Windows.Media.ColorConverter]::ConvertFromString($Hex)
    return New-Object System.Windows.Media.SolidColorBrush $c
}
function New-CMItem {
    param([string]$Header)
    $mi = New-Object System.Windows.Controls.MenuItem
    $mi.Header     = $Header
    $mi.Foreground = New-CMBrush '#FFCDD6F4'
    $mi.Background = New-CMBrush '#FF181825'
    return $mi
}

$ctxMenu = New-Object System.Windows.Controls.ContextMenu
$ctxMenu.Background      = New-CMBrush '#FF181825'
$ctxMenu.Foreground      = New-CMBrush '#FFCDD6F4'
$ctxMenu.BorderBrush     = New-CMBrush '#FF45475A'
$ctxMenu.BorderThickness = [System.Windows.Thickness]::new(1)

$ctxLock     = New-CMItem 'Lock'
$ctxUnlock   = New-CMItem 'Unlock'
$ctxNcpa     = New-CMItem 'Open in ncpa.cpl'
$ctxCopyMac  = New-CMItem 'Copy MAC'
$ctxCopyGuid = New-CMItem 'Copy GUID'

[void]$ctxMenu.Items.Add($ctxLock)
[void]$ctxMenu.Items.Add($ctxUnlock)
[void]$ctxMenu.Items.Add((New-Object System.Windows.Controls.Separator))
[void]$ctxMenu.Items.Add($ctxNcpa)
[void]$ctxMenu.Items.Add((New-Object System.Windows.Controls.Separator))
[void]$ctxMenu.Items.Add($ctxCopyMac)
[void]$ctxMenu.Items.Add($ctxCopyGuid)

$script:AdapterGrid.ContextMenu = $ctxMenu

# Track which row was right-clicked so the menu operates on the correct item
$script:RightClickedRow = $null

$script:AdapterGrid.Add_PreviewMouseRightButtonDown({
    param($sender, $e)
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
    } catch { }
})

$ctxMenu.Add_Opening({
    param($s, $e)
    if (-not $script:RightClickedRow) { $e.Handled = $true }
})

$ctxLock.Add_Click({
    $row = $script:RightClickedRow
    if ($row) { [void](Lock-Adapter   -Guid $row.Guid -Name $row.Name); Refresh-Grid }
})
$ctxUnlock.Add_Click({
    $row = $script:RightClickedRow
    if ($row) { [void](Unlock-Adapter -Guid $row.Guid -Name $row.Name); Refresh-Grid }
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
function Refresh-Grid {
    $script:StatusText.Text = 'Scanning adapters...'
    $rows = Get-AdapterRows
    $script:AdapterGrid.ItemsSource = $rows
    $locked  = ($rows | Where-Object { $_.IsLocked }).Count
    $partial = ($rows | Where-Object { $_.LockBadge -eq 'PARTIAL' }).Count
    $msg     = "Loaded $($rows.Count) adapter(s). $locked locked"
    if ($partial -gt 0) { $msg += " ($partial partial)" }
    $script:StatusText.Text = $msg + '.'
    Write-AppLog "Refresh: $($rows.Count) adapters, $locked locked, $partial partial"
}

function Apply-ToSelected {
    param([ValidateSet('Lock','Unlock')][string]$Action)
    $sel = @($script:AdapterGrid.SelectedItems)
    if ($sel.Count -eq 0) {
        $script:StatusText.Text = 'No adapter selected.'
        return
    }
    foreach ($row in $sel) {
        if ($Action -eq 'Lock') {
            [void](Lock-Adapter   -Guid $row.Guid -Name $row.Name)
        } else {
            [void](Unlock-Adapter -Guid $row.Guid -Name $row.Name)
        }
    }
    Refresh-Grid
}

$LockBtn.Add_Click({     Apply-ToSelected -Action 'Lock' })
$UnlockBtn.Add_Click({   Apply-ToSelected -Action 'Unlock' })
$RefreshBtn.Add_Click({  Refresh-Grid })
$OpenNcpaBtn.Add_Click({ try { Start-Process 'ncpa.cpl' } catch { Write-AppLog "ncpa open failed: $($_.Exception.Message)" 'ERROR' } })
$OpenLogBtn.Add_Click({  try { Start-Process (Split-Path $script:LogPath) } catch { } })

$window.Add_Loaded({
    Initialize-EventSource
    Write-AppLog "AdapterLock v$($script:Version) started"
    Refresh-Grid
})

[void]$window.ShowDialog()
#endregion
