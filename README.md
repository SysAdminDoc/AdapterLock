# AdapterLock

![Version](https://img.shields.io/badge/version-0.7.0-blue?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey?style=flat-square)

Per-adapter IP lockdown for Windows. Single-file PowerShell WPF GUI with headless CLI mode.

Locks a specific NIC's TCP/IP configuration at the registry ACL level so that `ncpa.cpl`, `netsh interface ip set`, `Set-NetIPAddress`, and DHCP reassignment all fail with access denied on that interface — **even for local administrators** — while every other adapter stays fully editable.

Built for environments where a specific NIC must not drift: PACS modality links, X-ray acquisition hosts, lab instruments, industrial control, kiosks.

## How it works

Windows stores each adapter's IP configuration in:

```
HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{InterfaceGuid}
HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{InterfaceGuid}
HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{InterfaceGuid}
```

`Lock` adds a **Deny** ACE for `Authenticated Users` on `SetValue | CreateSubKey | Delete | WriteKey` on all three keys for the selected adapter. Every tool that configures IPs writes through these keys, so the lock is enforced at the OS level rather than by hiding UI. Admins retain `WRITE_DAC`, so this tool (running elevated) can remove the deny on demand to unlock.

`Unlock` removes the deny ACEs. Before any ACL change, the current SDDL for each key is snapshotted to `%ProgramData%\AdapterLock\Backups\` so the state is recoverable even if the tool is deleted.

Lock/Unlock events are written to the **Windows Application event log** under source `AdapterLock` (EventId 1001) for SIEM/audit pickup.

## Why not Group Policy?

No native GPO locks IP settings per-adapter. The available controls are all-or-nothing:

- `Prohibit access to properties of components of a LAN connection` (`NC_LanProperties`) — disables the TCP/IP properties button for all adapters, and admins bypass it.
- `Show only specified network connections` — hides connections, doesn't lock them.
- Network List Manager Policies — controls profile categorization, not IP.

The registry ACL technique is the real solution and what this tool automates.

## Requirements

- Windows 10 / 11 / Server 2016+
- PowerShell 5.1+
- Local administrator (the tool self-elevates)

## Usage

### GUI mode

```powershell
.\AdapterLock.ps1
```

1. The tool self-elevates and hides its console
2. Select one or more adapters in the grid
3. Click **Lock Selected** or **Unlock Selected** — the GUI asks for confirmation before changing ACLs
4. Lock state is verified by re-reading the ACL and shown in the `Lock` column

The `Mode` column shows whether the adapter is DHCP or Static. Locking a DHCP adapter shows a warning because lease renewals may be blocked from updating registry values.

The **Lock** badge is colour-coded:

| Badge | Meaning |
|-------|---------|
| 🟢 Unlocked | No deny ACE on any stack key |
| 🔴 LOCKED | Deny ACE present on all applicable stack keys |
| 🟡 PARTIAL | Mismatch — one IP stack locked but not the other |

Hover over the badge for a per-stack breakdown tooltip (e.g. `v4 + v6`, `v4 only (!)`).

Right-click any row to: **Lock**, **Unlock**, **Restore from Backup**, **Open in ncpa.cpl**, **Copy MAC**, or **Copy GUID**.

**Save Policy** / **Load Policy** — export the current lock state as JSON, then apply it on another machine or at startup via the enforcement task.

Changes take effect immediately — no reboot, no service restart.

### CLI / silent mode (Intune, SCCM, GPO startup scripts)

```powershell
# Lock by adapter name
.\AdapterLock.ps1 -Lock -Adapter "Ethernet" -Silent

# Lock by MAC address (separators normalised automatically)
.\AdapterLock.ps1 -Lock -Mac "AA:BB:CC:DD:EE:FF" -Silent

# Lock by interface GUID
.\AdapterLock.ps1 -Lock -Guid "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}" -Silent

# Unlock
.\AdapterLock.ps1 -Unlock -Adapter "Ethernet 2" -Silent

# Preview only — shows what would change, no registry writes
.\AdapterLock.ps1 -Lock -Adapter "Ethernet" -Silent -DryRun

# Load and apply a policy file
.\AdapterLock.ps1 -LoadPolicy C:\policy.json -Silent

# Install a scheduled task that re-applies the policy at startup
.\AdapterLock.ps1 -InstallTask -PolicyFile C:\policy.json

# Remove the scheduled enforcement task
.\AdapterLock.ps1 -UninstallTask

# Restore the latest saved ACL backup for an adapter
.\AdapterLock.ps1 -RestoreBackup -Guid "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}" -Silent

# Verify all locks are intact (exits 1 if drift detected)
.\AdapterLock.ps1 -VerifyLocks -Silent

# Verify and auto-remediate any ACL drift
.\AdapterLock.ps1 -VerifyLocks -Remediate -Silent

# Query lock state on remote hosts (requires PS remoting)
.\AdapterLock.ps1 -Query -ComputerName host1,host2,host3 -Silent

# Install WMI drift watcher (logs EventId 1002 on registry changes)
.\AdapterLock.ps1 -InstallWatcher

# Remove the WMI drift watcher
.\AdapterLock.ps1 -UninstallWatcher
```

Exit codes: `0` = success, `1` = adapter not found / operation failed / drift detected, `2` = bad arguments.

## Verifying the lock

With an adapter locked, try any of these and they will fail with access denied:

```powershell
Set-NetIPAddress -InterfaceIndex <idx> -IPAddress 10.0.0.99
netsh interface ip set address name="Ethernet" static 10.0.0.99 255.255.255.0
```

Opening TCP/IPv4 properties in `ncpa.cpl` and clicking OK on a changed value will also fail.

## Logs and backups

- **Log:** `%APPDATA%\AdapterLock\adapterlock.log` — every lock/unlock operation
- **SDDL backups:** `%ProgramData%\AdapterLock\Backups\` — ACL snapshot taken before each change; files are named `{Guid}.{keyTag}.{timestamp}.sddl`
- **Event Log:** Windows Application log, source `AdapterLock`, EventId 1001

Use `-RestoreBackup -Guid "{...}" -Silent` or the row context menu to restore the latest saved SDDL backup for an adapter.

## Testing

```powershell
Invoke-Pester -Script .\AdapterLock.Tests.ps1
Invoke-ScriptAnalyzer -Path .\AdapterLock.ps1 -Severity Error,Warning
```

## Version

v0.7.0
