# Changelog

## v0.2.0 — 2026-04-26

### Added
- **CLI / silent mode** — `-Lock` / `-Unlock` with `-Adapter`, `-Mac`, or `-Guid` identifiers; `-Silent` flag suppresses the GUI entirely for use in Intune, SCCM, or GPO startup scripts. Exit codes: 0 = success, 1 = failure, 2 = bad args.
- **Dry-run mode** (`-DryRun`) — logs the exact registry keys that would be modified without writing any ACL changes; works in both GUI-triggered operations and CLI mode.
- **SDDL rollback snapshots** — before every Lock or Unlock the current ACL SDDL for each affected key is saved to `%ProgramData%\AdapterLock\Backups\{Guid}.{keyTag}.{timestamp}.sddl`. Recoverable even if the tool is deleted.
- **NetBT key locking** — `Get-InterfaceKeyPaths` now includes `HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{GUID}` so NetBIOS / WINS configuration is also immutable when locked.
- **IPv4 / IPv6 parity detection** — `Test-AdapterLockedDetailed` reports per-stack lock state; the Lock badge shows `LOCKED` (both stacks), `PARTIAL` (mismatch, yellow), or `Unlocked` (green). Tooltip shows the stack detail string.
- **NIC type column** — new `Type` column showing `Phys`, `WiFi`, `Virt`, `Tunl`, or `Loop` based on `InterfaceDescription` and `PhysicalMediaType`.
- **Per-row context menu** — right-click any row: **Lock**, **Unlock**, **Open in ncpa.cpl**, **Copy MAC**, **Copy GUID**. `PreviewMouseRightButtonDown` handler ensures the correct row is selected before the menu opens.
- **Windows Event Log** — Lock and Unlock operations write to the Windows Application log under source `AdapterLock` (EventId 1001) for SIEM / audit pickup. Source is auto-created on first run.
- **`#Requires -Version 5.1`** at the top of the script.
- **`[CmdletBinding()]` + `param()` block** — parameters forwarded correctly through the self-elevate re-launch; console window stays visible in CLI mode.

### Changed
- Lock badge column now uses `LockBadge` string binding with three colour states instead of a boolean `IsLocked` binding.
- Status bar shows partial-lock count when any adapter is in a mismatch state.
- Subtitle text updated to mention the right-click context menu hint.
- Window width increased 1040 → 1100 to accommodate the new Type column.

## v0.0.1 — 2026-04-10

- Initial release: single-file PowerShell WPF GUI, Catppuccin Mocha theme, Lock/Unlock via registry Deny ACE on `Tcpip` and `Tcpip6` interface keys, embedded log panel, self-elevation, console hiding.
