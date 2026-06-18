# Changelog

## v0.8.11 - 2026-06-18

### Added
- **WPF layout/accessibility validation** -- build validation now loads the real XAML at default and compact sizes, checks primary controls for measurable layout, and verifies accessible names, content, or tooltips.

## v0.8.10 - 2026-06-18

### Added
- **PowerShell safety semantics** -- state-changing CLI paths now support native `-WhatIf` and `-Confirm` behavior while preserving existing `-DryRun` previews.

## v0.8.9 - 2026-06-18

### Added
- **CLI adapter discovery** -- `-ListAdapters` now lists visible and hidden adapter identifiers in table, JSON, or CSV output.

### Changed
- **Safer adapter resolution** -- failed and ambiguous CLI matches now log closest visible candidates and refuse ACL writes instead of choosing implicitly.

## v0.8.8 - 2026-06-18

### Changed
- **Shared lock-state evaluator** -- local UI rows, CLI integrity checks, reports, and remote query output now use one lock-state schema for `LOCKED`, `PARTIAL`, and `Unlocked` semantics.

## v0.8.7 - 2026-06-17

### Changed
- **Build validation gate** -- `build.ps1 -Validate` now runs PSScriptAnalyzer with the repository settings and fails on warnings/errors before running the existing high-risk behavior Pester suite.

## v0.8.6 - 2026-06-17

### Changed
- **Build provenance** -- package and exe builds now emit SHA256 manifests and provenance JSON; `build-exe.ps1` no longer auto-installs `ps2exe`, checks a minimum module version, records the `ps2exe` version, and labels unsigned exe artifacts clearly.

## v0.8.5 - 2026-06-17

### Added
- **Generated enterprise deployment kit** -- `build.ps1 -Package` now emits Intune detection/remediation scripts, an RMM JSON verification sample, a startup-task installer sample, a GPO task XML template, and a plain-text deployment checklist under `dist\deployment\`.

## v0.8.4 - 2026-06-17

### Added
- **Backup inventory and exact restore** -- `-ListBackups` lists saved SDDL backups, `-RestoreBackup -BackupFile` restores a selected file, and the GUI restore action now shows timestamped stack/file choices.

## v0.8.3 - 2026-06-17

### Added
- **Machine-readable fleet output** -- `-Query` and `-Report` now support `-OutputFormat Json` and `-OutputFormat Csv`, with stable `Computer`, `Adapter`, `GUID`, `Locked`, `Detail`, and `Mode` fields.

### Fixed
- **Partial remote-query resilience** -- remote fleet query now gathers usable rows per host and only returns no data when every queried host fails.

## v0.8.2 - 2026-06-17

### Changed
- **Responsive WPF operations** -- adapter refresh, lock, unlock, restore, and policy apply now run through background workers with busy-state controls and Dispatcher-marshaled UI updates.

## v0.8.1 - 2026-06-17

### Added
- **Full-stack WMI drift watcher** -- watcher installation now creates registry tree subscriptions for Tcpip, Tcpip6, and NetBT instead of a single Tcpip value-change query.
- **Policy application summaries** -- CLI and GUI policy application now report applied, dry-run, partial-skipped, missing, and failed target counts.

### Fixed
- **HTML report encoding** -- fleet reports encode host, adapter, GUID, mode, lock, and detail values before writing HTML.
- **Policy state safety** -- imported policies validate state, GUIDs, MACs, and duplicate identifiers; `partial` entries are skipped unless explicitly changed to `locked`.
- **Remediation exit truth** -- `-VerifyLocks -Remediate` now re-checks after remediation and exits success only when the final state is clean.
- **Task install fail-closed behavior** -- `-InstallTask` now refuses to register a dry-run startup task when the policy file is missing or invalid.

## v0.8.0 - 2026-06-16

### Added
- **Premium WPF shell polish** -- rebuilt the GUI hierarchy with a refined header, adapter counters, search summary, clearer action grouping, polished activity log, and status bar.
- **Empty/loading/error states** -- adapter scans now show deliberate scanning, no-results, no-adapters, and scan-failed states instead of an abrupt blank grid.
- **Styled safety dialogs** -- lock, unlock, restore, and DHCP warnings now use one cohesive in-app confirmation treatment instead of mixed Windows message boxes.
- **Pester 5-compatible tests** -- migrated assertions/mocks and added coverage for NetBT-aware lock badge derivation.

### Changed
- **Lock badge semantics** -- `LOCKED` now requires IPv4 plus every present applicable IPv6/NetBT key; NetBT mismatches show `PARTIAL` instead of overstating protection.
- **Policy microcopy** -- GUI buttons now read **Export Policy** and **Apply Policy** for clearer user intent.
- **Build validation** -- `build.ps1 -Validate` now pins Windows PowerShell-compatible PackageManagement/PowerShellGet modules and uses the Pester 5 configuration API when available.

## v0.7.0 - 2026-06-16

### Added
- **Comment-based help** -- `Get-Help .\AdapterLock.ps1 -Full` now shows synopsis, all parameters, and 6 usage examples.
- **Policy file schema validation** -- `Import-LockPolicy` validates Version field, Adapters array, and adapter identifiers before applying.
- **Lock integrity verifier** -- `-VerifyLocks` checks all locked adapters for ACL drift; `-Remediate` auto-fixes.
- **Adapter search/filter** -- real-time filter textbox above the DataGrid; matches name, description, MAC, IPv4, or GUID.
- **Remote lock-state query** -- `-Query -ComputerName host1,host2` reports lock state across remote hosts via `Invoke-Command`.
- **PSGallery metadata** -- PSScriptInfo block passes `Test-ScriptFileInfo`; `build.ps1` validates and packages.
- **PS2EXE build script** -- `build-exe.ps1` compiles the script to a standalone `.exe` via the `ps2exe` module.
- **Hidden/ghost adapter detection** -- "Show Hidden" toggle in the GUI reveals unplugged/virtual adapters with "(hidden)" label.
- **WMI drift watcher** -- `-InstallWatcher` creates a permanent WMI event subscription that logs registry changes to locked adapter keys (EventId 1002).
- **HTML fleet report** -- `-Report -ComputerName host1,host2 -OutputFile report.html` generates a self-contained dark-themed HTML report of lock state across remote hosts.

## v0.6.0 - 2026-06-16

### Added
- **PSScriptAnalyzer settings** - added `.vscode/PSScriptAnalyzer.psd1` with Windows PowerShell 5.1 compatibility rules.

### Fixed
- Renamed helper functions and event parameters so `Invoke-ScriptAnalyzer -Path .\AdapterLock.ps1 -Severity Error,Warning` returns zero findings.

## v0.5.0 - 2026-06-16

### Added
- **Pester coverage** - added `AdapterLock.Tests.ps1` covering lock-state detection, dry-run lock/unlock paths, adapter lookup, policy JSON round-trip, NIC type classification, and glyph mapping.

## v0.4.0 - 2026-06-16

### Added
- **SDDL restore** - `-RestoreBackup -Guid "{...}" -Silent` restores the latest saved ACL backup for an adapter; the GUI row context menu includes **Restore from Backup**.
- **DHCP safety checks** - the grid shows DHCP/Static mode, CLI locks log a warning for DHCP adapters, and GUI locks show a cancelable DHCP warning.
- **GUI action confirmation** - Lock and Unlock actions require confirmation, with a per-session "Don't ask again" option.

### Fixed
- Removed silently swallowed exceptions from elevation, event log setup, task cleanup, context menu row detection, policy export scan, and log-folder launch paths.
- SDDL backup filenames now include the IP stack name so IPv4 and IPv6 backups do not overwrite each other.

## v0.3.0 — 2026-04-26

### Added
- **JSON policy file** — `Export-LockPolicy` / `Import-LockPolicy`; Save/Load Policy buttons in GUI; declarative `{adapter, state}` for fleet deployment.
- **Scheduled enforcement task** — `Install-EnforcementTask` / `Uninstall-EnforcementTask` registers a Task Scheduler job that re-applies policy at startup.
- **Last-changed registry timestamp** — P/Invoke `RegQueryInfoKey` to read FILETIME from Tcpip key; displayed in new "Changed" column (yyyy-MM-dd HH:mm).
- **Adapter type glyphs** — replaces text (Phys/WiFi/Virt/Tunl/Loop) with Segoe MDL2 Assets icons (network / wifi / vm / vpn / arrow glyphs).
- **CLI policy loading** — `-LoadPolicy <file>` applies saved policy from the command line (compatible with Intune/SCCM).
- **CLI task management** — `-InstallTask [-PolicyFile <file>]` and `-UninstallTask` to manage scheduled enforcement from scripts.

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
