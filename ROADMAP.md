# AdapterLock Roadmap

Per-adapter IP lockdown for Windows via registry ACL deny ACEs. Planned work focuses on scale, audit, and remote enforcement for fleets of locked modality/kiosk hosts.

## Planned Features

## Core locking engine
- [x] **IPv4 + IPv6 parity verification** — `Test-AdapterLockedDetailed` returns per-stack lock state; LockBadge: `LOCKED` / `PARTIAL` / `Unlocked` (PARTIAL = mismatch); tooltip shows `v4 + v6`, `v4 only (!)`, etc. _(v0.2.0)_
- [x] **NetBT key locking** — `Get-InterfaceKeyPaths` now includes `NetBT\Parameters\Interfaces\Tcpip_{GUID}` so NetBIOS name resolution is also locked. _(v0.2.0)_
- [ ] **Gateway + DNS + WINS key locking** — extend deny ACE to remaining resolver keys (`DhcpDefaultGateway`, DNS suffix list)
- [ ] **DHCP-lease force-renew guard** — lock `DhcpIPAddress`, `DhcpSubnetMask`, `DhcpDefaultGateway`
- [ ] **Static vs DHCP lock modes** — one-click toggle (freeze static config vs freeze DHCP lease)
- [ ] **Lock integrity verifier** — scheduled task that re-reads ACLs and logs/remediates drift

### UX / GUI
- [x] **NIC type column** — shows Phys / WiFi / Virt / Tunl / Loop _(v0.2.0)_
- [x] **Per-row context menu** — right-click: Lock, Unlock, Open in ncpa.cpl, Copy MAC, Copy GUID; PreviewMouseRightButtonDown ensures correct row is selected _(v0.2.0)_
- [ ] **Adapter icon column** — replace text NIC type with icon glyph
- [ ] **Last-changed timestamp** — from registry key `LastWriteTime` (requires P/Invoke on PS 5.1)
- [ ] **Dark Catppuccin Mocha theme** — ComboBox ControlTemplate (not needed until a ComboBox is added)
- [x] **Log viewer pane** — tails `adapterlock.log` inside the GUI _(v0.0.1)_

### Fleet / enterprise
- [x] **`-Silent` CLI mode** — `AdapterLock.ps1 -Lock -Adapter "Ethernet" -Silent` for Intune / SCCM / GPO startup script deployment _(v0.2.0)_
- [x] **`-DryRun` preview mode** — logs exact ACE changes that would be applied; does not commit _(v0.2.0)_
- [ ] **JSON policy file** — declarative `{adapter: mac|guid|name, state: locked|unlocked}` consumed by GUI and CLI
- [ ] **Scheduled enforcement task installer** — Task Scheduler job that re-applies policy on boot / every N minutes
- [x] **Event Log channel** — Lock/Unlock events written to Windows Application log, source `AdapterLock`, EventId 1001 _(v0.2.0)_

### Safety
- [x] **Rollback snapshot** — SDDL of all adapter keys saved to `%ProgramData%\AdapterLock\Backups\{Guid}.{keyTag}.{timestamp}.sddl` before any ACL change _(v0.2.0)_

## Competitive Research

- **NetSetMan / TCPIPConfig tools** — focus on fast profile switching, not lockdown. Gap: none enforce immutability at the ACL level.
- **Microsoft `NC_LanProperties` GPO** — disables TCP/IP properties dialog, bypassable by admins and by `netsh`. AdapterLock is specifically designed to survive admin bypass.
- **Group Policy Preferences > TCP/IP Settings** — applies settings periodically but does not prevent local override between refresh cycles. AdapterLock complements this by freezing the key itself.
- **Intune `Network Connection` CSP** — vendor-locked, cloud-only, no per-adapter granularity. Opportunity: AdapterLock as the on-device enforcement layer referenced by Intune compliance scripts.

## Nice-to-Haves

- **WMI event subscriber** — watches for `MSFT_NetIPAddress` change attempts and writes a structured audit record
- **Remote query mode** — `Invoke-Command` wrapper that reports lock state across a list of machines
- **Driver-level guard** — optional kernel filter driver (WFP callout) for environments that cannot tolerate even the transient window of `WRITE_DAC` removal
- **PowerShell module** — publish as `AdapterLock` on PSGallery with pester tests
- **HTML report generator** — fleet-wide lock-state dashboard (adapter × host matrix) exported as a single-file HTML
- **Integration with NVMe Driver Patcher watchdog service** — shared Windows Service host that also enforces adapter locks in real time

## Open-Source Research (Round 2)

### Related OSS Projects
- **microsoft/Network-Adapter-Class-Extension** — https://github.com/microsoft/Network-Adapter-Class-Extension — NetAdapterCx source; `KRegKey.h` and `KSpinLock.h` wrappers are a reference for kernel-side registry-access patterns.
- **devops-collective-inc/powershell-networking-guide** — https://github.com/devops-collective-inc/powershell-networking-guide — Canonical reference for `Get-NetAdapter` / `Set-NetIPInterface` ergonomics to match in the UI.
- **alexjebens/ghost-network-adapters-powershell.ps1** (gist) — https://gist.github.com/alexjebens/a027f8757348bdacbcbb5aa85612d045 — PnP-device enumeration pattern for hidden/ghost NICs that still have registered interface GUIDs.
- **akahobby/All-in-One-Network-Optimizer** — https://github.com/akahobby/All-in-One-Network-Optimizer — PowerShell WPF precedent for registry-backup-and-rollback UX; worth cribbing the backup-folder layout.
- **microsoft/winget-pkgs** + `sc.exe` pattern (general) — reference for how to survive silent automation when user profile is locked down.

### Features to Borrow
- **PnP-aware adapter enumeration** (ghost-adapter gist) — show hidden/unplugged adapters that still have configured GUIDs, with a "Lock even though currently disconnected" option. Common in PACS environments where a DICOM NIC is unplugged during maintenance.
- **Registry ACL backup-before-change** (All-in-One-Network-Optimizer) — dump the current SDDL of the interface key to `%ProgramData%\AdapterLock\Backups\{Guid}.{timestamp}.sddl` before applying the Deny ACE, so Unlock is recoverable even if the tool is deleted.
- **Friendly-name + MAC + GUID display** (powershell-networking-guide) — any UI that shows only GUIDs is unusable; every Lock/Unlock row should show `InterfaceAlias / MacAddress / InterfaceGuid / Status / LockState`.
- **Dry-run / "What would Lock do?"** — Preview the exact SDDL delta before writing, rendered as a diff. Borrows from Blocky-style dry-run and is critical for medical imaging audits.
- **DHCP-vs-static lock mode** — two distinct lock flavors: "freeze current IP assignment" vs "freeze DHCP mode"; second mode is useful when a site wants a modality to always renew via DHCP but not be manually overridden.
- **Audit log to Windows Event Log + append-only JSONL** — every Lock/Unlock writes `System` or custom channel event with user SID + hostname + GUID + before/after SDDL.

### Patterns & Architectures Worth Studying
- **`Set-Acl` + `RegistrySecurity` over `[System.Security.AccessControl]`** (PowerShell Networking Guide) — prefer .NET `RegistrySecurity` with `RegistryAccessRule(Deny)` over `subinacl.exe` or raw `icacls` for testability and to avoid shelling out.
- **Kernel-view-of-the-same-key** (NetAdapterCx KRegKey.h) — study which registry values the OS actually reads at adapter bring-up (`NameServer`, `EnableDHCP`, `IPAddress`, `SubnetMask`, `Domain`, `DhcpDefaultGateway`) so Lock can target only IP-config values instead of the entire interface key, letting WINS/netbios still be adjusted.
- **Separate Tcpip vs Tcpip6 handling** — the Tcpip6 path is frequently missed; mirror the AdGuard-Home-style "dual-stack" attitude from day one.
- **WPF + `[PowerShell]::Create()`+`BeginInvoke()`** (All-in-One-Network-Optimizer) — async pattern for the Lock/Unlock call so the UI doesn't freeze on slow ACL propagation across many interfaces.
- **Group Policy export** — emit a `.pol` / ADMX template that a domain admin can push; useful because site-wide deployment is the real target market.
