# Research -- AdapterLock

## Executive Summary
AdapterLock is a Windows PowerShell 5.1/WPF administrative utility that locks one adapter's IP configuration by applying registry Deny ACEs to the adapter's `Tcpip`, `Tcpip6`, and `NetBT` keys. Its strongest current shape is not another network profile switcher; it is an enforcement, rollback, and audit tool for PACS, X-ray, lab, kiosk, and industrial hosts where one interface must not drift. Verified highest-value direction: harden the enforcement loop and fleet trust surface before adding convenience features. Top opportunities, in order: fix WMI drift watcher coverage and event class choice; make policy import/apply state-safe; encode HTML reports; make `-VerifyLocks -Remediate` re-check and return success only when clean; fail closed when installing enforcement without a policy; move WPF scan/lock work off the UI thread; add machine-readable fleet output; expose backup selection; add enterprise deployment artifacts; and gate release builds with analyzer/report/policy tests.

## Product Map
- Core workflows: scan adapters and lock/unlock selected registry keys; export/apply JSON lock policies; verify/remediate drift; restore saved SDDL backups; query/report remote hosts.
- User personas: imaging/biomed/PACS admins, lab and industrial support techs, kiosk admins, Windows endpoint admins using Intune/SCCM/GPO/RMM.
- Platforms and distribution: Windows 10/11/Server 2016+, Windows PowerShell 5.1+, single `AdapterLock.ps1`, optional ps2exe build, MIT license.
- Key integrations and data flows: `Get-NetAdapter` -> registry ACL reads/writes -> SDDL backups in `%ProgramData%\AdapterLock\Backups\`; events/logs to Application Event Log and `%APPDATA%\AdapterLock\adapterlock.log`; remote query through PowerShell remoting; HTML report export.

## Competitive Landscape
- NetSetMan: strong profile UX, activation progress, tray/compact modes, Wi-Fi/location auto-switch, and administration controls. Learn from its progress/log feedback and adapter reassignment behavior; avoid becoming a broad profile-switching suite.
- Simple IP Config: popular OSS portable IP profile changer with active user pain around adapter refresh, UI scaling, unsigned/unknown publisher trust, and Defender false positives. Learn from these trust and adapter-discovery failures; avoid duplicating its editable-profile surface.
- Net Profiles mod: OSS Windows profile tool with UAC/service, tray affordances, dynamic interface requests, and multi-IP/gateway feature demand. Learn from limited-user and changing-NIC scenarios; avoid inherited fragility from broad profile activation.
- TCP/IP Manager, Argon Network Switcher, and Free IP Switcher: older profile-switching tools show that profile storage, one-click activation, portability, and printer/proxy/script extras are table stakes in that category. AdapterLock should intentionally stay narrower and own enforcement/rollback.
- Microsoft GPO/CSP and Intune Remediations: GPO can hide or restrict all LAN properties, and Intune models detection/remediation as reportable scripts. Learn packaging and reporting patterns; do not claim native policy can replace AdapterLock's per-adapter ACL enforcement.
- NetworkingDsc: mature declarative network configuration with resources for IP, DNS, gateway, NetBIOS, routes, bindings, and release discipline. Learn from desired-state tests and examples; avoid taking a module dependency that breaks AdapterLock's single-file operational model.
- RMM/deployment tools such as PDQ, NinjaOne, and ManageEngine: endpoint tools expect script exit codes, logs, custom fields, and machine-readable output. Learn from their reporting surfaces; avoid vendor-specific coupling.

## Security, Privacy, and Reliability
- Verified: `Install-WmiWatcher` watches only `Tcpip\Parameters\Interfaces\%` with `RegistryValueChangeEvent` (`AdapterLock.ps1:405`, `AdapterLock.ps1:429`), while lock state covers `Tcpip`, `Tcpip6`, and `NetBT` (`AdapterLock.ps1:612`). Microsoft documents `RegistryTreeChangeEvent` for key hierarchies and `RegistryValueChangeEvent` for a single value, so the current watcher is likely incomplete and may be semantically wrong.
- Verified: `Export-LockReport` interpolates remote computer, adapter, GUID, mode, lock, and detail fields directly into HTML (`AdapterLock.ps1:915`, `AdapterLock.ps1:922`). OWASP output-encoding guidance applies because remote adapter names and host strings are untrusted report content.
- Verified: `Export-LockPolicy` records `partial` state (`AdapterLock.ps1:315`, `AdapterLock.ps1:321`), but CLI and GUI policy apply lock every imported entry regardless of `State` (`AdapterLock.ps1:1075`, `AdapterLock.ps1:2125`). That can turn a partial diagnostic snapshot into a full enforced lock.
- Verified: `Import-LockPolicy` validates `Version`, `Adapters`, and at least one identifier (`AdapterLock.ps1:345`, `AdapterLock.ps1:356`), but not state enum, GUID/MAC shape, duplicate targets, or unknown fields. Tests cover only missing version/adapters/id (`AdapterLock.Tests.ps1:160`).
- Verified: `Install-EnforcementTask` silently installs a startup task that runs `-DryRun -Silent` when no policy file is found (`AdapterLock.ps1:371`, `AdapterLock.ps1:379`). That creates a false sense of enforcement.
- Verified: `-VerifyLocks -Remediate` logs remediation but exits `1` whenever pre-remediation drift was found (`AdapterLock.ps1:1091`, `AdapterLock.ps1:1100`). For Intune/RMM usage, remediation should be followed by a second verification and exit `0` only if clean.
- Likely: GUI refresh and lock/unlock are synchronous on the WPF UI thread (`AdapterLock.ps1:1999`, `AdapterLock.ps1:2007`, `AdapterLock.ps1:2075`). WPF threading guidance recommends background work with Dispatcher marshaling; live freeze needs validation on a host with slow WMI/registry calls.
- Verified: `build-exe.ps1` auto-installs `ps2exe` without version pinning (`build-exe.ps1:11`) and emits an unsigned exe without hash/signature metadata (`build-exe.ps1:23`). Code signing is blocked in `Roadmap_Blocked.md`, but deterministic build inputs and SHA256 manifests are not blocked.

## Architecture Assessment
- Centralize lock-state evaluation. `Test-AdapterLockedDetailed` and `Invoke-RemoteLockQuery` duplicate ACL/key logic (`AdapterLock.ps1:610`, `AdapterLock.ps1:821`), raising drift risk as stack coverage changes.
- Separate policy import, validation, planning, and execution. Current import returns raw adapter objects (`AdapterLock.ps1:332`) and apply loops perform immediate locks (`AdapterLock.ps1:1079`, `AdapterLock.ps1:2127`), leaving no dry-run diff, warning summary, or deterministic partial-state behavior.
- Make drift detection an explicit desired-state loop. `Test-LockIntegrity` currently marks drift and optionally calls `Lock-Adapter` (`AdapterLock.ps1:789`, `AdapterLock.ps1:810`) but does not return post-fix truth.
- Add report and policy security tests. The current HTML test checks structure only (`AdapterLock.Tests.ps1:252`) and policy tests do not cover `partial`, invalid state, duplicate identifiers, or GUID/MAC validation.
- Add release and analyzer gates. README documents `Invoke-ScriptAnalyzer` (`README.md:151`), but `build.ps1` validates metadata/help/Pester only (`build.ps1:29`, `build.ps1:44`).
- Accessibility and responsiveness remain partially verified. v0.8.0 claims WPF render checks in `CLAUDE.md:43`, but there is no automated UIA/focus/contrast regression or background worker test.
- Category coverage: security, reliability, observability, testing, docs, distribution, offline recovery, upgrade strategy, and accessibility all map to actionable items. i18n/l10n, plugin ecosystem, mobile, cloud multi-user, kernel drivers, and full profile switching are rejected below because they conflict with the single-file Windows enforcement tool philosophy or require external gates.

## Rejected Ideas
- Full IP profile switcher, with printer/proxy/Wi-Fi/scripts: rejected because NetSetMan, Simple IP Config, Net Profiles mod, TCP/IP Manager, Argon, and Free IP Switcher already occupy profile switching; AdapterLock's unique value is immutable per-adapter enforcement.
- Per-value static-vs-DHCP lock modes: rejected because repo research already records Windows registry ACLs as key-level, not per-value, in `Roadmap_Blocked.md:29`.
- Kernel/WFP driver guard: rejected because `Roadmap_Blocked.md:19` documents WHQL/signing/driver complexity that contradicts the single-file PowerShell tool.
- Cloud service, multi-user console, or plugin ecosystem: rejected because no current code, docs, or competitor evidence shows this product needs a hosted control plane; Intune/RMM/GPO integrations cover fleet operation with less risk.
- Mobile or cross-platform support: rejected because enforcement depends on Windows registry ACLs and PowerShell/WPF.
- Broad localization: rejected for now because the product targets technical Windows admins, has no resource system, and higher-risk reliability work is more urgent; keep strings concise and accessible instead.
- Bundling NetworkingDsc or a profile-switching dependency: rejected because it would add module/version friction to a deliberately portable single-script tool.

## Sources
### Project
- https://github.com/SysAdminDoc/AdapterLock

### Competitors and Adjacent Tools
- https://www.netsetman.com/en/help?hf=en
- https://www.netsetman.com/en/freeware
- https://github.com/KurtisLiggett/Simple-IP-Config
- https://github.com/KurtisLiggett/Simple-IP-Config/issues/206
- https://github.com/KurtisLiggett/Simple-IP-Config/issues/210
- https://github.com/netprofilesmod/netprofilesmod
- https://github.com/netprofilesmod/netprofilesmod/issues/66
- https://github.com/netprofilesmod/netprofilesmod/issues/75
- https://tcpipmanager.sourceforge.io/
- https://sourceforge.net/projects/argonswitcher/
- https://www.eusing.com/ipswitch/fishelp.htm
- https://github.com/dsccommunity/NetworkingDsc
- https://github.com/microsoft/PowerToys/issues/42029

### Platform, Standards, and Security
- https://learn.microsoft.com/en-us/windows/win32/wmisdk/registering-for-system-registry-events
- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/regprov/registrytreechangeevent
- https://powershell.one/wmi/root/default/registryvaluechangeevent
- https://learn.microsoft.com/en-us/windows/win32/wmisdk/receiving-a-wmi-event
- https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl
- https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-networkconnections
- https://learn.microsoft.com/en-us/intune/device-management/tools/deploy-remediations
- https://learn.microsoft.com/en-us/dotnet/desktop/wpf/advanced/threading-model
- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- https://attack.mitre.org/techniques/T1546/003/
- https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/persistence_sysmon_wmi_event_subscription

### Distribution, Testing, and Community Signal
- https://github.com/MScholtes/PS2EXE
- https://github.com/PowerShell/PSScriptAnalyzer
- https://pester.dev/docs/quick-start
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_signing
- https://www.pdq.com/blog/powershell-automation-for-sysadmins/
- https://www.ninjaone.com/docs/endpoint-management/custom-fields/advanced-custom-fields/

## Open Questions
- None block prioritization. Authenticode signing and PSGallery publishing remain credential-gated in `Roadmap_Blocked.md`.
