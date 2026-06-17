# AdapterLock Roadmap

Per-adapter IP lockdown for Windows via registry ACL deny ACEs.

## Research-Driven Additions

### P1

- [ ] P1 -- Add backup inventory and exact restore selection
  Why: Restore currently chooses the latest matching SDDL backup per key, which is not enough for rollback after repeated lock/unlock attempts.
  Evidence: `AdapterLock.ps1:560`, `AdapterLock.ps1:574`, `README.md:141`.
  Touches: `AdapterLock.ps1`, `AdapterLock.Tests.ps1`, `README.md`.
  Acceptance: CLI exposes `-ListBackups` and exact backup selection, GUI restore shows timestamp/key/source choices before applying, and tests cover latest and explicit restore paths.
  Complexity: M

- [ ] P1 -- Ship an enterprise deployment kit without requiring credentials
  Why: The target users deploy through Intune, SCCM, GPO startup scripts, and RMMs, but the repo has no ready detection/remediation package or task XML.
  Evidence: `README.md:79`, `README.md:115`, Microsoft Intune Remediations, PDQ/NinjaOne deployment docs.
  Touches: `AdapterLock.ps1`, `build.ps1`, `README.md`.
  Acceptance: release artifacts include sample Intune detection/remediation commands, GPO scheduled-task XML or documented commands, RMM-safe exit-code guidance, and a minimal deployment checklist that does not require PSGallery or a signing certificate.
  Complexity: M

- [ ] P1 -- Harden exe/package build provenance
  Why: `build-exe.ps1` auto-installs `ps2exe` and emits no SHA256 or provenance manifest for the unsigned executable.
  Evidence: `build-exe.ps1:11`, `build-exe.ps1:23`; Simple IP Config unknown-publisher and Defender issue signals.
  Touches: `build-exe.ps1`, `build.ps1`, `README.md`.
  Acceptance: builds require an explicit ps2exe prerequisite or pinned version check, emit SHA256 hashes for script/zip/exe artifacts, record ps2exe version, and clearly label unsigned artifacts until code signing is available.
  Complexity: M

- [ ] P1 -- Gate builds with analyzer and high-risk behavior tests
  Why: README documents ScriptAnalyzer, but `build.ps1` does not run it; current tests miss report encoding, watcher WQL, policy state safety, and remediation exit behavior.
  Evidence: `README.md:151`, `build.ps1:29`, `build.ps1:44`, `AdapterLock.Tests.ps1:252`.
  Touches: `build.ps1`, `.vscode/PSScriptAnalyzer.psd1`, `AdapterLock.Tests.ps1`.
  Acceptance: `.\build.ps1 -Validate` runs PSScriptAnalyzer with repo settings and fails on warnings/errors, and Pester covers WMI watcher coverage, HTML encoding, policy validation/apply planning, task fail-closed behavior, and remediate re-check.
  Complexity: M

### P2

- [ ] P2 -- Centralize local and remote lock-state evaluation
  Why: Remote query duplicates the local ACL/key-state logic, so future stack or identity-rule changes can drift.
  Evidence: `AdapterLock.ps1:610`, `AdapterLock.ps1:821`.
  Touches: `AdapterLock.ps1`, `AdapterLock.Tests.ps1`.
  Acceptance: local UI, CLI verify, HTML/JSON/CSV report, and remote query use one shared lock-state schema with identical `LOCKED`/`PARTIAL`/`Unlocked` semantics.
  Complexity: M

- [ ] P2 -- Add CLI adapter discovery and ambiguity feedback
  Why: CLI users must know exact names, MACs, or GUIDs before acting, while competitor and community issues show adapter discovery/refresh is a recurring failure point.
  Evidence: `AdapterLock.ps1:1137`, `AdapterLock.ps1:1144`; Simple IP Config issue #206; Net Profiles mod dynamic-interface issue #75.
  Touches: `AdapterLock.ps1`, `AdapterLock.Tests.ps1`, `README.md`.
  Acceptance: `-ListAdapters -Silent` outputs visible/hidden adapter identifiers in table/JSON modes, failed matches include nearest visible candidates, and ambiguous names do not perform ACL writes.
  Complexity: S

- [ ] P2 -- Add accessibility and compact-layout regression checks
  Why: The v0.8.0 UI was render-checked manually, but there is no repeatable focus/name/contrast/overflow guard.
  Evidence: `CLAUDE.md:43`; Simple IP Config scaling issues #181/#204/#209.
  Touches: `AdapterLock.ps1`, `build.ps1`, test tooling.
  Acceptance: validation captures at least compact and default WPF layouts, checks no clipped primary controls, verifies focusable controls have names/tooltips, and records any manual-only accessibility gaps.
  Complexity: M

- [ ] P2 -- Add PowerShell `SupportsShouldProcess` compatibility around state changes
  Why: AdapterLock has `-DryRun`, but PowerShell admins expect `-WhatIf`/`-Confirm` semantics for registry ACL changes.
  Evidence: `Lock-Adapter` and `Unlock-Adapter` state changes at `AdapterLock.ps1:680`, `AdapterLock.ps1:725`; PowerShell ShouldProcess guidance.
  Touches: `AdapterLock.ps1`, `AdapterLock.Tests.ps1`, `README.md`.
  Acceptance: state-changing CLI paths support `-WhatIf` without writes, existing `-DryRun` behavior remains compatible, and tests prove no `Set-Acl` call occurs under preview modes.
  Complexity: M

### P3

- [ ] P3 -- Add an optional compact read-only status mode
  Why: NetSetMan and Net Profiles mod show tray/compact status value, but AdapterLock should expose this only as read-only enforcement visibility, not profile switching.
  Evidence: NetSetMan compact/tray documentation; Net Profiles mod tray enhancement issues #71/#72.
  Touches: `AdapterLock.ps1`, `README.md`.
  Acceptance: optional compact mode shows lock counts, selected adapter detail, last drift event, and open log/report actions without adding background profile switching or new persistent services.
  Complexity: L
