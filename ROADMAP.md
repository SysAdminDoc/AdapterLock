# AdapterLock Roadmap

Per-adapter IP lockdown for Windows via registry ACL deny ACEs.

## Research-Driven Additions

### P2

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
