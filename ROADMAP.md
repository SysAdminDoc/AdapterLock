# AdapterLock Roadmap

Per-adapter IP lockdown for Windows via registry ACL deny ACEs.

## Research-Driven Additions

### P2

### P3

- [ ] P3 -- Add an optional compact read-only status mode
  Why: NetSetMan and Net Profiles mod show tray/compact status value, but AdapterLock should expose this only as read-only enforcement visibility, not profile switching.
  Evidence: NetSetMan compact/tray documentation; Net Profiles mod tray enhancement issues #71/#72.
  Touches: `AdapterLock.ps1`, `README.md`.
  Acceptance: optional compact mode shows lock counts, selected adapter detail, last drift event, and open log/report actions without adding background profile switching or new persistent services.
  Complexity: L
