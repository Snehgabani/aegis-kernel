# Changelog — aegis-kernel-browser-guard

## 1.1.0 (2026-08-21)

### Features

- Initial release of the turn-key Browser-Use / OpenManus browser-agent guard.
- `BrowserPolicy` — declarative navigation/input/file policy with SHA-256 commitment hash.
- `AegisBrowserGuard.evaluate_action` — deterministic clearance across the browser action taxonomy (navigate, type, download, upload, generic).
- Rules `BROWSER-001…011`: zero-width URL smuggling, dangerous schemes, IP literals, punycode homographs, embedded credentials, domain allow/deny lists, keystroke secret/PII scan, executable download blocking, sensitive upload paths.
- `guard_browser_use_controller` — one-line in-place hardening of a Browser-Use `Controller` registry.
- `guard_openmanus_tool` — wraps OpenManus `execute(action=...)` tools.
- `guard_browser_action` — generic sync/async action wrapper; `on_block="raise"` strict mode; `mode="monitor"` staged rollout.
