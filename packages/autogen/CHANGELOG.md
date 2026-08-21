# Changelog — aegis-kernel-autogen

## 1.1.0 (2026-08-21)

### Features

- Initial release of the turn-key AutoGen + Semantic Kernel middleware.
- `guard_function` — sync/async AutoGen tool-function wrapper with metadata preservation for schema derivation.
- `guard_tool` / `AegisGuardedFunctionTool` — duck-typed autogen-core `FunctionTool` wrapper (`run`, `run_json`, `schema`).
- `guard_function_map` / `guard_agent` — in-place hardening for legacy `pyautogen`/AG2 executors and modern agents.
- `AegisSemanticKernelFilter` / `aegis_invocation_filter` / `add_aegis_filter` — Semantic Kernel function-invocation filter with short-circuit blocking.
- Structured `AEGIS_BLOCKED` self-healing payloads (default) and `on_block="raise"` strict mode.
