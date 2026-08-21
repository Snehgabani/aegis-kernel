# Changelog — aegis-kernel-crewai

## 1.1.0 (2026-08-21)

### Features

- Initial release of the turn-key CrewAI middleware.
- `guard_tool` / `guard_tools` — duck-typed `BaseTool` wrappers preserving `name`, `description`, `args_schema`.
- `guard_agent` / `guard_crew` — one-line hardening of agents and full crews under a single shared policy commitment.
- `@aegis_crewai_tool` decorator for plain-function tools (sync + async).
- Structured `AEGIS_BLOCKED:` self-healing feedback mode (default) and `on_block="raise"` strict mode.
- SHA-256 proof hash + policy commitment hash on every verdict.
