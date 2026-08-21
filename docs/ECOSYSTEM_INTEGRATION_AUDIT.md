# Ecosystem Integration Audit — 2026-08-21

Full audit of every framework integration in `packages/`, performed as part of
the ecosystem-growth mission. All test counts verified locally on this date.

## Verdict Summary

| Package | Version | Registry | Tests | Verdict |
|---------|---------|----------|-------|---------|
| `@aegis-kernel/langchain` | 1.1.0 | npm (published as 1.0.x line) | ✅ 5/5 | **Healthy** |
| `@aegis-kernel/openai` | 1.1.0 | npm | ✅ 4/4 | **Healthy** |
| `@aegis-kernel/anthropic` | 1.1.0 | npm | ✅ 4/4 | **Healthy** |
| `@aegis-kernel/vercel-ai` | 1.1.0 | npm | ✅ 4/4 | **Healthy** |
| `@aegis-kernel/mcp` | 1.1.0 | npm | ✅ 10/10 | **Healthy** |
| `aegis-kernel` (Python, incl. basic adapters) | 1.1.0 | PyPI | ✅ 11/11 | **Healthy** |
| `aegis-kernel-crewai` *(new)* | 1.1.0 | PyPI publish pending | ✅ 11/11 | **Ready to publish** |
| `aegis-kernel-autogen` *(new)* | 1.1.0 | PyPI publish pending | ✅ 16/16 | **Ready to publish** |
| `aegis-kernel-browser-guard` *(new)* | 1.1.0 | PyPI publish pending | ✅ 23/23 | **Ready to publish** |

## Detailed Findings

### `@aegis-kernel/langchain`
- **Surface:** `AegisLangChainGuard.wrap(tool)` — monkey-patches `invoke`/`call`
  on `StructuredTool`-shaped objects; throws tagged
  `[Aegis Safety Violation]` errors with `suggestedFix`.
- **State:** Solid. Accepts either an `AegisConfig` or a shared `AegisEngine`
  (good for cross-tool policy commitment).

### `@aegis-kernel/openai`
- **Surface:** `AegisOpenAIGuard.evaluate(toolCall)` +
  `handleToolCall(toolCall, executor)` which emits a well-formed
  `{role:'tool', tool_call_id, content}` message on block — the model
  self-corrects on the next turn. Malformed JSON arguments degrade safely to
  `{raw: arguments}` instead of bypassing evaluation.

### `@aegis-kernel/anthropic`
- **Surface:** mirrors the OpenAI guard for Claude `tool_use` blocks →
  `tool_result` with `is_error` semantics. Consistent with the rest of the family.

### `@aegis-kernel/vercel-ai`
- **Surface:** `wrapTool` / `wrapVercelTool` around AI SDK `execute` tools.
  Generic over params/result types.

### `@aegis-kernel/mcp`
- **Surface:** richest adapter — `wrapToolHandler`, `pinToolDefinition` +
  `verifyToolSchema` (rug-pull detection), `MCPToolPoisoningScanner`
  (zero-width Unicode payloads, injection heuristics, OWASP ASI02 signals),
  `SchemaRugPullDetector` with fingerprint registry.

### `aegis-kernel` (Python) — basic adapters
- `AegisCrewAITool`, `wrap_autogen_function`, `AegisLangChainTool` remain in
  the core package for zero-extra-install use. The new dedicated packages
  (below) supersede them for turn-key deployments and are the recommended path;
  the core adapters stay for backward compatibility.

### New in this audit cycle

- **`packages/crewai/` → `aegis-kernel-crewai`** — `guard_crew` /
  `guard_agent` / `guard_tool` / `@aegis_crewai_tool`; single shared policy
  commitment per crew; `AEGIS_BLOCKED` self-healing feedback (default) or
  `on_block="raise"`.
- **`packages/autogen/` → `aegis-kernel-autogen`** — AutoGen legacy
  (`guard_function_map`) and ≥0.4 (`guard_tool`/`AegisGuardedFunctionTool`
  with `run_json` + schema passthrough), plus Microsoft Semantic Kernel
  function-invocation filter (`add_aegis_filter(kernel)`).
- **`packages/browser-guard/` → `aegis-kernel-browser-guard`** — Browser-Use
  controller hardening, OpenManus `execute` wrapping, `BrowserPolicy` with
  rules BROWSER-001…011 (zero-width smuggling, dangerous schemes, IP literals,
  punycode homographs, URL credentials, domain lists, keystroke secret scan,
  executable downloads, sensitive uploads).

## Gaps / Follow-ups

1. **Publish the three new packages to PyPI** (wheels build clean via
   `python -m build`; wired into `python-package.yml`).
2. **Publish `packages/rust` to crates.io** — currently unpublished, which is
   the root cause of the awesome-rust PR #2718 CI failure
   (see `docs/DISTRIBUTION_STATUS.md`, Playbook A).
3. npm `@aegis-kernel/core` latest is 1.0.0 while the monorepo is at 1.1.0 —
   cut the 1.1.0 npm release when ready.
4. Consider a TS-side CrewAI adapter if/when CrewAI's TypeScript port matures
   (not warranted today).
