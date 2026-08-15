# 🤖 Autonomous AI Agent Instructions & Operating Manual (AGENTS.md)

This file contains operational instructions for all autonomous AI coding agents (including **Devin**, **Claude Code**, **Antigravity**, **OpenHands**, **Cursor**, and **Aider**) working inside the **Aegis Invariant Kernel** repository.

---

## 🎯 Primary Directives

1. **Safety & Zero-Egress Invariant**: Never add external HTTP calls or telemetric egress to `packages/core`. All evaluations must be purely local and deterministic.
2. **ReDoS Immunity**: Every regex pattern must be linear $O(N)$ with zero catastrophic backtracking. Prefer tokenizers or single-pass state machines.
3. **Process Reward Verification**: Always run `npm run build && npm run test` before finalizing any edit. Never commit code that breaks any of the 47 test suites.
4. **Sub-1.5ms Performance**: Ensure benchmark tests in `packages/evals` maintain $\ge 100\%$ F1 score and $P_{95} < 5\text{ms}$.

---

## 🛠️ Monorepo Quick Reference

| Package | Path | Purpose |
| :--- | :--- | :--- |
| `@aegis-kernel/core` | `packages/core` | Core runtime engine, AST checkers, HMAC proofs, GRC exporter |
| `@aegis-kernel/cli` | `packages/cli` | Command-line tool (`aegis init`, `scan`, `test`, `doctor`) |
| `@aegis-kernel/mcp` | `packages/mcp` | Model Context Protocol security proxy and tool poisoning scanner |
| `@aegis-kernel/langchain` | `packages/langchain` | LangChain / LangGraph tool call interceptor |
| `@aegis-kernel/openai` | `packages/openai` | OpenAI SDK tool call wrapper |
| `@aegis-kernel/anthropic` | `packages/anthropic` | Anthropic Claude SDK tool call wrapper |
| `@aegis-kernel/evals` | `packages/evals` | Adversarial testbed (100 tricky attack vectors) |
| `@aegis-kernel/diagnostics` | `packages/diagnostics` | Subsystem diagnostic suite (`AegisDiagnostics`) |

---

## 🧪 Verification Loop

Before submitting or pushing changes, run this complete verification sequence:

```bash
# 1. Build and verify type consistency
npm run build

# 2. Run all unit and integration tests
npm run test

# 3. Verify repository health
node packages/cli/bin/aegis.js doctor

# 4. Verify all 25 operational subsystems
node scripts/live-e2e-proof.mjs
```
