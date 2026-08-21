# Distribution & Ecosystem Status

> Living document maintained by Developer Relations. Automated daily by
> [`distribution-watch.yml`](../.github/workflows/distribution-watch.yml) →
> `node scripts/check-distribution-prs.mjs`.
>
> **Last manual audit: 2026-08-21**

---

## 1. Awesome-List Submissions

| List | PR | State | Checks | Action Needed |
|------|----|-------|--------|---------------|
| [rust-unofficial/awesome-rust](https://github.com/rust-unofficial/awesome-rust) | [#2718](https://github.com/rust-unofficial/awesome-rust/pull/2718) | 🟡 OPEN | ❌ `build` failing | **Yes — see playbook A** |
| [e2b-dev/awesome-ai-agents](https://github.com/e2b-dev/awesome-ai-agents) | [#1416](https://github.com/e2b-dev/awesome-ai-agents/pull/1416) | 🟡 OPEN | ❌ `verification/cla-signed` | **Yes — see playbook B** |
| [corca-ai/awesome-llm-security](https://github.com/corca-ai/awesome-llm-security) | [#296](https://github.com/corca-ai/awesome-llm-security/pull/296) | 🟢 OPEN | ✅ CodeRabbit passing | Awaiting maintainer review |

### Playbook A — awesome-rust #2718 (`build` check failure)

**Root cause (verified 2026-08-21):** the PR entry links
`[[aegis-kernel](https://crates.io/crates/aegis-kernel)]`, but the crate is
**not published on crates.io** (`GET /api/v1/crates/aegis-kernel` → 404). The
awesome-rust CI's link checker validates every crates.io link, so the `build`
job fails deterministically on our line.

Fix (either):
1. **Preferred:** publish `packages/rust/` (name `aegis-kernel`, v1.1.0) to
   crates.io — `cargo publish` with the crates.io token (see
   `.github/workflows/rust-crate.yml`), then re-run the PR checks.
2. Or amend the PR entry to drop the `[[aegis-kernel](https://crates.io/...)]`
   crate badge until publication.

> Note: the README crates.io badge in this repo also 404s until the crate is
> published — publishing resolves both.

### Playbook B — e2b awesome-ai-agents #1416 (CLA)

The `cla-bot` requires @Snehgabani's signature; the CLA portal
(`https://cla.e2b.dev`) was returning an OAuth `error=Configuration` at last
attempt (comment already left on the PR). Retry the signature periodically,
then comment `@cla-bot check` on the PR. If the portal stays broken >1 week,
open an issue on `e2b-dev/awesome-ai-agents` referencing the PR.

### Playbook C — corca-ai awesome-llm-security #296

All checks green; no action beyond a polite maintainer ping if idle >30 days.

---

## 2. Registry Presence (audited 2026-08-21)

| Registry | Package | Status |
|----------|---------|--------|
| npm | `@aegis-kernel/core` | ✅ v1.0.0 published (monorepo is at 1.1.0 — release pending) |
| PyPI | `aegis-kernel` | ✅ v1.1.0 published |
| PyPI | `aegis-kernel-crewai` | 🚧 built & tested in repo — **publish pending** |
| PyPI | `aegis-kernel-autogen` | 🚧 built & tested in repo — **publish pending** |
| PyPI | `aegis-kernel-browser-guard` | 🚧 built & tested in repo — **publish pending** |
| crates.io | `aegis-kernel` | ❌ **NOT published** (breaks awesome-rust PR — Playbook A) |

---

## 3. Framework Integration Matrix

| Framework | Package | Language | Entry Points | Tests |
|-----------|---------|----------|--------------|-------|
| MCP (Claude Desktop, Cursor, Windsurf) | `@aegis-kernel/mcp` | TS | JSON-RPC middleware + tool-definition scanner | ✅ 10 |
| LangChain / LangGraph | `@aegis-kernel/langchain` | TS | tool wrapper | ✅ 5 |
| OpenAI Function Calling | `@aegis-kernel/openai` | TS | `AegisOpenAIGuard.handleToolCall` | ✅ 4 |
| Anthropic tool_use | `@aegis-kernel/anthropic` | TS | tool_use guard | ✅ 4 |
| Vercel AI SDK | `@aegis-kernel/vercel-ai` | TS | middleware + tool wrapper | ✅ 4 |
| LangChain / CrewAI / AutoGen (basic) | `aegis-kernel` (adapters) | Python | `AegisCrewAITool`, `wrap_autogen_function`, `AegisLangChainTool` | ✅ 11 |
| **CrewAI (turn-key)** | `aegis-kernel-crewai` | Python | `guard_crew`, `guard_agent`, `guard_tool`, `@aegis_crewai_tool` | ✅ 11 |
| **AutoGen / AG2 + Semantic Kernel** | `aegis-kernel-autogen` | Python | `guard_function`, `guard_tool`, `guard_agent`, `add_aegis_filter` (SK) | ✅ 16 |
| **Browser-Use / OpenManus** | `aegis-kernel-browser-guard` | Python | `guard_browser_use_controller`, `guard_openmanus_tool`, `AegisBrowserGuard` | ✅ 23 |

---

## 4. Monitoring Cadence

- **Daily (automated):** `distribution-watch.yml` checks PR states + failing
  checks + registry presence; posts a job summary and opens/updates a tracking
  issue when action is needed.
- **Manual:** `node scripts/check-distribution-prs.mjs` (add `--json` for
  machine-readable output; set `GITHUB_TOKEN` for higher rate limits).
