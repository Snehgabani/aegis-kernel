# Aegis Platform Upgrade 2026-H2 — OODA Review & Execution Record

**Date:** 2026-08-20 · **Executed on:** branch `arena/01a0209c-aegis-kernel` (base `20ba7d9`)

This document records an end-to-end product review cycle executed with an
OODA (Observe → Orient → Diagnose → Act) discipline. Every claim in the external
review was re-verified against live code before acting; every fix is gated by the
full test suite (baseline: **546/546 tests, 76 files, all green**).

---

## 1. Observe — verified facts (not assumptions)

| # | Claim from review | Verification result |
|---|---|---|
| O1 | Gateway falls back to hardcoded license secret | **CONFIRMED** — `services/gateway/src/index.ts:14`, literal `'aegis_enterprise_lic_verification_secret_v1_deterministic'` |
| O2 | Canonical benchmarks never fetched | **CONFIRMED + root cause found** — `.benchmark/` is in `.gitignore` (line 5), so canonical data/results could never be committed; additionally **both hardcoded dataset URLs in `scripts/fetch-canonical-benchmarks.mjs` are dead** (`uiuc-kang-lab/InjecAgent/main/data/test_cases.json` → 404; `ethz-spylab/agentdojo/main/data/benchmark_suites.json` → 404, the repo has no `data/` dir) |
| O3 | Fetch script silently falls back to synthetic data | **CONFIRMED** — on HTTP≠200 it writes a 25-vector synthetic "offline seed" and exits 0, masking unavailability |
| O4 | Adapter can't parse the real dataset | **CONFIRMED** — real InjecAgent schema is Title-Case (`Attacker Tools`, `Tool Response`, `Modifed`); adapter expects snake_case (`user_instruction`, `injected_tool_call`) |
| O5 | README badge says 532 tests | **CONFIRMED stale** — actual: **546 tests / 76 files** (verified by full run) |
| O6 | Version drift | In-repo manifests are internally consistent at `1.0.1`; npm/PyPI show `1.0.0` (publish is a release action, documented in checklist) |
| O7 | LICENSE (MIT) vs schema.org "Apache 2.0 / MIT" | **CONFIRMED** — `site/index.html` line 49 |
| O8 | Landing leads with "0.25ms P50", ZK, SOC2 | **CONFIRMED** — `site/index.html` meta + schema markup; `.benchmark/evidence.json` real percentiles (benign p50 ≈ 0.037 ms, sql-simple p50 ≈ 1.10 ms) are not linked |
| O9 | Core has no asymmetric licensing | **REFUTED (partially)** — `packages/core/src/license.ts` already implements Ed25519 offline verification with a compiled-in public key; the defect is gateway-only (HMAC fallback) |

## 2. Orient — external ground truth (researched 2026-08-20)

- **OTel GenAI semantic conventions** (status: *Development*, the 2026 de-facto standard):
  spans `invoke_agent` / `chat` / `execute_tool` (name pattern `{operation} {name}`);
  required attributes `gen_ai.operation.name`, `gen_ai.provider.name`;
  recommended `gen_ai.request.model`, `gen_ai.tool.name`, `gen_ai.tool.call.id`, `error.type`;
  metric `gen_ai.client.operation.duration` (histogram, s). Content belongs in span
  *events*, not attributes. All major backends (Datadog, Langfuse, Grafana, Arize) ingest these.
- **OWASP Agentic AI Top 10 (ASI01–ASI10, Dec 2025)**: ASI01 Agent Goal Hijack,
  ASI02 Tool Misuse & Exploitation, ASI03 Identity & Privilege Abuse, ASI04 Agentic
  Supply Chain, ASI05 Unexpected Code Execution, ASI06 Memory & Context Poisoning,
  ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures, ASI09 Human-Agent
  Trust Exploitation, ASI10 Rogue Agents.
- **EU AI Act**: Digital Omnibus = **Regulation (EU) 2026/1744** (in force 2026-07-27).
  **Article 50 transparency applies since 2026-08-02** (chatbot disclosure, synthetic
  content marking; machine-readable marking grace until 2026-12-02 for pre-existing
  systems; fines up to €15M / 3% turnover). **Annex III high-risk deferred to
  2027-12-02**, Annex I to 2028-08-02. Art. 4 AI literacy applies since 2025-02-02.
- **Benchmark metrics (field standard)**: AgentDojo reports Benign Utility (BU),
  Utility under Attack (UA), Attack Success Rate (ASR), Risk = ASR/UA, per suite;
  InjecAgent reports ASR / defense rate. A bare "accuracy" is not comparable.

## 3. Diagnose — defects & root causes (priority order)

- **D1 (P0, security)** Gateway license fail-open. Root cause: dev convenience default
  compiled into source of an MIT-licensed product. Fix: asymmetric-by-default
  (Ed25519, no secret needed), HMAC only when explicitly configured, issuance
  fail-closed without secret, production boot fails without explicit licensing config.
- **D2 (P0, credibility)** Benchmark provenance chain is broken at four links:
  dead URLs → silent synthetic fallback → gitignored output dir → adapter that can't
  parse the real schema. Headline %s therefore cannot have been produced from the
  canonical datasets. Fix: repair all four links; publish honest in-tree evidence
  with explicit N; restate claims to exactly what is measured.
- **D3 (P0, hygiene)** Stale counts (532/74 → 546/76), license metadata drift
  (schema.org), version/registry drift documented for release.
- **D4 (P0, claim hygiene)** Simulated features (ZK, WASM, enclave) marketed as
  shipped. Fix: relabel to commitments/interfaces across README, WHITE_PAPER, site,
  llms.txt; link real latency evidence.
- **D5 (P1, product)** No OTel GenAI spans → verdicts invisible to enterprise
  observability. Fix: opt-in, zero-dependency, zero-egress span emitter in core.
- **D6 (P1, compliance)** Docs lean on Art. 13 (2027 story) while Art. 50 is the
  live obligation since 2026-08-02. Fix: re-date and reframe; refresh OWASP
  crosswalk to ASI 2026.

## 4. Act — workstreams (each gated by full suite)

| WS | Name | Scope | Gate |
|----|------|-------|------|
| WS-1 | SEC | Gateway fail-closed licensing (Ed25519 default, issuance guard, production boot guard) + new tests | 546 + new tests green |
| WS-2 | BENCH | Fix fetch script (URLs, fail-loud, SHA-256 manifest, committable `benchmarks/` dir), real-schema adapter + fixture tests, field-standard metrics, `benchmarks/EVIDENCE.md`, honest claims | same |
| WS-3 | HYGIENE | Badge 546/76, schema.org license MIT, relabel ZK/WASM/enclave, latency claims ← `evidence.json`, CHANGELOG release checklist | same |
| WS-4 | OTEL | `packages/core/src/otel.ts` GenAI-conformant opt-in span emitter + tests | same |
| WS-5 | COMPLIANCE | EU AI Act re-dating (Art. 50 now / Art. 13 → 2027), OWASP ASI 2026 crosswalk | same |
| WS-6 | VERIFY | Full suite + security audit, DECISION_JOURNAL entry, per-WS commits | all green |

**Non-negotiable constraints (no collateral damage):**
engine hot path untouched; zero-egress preserved (OTel sink is a user-registered
callback, off by default); every existing test must pass after every workstream;
docs changes propagated consistently (README, WHITE_PAPER, site, llms.txt,
COMPLIANCE_SELF_ASSESSMENT).

---

## 5. Execution record (2026-08-20)

| WS | Status | Result |
|----|--------|--------|
| WS-1 SEC | ✅ done | 4 regression tests; forged-license rejection, issuance 503, Ed25519 default |
| WS-2 BENCH | ✅ done | 7 tests; canonical pipeline repaired; evidence committed; claims withdrawn & replaced |
| WS-3 HYGIENE | ✅ done | measured latencies, MIT metadata, honest labels, CHANGELOG + release checklist |
| WS-4 OTEL | ✅ done | 11 tests; GenAI semconv spans, opt-in, zero-egress, content-free |
| WS-5 COMPLIANCE | ✅ done | Art. 50 live mapping (test-locked), Art. 9–15 dated 2027-12-02, ASI01–ASI10 crosswalk |
| WS-6 VERIFY | ✅ done | Final gate: **569/569 TS tests (78 files), 11/11 Python, build 12/12, security audit clean** |

Commits (branch `arena/01a0209c-aegis-kernel`): security → bench → docs(hygiene) →
feat(otel) → compliance → verify. Baseline at start: 546/546 (76 files); zero
pre-existing tests were modified except where correctness required it
(metrics type widening, harness delegation to `calculateMetrics`).

## 6. Execution record — cycle 2 (2026-08-20, post-review backlog)

| WS | Status | Result |
|----|--------|--------|
| WS-7 MCP-INVENTORY | ✅ done | `aegis scan-mcp` (review P1 #6): auth/transport/pinning audit + `aegis-mcp-lock.json` pin & rug-pull drift detection + embedded tool poisoning; 14 tests; secret-safe commitments |
| WS-8 AUDIT-STORE | ✅ done | Pluggable gateway persistence (review P2 #12 partial): `AuditStore` interface, JSONL durable store with boot replay + crash tolerance, D1 reference schema; 7 tests; default behavior preserved |
| WS-9 CANONICAL-CI | ✅ done | `benchmark-canonical` workflow: fail-loud canonical fetch + evaluation in network-enabled CI, artifacts + step-summary, opt-in human-reviewed evidence PR — mechanically closes the "pending CI egress" loop |
| WS-10 RELEASE-WIRING | ✅ done | SBOMs attach to GitHub releases (least-privilege job), SLSA provenance on release events; checklist now verifies automatic steps (review P2 #17) |
| WS-10b DELIVERY-CONSTRAINT | ✅ handled | Session token lacks GitHub `workflows` permission → workflow definitions shipped as versioned templates in `scripts/ci-templates/` + `install-ci-templates.sh` installer (maintainer installs; `--check` mode is a CI drift guard); `.github/workflows/` left at upstream state |

## 7. Execution record — cycle 3 (2026-08-20, adaptive red-team + real security fix)

| WS | Status | Result |
|----|--------|--------|
| WS-11 REDTEAM | ✅ done | `aegis red-team run`: TAP depth-4×4 search across 3 attack families (341 nodes each) + 12-vector tool-poisoning stress suite; strict exit semantics; JSON evidence artifact. **Found a REAL bypass on first live fire** (see WS-11b) |
| WS-11b SECURITY FIX | ✅ done | PII checker layered-evasion bypass (base64-wrap, homoglyph-corrupted b64 alphabet, separator-spacing, bidi, percent/hex, double-b64): TAP resilience 67.5% → 93.8% (first fix) → **100%** (bounded recursive strip→UTS#39-fold→decode cascade). Regression tests R1–R6 + benign controls; pre-existing DATA-002/JWT and US_NPI semantics preserved and documented |
| WS-11c SCANNER GAPS | ✅ done | MCP scanner: UNBOUNDED_PROPERTIES now fires; new CAPABILITY_ESCALATION threat (read-named tools advertising destructive powers, OWASP ASI02); both core+ mcp copies kept in sync |
| WS-12 DOCS-SYNC | ✅ done | CHANGELOG (cycle-2/3 features + security fix), README commands & benchmark rows, llms.txt refresh incl. removing a surviving "ZK policy circuits" overclaim (Rust source itself was already honest) |

**Security finding record (first real product of the harness):** the red-team
command was run once at depth 3 on live fire and immediately surfaced 13
bypassing payload mutations — proving both the review's thesis (static suites
flatter defenses) and the harness's value. The fix chain (wider invisible-char
strip set → decode-before-match → fold-before-decode → recursive cascade) is
exactly the OODA discipline applied to the engine itself.

## 8. Verification cycle (2026-08-21, independent re-verification OODA loop)

Every claim from cycles 1–3 re-verified from a clean process, not from memory:

| Verification | Result |
|---|---|
| Full TS suite | ✅ 611/611, 83 files |
| Build (turbo, all 12 tasks) | ✅ green |
| npm audit / tsc | ✅ zero known vulns / clean |
| Python suite | ✅ 11/11 |
| **Live attack scenarios** (independent script, not the test suite) | ✅ 8/8: forged license w/ old hardcoded secret REJECTED; PII evasions (base64, double-b64, bidi, EN-SPACE) all BLOCKED; benign base64 passes; OTel span emitted with gen_ai.* attrs; audit events survive restart |
| `aegis red-team run` at production defaults | ✅ PASS — 3×341 nodes, 0 bypasses, 12/12 poisoning detected, 0 false positives, exit 0 |
| `scripts/run-benchmarks.mjs` reproducibility | ✅ field-standard metrics reproduce (ASR 0 / utility 100 on in-tree corpora) |
| Git hygiene | ✅ tree clean; remote branch == HEAD (`600c538`); duplicate verification artifacts removed |
| Docs consistency | ✅ badge/counts 611/83 everywhere; withdrawn 93.5%/86.6% appear ONLY in corrections-register contexts; CI drift-check correctly reports templates not yet installed (maintainer action) |
| Residual defect found | `benchmarks/reports/latest.json` was modified by the verification run (expected side-effect) → restored; no other drift |

**Conclusion: 3 cycles, 11 commits, 65 net-new tests (546 → 611), one real
security vulnerability found and fixed by the new tooling itself, zero
regressions.** Remaining work is fully specified in
`docs/ROADMAP_BACKLOG_2026H2.md` (literature-backed, tiered by who must act).

Cycle-3 final gate: **611/611 TS tests (83 files) · 11/11 Python · build green · audit clean.**

Cycle-2 final gate: **590/590 TS tests (80 files) · 11/11 Python · build green · npm audit clean · tsc clean.**

**Carried to next cycle** (not executable in this sandbox): Go/Rust toolchain
verification (no go/cargo available locally) + crates.io/Go proxy publication;
npm/PyPI registry publishes (maintainer credentials required); adaptive
red-team harness (`aegis red-team run`); SSO/OIDC + mTLS; fleet-wide policy
drift dashboard; policy lifecycle (versioned rule packs → review → staged
rollout → rollback).
