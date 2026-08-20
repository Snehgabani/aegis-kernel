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

**Carried to next cycle** (from the external review's P1/P2, not executable in
this sandbox): canonical dataset runs in network-enabled CI; Go/Rust/Python CI
matrices verified green + crates.io/Go proxy publication; SBOM/SLSA artifact
wiring into the release; persisted gateway audit store; `aegis scan mcp`
inventory mode; adaptive red-team harness.
