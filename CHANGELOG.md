# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.1] - 2026-08-20

> **Release note:** in-repo manifests are at `1.0.1`. npm and PyPI still serve
> `1.0.0`; publishing `1.0.1` to the registries is a pending release action
> (see `docs/RELEASE_CHECKLIST.md`).

### Security
- **Red-team finding fixed (PII checker layered-evasion bypass)**: base64-wrapped
  PII, homoglyph-corrupted base64 alphabets, separator-spaced payloads
  (EN-SPACE/NBSP), bidi overrides/isolates, percent/hex encoding, and
  double-base64 wrapping could evade PII detection (TAP resilience was 67.5% on
  the PII exfiltration tree). The checker now runs a bounded recursive
  strip→fold(UTS #39)→decode cascade before pattern matching; resilience is
  100% at full search depth, pinned by regression tests R1–R6.
- **MCP scanner coverage gaps closed**: `UNBOUNDED_PROPERTIES` now actually fires
  (additionalProperties:true / constraint-less properties) and the new
  `CAPABILITY_ESCALATION` threat flags read-named tools advertising destructive
  capabilities (OWASP ASI02 confused-deputy).
- **Gateway license bootstrap is now fail-closed** (`services/gateway`): removed the
  hardcoded HMAC fallback secret that allowed enterprise-license forgery against
  deployments without `AEGIS_LICENSE_SECRET`. Verification is asymmetric-by-default
  (Ed25519, compiled-in public key); HMAC paths require an explicit secret; Stripe
  license issuance returns 503 when unconfigured; `AEGIS_ALLOW_UNSAFE_LICENSE=1` is
  refused in production. Regression tests included.

### Changed (claims & evidence hygiene)
- **Withdrew unreproducible benchmark headline numbers** ("93.5% InjecAgent
  resilience", "86.6% AgentDojo accuracy"). Every published figure now carries
  corpus provenance and traces to a committed artifact in `benchmarks/`
  (see `benchmarks/EVIDENCE.md`, corrections register included).
- Benchmarks reported in field-standard metrics: ASR, defense rate, benign
  utility, risk, confusion matrix.
- Latency claims restated from measured per-workload percentiles
  (benign p50 ≈ 0.04ms, SQL simple ≈ 1.1ms, SQL complex ≈ 1.9ms) instead of a
  blended "0.25ms P50"; landing page and comparison pages updated accordingly.
- License metadata unified to MIT (site schema.org previously said "Apache 2.0 / MIT").
- Simulated features relabeled honestly: ZK → "cryptographic hash commitments",
  WASM → "plugin validator interface (runtime: roadmap)", enclave attestation →
  development simulation (unchanged, already disclosed in
  `docs/LIMITATIONS_AND_BOUNDARIES.md`).

### Added
- **Signed rule packs** (`aegis pack sign/verify`, AISVS C10.1.1 / MCP03/MCP04):
  canonical (key-order-invariant) SHA-256 pack commitments + Ed25519 sidecar
  manifests; fail-closed verification (commitment recompute detects tampering,
  id/version binding prevents manifest replay, multi-maintainer trusted-key sets).
- **Policy lifecycle** (`PolicyLifecycle`): shadow evaluation of candidate pack
  sets beside the current policy with fail-closed promotion gates (no
  NEW_ALLOWS_MORE on attacks, FP-regression tolerance, minimum shadow samples)
  and snapshot-backed instant rollback — the ISO 42001/NIST AI RMF MANAGE
  control-operation loop.
- **Information-flow control (IFC-001)**: deterministic taint tracking (FIDES/NeuroTaint
  lineage, CaMeL sink-capability model) — `engine.registerUntrustedSource()` +
  `informationFlow` policy; untrusted content flowing into sensitive sinks is
  blocked even when it matches no content rule (ADI-class defense). Cross-call
  persistence, FIFO-bounded sources, cross-session ledger; evasion-normalized
  matching; paraphrase-taint explicitly NOT claimed.
- **Trajectory stress harness** (`aegis red-team run --suite trajectory`):
  500-step deterministic sessions with Mann-Kendall trend test + Theil-Sen slope
  (AgentDyn/HORIZON literature-aligned), attacks-at-depth, FP rate with Wilson CI.
- **Full-corpus ablation (N=1,054)**: hipaa-guard measured +0.0pp unique coverage
  on the synthetic corpus (subsumed by data-guard) — disclosed; canonical
  ablation pending Tier-0 CI run.
- `aegis red-team run` — adaptive red-team harness (TAP payload-mutation tree search,
  depth 4 × branching 4, 3 attack families + MCP tool-poisoning stress suite of 12
  vectors; exit 1 on any bypass or detection miss; JSON evidence artifact).
- `aegis scan-mcp` — MCP server inventory security audit (auth presence, transport
  security, package pinning, `aegis-mcp-lock.json` pin & rug-pull drift detection,
  embedded tool-poisoning scan; secret values never hashed or logged).
- Gateway: pluggable durable audit store (`AuditStore` interface; JSONL persistence
  with boot replay + crash tolerance; D1 reference schema documented).
- OTel GenAI observability spans; canonical-benchmark CI pipeline (templates +
  installer); SBOM/SLSA release attachment wiring (templates).
- `benchmarks/` committable evidence directory (reports, checksums, corrections register).
- Canonical benchmark fetch pipeline repaired: correct upstream URLs (previous
  both 404), dynamic AgentDojo suite discovery, SHA-256 manifest, fail-loud
  behavior (no silent synthetic fallback).
- `scripts/run-benchmarks.mjs` evidence runner (`--canonical` mode).
- InjecAgent adapter support for the real canonical Title-Case schema
  (`Attacker Tools` array, `Attack Type`, dh/ds file-level categories).
- OTel GenAI-conformant observability spans (opt-in, zero-egress) — see docs.
- EU AI Act compliance docs re-dated post-Digital-Omnibus
  (Regulation (EU) 2026/1744) and OWASP crosswalk refreshed to the Agentic AI
  Top 10 (ASI01–ASI10).

## [1.0.0] - 2026-08-15

### Added
- **Core Invariant Engine (`@aegis-kernel/core`)**:
  - Deterministic AST evaluation for SQL queries (`SqlChecker`) with syntax token normalization and dialect recognition.
  - Sub-millisecond regular expression matching (`PiiChecker`) with automated Unicode NFKD homoglyph and zero-width character stripping (`\u200B`, `\uFEFF`, `\u00AD`).
  - Strict numeric bound enforcement (`NumericChecker`) supporting exponential/scientific notation coercion and nested payload recursion.
  - Stateful pre/post condition assertions (`StateChecker`) with multi-tenant session isolation (`SOC2-004`).
  - Zero-eval custom rule evaluator (`CustomChecker`) featuring strict prototype pollution immunity.
  - Self-healing recovery feedback generation with `suggestedFix` remediation payloads.
- **Enterprise Compliance Packs**:
  - Built-in rule packs for `hipaa-guard`, `pci-dss-guard`, `soc2-guard`, `eu-ai-act-guard`, `finance-guard`, `fintech-trade-guard`, `sql-guard`, and `data-guard`.
- **Framework Adapters & Ecosystem**:
  - `@aegis-kernel/mcp`: Automatic tool clearance middleware and runtime schema pinning for Model Context Protocol servers.
  - `@aegis-kernel/openai`: Stream and non-stream tool call interception for OpenAI Assistants and Chat APIs.
  - `@aegis-kernel/anthropic`: Message pre-processor and tool_use validator with structured self-healing feedback.
  - `@aegis-kernel/langchain`: Agent executor hooks and Runnable middleware.
  - `aegis-kernel` (PyPI): Python 3.9+ synchronous and async coroutine decorators (`@aegis_guard`).
- **Developer CLI (`@aegis-kernel/cli`)**:
  - Commands: `init`, `test`, `report`, `repl`, `pack list/validate`, `license activate/status`, `pricing`, and `benchmark --tricky`.
- **Evaluation & Benchmarking (`@aegis-kernel/evals`)**:
  - 100-vector adversarial benchmark testbed across 10 security domains achieving 100.0% Empirical F1 score and sub-1.5ms latency.
- **Cloud Gateway & Monetization (`@aegis-kernel/gateway`)**:
  - Hono-based Cloudflare Worker & Docker gateway with Stripe webhook subscription fulfillment and offline HMAC license token generation.
- **Enterprise Automation & Governance**:
  - Full CI/CD multi-runtime matrix (Node 18/20/22 + Python 3.9–3.12), CodeQL SAST scanning, Dependabot governance, and Git pre-commit hooks.
