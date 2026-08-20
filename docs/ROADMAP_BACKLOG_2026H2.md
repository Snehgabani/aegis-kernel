# Aegis Remaining-Work Backlog — Literature-Backed (2026-08-21)

**Verification status:** all three upgrade cycles verified green (see
`docs/PLATFORM_UPGRADE_2026H2.md` §8). This document lists what is LEFT, with
every item grounded in 2026 standards, benchmarks, or peer-reviewed literature.

---

## Tier 0 — Maintainer unblock actions (no code required; everything else waits on these)

| # | Action | Evidence / backing |
|---|--------|--------------------|
| 0.1 | **Install CI templates** (`bash scripts/install-ci-templates.sh`) — canonical-benchmark pipeline + SBOM-release attachment + SLSA provenance-on-release. Ready to run; blocked only by GitHub `workflows` permission (automation tokens cannot write `.github/workflows/`). | SLSA spec is **v1.2** (Nov 2025; Source track now approved). GitHub Artifact Attestations give SLSA Build **L2 by default**, **L3 via reusable workflows**; npm trusted publishing auto-generates provenance attestations. Caution from SLSA's own post-incident analysis: provenance ≠ safety — verification at install time is the weakest link ([SLSA overview 2026](https://rywalker.com/research/slsa), [practical SLSA L3 guide 2026](https://safeguard.sh/resources/blog/how-to-implement-slsa-level-3-practical-guide)). |
| 0.2 | **Run the first canonical evidence run** (workflow_dispatch → `commit_evidence=true`) and merge the human-reviewed PR. Closes `benchmarks/EVIDENCE.md` §2 permanently. | AgentDojo (Debenedetti et al., NeurIPS 2024, arXiv:2406.13314) defines the dual reporting we implemented (utility + targeted ASR, per-suite); static-only ASR is explicitly criticized in the usage guidelines. |
| 0.3 | **Publish registries**: npm workspaces @1.0.1+ (use *trusted publishing* for automatic Sigstore provenance), PyPI `aegis-kernel`, tag Go module (proxy auto-picks tags), publish crates.io crate (docs.rs build must be green). | Registry version drift (npm/PyPI at 1.0.0 vs manifests 1.0.1) is a documented procurement-trust gap. A security kernel in Rust published to crates.io is a credibility multiplier; SLSA research stresses per-artifact provenance + consumer-side verification instructions. |

## Tier 1 — Engineering (next sandbox-executable cycles)

| # | Action | Evidence / backing |
|---|--------|--------------------|
| 1.1 | **Signed tool & rule-pack manifests** (Ed25519): extend `aegis-mcp-lock.json` → signed manifests; `aegis pack verify` / `aegis hub install --require-signature`. | **OWASP AISVS C10** (MCP Security verification standard): C10.1.1 "verify MCP components using signatures/checksums… rejecting unsigned builds" (L1); C10.4.8 "schema manifests validated for authenticity using signatures" (L3). OWASP notes **the MCP spec has NO native signing mechanism** — signing tooling is "aspirational" for most orgs → open differentiation lane. Maps to OWASP MCP Top-10 **MCP03 Tool Poisoning** & **MCP04 Supply Chain** ("signed components & provenance verification… validate during install + startup"). |
| 1.2 | **Tool-definition change re-approval**: hook `tools/list_changed`; hash-snapshot every tool definition (extend `SchemaRugPullDetector`); any change → quarantine + HITL re-approval before invocation. | AISVS **C10.4.5** (L2): "clients maintain a hash or versioned snapshot of tool definitions and any change triggers re-approval". Directly the rug-pull defense; our lock-file already implements the inventory variant (C10.1.2 allowlisted server IDs). |
| 1.3 | **Provenance / taint tracking on the causal DAG** — per-value trust labels (trusted user input vs untrusted tool output), policy on flows, optional STRICT mode. | **CaMeL** (Debenedetti et al., Google DeepMind + ETH, arXiv:2503.18813): control-flow/data-flow separation with capabilities solves AgentDojo security *by design* (77% utility with provable security vs 84% undefended). **Agent Data Injection attacks** (arXiv:2607.05120, Jul 2026): only CaMeL-**Strict** (implicit-flow tracking) reached **0% ASR** — but utility fell to **36.5%** vs 86.5% baseline; document the trade-off, ship strict mode as opt-in per tool. Aegis's causal execution DAG is the natural substrate. |
| 1.4 | **Red-team harness v2**: (a) trajectory-length stress mode; (b) "helpful third-party instructions" poisoning family; (c) report utility-and-ASR deltas (not only resilience). | **AgentDyn** (Li et al., arXiv:2602.03117): static-benchmark defenses collapse in dynamic environments (Meta SecAlign: 80% utility on AgentDojo → 53.4% on AgentDyn; ASR ×4); **utility drops 100% → 23.6% as trajectory length exceeds 10 steps** → Aegis must be stressed on long chains, not just single calls. **PIArena** (arXiv:2604.08499): effective-utility trade-off quantified via dual Utility+ASR metrics — exactly the dual axis we adopted; multi-step IPI analysis (arXiv:2604.03870) shows single-turn benchmarks hide fragility. |
| 1.5 | **Policy lifecycle**: versioned rule packs → review → staged rollout (1%→10%→100% in monitor-only) → auto-rollback on benign-utility regression. | ISO/IEC 42001 (certifiable management system) + NIST AI RMF as operating model is the 2026 enterprise pattern (NIST MAP/MEASURE outputs serve as EU AI Act Art. 9/11 evidence; official crosswalk exists). Staged rollout + rollback is the control-operation record internal audits require ([framework comparison 2026](https://neuraltrust.ai/blog/ai-governance-framework-comparison), [GAICC comparison](https://gaicc.org/blog/ai-governance-comparison-eu-ai-act-nist-iso-42001/)). |
| 1.6 | **Gateway hardening: mTLS + OIDC/SSO** (gateway↔control-plane), short-lived scoped tokens. | OWASP MCP Top-10 **MCP07**: OAuth 2.1 + per-server audience validation "should become the baseline"; static PATs in env vars called out as the anti-pattern our `scan-mcp` already flags. |
| 1.7 | **Control-plane persistence + fleet drift dashboard** (D1/Postgres per `docs/enterprise/AUDIT_STORE_D1.md`). | OWASP MCP Top-10 **MCP08** (immutable audit logs, behavioral monitoring) + **MCP09 Shadow MCP servers** (continuous discovery) — a fleet view of policy-commitment-hash drift across hosts is the enterprise governance loop. |

## Tier 2 — Strategic (conditional / larger bets)

| # | Action | Evidence / backing |
|---|--------|--------------------|
| 2.1 | **Real WASM plugin runtime** (wasmtime/wasmer: memory caps, fuel metering, timeout) replacing the interface-only runner. | Removes the last "simulated" flagship item; enables OPA/Rego policy later. Keep the fail-closed export contract already tested. |
| 2.2 | **Real ZK range proofs (Groth16/PLONK)** — only if enterprise demand confirms; otherwise keep hash commitments (already honestly labeled). | CaMeL design philosophy: build defenses whose components can be precisely studied rather than claimed; our corrections register shows overclaiming costs more than it buys. |
| 2.3 | **Community & trust program**: external red-team bounty, `good-first-issue` backlog, 2–3 named non-author contributors, independent security audit, Discord/Discussions. | 2026 market consolidation (Lakera→Check Point, Invariant→Snyk, Protect AI→Palo Alto) means open verification is the surviving differentiator for independent OSS; PIArena/AgentDyn show independent adaptive evaluation is where credibility now lives. |
| 2.4 | **US/state law pack expansion** (Texas TRAIGA effective 2026-01-01, California SB 53, Colorado SB 26-189 effective 2027-01-01; EU Art. 50 already covered). | 2026 compliance landscape tables show multi-jurisdiction agent governance becoming standard procurement questions ([global compliance map 2026](https://www.modulos.ai/ai-compliance-guide/)). |

---

## Key literature & standards register (for README/research docs)

1. **CaMeL** — Debenedetti, Shumailov, Fan, Hayes, Carlini, Fabian, Kern, Shi, Terzis, Tramèr. *Defeating Prompt Injections by Design*. arXiv:2503.18813 (DeepMind/ETH; NeurIPS 2024 AgentDojo solved-by-design at 77% utility). https://github.com/google-research/camel-prompt-injection
2. **Agent Data Injection (ADI)** — arXiv:2607.05120 (2026): dual-LLM + data-flow defenses; only strict tracking hits 0% ASR (36.5% utility).
3. **AgentDyn** — Li, Wen, Shi, Zhang, Xiao. arXiv:2602.03117 (2026): dynamic benchmark; defenses drop from ~perfect (AgentDojo) to brittle; trajectory length >10 ⇒ utility 23.6%.
4. **AgentDojo** — Debenedetti et al. NeurIPS 2024, arXiv:2406.13314: utility+ASR dual reporting, adaptive-attack usage guidelines.
5. **PIArena** — arXiv:2604.08499 (2026): unified Utility+ASR evaluation platform.
6. **Multi-step IPI fragility** — arXiv:2604.03870 (2026): single-turn benchmarks hide systemic fragility.
7. **OWASP AISVS C10** (MCP Security verification requirements, leveled L1–L3): https://github.com/OWASP/AISVS
8. **OWASP MCP Top 10 (2025/2026)** + Practical Guide for Secure MCP Server Development (Feb 2026): signed manifests, OAuth 2.1 baseline, no token passthrough.
9. **OWASP Agentic AI Top 10 (ASI01–ASI10)** — Dec 2025 taxonomy (crosswalk in-repo).
10. **EU AI Act + Digital Omnibus** — Regulation (EU) 2026/1744: Art. 50 in force 2026-08-02; Annex III high-risk deferred to 2027-12-02; GPAI Arts. 51–56.
11. **SLSA v1.2** (Nov 2025) + GitHub Artifact Attestations (Build L2 default, L3 via reusable workflows) + npm trusted publishing provenance.
12. **ISO/IEC 42001:2023 + NIST AI RMF (+AI 600-1 GenAI profile)** — complementary governance stack (certifiable system / operating model / legal layer).
