# Aegis Invariant Kernel: Institutional Decision Journal

> **Purpose:** Immutable, chronological log of architectural decisions, trade-offs, and design axioms for the Aegis Invariant Kernel. All future contributors and AI development agents must review this journal before proposing architectural changes.

---

## Decision 1: Monorepo Architecture with Pure TypeScript & Zero Network Egress
- **Date:** 2026-08-15
- **Status:** `ACTIVE`
- **Context:** Agent safety clearance requires sub-2ms local execution. External SaaS APIs introduce 50-300ms network latency and data egress compliance hurdles.
- **Decision:** Build Aegis as an open-core TypeScript monorepo with 0 remote network dependencies in the hot path. Core engine runs in-process with 0 telemetry egress.
- **Consequences:** Low latency (<2ms P50), full edge and on-prem portability, verifiable zero-data-leakage compliance for enterprise adopters.

---

## Decision 2: Stand on Giants via AST Parsing & Declarative Validation
- **Date:** 2026-08-15
- **Status:** `ACTIVE`
- **Context:** Regex-only SQL and payload safety checks are brittle and easily evaded via whitespace/comment obfuscation.
- **Decision:** Utilize proven AST parsing foundations (`node-sql-parser` for SQL, `ajv` for JSON Schema) with a resilient regex fallback chain for unsupported dialects.
- **Consequences:** High syntactic accuracy on structured tool calls with graceful degradation on novel dialects.

---

## Decision 3: Deterministic Invariants vs. Probabilistic LLM Classifiers
- **Date:** 2026-08-15
- **Status:** `ACTIVE`
- **Context:** Secondary LLM "safety judges" are slow, expensive, and subject to prompt injection.
- **Decision:** Aegis explicitly operates as the deterministic, mathematical clearance layer underneath probabilistic guardrails in a defense-in-depth architecture. It guarantees that what policy forbids cannot execute.
- **Consequences:** Clear positioning as compliance/infrastructure policy enforcement rather than a replacement for semantic intent classification.

---

## Decision 4: Granular Fail-Policy (Fail-Open vs. Fail-Closed)
- **Date:** 2026-08-15
- **Status:** `ACTIVE`
- **Context:** A global fail-open policy risks catastrophic breaches on financial actions, while a global fail-closed policy breaks developer workflow on benign errors.
- **Decision:** Implement granular fail policies: defaults to `fail-open` for non-critical developer heuristics, with `fail-closed` overrides configurable per-severity (`critical`) and per-rulepack (`finance-guard`).
- **Consequences:** Balances frictionless developer adoption with strict enterprise policy enforcement.

---

## Decision 5: Sandboxed Custom Predicate Execution
- **Date:** 2026-08-15
- **Status:** `SUPERSEDED by Decision 6`
- **Context:** Executing arbitrary user JS in-process using `new Function` with `Object.create(null)` or `node:vm` was proposed.
- **Flaw Identified:** In-process JS execution is vulnerable to prototype-chain escapes (`this.constructor.constructor`) and `node:vm` is not a security boundary.
- **Resolution:** Fully superseded by Decision 6.

---

## Decision 6: Zero-Eval Declarative AST Expression DSL
- **Date:** 2026-08-15
- **Status:** `ACTIVE`
- **Context:** Custom condition checks must never expose the host runtime to code injection or sandbox escapes.
- **Decision:** Replaced all in-process JS execution with a **Zero-Eval Declarative Expression Evaluator** (`CustomChecker`). Parses arithmetic (`+`, `-`, `*`, `/`), comparisons (`==`, `!=`, `<`, `<=`, `>`, `>=`), logical operators (`&&`, `||`, `!`), and containment (`in`, `contains`) using recursive descent AST evaluation without compiling machine code.
- **Consequences:** Eliminates the host JS execution surface and prototype-chain escapes by design.

---

## Decision 7: System State Provider Interface & Trust Boundary
- **Date:** 2026-08-15
- **Status:** `ACTIVE`
- **Context:** State invariant assertions (e.g. `state.spent_today + params.amount <= state.daily_budget`) require an authentic system state source.
- **Decision:** Define a developer-owned `StateProvider` interface (`(toolCall) => Promise<State>`) registered directly on the engine outside agent influence. The agent cannot spoof system state. If a state invariant requires state and the provider fails, the engine fails closed.
- **Consequences:** Pre-execution projection against authenticated current state with a verified trust boundary.

---

## Decision 8: Tamper-Evident Policy Commitment Binding in ProofHash
- **Date:** 2026-08-15
- **Status:** `ACTIVE`
- **Context:** Telemetry proof hashes must cryptographically commit to the exact policy configuration that produced the verdict.
- **Decision:** `proofHash` is computed as `SHA-256(verdict : toolFingerprint : policyCommitmentHash : timestamp : firedRuleIds)`, where `policyCommitmentHash` is a SHA-256 digest of all active rulepack IDs, versions, and rule definitions.
- **Consequences:** Verifiable, audit-proof cryptographic commitment linking tool calls to exact policy versions.

---

## Decision 9: AST Constant-Folding & Column-Reference Invariant Analysis for SQL WHERE Clauses
- **Date:** 2026-08-15
- **Status:** `ACTIVE`
- **Context:** Literal string-matching for tautologies (`1=1`, `true`, `'a'='a'`) is brittle and leaves unbounded constant bypasses open (`WHERE 2 > 1`, `WHERE NULL IS NULL`, `WHERE 1 IN (1)`, `WHERE 1 BETWEEN 0 AND 2`, `WHERE id = id`, `WHERE id = 123 OR 1=1`).
- **Decision:** Implement recursive AST constant-folding and column-reference invariant analysis in `SqlChecker`. Flag a WHERE clause as an unconstrained mass mutation if:
  1. It contains self-referential column comparisons (`id = id`, `table.col = table.col`).
  2. Any branch in an `OR` compound expression reduces to a constant tautology.
  3. The WHERE expression contains zero column references and folds to true (or unresolvable constant).
- **Consequences:** Replaces brittle keyword lists with principled AST invariant verification, preventing mass `DELETE` and `UPDATE` bypasses.

---

## Decision 10: Zero-Latency Cryptographic Licensing, Cloud Gateway, & Python SDK Expansion
- **Date:** 2026-08-15
- **Status:** `ACTIVE`
- **Context:** Monetization of enterprise compliance rule packs (@aegis/hipaa-guard, pci-dss-guard, soc2-guard, fintech-trade-guard, legal-privilege-guard) must never introduce external network calls or latency onto the sub-2ms tool evaluation hot path. Furthermore, the 60%+ Python agent builder ecosystem required first-class native support.
- **Decision:** 
  1. Built `AegisLicenseManager` using offline HMAC-SHA256 / Ed25519 token signatures (`aegis_lic_...`) validated in memory with zero network delay.
  2. Built `@aegis-kernel/gateway` as a zero-cost Cloudflare Worker service providing asynchronous batch telemetry ingestion and automated Stripe `checkout.session.completed` license issuance.
  3. Created `packages/python` (`aegis-kernel` source package — **PyPI publication pending**) providing `@aegis_guard` decorator with zero external dependencies in pure Python 3.9+.
  4. Added `@aegis-kernel/evals` package with an internal curated 100-vector testbed. **Correction (2026-08-16):** the original journal entry claimed standardized execution against InjecAgent, AgentDojo, and MCPTox datasets — this was premature. Those public benchmarks are planned, not yet implemented; all published metrics come from the internal testbed.
- **Consequences:** Enables a potential commercial licensing path; the monetization model is not yet finalized and the codebase remains MIT-licensed.



---

## Decision 11: Evidence-Integrity Doctrine — Fail-Closed Licensing, Provenanced Benchmarks, Live-Law Compliance
- **Date:** 2026-08-20
- **Status:** `ACTIVE`
- **Context:** An external end-to-end product review (2026-08-20) verified four credibility defects: (1) the gateway fell back to a hardcoded HMAC license secret published in MIT source (forgeable enterprise licenses); (2) headline benchmark numbers (93.5% InjecAgent, 86.6% AgentDojo) were not reproducible from any in-repo dataset — the canonical fetch URLs were dead (404), outputs went to a gitignored directory, and a silent fallback wrote synthetic data in place of fetched data; (3) marketing claimed simulated features (ZK proofs, WASM execution, 0.25ms blended P50) beyond their real state; (4) compliance docs leaned on EU AI Act high-risk articles whose applicability the Digital Omnibus (Regulation (EU) 2026/1744) deferred to 2027-12-02 while Article 50 transparency went live 2026-08-02.
- **Decision:**
  1. **Fail-closed licensing:** gateway verification is asymmetric-by-default (Ed25519, compiled-in public key); HMAC requires an explicit `AEGIS_LICENSE_SECRET`; issuance returns 503 when unconfigured; `AEGIS_ALLOW_UNSAFE_LICENSE=1` is refused in production. Regression tests pin the forged-license rejection.
  2. **No claim without an artifact:** benchmarks live in a committable `benchmarks/` directory with SHA-256 manifests, dated reports, field-standard metrics (ASR / defense rate / benign utility / risk / confusion matrix), and a public corrections register (`benchmarks/EVIDENCE.md`). Unreproducible headline numbers were withdrawn and the withdrawal itself is documented. Canonical fetch fails loudly; it never writes synthetic data in place of canonical data.
  3. **Measured-only latency claims:** per-workload percentiles (benign ≈0.04ms, SQL simple ≈1.1ms, SQL complex ≈1.9ms) replace the blended "0.25ms P50" everywhere.
  4. **Live-law compliance:** dossier leads with Article 50 (in force 2026-08-02) and dates the Articles 9–15 package to 2027-12-02; OWASP crosswalk extended to the Agentic AI Top 10 (ASI01–ASI10) with honest per-category coverage labels.
  5. **Opt-in observability:** OTel GenAI-conformant `execute_tool` spans (required `gen_ai.*` attributes, content-free, zero-egress) via a user-registered sink; sink failures can never affect a verdict.
- **Consequences:** Every future benchmark, latency, or compliance number must trace to a committed artifact or it does not get published. This costs us marketing headline strength and buys the only durable asset a security vendor has: verifiable trust. Canonical-dataset runs remain pending a network-enabled CI environment and will be published only with checksummed artifacts.

---

## Decision 12: Scientific Evaluation Doctrine — CIs, Ablations, Metamorphic Properties
- **Date:** 2026-08-21
- **Status:** `ACTIVE`
- **Context:** Point estimates are not scientific claims. "100% detection" on N=13 carries a 95% exact upper bound of 30.8% ASR (Clopper-Pearson); the AgentDojo literature reports 95% CIs on every figure. Applying the scientific method to our own product (property-based metamorphic testing) immediately found two real engine gaps that 590+ example-based tests had missed.
- **Decision:**
  1. Every published security/utility proportion carries a 95% CI: Clopper-Pearson (exact, conservative) for the ASR upper bound; Wilson for utility-side reporting (Wilson 1927; Clopper-Pearson 1934; Brown-Cai-DasGupta 2001 coverage analysis). Zero-event claims state the rule of three (3/n; Hanley & Lippman-Hand 1983); claiming ASR < r requires ≥ 3/r zero-bypass attacks (≥300 for <1%).
  2. Ablation studies (component attribution) are part of the evidence pipeline: no-packs control, per-pack ΔASR/Δutility with the redundancy explicitly measured (sql-guard Δ0pp BECAUSE soc2-guard independently covers DDL — defense-in-depth quantified, not asserted).
  3. Metamorphic properties are regression law: determinism, blocking monotonicity, key-order invariance, evasion closure, fingerprint purity (proofHash deliberately binds time for ledger replay), and zero-FP on generated benign traffic. The two gaps they found (SELECT-tautology unbounded reads; encoded-numeric/SQL wraps) are fixed and pinned.
- **Consequences:** Our in-tree numbers now advertise their own weakness (wide CIs at small N) — this is intentional: it makes the canonical-dataset runs the only path to strong claims, and it makes marketing-grade overstatement structurally impossible. Statistics live in `packages/evals/src/stats.ts` (dependency-free, literature-pinned tests).

---

## Decision 13: Provenance-Aware Enforcement (IFC) + Long-Horizon Stress Discipline
- **Date:** 2026-08-21
- **Status:** `ACTIVE`
- **Context:** The 2026 provenance survey (arXiv:2606.04990) systematizes the shift from output-only safety to provenance-aware execution control: CaMeL capabilities, FIDES integrity labels, NeuroTaint's three flow classes, Agent-Sentry sink analysis. The ADI attack (arXiv:2607.05120) showed only strict data-flow tracking reaches 0% ASR — and CaMeL's Normal mode leaked through a taint-propagation bug, proving taint mechanics must be simple and tested. Separately, AgentDyn/HORIZON/MAGE establish long-horizon trajectories as the dimension where defenses fail.
- **Decision:**
  1. IFC ships as an opt-in deterministic layer: registered untrusted sources + sensitive-sink policy + normalized substring matching (same evasion cascade as checkers), violating flows produce IFC-001. Scope limited to NeuroTaint's "explicit content propagation" + mechanism-level cross-session persistence; implicit-control and paraphrase taint are explicitly not claimed.
  2. Trajectory stability is regression law: 500-step sessions with Mann-Kendall (tie-corrected) + Theil-Sen slope gates on latency drift, attacks-at-depth, and FP Wilson bounds — wired into the red-team command's strict exit semantics.
  3. Ablation extends to the full synthetic corpus; measured redundancy (sql-guard 0.0pp via soc2 subsumption; hipaa-guard 0.0pp via data subsumption) is disclosed in EVIDENCE.md with corpus-specificity caveats, pending canonical runs.
- **Consequences:** Aegis now defends a class of attack (data-flow injection) invisible to content rules, with honest scope boundaries; long-session engineering failures (drift, unbounded memory, depth evasion) become CI-detectable; pack redundancy is quantified, driving future pack consolidation decisions on canonical data rather than marketing.
