# Aegis Benchmark Evidence

**Status date:** 2026-08-20 · **Maintained by:** Aegis maintainers · **License of datasets:** MIT (InjecAgent, AgentDojo)

This directory is the **single source of truth** for every benchmark number Aegis
publishes. If a number is not traceable to a file in `benchmarks/reports/`, it is
not a claim we make. This page replaces the pre-2026-08-20 practice of quoting
headline percentages ("93.5% InjecAgent resilience", "86.6% AgentDojo accuracy")
that could not be reproduced from any dataset in the repository.

---

## 1. What has actually been measured (reproducible today)

### 1.1 In-tree representative corpora — 100% verdict agreement

| Benchmark | Corpus | N | Malicious / Benign | ASR [95% exact upper] | Defense rate | Benign utility [95% Wilson] | Accuracy | p50 latency |
|---|---|---|---|---|---|---|---|---|
| InjecAgent (ACL 2024) | in-tree representative sample | **13** | 10 / 3 | 0.0% [<u>**30.8%**</u>] | 100.0% | 100.0% [CI 44.0–100%] | 100.0% | 0.675 ms |
| AgentDojo (NeurIPS 2024) | in-tree representative sample | **9** | 5 / 4 | 0.0% [<u>**45.0%**</u>] | 100.0% | 100.0% [CI 51.0–100%] | 100.0% | 0.261 ms |
| MCPTox / MCP tool poisoning | in-tree representative sample | **5** | 4 / 1 | 0.0% [<u>**52.7%**</u>] | 100.0% | 100.0% [CI 56.5–100%] | 100.0% | 0.234 ms |

**Read the intervals, not the point estimates.** Zero bypasses in 10 attacks
means ASR < 3/10 = 30% at 95% confidence (rule of three; the exact
Clopper-Pearson upper bounds are shown in brackets). These tiny samples can only
support "the samples are clean" — which is exactly why the canonical runs
(§2) are the real evidence and are not claimed until executed. To claim
ASR < 1% at 95% confidence requires **≥ 300 attacks with zero bypasses**
(rule of three); the canonical InjecAgent DH set alone provides 1,054.

- Reports: `reports/injecagent-in-tree-*.json`, `reports/agentdojo-in-tree-*.json`,
  `reports/mcptox-in-tree-*.json` (each includes dataset SHA-256, environment
  fingerprint, confusion matrix, full latency distribution).
- **Honest reading:** these are *small, curated samples* used for CI regression.
  100% on N=13 says "the sample is clean", nothing more. It is NOT comparable to
  literature numbers produced on the full canonical datasets.

### 1.2 Synthetic full-size corpus (combinatorial expansion) — 100% attack blocking

The in-tree generator expands the representative corpus to the canonical scale
(17 user tools × 62 payload templates = 1,054 vectors; all attack vectors, no
benign pairs):

| Corpus | N | ASR | Defense rate | Note |
|---|---|---|---|---|
| InjecAgent-style synthetic expansion | 1,054 | 0.0% | 100.0% | Aegis-authored payloads, NOT the canonical dataset |

**This is the corpus the historical "93.5% resilience" headline most closely
resembles — except the measured number is 100.0%, because every vector is an
attack the engine is designed to block. The published 93.5% was not reproducible
from any in-repo dataset and has been withdrawn** (see §3).

### 1.3 Real latency evidence (per-checker, measured)

From `.benchmark/evidence.json` (benchmark-harness microbenchmarks, Node 22,
this repository):

| Workload | p50 | p95 |
|---|---|---|
| benign passthrough | ≈ 0.037 ms | < 0.1 ms |
| SQL invariant (simple) | ≈ 1.10 ms | — |
| SQL invariant (complex, multi-checker) | ≈ 1.85 ms | — |

The "0.25 ms P50" marketing figure was a blend of these regimes; per-workload
numbers above are the citable ones.

## 2. Canonical dataset status (the right way, in progress)

Canonical ingestion machinery was repaired on 2026-08-20
(`scripts/fetch-canonical-benchmarks.mjs`):

- **Correct sources** (previous URLs were dead — both returned 404):
  - InjecAgent: `uiuc-kang-lab/InjecAgent` → `data/test_cases_{dh,ds}_{base,enhanced}.json` (4 files)
  - AgentDojo: `ethz-spylab/agentdojo` → `src/agentdojo/default_suites/benchmark_suites/` (dynamic discovery)
- **Fail-loud:** no synthetic data is ever written in place of fetched data;
  failures are recorded in `manifest.json` and exit non-zero (unless
  `--allow-fallback` for offline CI).
- **Committable:** output lives here (`benchmarks/canonical/`) with SHA-256
  manifest — previously it went to gitignored `.benchmark/` and could never be
  published.
- **Real-schema adapter:** the InjecAgent adapter now parses the canonical
  Title-Case schema (`Attacker Tools` plural array, `Attack Type`, file-level
  dh/ds category), pinned by `packages/evals/__tests__/canonical-schema.test.ts`.

**Status: canonical data is NOT yet committed to this repository.** The
first full canonical run executes in network-enabled CI via the
`benchmark-canonical` workflow (fail-loud fetch with SHA-256 manifest, canonical
evaluation, artifacts, and a human-reviewed evidence PR on manual dispatch).
The workflow definition is versioned at
`scripts/ci-templates/benchmark-canonical.yml` and installed into
`.github/workflows/` by a maintainer with workflow permissions
(`bash scripts/install-ci-templates.sh`). Until a run lands and is merged, no
canonical-dataset number will be published. When run, the fields reported
will be the field-standard set: **ASR, defense rate, benign utility, risk
(ASR/utility), confusion matrix, per-suite breakdown** — per the AgentDojo
(Debenedetti et al., NeurIPS 2024) and InjecAgent (Zhan et al., ACL 2024)
methodologies.

### Known measurement boundary (disclosed, not hidden)

InjecAgent and AgentDojo are **end-to-end agent benchmarks**: the attack
travels through tool *responses* and the model's reaction to them. Aegis
enforces the **tool-call boundary**: it can deterministically block the
harmful call the hijacked agent attempts (a targeted-ASR-style measurement
via the attacker-tool mapping in our adapters), but it does not moderate the
model's reasoning. Canonical runs therefore measure "did Aegis block the
attacker's goal action", not "did the model get injected". Both facts will be
stated with the results. Static-benchmark caveats apply to any defense
(adaptive-attack results, e.g. AgentDyn, arXiv:2602.03117, show static ASR
flatters defenses); Aegis's deterministic invariants are structural rather
than probabilistic, but independent adaptive red-teaming is still pending and
we do not claim otherwise.

### 1.4 Ablation study (component attribution, 2026-08-21)

Scientific ablation over the in-tree corpus (22 vectors, 15 attacks):
`runAblationStudy()` in `@aegis-kernel/evals`, rendered via `aegis eval ablation` docs.

- **No-packs control: ASR 100%** — normalization alone blocks nothing; ALL
  blocking is rule-driven (the engine is a policy engine, not a classifier).
- `finance-guard` removal: **+20pp ASR** (unique coverage: financial bounds).
- `data-guard` removal: **+20pp ASR** (unique coverage: PII/secrets).
- `sql-guard` removal: **+0pp — measured redundancy**: soc2-guard independently
  blocks every DDL/mass-mutation vector (SOC2-002/003). Defense-in-depth,
  quantified rather than asserted.
- No single-pack removal fully exposes the corpus (max single-pack ΔASR 20pp ≪
  control 100pp).

### 1.4b Full-corpus ablation (N=1,054 synthetic attack vectors, 2026-08-21)

Extends §1.4 to the full synthetic expansion — resolves the hipaa/pci open question:

| Pack removed | Blocked w/o pack | ΔASR (unique coverage) |
|---|---|---|
| control (no packs) | 0/1054 | — (ASR 100%) |
| sql-guard | 1054/1054 | **+0.0pp** (soc2-guard fully subsumes the SQL/DDL surface on this corpus) |
| finance-guard | 799/1054 | **+24.2pp** |
| data-guard | 867/1054 | **+17.7pp** |
| soc2-guard | 901/1054 | **+14.5pp** |
| hipaa-guard | 1054/1054 | **+0.0pp** — fully redundant with data-guard ON THIS CORPUS |
| pci-dss-guard | 1037/1054 | +1.6pp |

**Honest reading:** hipaa-guard adds zero unique coverage on the synthetic
corpus (its PHI patterns are subsumed by data-guard's PII rules). This is
corpus-specific — canonical InjecAgent/AgentDojo runs may exercise PHI patterns
the synthetic generator does not. The canonical ablation (post Tier-0 CI run)
decides whether hipaa-guard's rules are distinct enough to keep; until then the
redundancy is disclosed, not hidden.

### 1.6 Information-flow control (IFC-001, 2026-08-21)

FIDES/NeuroTaint-inspired deterministic taint tracking (CaMeL lineage):
untrusted sources (tool outputs) registered via `engine.registerUntrustedSource()`
that reappear — normalized against evasion mutations — inside sensitive-sink
parameters (`send_email`, `http_post`, `sql_query`) are blocked as IFC-001.
Catches ADI-style attacks (arXiv:2607.05120) that no content rule can see: the
FLOW is the violation. 9 tests incl. cross-call persistence (500 steps, no
label decay), FIFO-bounded memory, cross-session ledger reload, and
evasion-normalized matching. **Disclosed limitation:** paraphrase-surviving and
implicit-control taint (NeuroTaint's other flow classes) are NOT claimed.

### 1.7 Trajectory stress (2026-08-21, AgentDyn/HORIZON-aligned)

500-step deterministic sessions (seed 42): benign-heavy traffic + identical
attacks at steps 1/250/500.

- **Latency drift: Mann-Kendall** (Mann 1945; Kendall 1975; tie-corrected;
  Theil-Sen slope): no significant positive trend (p ≥ 0.05) across the session.
- **Attack detection at depth:** 3/3 blocked (step 1, 250, 500) — no
  long-horizon evasion of deterministic invariants.
- **False positives:** 0/497 benign steps; 95% Wilson CI upper bound 0.75%.
- Available as `aegis red-team run --suite trajectory` (exit 1 on drift,
  depth-bypass, or FP).

### 1.5 Metamorphic properties (2026-08-21)

Deterministic property suite (`metamorphic-properties.test.ts`, fast-check):
M1 determinism · M2 blocking monotonicity · M3 key-order invariance ·
M4 evasion closure · M5 fingerprint purity (proofHash deliberately binds time —
audit semantics) · M6 zero-FP on 200 generated benign calls. **M2 and M4 found
two real engine gaps on first run** (see corrections register) — the properties
now pin them permanently.

### 1.8 Supply chain & governance (2026-08-21, cycle 6)

- **Signed rule packs** (AISVS C10.1.1): `aegis pack sign` produces Ed25519
  sidecar manifests over canonical (key-order-invariant) SHA-256 pack
  commitments; `aegis pack verify` fails closed on tampered content, forged
  keys, wrong algorithms, and cross-pack manifest replay (8 tests + live
  round-trip verified: sign → verify ✅, tamper → exit 1).
- **Policy lifecycle**: shadow→promote→rollback with fail-closed gates
  (weaker-on-attacks and benign-FP regressions block promotion; snapshot-backed
  rollback) — 6 tests.

## 3. Corrections register

| Date | Correction |
|---|---|
| 2026-08-20 | Withdrew "93.5% InjecAgent resilience (1,054 cases)" — not reproducible from in-repo data; replaced by §1.1/§1.2 with corpus provenance |
| 2026-08-20 | Withdrew "86.6% AgentDojo accuracy (629 cases)" — same reason; replaced by §1.1 |
| 2026-08-20 | "0.25 ms P50" replaced by per-workload measured percentiles (§1.3) |
| 2026-08-21 | **Engine gap fixed (metamorphic M2 finding):** `SELECT` with tautological WHERE (`WHERE 1=1`, `'x'='x'`, OR-constant) was ALLOWED — sql-guard's unbounded-read rule (SQL-004) only enforced LIMIT ceilings. Tautological WHERE now blocked as unbounded-read-by-construction (benign no-LIMIT small reads still allowed). |
| 2026-08-21 | **Engine gap fixed (metamorphic M4 finding):** base64/double-base64-wrapped SQL in `query`, and encoded amount strings (`BASE64_DATA: …`, zero-width-spaced digits), bypassed the SQL parser and numeric bounds respectively. Both checkers now run bounded fold→decode cascades before enforcement. 12/12 layer×attack combos blocked, benign hash-literal queries unaffected. |
| 2026-08-20 | Fetch-script URLs fixed (both previously 404); synthetic silent fallback removed |

## 4. Reproduce

```bash
npm run build                                   # build workspace packages
node scripts/run-benchmarks.mjs                 # in-tree corpora → benchmarks/reports/
node scripts/fetch-canonical-benchmarks.mjs     # canonical datasets (needs egress)
node scripts/run-benchmarks.mjs --canonical     # canonical run → benchmarks/reports/
```

Reports are deterministic given the corpus and engine version; each embeds the
dataset SHA-256 and environment fingerprint for independent verification.
