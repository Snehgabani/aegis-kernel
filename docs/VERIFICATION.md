# 🧪 Aegis Invariant Kernel — Verification & Reproducibility Guide

> **How to independently verify every claim in the Aegis project.**

---

## 📋 Benchmark Reproduction

All academic benchmarks can be reproduced locally or in CI:

```bash
# Run the full academic evaluation suite
node packages/cli/dist/index.js eval all --output attestation.json

# Expected output:
#   Accuracy:             100%
#   Precision:            100%
#   Recall:               100%
#   F1 Score:             100%
#   SHA-256 Attestation:  34293e4f...
```

### Benchmark Datasets

| Benchmark | Source | Our Implementation |
|-----------|--------|-------------------|
| **InjecAgent (ACL 2024)** | [uiuc-kang-lab/InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) | `packages/evals/src/benchmarks/injecagent-dataset.ts` — representative samples. Full canonical dataset ingestion: `aegis eval all --canonical` (requires download). |
| **AgentDojo (NeurIPS 2024)** | [vllm-project/agentdojo](https://github.com/vllm-project/agentdojo) | `packages/evals/src/benchmarks/agentdojo-adapter.ts` |
| **MCPTox / MCP-Bench** | Community standard | `packages/evals/src/benchmarks/mcp-bench-suite.ts` |
| **Adversarial Fuzz** | Internal 433-vector corpus | `packages/evals/__tests__/adversarial-fuzz.test.ts` |
| **Tricky-100** | Internal 100-vector testbed | `packages/evals/__tests__/tricky-100.test.ts` |

### Running the Full Test Suite

```bash
# Core TypeScript (532 tests)
npm install && npm run build && npm test

# Go engine
cd packages/go && go test ./...

# Rust crate
cd packages/rust && cargo test

# Python SDK
cd packages/python && python -m unittest discover tests
```

---

## 🔐 Security Claims Verification

### Claim: "Zero network egress on the hot path"
**Verify:** Run `strace -e network npm test` and confirm zero `connect()` syscalls during test execution. The only network calls should be from test infrastructure (Vitest, etc.) not the engine itself.

### Claim: "<1.5ms P50 latency"
**Verify:**
```bash
node packages/cli/dist/index.js benchmark
```
This runs a statistical benchmark harness and outputs P50/P95/P99 latency.

### Claim: "Deterministic AST analysis catches DROP TABLE"
**Verify:**
```bash
node -e "
const { AegisEngine } = require('./packages/core/dist/index.cjs');
const engine = new AegisEngine();
console.log(engine.evaluate({tool:'sql', params:{query:'DROP TABLE users'}}).allowed
  ? '❌ FAIL' : '✅ PASS (blocked)');
console.log(engine.evaluate({tool:'sql', params:{query:'SELECT 1'}}).allowed
  ? '✅ PASS (allowed)' : '❌ FAIL');
"
```

### Claim: "PII detection masks secrets"
**Verify:**
```bash
node -e "
const { AegisEngine } = require('./packages/core/dist/index.cjs');
const engine = new AegisEngine();
console.log(engine.evaluate({tool:'email', params:{body:'SSN: 123-45-6789'}}).allowed
  ? '❌ FAIL' : '✅ PASS (SSN blocked)');
"
```

---

## 📊 Audit Log & Proof Verification

```bash
# View recent evaluation events
node packages/cli/dist/index.js stats

# Generate a SOC 2 / ISO 42001 self-assessment report
node packages/cli/dist/index.js audit-report .

# Recompute Merkle proofs from historical audit log
node packages/cli/dist/index.js verify .aegis/events.jsonl
```

---

## 🛡️ Red Team Testing

```bash
# Run the 433-vector adversarial test suite (CI-friendly)
npx vitest run packages/evals/__tests__/adversarial-fuzz.test.ts

# Run the full red-team security harness
node packages/cli/dist/index.js red-team run

# Run property-based fuzz tests (randomized SQL/PII payloads)
npm run test:fuzz
```

---

## 📦 Release Artifact Verification

```bash
# Verify npm tarball integrity
cd dist-release
sha256sum -c CHECKSUMS.txt

# Verify Sigstore signatures (when configured)
cosign verify-blob --signature aegis-kernel-core-1.0.0.tgz.sig aegis-kernel-core-1.0.0.tgz
```

---

## 📋 CI/CD Pipeline

All verifications run automatically on every push/PR:
1. TypeScript build + lint + test (Node 20.x, 22.x)
2. Go build + test + vet (Go 1.21, 1.22, 1.23)
3. Rust build + test + clippy + fmt (stable, beta)
4. Python test + lint (3.10, 3.11, 3.12)
5. Diagnostics integrity check (`aegis doctor`)
6. End-to-end live verification suite
7. CodeQL SAST scanning
8. Dependabot dependency monitoring
9. Security audit (`npm run test:security`)

---

> **Last updated:** 2026-08-20  
> Any claim not reproducible via the steps above should be reported as a [GitHub Issue](https://github.com/Snehgabani/aegis-kernel/issues).