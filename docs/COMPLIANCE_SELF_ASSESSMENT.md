# Aegis Invariant Kernel — Compliance Self-Assessment & Audit-Evidence Tooling

**Document type:** Vendor self-assessment (NOT a certification)
**Last updated:** 2026-08-16
**Version assessed:** `1.0.0` (unreleased — install from source)

---

## ⚠️ Read This First: What This Document Is and Is Not

- **This is a SELF-ASSESSMENT.** It was written by the project's own authors.
- **It is NOT a SOC 2 Type II certification, HIPAA certification, PCI-DSS attestation, or any other formal certification.** Certifications can only be issued by accredited third-party auditors (e.g., a licensed CPA firm for SOC 2, a Qualified Security Assessor for PCI-DSS). No such audit has been performed on this project.
- **It does NOT make you compliant.** Deploying this software does not confer regulatory compliance on your organization. Compliance is a property of your whole system, your processes, and your evidence — not of any single library.
- The companion legal disclaimer in [`DISCLAIMER.md`](../DISCLAIMER.md) states the same in binding terms.

---

## 1. What Aegis Provides for Compliance Programs

Aegis is a deterministic, in-process tool-call clearance kernel. For compliance teams, it can serve as **technical evidence-generating tooling**:

| Purpose | What Aegis does | What it does NOT do |
| :--- | :--- | :--- |
| Audit trail | Emits per-event SHA-256 `proofHash` commitments binding tool arguments to policy hashes | Is not a certified audit log / WORM storage system |
| Policy enforcement evidence | Rule packs map to common control families (SOC 2 CC6.1/6.6/6.8-style, HIPAA §164.312-style, PCI-DSS Req 3.4/6.5-style, EU AI Act Art. 5/15-style) | Is not a control implementation checklist; control mapping is indicative only |
| GRC dossier export | `generateComplianceDossier` produces a Merkle-rooted, tamper-evident export of evaluation events | The dossier is self-generated evidence, not an auditor-approved report |

> **Control-family note:** the rule packs (`soc2-guard`, `hipaa-guard`, `pci-dss-guard`, `eu-ai-act-guard`, `gdpr-guard`) are *inspired by* common control objectives. They do not implement or guarantee compliance with any regulation, and no regulator or auditor has reviewed them.

---

## 2. Empirically Measured Metrics (Reproducible)

These numbers are produced by the repository's own test and benchmark suites; run them yourself:

| Metric | Value | How to reproduce |
| :--- | :--- | :--- |
| Unit/integration tests | 266 / 266 passing (47 files) | `npm install && npm test` |
| Python SDK tests | 7 / 7 passing | `cd packages/python && python3 -m pytest tests/` |
| Internal adversarial testbed (100 vectors, 10 threat domains) | 100% F1 (malicious blocked, benign passed) | `npx vitest run packages/evals` |
| Latency (simple calls) | P50 ≈ 0.3 ms, mean ≈ 0.36 ms | `npx aegis benchmark` |
| Latency (worst case, multi-statement SQL) | P99 ≈ 23–51 ms depending on hardware | same benchmark run |
| Network egress during clearance | 0 bytes (no outbound calls in the hot path) | static review + network monitoring |
| External public benchmarks (InjecAgent / AgentDojo / MCPTox) | **Not yet evaluated** | n/a — planned, not done |

---

## 3. Known Gaps & Open Items (Disclosed, Not Hidden)

1. **No independent security audit** has been performed (no third-party pentest, no CodeQL/Semgrep sign-off beyond CI scans).
2. **No formal certification** of any kind (SOC 2 / ISO 27001 / PCI-DSS / HIPAA) exists.
3. **Nothing is published** to npm/PyPI/Homebrew yet; consumers must build from source and pin a commit.
4. **Single maintainer; ~24-hour commit history at time of writing.** The project has not demonstrated sustained maintenance.
5. **The WASM plugin runner and several "enterprise" subsystems are new and lightly exercised** in production-like conditions.
6. **License-gating code** (HMAC license keys, Stripe billing hooks) exists in the repo even though the software is MIT-licensed — the commercial model is not yet finalized.

---

## 4. What an Independent Auditor Would Need to Verify

The repository is public and reproducible. An auditor (or you) can independently verify the claims in Section 2:

```bash
git clone https://github.com/Snehgabani/aegis-kernel.git
cd aegis-kernel
npm install
npm test                                  # 266/266 tests
npx vitest run packages/evals             # internal 100-vector adversarial testbed
npx aegis benchmark --tricky              # latency + F1
```

---

## 5. Recommendation to Adopters

Treat Aegis as **early-stage open-source tooling with unverified compliance claims**, and do not rely on any compliance statement in this repository without (a) your own evaluation, (b) a third-party audit, and (c) review by your legal/compliance team. This document exists to make that boundary explicit.
