# 🛡️ Aegis GitHub Action: Enterprise AI Agent Security & Compliance Gate

> **The Official GitHub Marketplace Action for Continuous AI Agent Safety Verification**  
> *Audit SQL AST Invariants • Enforce Financial Risk Bounds • Generate Cryptographic SOC2/HIPAA Evidence in CI/CD*

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-Aegis%20Action-blue.svg?logo=github)](https://github.com/marketplace/actions/aegis-ai-agent-security-compliance-audit-action)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

---

## ⚡ Quickstart: Add to Your GitHub Actions Workflow

Add **Aegis** to your CI/CD pipeline to automatically block malicious or non-compliant agent tool behaviors before deploying changes:

```yaml
name: AI Agent Safety & Compliance Gate

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  aegis-safety-audit:
    name: Aegis Deterministic Policy Clearance
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run Aegis Security & Compliance Audit
        uses: Snehgabani/aegis-kernel@v1
        with:
          config-path: "./aegis.config.yaml"
          mode: "enforce"
          generate-report: "true"
```

---

## ⚙️ Inputs & Configuration

| Input | Description | Required | Default |
| :--- | :--- | :--- | :--- |
| `config-path` | Path to the `aegis.config.yaml` policy configuration file. | No | `./aegis.config.yaml` |
| `mode` | Security enforcement mode (`enforce` = hard block violations, `shadow` = log only). | No | `enforce` |
| `generate-report` | Automatically writes an executive SOC 2 / HIPAA compliance report to `$GITHUB_STEP_SUMMARY`. | No | `true` |

---

## 📊 Outputs

| Output | Description |
| :--- | :--- |
| `safety-score` | Calculated Agent Safety Score ($0 - 100$) based on empirical invariant evaluations. |
| `verdict` | Final clearance decision: `PASSED` or `FAILED`. |

---

## 💼 Why Engineering Leaders & CISOs Use Aegis in CI/CD

1. **Shift-Left AI Governance**: Catch rogue agent tools and SQL injection vulnerabilities before merging to production.
2. **Zero False Positives**: Replaces noisy probabilistic LLM tests with deterministic Abstract Syntax Tree (AST) compilation.
3. **Automated GRC Evidence**: Every run produces an immutable SHA-256 cryptographic audit trail attached directly to the GitHub Pull Request.
