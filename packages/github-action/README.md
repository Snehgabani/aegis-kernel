# 🛡️ Aegis Security & Compliance Audit Action

> **Deterministic AI Agent Safety & Compliance CI/CD Gate for GitHub Actions**  
> *Shift-Left Tool Invariant Auditing • MCP Schema Verification • Automated GRC Evidence Generation*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![GitHub Action](https://img.shields.io/badge/GitHub_Action-v1-blue?logo=github-actions&logoColor=white)](https://github.com/Snehgabani/aegis-kernel)

---

## 🚀 Overview

The **Aegis GitHub Action** (`Snehgabani/aegis-kernel@v1`) integrates deterministic agent safety clearance directly into continuous integration workflows. It automatically:

- **Scans Prompts & Code**: Detects hardcoded secrets, unsafe queries, and prompt injection patterns.
- **Validates MCP Tools**: Scans Model Context Protocol JSON/YAML definitions for zero-width Unicode injection and schema rug-pull vulnerabilities.
- **Executes Invariant Testbeds**: Runs the Agent Safety Scorecard harness on every pull request.
- **Generates GRC Compliance Evidence**: Produces signed audit dossiers mapped to SOC 2, HIPAA, ISO 42001, and the EU AI Act.

---

## ⚡ Usage

Add this step to your GitHub Actions workflow (e.g. `.github/workflows/aegis-audit.yml`):

```yaml
name: Aegis AI Agent Security Audit

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  audit:
    name: Agent Invariant Clearance & Compliance Gate
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
          fail-on-violation: "true"

      - name: Upload GRC Compliance Evidence Dossier
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: aegis-compliance-dossier
          path: aegis-evidence.json
```

---

## ⚙️ Inputs

| Input | Description | Required | Default |
| :--- | :--- | :--- | :--- |
| `config-path` | Path to `aegis.config.yaml` configuration file | No | `./aegis.config.yaml` |
| `mode` | Clearance mode (`enforce` to fail build on violations, `shadow` to log only) | No | `enforce` |
| `generate-report` | Whether to generate a structured JSON GRC compliance dossier | No | `true` |
| `fail-on-violation` | Whether to exit with code 1 if critical invariant violations are detected | No | `true` |

---

## 📄 License

Distributed under the [MIT License](https://opensource.org/licenses/MIT). Copyright (c) 2026 Sneh Gabani.
