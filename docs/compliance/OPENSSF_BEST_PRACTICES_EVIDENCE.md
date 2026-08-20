# OpenSSF Best Practices Badge (CII Badge) — Complete Criteria Attestation & Submission Guide

**Project**: Aegis Invariant Kernel (`aegis-kernel`)  
**Repository**: [github.com/Snehgabani/aegis-kernel](https://github.com/Snehgabani/aegis-kernel)  
**Standard**: OpenSSF Best Practices Badge (Passing Level — 100% Complete)  
**Date**: August 2026

---

## Complete OpenSSF Passing Level Questionnaire & Evidence Mapping

This document provides the exact justifications, file references, and URLs required to achieve a **100% Passing Score** on [bestpractices.dev](https://www.bestpractices.dev/). Badge Project ID: [14173](https://www.bestpractices.dev/en/projects/14173).

---

### 1. Basics

| Criterion ID | Criterion Title | Status | Official Justification & Evidence URL |
| :--- | :--- | :---: | :--- |
| `description_good` | Project Description | **MET** | Aegis provides a clear, concise summary in `README.md` and repository metadata: *"Deterministic safety verification for AI agent tool calls. In-process AST analysis, sub-1.5ms latency, zero network egress."* Reference: [`README.md`](https://github.com/Snehgabani/aegis-kernel/blob/main/README.md). |
| `interact` | Community Interaction | **MET** | The project provides a public issue tracker and discussion forum at [`https://github.com/Snehgabani/aegis-kernel/issues`](https://github.com/Snehgabani/aegis-kernel/issues). |
| `contribution` | Contribution Process | **MET** | The project maintains a non-trivial contributing guide at [`CONTRIBUTING.md`](https://github.com/Snehgabani/aegis-kernel/blob/main/CONTRIBUTING.md). |
| `contribution_requirements` | Contribution Requirements | **MET** | Contribution rules, PR verification gates, code formatting, and test matrix requirements are detailed in [`CONTRIBUTING.md`](https://github.com/Snehgabani/aegis-kernel/blob/main/CONTRIBUTING.md). |
| `license_location` | License Location | **MET** | The project license is located in standard top-level [`LICENSE`](https://github.com/Snehgabani/aegis-kernel/blob/main/LICENSE). |
| `floss_license` | FLOSS License | **MET** | The project is released under the permissive [MIT License](https://opensource.org/licenses/MIT). |
| `floss_license_osi` | OSI-Approved License | **MET** | The MIT License is officially approved by the Open Source Initiative (OSI). |
| `documentation_basics` | Basic Documentation | **MET** | Comprehensive getting started and security guides are provided: [`docs/GETTING_STARTED.md`](https://github.com/Snehgabani/aegis-kernel/blob/main/docs/GETTING_STARTED.md) (installation, startup, 3 tutorials) and [`docs/SECURITY_USER_GUIDE.md`](https://github.com/Snehgabani/aegis-kernel/blob/main/docs/SECURITY_USER_GUIDE.md) (operational dos and don'ts). |
| `documentation_interface` | Interface Reference Documentation | **MET** | Exhaustive reference documentation describing public classes, methods, inputs (`ToolCall`), outputs (`AegisResult`), REST API endpoints, and CLI options is provided in [`docs/API_REFERENCE.md`](https://github.com/Snehgabani/aegis-kernel/blob/main/docs/API_REFERENCE.md). |
| `sites_https` | HTTPS Everywhere | **MET** | All project URLs and documentation endpoints use TLS/HTTPS: `https://github.com/Snehgabani/aegis-kernel` and `https://snehgabani.github.io/aegis-kernel/`. |

---

### 2. Change Control

| Criterion ID | Criterion Title | Status | Official Justification & Evidence URL |
| :--- | :--- | :---: | :--- |
| `repo_public` | Public Repository | **MET** | The source code is publicly accessible at [`https://github.com/Snehgabani/aegis-kernel`](https://github.com/Snehgabani/aegis-kernel). |
| `repo_track` | Track Changes | **MET** | Uses Git to track all code changes, authors, and timestamps. |
| `repo_interim` | Interim Releases | **MET** | Interim development versions are tracked live on the `main` branch. |
| `repo_distributed` | Distributed VCS | **MET** | Uses Git, a distributed version control system. |
| `version_unique` | Unique Versioning | **MET** | Uses unique version strings across `package.json` (`1.0.1`), `pyproject.toml`, and `Cargo.toml`. |
| `version_semver` | Semantic Versioning | **MET** | Adheres strictly to SemVer 2.0.0 (`MAJOR.MINOR.PATCH`). |
| `version_tags` | Release Tags | **MET** | Every public release is tagged in Git (e.g. `v1.0.0`, `v1.0.1`). |
| `release_notes` | Release Notes | **MET** | Published in [`CHANGELOG.md`](https://github.com/Snehgabani/aegis-kernel/blob/main/CHANGELOG.md) and GitHub Releases. |
| `release_notes_vulns` | Vulnerability Release Notes | **MET** | Security advisories and CVE remedies are tracked in [`docs/advisories/`](https://github.com/Snehgabani/aegis-kernel/tree/main/docs/advisories) and release changelogs. |

---

### 3. Reporting & Issue Tracking

| Criterion ID | Criterion Title | Status | Official Justification & Evidence URL |
| :--- | :--- | :---: | :--- |
| `report_tracker` | Bug Tracker | **MET** | Public issue tracking at [`https://github.com/Snehgabani/aegis-kernel/issues`](https://github.com/Snehgabani/aegis-kernel/issues). |
| `report_process` | Bug Report Process | **MET** | Issue templates provided in [`.github/ISSUE_TEMPLATE/`](https://github.com/Snehgabani/aegis-kernel/tree/main/.github/ISSUE_TEMPLATE). |
| `report_responses` | Issue Responses | **MET** | Issues receive initial triage within 24–48 hours per [`CONTRIBUTING.md`](https://github.com/Snehgabani/aegis-kernel/blob/main/CONTRIBUTING.md). |
| `enhancement_responses` | Feature Requests | **MET** | Feature proposals are tracked via GitHub Discussions and Issues. |
| `report_archive` | Public Issue Archive | **MET** | All past issues and discussions are permanently searchable on GitHub. |
| `vulnerability_report_private` | Private Security Reporting | **MET** | Private reporting via [GitHub Security Advisories](https://github.com/Snehgabani/aegis-kernel/security/advisories/new) and encrypted email `security@aegis-kernel.dev` per [`SECURITY.md`](https://github.com/Snehgabani/aegis-kernel/blob/main/SECURITY.md). |
| `vulnerability_report_response` | Security Response SLA | **MET** | Security policy commits to triage response within **12 hours** and patch release within **24–48 hours** per [`SECURITY.md`](https://github.com/Snehgabani/aegis-kernel/blob/main/SECURITY.md). |

---

### 4. Quality & Testing

| Criterion ID | Criterion Title | Status | Official Justification & Evidence URL |
| :--- | :--- | :---: | :--- |
| `build` | Working Build System | **MET** | Monorepo builds via standard `npm run build` (`tsup` + `turborepo`). |
| `build_common_tools` | Standard Build Tools | **MET** | Standard tooling: Node.js/npm, Python pip, Cargo, Go. |
| `build_floss_tools` | FLOSS Build Tooling | **MET** | 100% of compilers, bundlers, and test runners are open source (FLOSS). |
| `test` | Automated Test Suite | **MET** | Comprehensive suite of **74 test files (532 tests)** passing with 100% success rate via `npm test`. |
| `test_continuous_integration` | Continuous Integration | **MET** | Automated GitHub Actions CI executes full test matrix on every push and pull request (`.github/workflows/ci.yml`). |
| `test_policy` | Test Coverage Policy | **MET** | Policy in `CONTRIBUTING.md` requires unit tests for all new invariants and bug fixes. |
| `warnings` | Compiler Warning Hygiene | **MET** | Strict TypeScript compilation (`tsc --noEmit`) with zero unresolved lints or type errors. |

---

### 5. Security & Cryptography

| Criterion ID | Criterion Title | Status | Official Justification & Evidence URL |
| :--- | :--- | :---: | :--- |
| `know_secure_design` | Secure Design Knowledge | **MET** | Architecture applies deterministic AST invariance, constant-folding tautology detection, fail-closed defaults, and air-gapped zero network egress. Documented in [`WHITE_PAPER.md`](https://github.com/Snehgabani/aegis-kernel/blob/main/WHITE_PAPER.md) and [`docs/LIMITATIONS_AND_BOUNDARIES.md`](https://github.com/Snehgabani/aegis-kernel/blob/main/docs/LIMITATIONS_AND_BOUNDARIES.md). |
| `crypto_floss` | FLOSS Cryptography | **MET** | All cryptography relies on standard open-source libraries: Node `node:crypto` (OpenSSL FLOSS), Python `hashlib`/`secrets` (FLOSS), Rust `sha2`/`hmac` (FLOSS), and Go `crypto/*` (FLOSS). |
| `crypto_keylength` | NIST 2030+ Key Lengths | **MET** | All cryptographic mechanisms exceed NIST recommendations through 2030+: SHA-256 (256-bit hash >= 224 bits), HMAC-SHA256 (256-bit symmetric key >= 112 bits), Ed25519 (256-bit curve >= 224 bits). Insecure algorithms (MD5, SHA-1, DES) are unsupported and disabled. |
| `crypto_password_storage` | Password Storage | **N/A** | **Not Applicable**. Aegis Invariant Kernel does not store user passwords for inbound user authentication. Secret masking uses ephemeral salted HMAC tokenization (`PiiTokenVault`). |
| `crypto_random` | CSPRNG Random Generation | **MET** | All keys, nonces, tokens, and salts are generated exclusively using OS-backed CSPRNGs (`crypto.randomBytes`, `crypto.randomUUID`, `secrets.token_hex`). Zero usage of insecure random generators (`Math.random`). |
| `delivery_mitm` | Anti-MITM Delivery | **MET** | Releases are distributed over HTTPS (npm, PyPI, GHCR) with SLSA Level 3 cryptographic provenance (`actions/attest-build-provenance`) and Sigstore Cosign container signatures. |
| `vulnerabilities_fixed_60_days` | Rapid Vulnerability Remediation | **MET** | Security policy commits to resolving critical vulnerabilities in <24-48 hours per [`SECURITY.md`](https://github.com/Snehgabani/aegis-kernel/blob/main/SECURITY.md). |
| `static_analysis` | Continuous SAST | **MET** | Continuous multi-engine SAST runs on every PR: GitHub CodeQL (`codeql.yml`), Semgrep OSS (`semgrep.yml`), Microsoft DevSkim (`devskim.yml`), PyCQA Bandit (`bandit.yml`), Gitleaks (`gitleaks.yml`), and Aqua Trivy (`trivy-scan.yml`). |
| `dynamic_analysis` | Dynamic Fuzzing Analysis | **MET** | Automated nightly fuzzer runs 1,000-iteration concurrency tests and the 100-vector adversarial boundary testbed (`.github/workflows/nightly-fuzz.yml`). |
