# 🏛️ Aegis Invariant Kernel Governance & Project Leadership

This document outlines the governance model, decision-making framework, and maintainer responsibilities for the **Aegis Invariant Kernel** project.

---

## 🎯 Governance Principles

1. **Zero-Egress & Zero-Compromise Security**: No change may introduce unconsented network egress or bypass the deterministic evaluation pipeline.
2. **Open & Transparent Evolution**: Major architectural proposals, rule packs, and RFCs are discussed publicly in GitHub Discussions.
3. **Consensus-Driven Technical Direction**: Core maintainers aim for rough consensus on technical decisions, backed by empirical benchmarks.

---

## 👥 Roles & Responsibilities

### Contributors
Anyone who opens issues, submits pull requests, improves documentation, or participates in discussions. Contributors must adhere to the [Code of Conduct](CODE_OF_CONDUCT.md).

### Maintainers
Maintainers are trusted contributors responsible for repository health, reviewing PRs, managing releases, and guiding project architecture. Maintainer responsibilities include:
- Reviewing PRs with thorough automated and manual quality checks.
- Upholding code coverage $>90\%$ and invariant benchmarks ($P_{95} < 5\text{ms}$).
- Maintaining zero open security alerts across SAST, secret scanning, and dependency audits.
- Triaging issues and guiding community contributors.

### Security Committee
A dedicated subset of maintainers tasked with handling private vulnerability reports in accordance with [SECURITY.md](SECURITY.md), conducting quarterly threat model reviews, and coordinating CVE disclosures.

---

## 🔄 RFC (Request for Comments) Lifecycle

Major feature additions (e.g. new formal policy engines, zero-knowledge verification backends, framework adapters) follow the 4-stage RFC process:

1. **Proposal**: Open an RFC in GitHub Discussions under `Ideas & RFCs`.
2. **Review**: Community review and adversarial red-teaming (minimum 7-day review window).
3. **Decision**: Core maintainer consensus and specification sign-off.
4. **Implementation**: Pull request submission with 100% test coverage and benchmark verification.
