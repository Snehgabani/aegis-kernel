# Security Policy & Vulnerability Disclosure

## 🛡️ Our Commitment to Security

Security and invariant integrity are the foundational core of **Aegis Invariant Kernel**. We take all security reports seriously and are committed to swift, transparent, and coordinated vulnerability disclosure.

---

## 📦 Supported Versions

Only the latest active major version receives active security patches and CVE remediation:

| Version | Supported | Security Patch SLA |
| :--- | :--- | :--- |
| **v1.x.x (Current)** | ✅ Yes | Critical: < 24 Hours / High: < 72 Hours |
| < v1.0.0 (Beta) | ❌ No | End of Life |

---

## 🔒 Reporting a Vulnerability

**Please DO NOT file public GitHub Issues for security vulnerabilities.**

To report a vulnerability:
1. **GitHub Private Advisory (Recommended)**: Use the [GitHub Security Advisory form](https://github.com/Snehgabani/aegis-kernel/security/advisories/new).
2. **Direct Email**: Send encrypted or plain-text details to `security@aegis-kernel.dev` with the subject `[SECURITY DISCLOSURE] <Summary>`.

### Report Requirements:
Please include:
- A clear description of the attack vector or bypass.
- A minimal reproduction script or JSON tool payload that evades the invariant checkers.
- The specific rule pack or checker involved (`SqlChecker`, `NumericChecker`, `PiiChecker`, `StateChecker`, `CustomChecker`).
- Impact assessment on autonomous agent environments.

---

## ⏱️ Response SLA & Security Hall of Fame
- **Initial Triage & Acknowledgment**: Within **12 hours**.
- **Proof of Concept Validation & Patch Delivery**: Within **24 to 48 hours**.
- **Public CVE Release & Attribution**: Coordinated with the reporter with full credit in our security advisories directory (`docs/advisories/`) and permanent inclusion in the **Aegis Security Hall of Fame**.

### 🏆 The Aegis Community Red-Team Challenge
We invite security researchers and red-teamers to test the kernel's deterministic boundaries:
- **Challenge Scope**: Craft a single SQL tool call payload (under standard `@aegis/sql-guard` rules) that bypasses AST comment-stripping, tautology constant folding, and mutation checkers to execute an unauthorized `DROP TABLE`, `TRUNCATE`, or unconstrained `DELETE/UPDATE`.
- **Submission**: Submit your reproducible PoC via [GitHub Security Advisories](https://github.com/Snehgabani/aegis-kernel/security/advisories/new) or email `security@aegis-kernel.dev`. Valid, confirmed bypasses receive top-tier recognition, CVE credit, and permanent inclusion in the **Aegis Security Hall of Fame**.

---

## 🛡️ Security Researcher Safe Harbor

We consider good-faith security research to be vital for the open-source and AI safety ecosystem. We pledge that:

1. **No Legal Action**: We will not pursue civil or criminal legal action (including under the Computer Fraud and Abuse Act (CFAA) or DMCA) against researchers who conduct security research and report vulnerabilities in good faith in accordance with this policy.
2. **Good-Faith Research Defined**: To qualify for safe harbor, researchers must:
   - Make every effort to avoid privacy violations, degradation of user experience, and disruption to production systems.
   - Only interact with test accounts or systems owned or authorized by the researcher.
   - Refrain from accessing, modifying, or retaining non-public data beyond the minimum necessary to demonstrate a proof of concept.
   - Give our engineering team a reasonable period (standard 90-day coordinated disclosure) to address the issue before making details public.
