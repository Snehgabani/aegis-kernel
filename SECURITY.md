# Security Policy & Vulnerability Disclosure

## 🛡️ Our Commitment to Security

Security and invariant integrity are the foundational core of **Aegis Invariant Kernel**. We take all security reports seriously and are committed to swift, transparent, and coordinated vulnerability disclosure.

---

## 📦 Supported Versions

Only the latest active major version receives active security patches and CVE remediation:

| Version | Supported | Security Patch SLA |
| :--- | :--- | :--- |
| **v1.x.x (Current)** |  Yes | Critical: < 24 Hours / High: < 72 Hours |
| < v1.0.0 (Beta) |  No | End of Life |

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
- The specific rule pack or checker involved (`SqlChecker`, `NumericChecker`, `PiiChecker`, `StateChecker`).
- Impact assessment on autonomous agent environments.

---

## ⏱️ Response SLA & Bug Bounty
- **Initial Triage & Acknowledgment**: Within **12 hours**.
- **Proof of Concept Validation & Patch Delivery**: Within **24 to 48 hours**.
- **Public CVE Release & Attribution**: Coordinated with the reporter with full credit in our security advisories directory (`docs/advisories/`).
