# Software Supply Chain Security, Trust & Cryptographic Provenance

> **How to mathematically and independently verify that Aegis Invariant Kernel is genuine, authentic, and backdoor-free.**

---

## 1. The Trust Model of Aegis

When deploying a security layer to govern autonomous AI agents in production, you must have mathematical certainty that the safety tool itself is authentic and uncompromised. Aegis implements a multi-layer **defense-in-depth supply chain integrity protocol** adhering to:

1. **SLSA Level 3** (Supply-chain Levels for Software Artifacts) Build Attestation.
2. **Keyless Sigstore & OIDC Cryptographic Signatures** for all published npm packages, PyPI wheels, and Docker container images.
3. **Dual Software Bill of Materials (SBOM)** in ISO/IEC SPDX 2.3 and OWASP CycloneDX 1.5 formats.
4. **Bit-for-Bit Bitstream Reproducible Builds** verified in continuous integration.
5. **Continuous Multi-Engine SAST** (CodeQL, Semgrep, Microsoft DevSkim, Bandit, Gitleaks, Aqua Security Trivy, Google OSV).
6. **Air-Gapped Zero Network Egress Invariant**: The clearance hot path contains zero network sockets, telemetry phone-home hooks, or third-party cloud dependencies.

---

## 2. Independent Verification Guide

Any developer, security researcher, or enterprise auditor can verify the authenticity of Aegis artifacts using standard open-source verification tooling:

### A. Verifying npm Package Provenance (Sigstore / GitHub OIDC)

Every official `@aegis-kernel/*` package published to the npm registry includes cryptographic build provenance:

```bash
# 1. Audit package signatures directly with npm CLI
npm audit signatures

# 2. Inspect cryptographic attestation via GitHub CLI
gh attestation verify @aegis-kernel/core-1.0.1.tgz --owner Snehgabani
```

### B. Verifying Gateway Container Signatures (Sigstore Cosign)

Official container images published to GitHub Container Registry (`ghcr.io/snehgabani/aegis-gateway`) are signed via Sigstore keyless OIDC:

```bash
# Verify the Docker container signature and workflow identity
cosign verify ghcr.io/snehgabani/aegis-gateway:latest \
  --certificate-identity-regexp="https://github.com/Snehgabani/aegis-kernel/.github/workflows/docker-publish.yml@refs/heads/main" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```

### C. Verifying Software Bill of Materials (SBOM)

To inspect every transitive library, hash, and license in the codebase:

```bash
# Generate a local SPDX SBOM with Syft
syft packages dir:. -o spdx-json=local-sbom.json

# Scan against live CVE databases with Grype
grype sbom:local-sbom.json --fail-on critical
```

### D. Verifying Bit-for-Bit Reproducible Builds

Aegis builds are deterministic. Compiling the source code on any standard Node.js 22+ environment produces identical SHA-256 binary distributions:

```bash
git clone https://github.com/Snehgabani/aegis-kernel.git
cd aegis-kernel
npm ci && npm run build

# Compute distribution checksums
find packages/*/dist -type f -exec sha256sum {} + | sort
```

---

## 3. Continuous Security Scanners & CI Gates

Aegis runs continuous automated static analysis, secret scanning, and fuzz testing on every pull request and nightly schedule:

| Security Engine | Purpose | Configuration & Schedule |
| :--- | :--- | :--- |
| **GitHub CodeQL** | Multi-language semantic AST taint tracking (TypeScript & Python) | `.github/workflows/codeql.yml` (PR + Weekly) |
| **Semgrep OSS** | OWASP Top 10 and security-audit rule packs | `.github/workflows/semgrep.yml` (PR + Weekly) |
| **Microsoft DevSkim** | Source code security and cryptography linting | `.github/workflows/devskim.yml` (PR + Weekly) |
| **Gitleaks** | Full git history token and private key scanner | `.github/workflows/gitleaks.yml` (All commits) |
| **Aqua Security Trivy** | Filesystem, package-lock, and container CVE audit | `.github/workflows/trivy-scan.yml` (PR + Weekly) |
| **Google OSV-Scanner** | Open Source Vulnerabilities database sync | `.github/workflows/osv-scanner.yml` (PR + Weekly) |
| **PyCQA Bandit** | Python SDK AST security analyzer | `.github/workflows/bandit.yml` (PR + Weekly) |
| **Adversarial Fuzzer** | 1,000-iteration concurrency and 100-vector boundary testbed | `.github/workflows/nightly-fuzz.yml` (Nightly) |

---

## 4. Responsible Disclosure & Disclose.io Safe Harbor

We maintain a strict coordinated vulnerability disclosure policy under [ISO/IEC 29147](https://www.iso.org/standard/72311.html):

- **Private Reporting Channel**: [GitHub Security Advisories](https://github.com/Snehgabani/aegis-kernel/security/advisories/new) or `security@aegis-kernel.dev`.
- **Response SLA**: Initial triage within **12 hours**; patch delivery within **24–48 hours**.
- **Legal Safe Harbor**: We pledge never to initiate legal action (under the CFAA, DMCA Section 1201, or equivalent international statutes) against security researchers conducting good-faith research in accordance with our [`SECURITY.md`](../../SECURITY.md).
