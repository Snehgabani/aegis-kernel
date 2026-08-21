# Aegis Invariant Kernel — Sample Audit Evidence Bundle (Big-4 Ready)

Generated: 2026-08-21T06:52:01.092Z

This directory is a self-contained, cryptographically sealed evidence package
for an independent auditor examining **SOC 2 Type II**, **ISO/IEC 42001:2023**,
**HIPAA §164.312**, **NIST AI RMF 1.0**, and the **EU AI Act** (Article 50 in
force 2026-08-02; Articles 12/14/15 high-risk package applicable 2027-12-02).

## Artifacts

| File | Purpose |
| :--- | :--- |
| `dossier.json` | Signed compliance dossier (Merkle root + Ed25519 seal + control crosswalk). |
| `dossier.md` | Executive Markdown report for CISO / audit committee. |
| `dossier.html` | Print-ready HTML report. |
| `dossier.pdf` | Printable PDF report. |
| `verification-report.json` | Independent re-verification findings (dossier + WORM integrity). |
| `worm-manifest.json` | WORM chain-of-custody manifest for S3 Object Lock / GCS retention. |
| `hitl-verifiable-credential.json` | W3C JSON-LD Verifiable Credential (EU AI Act Art. 14 HITL). |
| `threat-intel.json` | STIX 2.1 bundle + OpenDXL message for SIEM/SOC ingestion. |

## How to re-verify (auditor working paper)

```sh
npm run build -w @aegis-kernel/core
node scripts/generate-sample-audit-reports.mjs   # regenerates deterministically
```

Then recompute:

```sh
sha256sum dossier.pdf  # must match dossier.json -> tamperProofSummary integrity
```

Every artifact's SHA-256 is recorded in `worm-manifest.json`'s chain-of-custody;
any post-hoc modification is cryptographically detectable.
