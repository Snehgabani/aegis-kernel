# Aegis Invariant Kernel — Sample Audit Evidence Bundle (Big-4 Ready)

Generated: 2026-08-21T07:08:24.393Z

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
| `verification-report.json` | Independent re-verification findings (dossier + WORM integrity + STIX conformance). |
| `worm-manifest.json` | WORM chain-of-custody manifest for S3 Object Lock / GCS retention. |
| `worm-objects/` | The WORM bundle's actual objects, stored under their manifest keys. |
| `gcs-bucket-retention-policy.json` | GCS bucket-level retention policy (Object-Lock analog). |
| `hitl-verifiable-credential.json` | W3C JSON-LD Verifiable Credential (EU AI Act Art. 14 HITL). |
| `threat-intel.json` | STIX 2.1 bundle + OpenDXL message for SIEM/SOC ingestion. |

## How to re-verify (auditor working paper)

```sh
npm run build -w @aegis-kernel/core
node scripts/generate-sample-audit-reports.mjs   # regenerates the bundle
bash scripts/verify-sample-audit-reports.sh      # independent re-hash + chain walk
```

The verification script re-hashes every object in `worm-objects/` against the
SHA-256 digests recorded in `worm-manifest.json` and recomputes the
chain-of-custody link hashes. Any post-hoc modification of any artifact is
cryptographically detectable.

> **Note on the HITL credential:** the proof is an Ed25519 signature over the
> JSON Canonicalization Scheme (JCS, RFC 8785) serialization of the credential
> (sans `proof`). This is deliberately dependency-free and independently
> recomputable, but it is *not* the URDNA2015 canonicalization used by the W3C
> Data Integrity `Ed25519Signature2020` suite. For strict W3C DI conformance,
> integrate a URDNA2015 processor and re-sign.
