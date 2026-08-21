# Compliance Engine Verification Methodology & Findings

This document records the adversarial verification applied to the Aegis GRC
exporters (STIX/OpenDXL feeds, WORM bundle exporter, JSON-LD HITL credentials)
and the concrete defects it uncovered and fixed. It is intended to be read by
the same auditors who will consume the generated evidence.

## 1. Verification method (layered, independent of the code under test)

The exporters were verified with four mutually reinforcing techniques. "OODA"
(Observe–Orient–Decide–Act) was used as the iteration loop; the actual
*evidence* comes from the layers below, not from a metaphor.

| Layer | What it does | Tooling |
| :--- | :--- | :--- |
| **1. Spec cross-reference** | Every output schema is checked against the authoritative standard (OASIS, W3C, AWS, GCP, AICPA, EU). | Web research of primary sources. |
| **2. Independent re-derivation** | Recompute hashes/signatures/PDFs with tools that do **not** run the project code. | `openssl pkeyutl`, `sha256sum` + `jq`, hand-rolled PDF xref parse. |
| **3. Reference-vector testing** | Canonicalization is checked against official published test vectors. | RFC 8785 §3.2 JCS vectors. |
| **4. Property-based fuzzing** | Random inputs verify round-trip and tamper-evidence properties. | `fast-check` (already a repo devDependency). |

## 2. Findings (defects found, then fixed)

Verification is only meaningful if it finds things. It did — **seven** concrete
defects, each fixed and covered by a regression test.

| # | Defect | Severity | Root cause | Fix |
| :--- | :--- | :--- | :--- | :--- |
| 1 | STIX 2.1 `bundle`/`indicator` `id` values were **not RFC 4122 UUIDs** (e.g. `bundle--evt-000`), violating OASIS §2.9. | High | Existing `siem.ts` used raw event IDs. | Added `uuidv5()`; identifiers are now `type--<UUID>`. |
| 2 | STIX pattern mixed two SCO types in one observation expression (`[process:name='x' AND file:hashes.'SHA-256'='y']`), which is invalid patterning grammar; and a Merkle proof hash was misrepresented as a *file* hash. | High | Existing `siem.ts`. | Pattern is now a single valid observation `[process:name='x']`; the proof hash moved to `external_references`. |
| 3 | SOC 2 crosswalk labeled **CC6.8** as "Change Management" — CC6.8 is actually *detection & mitigation of unauthorized software/malware*; change management is **CC8.1**. A Big-4 reviewer would have rejected the mapping. | High | Existing `grc-exporter.ts`. | Corrected CC6.8 title/evidence; added a proper CC8.1 change-management entry. |
| 4 | HITL credential `publicKeyMultibase` was **missing the `0xed01` multicodec prefix** required by the EdDSA Cryptosuite. | Medium | New code. | Now `z` + base58btc(`0xed01` ‖ 32-byte key). |
| 5 | `uuidv5()` emitted a 33-hex-char UUID (last segment 20 chars instead of 12). | High (bug in new code) | New code. | Corrected segment slicing; caught by the conformance test. |
| 6 | Signed dossier did **not embed the verification public key**, so an auditor could not verify the Ed25519 signature from the artifact alone. | Medium | Existing `grc-exporter.ts`. | `publicKeyPem` is now embedded on Ed25519-signed dossiers (still requires out-of-band pinning for non-repudiation). |
| 7 | HITL credential defaulted to a **5-minute `expirationDate`** (mirroring the authorization *ticket* TTL), so audit evidence self-expired almost immediately; `agentId` was also mislabeled as the event ID. | Medium | New code. | Credential (evidence) now defaults to 10-year retention; `agentId` is a proper URN or caller-supplied. |

## 3. Independent verification results (reproducible)

```text
# Ed25519 dossier root signature, verified by OpenSSL (not project code):
$ openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in msg.bin -sigfile sig.bin
Signature Verified Successfully

# Ed25519 HITL credential proof, verified by OpenSSL:
Signature Verified Successfully

# JCS canonicalization vs RFC 8785 official test vectors: 5/5 PASS

# WORM object hashes + chain-of-custody, verified by sha256sum + jq only:
RESULT: PASS — all WORM objects and chain-of-custody links verified.

# PDF structural check (header/startxref/%%EOF/object table): PASS
```

Run them again with:

```sh
npm run build -w @aegis-kernel/core
node scripts/generate-sample-audit-reports.mjs
bash scripts/verify-sample-audit-reports.sh
```

## 4. Known boundaries (honest limits)

- The HITL credential proof is an **Ed25519 signature over JCS (RFC 8785)**
  canonicalization, which is dependency-free and independently recomputable,
  but is **not** the URDNA2015 canonicalization used by the W3C Data Integrity
  `Ed25519Signature2020` suite. Full W3C DI conformance requires integrating a
  URDNA2015 processor. This is documented in the generated README and in the
  proof's `cryptosuiteNote`.
- STIX identifiers use deterministic **UUIDv5** (RFC 4122) derived from the
  event identity for reproducible CTI; STIX §2.9 recommends UUIDv4 (a "SHOULD",
  permitted to deviate for reproducibility).
- OpenDXL output is the *application-layer* message (topic + JSON payload); the
  DXL wire headers are populated by the dxlclient runtime on the fabric.
