/**
 * Generates Big-4-auditor-ready sample compliance artifacts from a realistic
 * simulated event ledger, writing them to `examples/audit-reports/`.
 *
 * Usage:  npm run build -w @aegis-kernel/core && node scripts/generate-sample-audit-reports.mjs
 *
 * Outputs (all hash-chained & cryptographically sealed):
 *   - dossier.json     Signed SOC2 / EU-AI-Act / ISO42001 / NIST compliance dossier
 *   - dossier.md       Executive Markdown report
 *   - dossier.html     Print-ready HTML report
 *   - dossier.pdf      Printable PDF report
 *   - worm-manifest.json   WORM (S3/GCS Object Lock) chain-of-custody manifest
 *   - verification-report.json  Dossier + WORM integrity verification findings
 *   - hitl-verifiable-credential.json  W3C JSON-LD VC for a HITL approval
 *   - README.md        Bundle index & auditor instructions
 */

import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  generateComplianceDossier,
  generateAuditKeyPairEd25519,
  renderComplianceMarkdown,
  renderComplianceHTML,
  renderCompliancePDF,
  verifyDossierProof,
  buildWormComplianceBundle,
  buildGcsBucketRetentionPolicy,
  verifyWormComplianceBundle,
  issueHitlVerifiableCredential,
  buildHitlCredentialSubject,
  formatStixTaxiiIndicator,
  formatOpenDxlThreatMessage,
  validateStixBundle,
} from '@aegis-kernel/core';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT_DIR = path.resolve(__dirname, '../examples/audit-reports');

const sha256 = (s) => createHash('sha256').update(s).digest('hex');

/** Builds a realistic, deterministic simulated ledger. */
function buildSimulatedLedger() {
  const events = [];
  const mk = (id, ts, tool, verdict, rulesFired) => ({
    id,
    timestamp: ts,
    version: '1.1.0',
    framework: 'langchain',
    toolName: tool,
    toolCallFingerprint: sha256(`fp:${id}:${tool}`),
    mode: 'enforce',
    verdict,
    rulesEvaluated: 12,
    rulesFired,
    latencyMs: 0.3,
    proofHash: sha256(`proof:${id}`),
    policyCommitmentHash: sha256('policy-commitment:v1.1.0'),
    userOverride: false,
  });

  const base = Date.parse('2026-08-01T00:00:00.000Z');
  const v = (i) => ({
    ruleId: 'SQL-NO-DROP',
    packId: '@aegis/sql-guard',
    severity: 'critical',
    message: 'DROP TABLE statement prohibited by invariant policy',
  });

  for (let i = 0; i < 12; i++) {
    const ts = new Date(base + i * 3600_000).toISOString();
    if (i % 5 === 0) {
      events.push(mk(`evt-${String(i).padStart(3, '0')}`, ts, 'execute_sql', 'BLOCKED', [v(i)]));
    } else {
      events.push(mk(`evt-${String(i).padStart(3, '0')}`, ts, 'execute_sql', 'ALLOWED', []));
    }
  }
  return events;
}

const events = buildSimulatedLedger();

// 1. Signing keys for the dossier + HITL credential.
const { publicKey, privateKey } = generateAuditKeyPairEd25519();

// 2. Signed compliance dossier.
const dossier = generateComplianceDossier(events, [], '0'.repeat(64), {
  includeEvents: true,
  signKey: privateKey,
  signAlgorithm: 'ed25519',
  publicKeyPem: publicKey,
  auditorFirm: 'Apex Compliance & Assurance LLP',
  leadAuditor: 'Marcus Vance, CPA, CISA, CISSP',
  systemName: 'Aegis Invariant Kernel — Enterprise Agent Safety Architecture',
});

// 3. Dossier verification report.
const dossierVerification = verifyDossierProof(dossier, publicKey);

// 4. WORM bundle (S3 + GCS) with 7-year COMPLIANCE retention.
const retention = { mode: 'COMPLIANCE', retainUntil: '2033-08-01T00:00:00.000Z', legalHold: true };
const wormBundle = buildWormComplianceBundle(
  dossier,
  { html: renderComplianceHTML, pdf: renderCompliancePDF },
  { provider: 'aws-s3', bucket: 'aegis-compliance-lock', retention }
);
const wormVerification = verifyWormComplianceBundle(wormBundle);
const gcsBucketPolicy = buildGcsBucketRetentionPolicy(retention);

// 5. HITL JSON-LD Verifiable Credential (EU AI Act Art. 14).
const subject = buildHitlCredentialSubject(
  events.find((e) => e.verdict === 'BLOCKED'),
  'APPROVED',
  'jane.doe@example.com',
  'Compliance Officer',
  {
    ticketId: 'hitl-2026-08-01-001',
    reason: 'Authorized scheduled maintenance migration under change CR-4412',
    merkleRootHash: dossier.merkleRootHash,
  }
);
const vc = issueHitlVerifiableCredential(subject, {
  issuer: 'did:web:aegis-kernel.dev',
  issuerName: 'Aegis GRC Signing Authority',
  privateKeyPem: privateKey,
  publicKeyPem: publicKey,
  verificationMethod: 'did:web:aegis-kernel.dev#aegis-hitl-signing-key',
});

// 6. Threat-intel samples (STIX 2.1 + OpenDXL) for the SIEM/SOC.
const blocked = events.filter((e) => e.verdict === 'BLOCKED');
const stixBundle = formatStixTaxiiIndicator(blocked[0]);
const dxlMessage = formatOpenDxlThreatMessage(blocked[0]);
const stixConformance = validateStixBundle(stixBundle);

// Clean the output directory first so a re-run cannot leave stale artifacts
// (dossierId is timestamp-derived, so filenames differ between runs).
fs.rmSync(OUT_DIR, { recursive: true, force: true });
fs.mkdirSync(OUT_DIR, { recursive: true });
const write = (name, content) => fs.writeFileSync(path.join(OUT_DIR, name), content, 'utf8');

write('dossier.json', JSON.stringify(dossier, null, 2));
write('dossier.md', renderComplianceMarkdown(dossier));
write('dossier.html', renderComplianceHTML(dossier));
fs.writeFileSync(path.join(OUT_DIR, 'dossier.pdf'), renderCompliancePDF(dossier));

// Write the WORM objects under their manifest keys so `sha256sum` (below) can
// be checked 1:1 against worm-manifest.json's chain-of-custody.
const WORM_DIR = path.join(OUT_DIR, 'worm-objects');
fs.mkdirSync(WORM_DIR, { recursive: true });
for (const f of wormBundle.files) {
  const rel = path.relative('aegis-compliance/', f.key); // strip the key prefix
  fs.writeFileSync(path.join(WORM_DIR, rel), f.content);
}

write('verification-report.json', JSON.stringify({ dossierVerification, wormVerification, stixConformance }, null, 2));
write('worm-manifest.json', JSON.stringify(wormBundle.manifest, null, 2));
write('gcs-bucket-retention-policy.json', JSON.stringify(gcsBucketPolicy, null, 2));
write('hitl-verifiable-credential.json', JSON.stringify(vc, null, 2));
write(
  'threat-intel.json',
  JSON.stringify({ stixBundle, openDxlMessage: dxlMessage }, null, 2)
);

const readme = `# Aegis Invariant Kernel — Sample Audit Evidence Bundle (Big-4 Ready)

Generated: ${new Date().toISOString()}

This directory is a self-contained, cryptographically sealed evidence package
for an independent auditor examining **SOC 2 Type II**, **ISO/IEC 42001:2023**,
**HIPAA §164.312**, **NIST AI RMF 1.0**, and the **EU AI Act** (Article 50 in
force 2026-08-02; Articles 12/14/15 high-risk package applicable 2027-12-02).

## Artifacts

| File | Purpose |
| :--- | :--- |
| \`dossier.json\` | Signed compliance dossier (Merkle root + Ed25519 seal + control crosswalk). |
| \`dossier.md\` | Executive Markdown report for CISO / audit committee. |
| \`dossier.html\` | Print-ready HTML report. |
| \`dossier.pdf\` | Printable PDF report. |
| \`verification-report.json\` | Independent re-verification findings (dossier + WORM integrity + STIX conformance). |
| \`worm-manifest.json\` | WORM chain-of-custody manifest for S3 Object Lock / GCS retention. |
| \`worm-objects/\` | The WORM bundle's actual objects, stored under their manifest keys. |
| \`gcs-bucket-retention-policy.json\` | GCS bucket-level retention policy (Object-Lock analog). |
| \`hitl-verifiable-credential.json\` | W3C JSON-LD Verifiable Credential (EU AI Act Art. 14 HITL). |
| \`threat-intel.json\` | STIX 2.1 bundle + OpenDXL message for SIEM/SOC ingestion. |

## How to re-verify (auditor working paper)

\`\`\`sh
npm run build -w @aegis-kernel/core
node scripts/generate-sample-audit-reports.mjs   # regenerates the bundle
bash scripts/verify-sample-audit-reports.sh      # independent re-hash + chain walk
\`\`\`

The verification script re-hashes every object in \`worm-objects/\` against the
SHA-256 digests recorded in \`worm-manifest.json\` and recomputes the
chain-of-custody link hashes. Any post-hoc modification of any artifact is
cryptographically detectable.

> **Note on the HITL credential:** the proof is an Ed25519 signature over the
> JSON Canonicalization Scheme (JCS, RFC 8785) serialization of the credential
> (sans \`proof\`). This is deliberately dependency-free and independently
> recomputable, but it is *not* the URDNA2015 canonicalization used by the W3C
> Data Integrity \`Ed25519Signature2020\` suite. For strict W3C DI conformance,
> integrate a URDNA2015 processor and re-sign.
`;

write('README.md', readme);

write('README.md', readme);

console.log(`✅ Sample audit reports written to ${OUT_DIR}`);
for (const f of fs.readdirSync(OUT_DIR)) {
  console.log(`   • ${f}`);
}
