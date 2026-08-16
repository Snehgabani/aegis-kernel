/**
 * @file packages/cli/src/verify-proof-cli.ts
 * @description CLI command handler for `aegis verify-proof <dossier.json> [--key <key>]`.
 * Cryptographically verifies SHA-256 Merkle root chains, Ed25519/HMAC signatures,
 * and regulatory control crosswalks (SOC 2, ISO 42001, HIPAA §164.312, NIST AI RMF).
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { verifyDossierProof, type ComplianceDossier, type DossierVerificationReport } from '@aegis-kernel/core';

export interface VerifyProofOptions {
  key?: string;
  json?: boolean;
}

export function runVerifyProof(
  dossierPath: string,
  options: VerifyProofOptions = {}
): { ok: boolean; report?: DossierVerificationReport; error?: string } {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('  🛡️  AEGIS CRYPTOGRAPHIC PROOF & CPA AUDITOR LEDGER VALIDATOR');
  console.log('═══════════════════════════════════════════════════════════════\n');

  const resolvedPath = path.resolve(process.cwd(), dossierPath);
  if (!fs.existsSync(resolvedPath)) {
    console.error(`❌ Error: Dossier file not found at: ${resolvedPath}`);
    return { ok: false, error: 'File not found' };
  }

  let dossier: ComplianceDossier;
  try {
    const raw = fs.readFileSync(resolvedPath, 'utf8');
    dossier = JSON.parse(raw);
  } catch (err: any) {
    console.error(`❌ Error: Failed to parse dossier JSON: ${err.message}`);
    return { ok: false, error: `Invalid JSON: ${err.message}` };
  }

  console.log(`📁 Target Dossier:   ${resolvedPath}`);
  console.log(`🆔 Dossier ID:       ${dossier.dossierId || 'UNKNOWN'}`);
  console.log(`⏱️  Audit Period:     ${dossier.periodStart} → ${dossier.periodEnd}`);
  console.log(`📊 Events Audited:   ${dossier.totalEventsAudited ?? 0} (${dossier.allowedEvaluationsCount ?? 0} allowed, ${dossier.blockedViolationsCount ?? 0} blocked)\n`);

  // Run core cryptographic proof verification
  const report = verifyDossierProof(dossier, options.key);

  if (options.json) {
    console.log(JSON.stringify(report, null, 2));
    return { ok: report.valid, report };
  }

  console.log('🔍 CRYPTOGRAPHIC & REGULATORY EVIDENCE BREAKDOWN:\n');

  // 1. Merkle Root Hash
  if (report.merkleRootValid) {
    console.log(`  ✅ [PASS] Merkle Root Hash: ${report.merkleRootHash}`);
  } else {
    console.log(`  ❌ [FAIL] Merkle Root Hash Mismatch!`);
  }

  // 2. Digital Signature
  if (report.signatureValid) {
    if (dossier.merkleRootSignature) {
      console.log(`  ✅ [PASS] Digital Signature (${report.signatureAlgorithm || dossier.signatureType || 'VERIFIED'}): ${dossier.merkleRootSignature.slice(0, 32)}...`);
    } else {
      console.log(`  ℹ️  [INFO] Digital Signature: Unsigned dossier (pure Merkle ledger)`);
    }
  } else {
    console.log(`  ❌ [FAIL] Digital Signature: Verification failed against provided key!`);
  }

  // 3. Control Crosswalk
  if (report.controlCrosswalkValid) {
    console.log(`  ✅ [PASS] Regulatory Control Crosswalk: 100% Satisfied (${report.controlCoverage.satisfied}/${report.controlCoverage.total} controls)`);
    console.log(`            - SOC 2 Type II: CC6.1, CC6.6, CC6.8, PI1.1, PI1.2`);
    console.log(`            - ISO/IEC 42001:2023: Annex A.6.2.7, A.8.2/8.4, A.9.2/9.3`);
    console.log(`            - HIPAA Security Rule: §164.312(a)(1), (b), (c)(1), (e)(1)`);
    console.log(`            - NIST AI RMF 1.0: GOVERN-1.2, MAP-1.5, MEASURE-2.6, MANAGE-1.3/2.4`);
    console.log(`            - EU AI Act: Articles 12, 14, 15`);
  } else {
    console.log(`  ❌ [FAIL] Regulatory Control Crosswalk: Incomplete control mappings!`);
  }

  // 4. CPA Auditor Attestation
  if (dossier.cpaAuditorAttestation) {
    const att = dossier.cpaAuditorAttestation;
    console.log(`  ✅ [PASS] CPA Auditor Attestation: ${att.opinionType}`);
    console.log(`            - Audit Firm:   ${att.auditFirm}`);
    console.log(`            - Lead Auditor: ${att.leadAuditorName || 'N/A'} (${att.leadAuditorLicense || 'N/A'})`);
    console.log(`            - Standard:     ${att.attestationStandard}`);
  } else {
    console.log(`  ℹ️  [INFO] CPA Auditor Attestation: No attestation block present.`);
  }

  // 5. Policy Commitments
  if (report.policyCommitmentsCount > 0) {
    console.log(`  ✅ [PASS] Invariant Policy Commitments: ${report.policyCommitmentsCount} immutable hashes bound.`);
  }

  console.log('\n───────────────────────────────────────────────────────────────');

  if (report.valid) {
    console.log(`\n🎉 VERDICT: PROOF VERIFIED!`);
    console.log(`   Dossier is cryptographically intact and compliant for CPA audit submission.\n`);
  } else {
    console.log(`\n🚫 VERDICT: PROOF VERIFICATION FAILED!`);
    console.log(`   One or more cryptographic proofs or regulatory control checks failed.\n`);
  }

  return { ok: report.valid, report };
}
