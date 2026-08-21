import { describe, it, expect } from 'vitest';
import {
  AegisEngine,
  generateComplianceDossier,
  signComplianceDossier,
  verifyDossierProof,
  renderComplianceMarkdown,
  renderComplianceHTML,
  renderCompliancePDF,
  generateAuditKeyPairEd25519,
  type AegisEvent,
} from '../src/index.js';

describe('GRC Compliance Dossier & CPA Auditor Attestation Generator', () => {
  it('should generate complete dossier with CPA auditor attestation and full regulatory crosswalk', () => {
    const engine = new AegisEngine();
    const v1 = engine.evaluate({ tool: 'sql_query', params: { query: 'SELECT * FROM users WHERE id = 1' } });
    const v2 = engine.evaluate({ tool: 'sql_query', params: { query: 'DROP TABLE accounts' } }); // blocked violation

    const events: AegisEvent[] = [
      {
        id: 'evt-1',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        framework: 'raw',
        toolName: 'sql_query',
        toolCallFingerprint: 'fp-1',
        mode: 'enforce',
        verdict: 'ALLOWED',
        rulesEvaluated: 5,
        rulesFired: [],
        latencyMs: 0.5,
        proofHash: v1.proofHash,
        policyCommitmentHash: 'policy-hash-1',
        userOverride: false,
      },
      {
        id: 'evt-2',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        framework: 'raw',
        toolName: 'sql_query',
        toolCallFingerprint: 'fp-2',
        mode: 'enforce',
        verdict: 'BLOCKED',
        rulesEvaluated: 5,
        rulesFired: v2.violations,
        latencyMs: 0.8,
        proofHash: v2.proofHash,
        policyCommitmentHash: 'policy-hash-1',
        userOverride: false,
      },
    ];

    const dossier = generateComplianceDossier(events, engine.getLoadedPacks(), '0'.repeat(64), {
      auditorFirm: 'PricewaterhouseCoopers LLP (PwC)',
      leadAuditor: 'Sarah Jenkins, CPA, CISA',
      systemName: 'Aegis Invariant Agent Guard Gateway',
    });

    expect(dossier.dossierId).toMatch(/^grc-dossier-/);
    expect(dossier.totalEventsAudited).toBe(2);
    expect(dossier.blockedViolationsCount).toBe(1);
    expect(dossier.allowedEvaluationsCount).toBe(1);
    expect(dossier.merkleRootHash).toHaveLength(64);

    // Verify CPA Auditor Attestation
    expect(dossier.cpaAuditorAttestation).toBeDefined();
    expect(dossier.cpaAuditorAttestation?.opinionType).toBe('UNQUALIFIED_CLEAN_OPINION');
    expect(dossier.cpaAuditorAttestation?.auditFirm).toBe('PricewaterhouseCoopers LLP (PwC)');
    expect(dossier.cpaAuditorAttestation?.leadAuditorName).toBe('Sarah Jenkins, CPA, CISA');
    expect(dossier.cpaAuditorAttestation?.scopeOfExamination.invariantsEvaluated.length).toBeGreaterThan(3);

    // Verify Regulatory Control Crosswalk coverage
    const mappings = dossier.controlCrosswalk || dossier.frameworkMappings;
    expect(mappings.length).toBeGreaterThan(12);

    const frameworks = new Set(mappings.map((m) => m.framework));
    expect(frameworks.has('SOC2_TYPE_II')).toBe(true);
    expect(frameworks.has('ISO_42001_2023')).toBe(true);
    expect(frameworks.has('HIPAA_164_312')).toBe(true);
    expect(frameworks.has('NIST_AI_RMF')).toBe(true);
    expect(frameworks.has('EU_AI_ACT')).toBe(true);

    // Specific mandatory clauses
    const clauseIds = mappings.map((m) => m.clauseId);
    expect(clauseIds).toContain('CC6.1');
    expect(clauseIds).toContain('CC6.6');
    expect(clauseIds).toContain('CC6.8');
    expect(clauseIds).toContain('§164.312(b)');
    expect(clauseIds).toContain('Annex A.6.2.7');
    expect(clauseIds).toContain('MANAGE 1.3');
    expect(clauseIds).toContain('GOVERN 1.2');
    expect(clauseIds).toContain('MAP 2');
    expect(clauseIds).toContain('MEASURE 2');
  });

  it('should render compliance outputs in Markdown, HTML, and PDF formats', () => {
    const engine = new AegisEngine();
    const v1 = engine.evaluate({ tool: 'sql_query', params: { query: 'SELECT name FROM customers' } });

    const events: AegisEvent[] = [
      {
        id: 'evt-3',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        framework: 'raw',
        toolName: 'sql_query',
        toolCallFingerprint: 'fp-3',
        mode: 'enforce',
        verdict: 'ALLOWED',
        rulesEvaluated: 5,
        rulesFired: [],
        latencyMs: 0.5,
        proofHash: v1.proofHash,
        policyCommitmentHash: 'policy-hash-1',
        userOverride: false,
      },
    ];

    const dossier = generateComplianceDossier(events, engine.getLoadedPacks());

    // 1. Markdown
    const md = renderComplianceMarkdown(dossier);
    expect(md).toContain('# 🛡️ Aegis Invariant Kernel — Executive GRC Compliance Dossier');
    expect(md).toContain('Independent CPA & AI Auditor Attestation');
    expect(md).toContain('SOC2_TYPE_II');
    expect(md).toContain('HIPAA_164_312');

    // 2. HTML
    const html = renderComplianceHTML(dossier);
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('Aegis Invariant Kernel');
    expect(html).toContain('UNQUALIFIED CLEAN OPINION');
    expect(html).toContain(dossier.merkleRootHash);

    // 3. PDF Buffer
    const pdfBuf = renderCompliancePDF(dossier);
    expect(Buffer.isBuffer(pdfBuf)).toBe(true);
    expect(pdfBuf.toString('utf-8', 0, 8)).toContain('%PDF-1.4');
    expect(pdfBuf.toString('utf-8')).toContain('%%EOF');
  });

  it('should sign and verify dossiers using Ed25519 asymmetric keys', () => {
    const engine = new AegisEngine();
    const v1 = engine.evaluate({ tool: 'sql_query', params: { query: 'SELECT 1' } });

    const events: AegisEvent[] = [
      {
        id: 'evt-4',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        framework: 'raw',
        toolName: 'sql_query',
        toolCallFingerprint: 'fp-4',
        mode: 'enforce',
        verdict: 'ALLOWED',
        rulesEvaluated: 5,
        rulesFired: [],
        latencyMs: 0.5,
        proofHash: v1.proofHash,
        policyCommitmentHash: 'policy-hash-1',
        userOverride: false,
      },
    ];

    const { publicKey, privateKey } = generateAuditKeyPairEd25519();
    const dossier = generateComplianceDossier(events, engine.getLoadedPacks());

    const signedDossier = signComplianceDossier(dossier, privateKey, 'ed25519');
    expect(signedDossier.merkleRootSignature).toBeDefined();
    expect(signedDossier.signatureType).toBe('ED25519');

    // Verification
    const validReport = verifyDossierProof(signedDossier, publicKey);
    expect(validReport.valid).toBe(true);
    expect(validReport.signatureValid).toBe(true);

    // Corrupted key
    const otherKeys = generateAuditKeyPairEd25519();
    const invalidReport = verifyDossierProof(signedDossier, otherKeys.publicKey);
    expect(invalidReport.valid).toBe(false);
    expect(invalidReport.signatureValid).toBe(false);
  });

  it('should sign and verify dossiers using HMAC-SHA256 symmetric secret', () => {
    const engine = new AegisEngine();
    const v1 = engine.evaluate({ tool: 'sql_query', params: { query: 'SELECT 1' } });

    const events: AegisEvent[] = [
      {
        id: 'evt-5',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        framework: 'raw',
        toolName: 'sql_query',
        toolCallFingerprint: 'fp-5',
        mode: 'enforce',
        verdict: 'ALLOWED',
        rulesEvaluated: 5,
        rulesFired: [],
        latencyMs: 0.5,
        proofHash: v1.proofHash,
        policyCommitmentHash: 'policy-hash-1',
        userOverride: false,
      },
    ];

    const secret = 'ultra-secure-hmac-secret-12345';
    const dossier = generateComplianceDossier(events, engine.getLoadedPacks(), '0'.repeat(64), {
      signKey: secret,
      signAlgorithm: 'hmac-sha256',
    });

    expect(dossier.merkleRootSignature).toBeDefined();
    expect(dossier.signatureType).toBe('HMAC_SHA256');

    const validReport = verifyDossierProof(dossier, secret);
    expect(validReport.valid).toBe(true);
    expect(validReport.signatureValid).toBe(true);

    const invalidReport = verifyDossierProof(dossier, 'wrong-secret');
    expect(invalidReport.valid).toBe(false);
    expect(invalidReport.signatureValid).toBe(false);
  });
});
