import { describe, it, expect, vi } from 'vitest';
import { buildGrcEvidence, dispatchGrcEvidenceWebhook, buildContinuousComplianceBundle } from '../src/grc-evidence.js';
import { AegisEngine } from '@aegis-kernel/core';

describe('Aegis Continuous GRC Evidence Sync', () => {
  const engine = new AegisEngine();

  it('should build structured SOC2/HIPAA evidence payload with cryptographic commitments', () => {
    const payload = buildGrcEvidence(engine);

    expect(payload.vendor).toBe('Aegis Invariant Kernel');
    expect(payload.framework).toBe('SOC2_TYPE_II');
    expect(payload.evidence.continuousMonitoringActive).toBe(true);
    expect(payload.evidence.airGappedExecution).toBe(true);
    expect(payload.policyCommitmentHash).toBeDefined();
    expect(payload.auditTrailVerification.algorithm).toBe('SHA-256');
  });

  it('builds a continuous compliance bundle (dossier + WORM + integrity report)', () => {
    const bundle = buildContinuousComplianceBundle(engine, {
      provider: 'aws-s3',
      bucket: 'aegis-audit-lock',
      retention: { mode: 'COMPLIANCE', retainUntil: '2033-08-16T00:00:00.000Z' },
    });

    expect(bundle.evidence.vendor).toBe('Aegis Invariant Kernel');
    expect(bundle.dossier.dossierId).toMatch(/^grc-dossier-/);
    expect(bundle.wormBundle.provider).toBe('aws-s3');
    expect(bundle.wormBundle.manifest.schema).toBe('aegis-worm-bundle/1.0');
    expect(bundle.wormIntegrity.valid).toBe(true);
    expect(bundle.wormIntegrity.findings.every((f) => f.status === 'PASS')).toBe(true);
  });

  it('should attempt dispatch and handle response from webhook endpoint', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
    });
    global.fetch = fetchMock as any;

    const result = await dispatchGrcEvidenceWebhook('https://api.vanta.com/v1/evidence/test', engine);
    expect(result.success).toBe(true);
    expect(result.status).toBe(200);
    expect(fetchMock).toHaveBeenCalled();
  });
});
