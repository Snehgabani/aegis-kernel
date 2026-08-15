import { describe, it, expect, vi } from 'vitest';
import { buildGrcEvidence, dispatchGrcEvidenceWebhook } from '../src/grc-evidence.js';
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
