import { describe, it, expect } from 'vitest';
import type { AegisEvent } from '@aegis-kernel/core';
import { GRCSyncDispatcher, type GRCSyncConfig } from '../src/index.js';

function createMockAuditTrail(): AegisEvent[] {
  return [
    {
      id: 'evt_1',
      timestamp: new Date().toISOString(),
      toolName: 'sql_query',
      toolCallFingerprint: 'fp_1',
      mode: 'enforce',
      verdict: 'ALLOWED',
      rulesEvaluated: 4,
      rulesFired: [],
      latencyMs: 0.2,
      proofHash: 'proof_1',
      policyCommitmentHash: 'pol_1',
    },
    {
      id: 'evt_2',
      timestamp: new Date().toISOString(),
      toolName: 'drop_database',
      toolCallFingerprint: 'fp_2',
      mode: 'enforce',
      verdict: 'BLOCKED',
      rulesEvaluated: 4,
      rulesFired: ['SQL-002'],
      latencyMs: 0.18,
      proofHash: 'proof_2',
      policyCommitmentHash: 'pol_1',
    },
  ];
}

describe('Continuous GRC Evidence Sync Dispatcher (Drata & Vanta)', () => {
  const webhookSecret = 'whsec_drata_vanta_test_secret_12345';
  const drataConfig: GRCSyncConfig = {
    platform: 'drata',
    webhookUrl: 'https://api.drata.com/v1/evidence/aegis-connector',
    webhookSecret,
  };

  const vantaConfig: GRCSyncConfig = {
    platform: 'vanta',
    webhookUrl: 'https://api.vanta.com/v1/connectors/aegis-audit',
    webhookSecret,
  };

  it('should build a cryptographically signed GRC sync payload for Drata', () => {
    const events = createMockAuditTrail();
    const payload = GRCSyncDispatcher.buildSyncPayload('tenant_drata_corp', events, drataConfig);

    expect(payload.platform).toBe('drata');
    expect(payload.tenantId).toBe('tenant_drata_corp');
    expect(payload.merkleRootHash).toMatch(/^[a-f0-9]{64}$/);
    expect(payload.totalEventsAudited).toBe(2);
    expect(payload.blockedViolations).toBe(1);
    expect(payload.cpaAttestation.opinionType).toBe('UNQUALIFIED_CLEAN_OPINION');
    expect(payload.signature).toMatch(/^[a-f0-9]{64}$/);

    // Verify signature integrity
    const isValid = GRCSyncDispatcher.verifyWebhookSignature(payload, webhookSecret);
    expect(isValid).toBe(true);
  });

  it('should build a cryptographically signed GRC sync payload for Vanta', () => {
    const events = createMockAuditTrail();
    const payload = GRCSyncDispatcher.buildSyncPayload('tenant_vanta_corp', events, vantaConfig);

    expect(payload.platform).toBe('vanta');
    expect(payload.tenantId).toBe('tenant_vanta_corp');
    expect(payload.frameworkEvidence.soc2Type2).toBe(true);
    expect(payload.frameworkEvidence.iso42001).toBe(true);

    const isValid = GRCSyncDispatcher.verifyWebhookSignature(payload, webhookSecret);
    expect(isValid).toBe(true);
  });

  it('should reject tampered GRC sync payloads', () => {
    const events = createMockAuditTrail();
    const payload = GRCSyncDispatcher.buildSyncPayload('tenant_tamper', events, drataConfig);

    // Tamper with audit metrics
    const tamperedPayload = {
      ...payload,
      blockedViolations: 0,
    };

    expect(GRCSyncDispatcher.verifyWebhookSignature(tamperedPayload, webhookSecret)).toBe(false);
  });
});
