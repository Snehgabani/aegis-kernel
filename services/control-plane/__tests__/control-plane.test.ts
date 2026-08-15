import { describe, it, expect, beforeEach } from 'vitest';
import { AegisControlPlaneServer } from '../src/server.js';
import { CloudMarketplaceMeter } from '../src/metering/marketplace-metering.js';
import type { AegisEvent } from '@aegis-kernel/core';

describe('Aegis Enterprise SaaS Control Plane Suite', () => {
  let controlPlane: AegisControlPlaneServer;

  beforeEach(() => {
    controlPlane = new AegisControlPlaneServer();
  });

  const sampleEvent: AegisEvent = {
    id: 'evt_control_plane_01',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    framework: 'mcp',
    toolName: 'execute_sql',
    toolCallFingerprint: 'fp_cp_01',
    mode: 'enforce',
    verdict: 'BLOCKED',
    rulesEvaluated: 10,
    rulesFired: [{ ruleId: 'SQL-NO-DROP', packId: '@aegis/sql-guard', severity: 'critical', message: 'DROP TABLE prohibited' }],
    latencyMs: 0.25,
    proofHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    policyCommitmentHash: 'pol_hash_cp_01',
    userOverride: false,
  };

  it('should ingest audit events, generate continuous Merkle roots, and meter usage', () => {
    const res = controlPlane.ingestAuditEvent('tenant_acme_corp', sampleEvent);

    expect(res.eventId).toBe('evt_control_plane_01');
    expect(res.merkleRoot).toHaveLength(64);

    const meter = controlPlane.getMarketplaceMeter();
    expect(meter.getPendingCount()).toBe(1);

    const batch = meter.flushAwsMarketplaceBatch();
    expect(batch.status).toBe('SUCCESS');
    expect(batch.recordsProcessed).toBe(1);
    expect(meter.getPendingCount()).toBe(0);
  });

  it('should export audit-ready compliance dossiers for enterprise tenants', () => {
    controlPlane.ingestAuditEvent('tenant_fintech_inc', sampleEvent);
    const dossier = controlPlane.getTenantDossier('tenant_fintech_inc');

    expect(dossier.totalEventsAudited).toBe(1);
    expect(dossier.merkleRootHash).toHaveLength(64);
    expect(dossier.tamperProofSummary.integrityVerified).toBe(true);
    expect(dossier.frameworkMappings.some((f: any) => f.framework === 'EU_AI_ACT')).toBe(true);
    expect(dossier.frameworkMappings.some((f: any) => f.framework === 'SOC2_TYPE_II')).toBe(true);
  });

  it('should stream STIX 2.1 CTI threat intelligence indicators', () => {
    controlPlane.ingestAuditEvent('tenant_bank_01', sampleEvent);
    const stixFeed = controlPlane.getStixThreatFeed('tenant_bank_01');

    expect(stixFeed.length).toBe(1);
    expect(stixFeed[0].type).toBe('bundle');
    expect(stixFeed[0].objects[0].type).toBe('indicator');
  });

  it('should format Azure Marketplace SaaS Metered billing records', () => {
    const meter = new CloudMarketplaceMeter();
    const record = meter.recordUsage('tenant_health_plus', 'ToolCallExecutionUnits', 500);

    const azurePayload = meter.formatAzureMeteringPayload(record);
    expect(azurePayload.resourceId).toBe('tenant_health_plus');
    expect(azurePayload.quantity).toBe(500);
    expect(azurePayload.dimension).toBe('ToolCallExecutionUnits');
    expect(azurePayload.planId).toBe('aegis-enterprise-sovereign');
  });
});
