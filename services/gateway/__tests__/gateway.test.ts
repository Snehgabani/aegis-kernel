import { describe, it, expect, beforeEach } from 'vitest';
import { createGatewayApp } from '../src/index.js';
import type { AegisEvent } from '@aegis-kernel/core';

describe('Aegis Cloud Gateway Service', () => {
  let app: ReturnType<typeof createGatewayApp>;

  beforeEach(() => {
    app = createGatewayApp({
      AEGIS_LICENSE_SECRET: 'test_gateway_secret_key_123',
    });
  });

  it('GET /health should return 200 OK', async () => {
    const res = await app.request('/health');
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.status).toBe('ok');
    expect(data.service).toBe('aegis-gateway');
  });

  it('GET /metrics should expose Prometheus formatted golden signals', async () => {
    const res = await app.request('/metrics');
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).toContain('aegis_tool_calls_total');
    expect(text).toContain('aegis_clearance_latency_ms');
    expect(text).toContain('aegis_active_policy_info');
  });

  it('POST /api/telemetry should reject unauthenticated requests and accept valid batches', async () => {
    // 1. Unauthenticated
    const unauthRes = await app.request('/api/telemetry', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ events: [] }),
    });
    expect(unauthRes.status).toBe(401);

    // 2. Authenticated with event batch
    const sampleEvent: AegisEvent = {
      id: 'evt_test_1',
      timestamp: new Date().toISOString(),
      version: '1.0.0',
      framework: 'openai',
      toolName: 'execute_sql',
      toolCallFingerprint: 'fp_123',
      mode: 'enforce',
      verdict: 'BLOCKED',
      rulesEvaluated: 3,
      rulesFired: [
        {
          ruleId: 'SQL-001',
          packId: 'sql-guard',
          severity: 'critical',
          message: 'Mass DELETE without WHERE blocked',
        },
      ],
      latencyMs: 1.2,
      proofHash: 'hash_abc_123',
      policyCommitmentHash: 'commit_xyz',
      userOverride: false,
    };

    const authRes = await app.request('/api/telemetry', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer test_api_key_pro',
      },
      body: JSON.stringify({ events: [sampleEvent] }),
    });
    expect(authRes.status).toBe(200);
    const authData = await authRes.json();
    expect(authData.success).toBe(true);
    expect(authData.ingested).toBe(1);

    // 3. Check stats endpoint reflection
    const statsRes = await app.request('/api/dashboard/stats');
    const stats = await statsRes.json();
    expect(stats.totalChecks).toBe(1);
    expect(stats.totalBlocked).toBe(1);
    expect(stats.blockRatePercent).toBe('100.0');
    expect(stats.ruleBreakdown['SQL-001']).toBe(1);
  });

  it('POST /api/billing/stripe-webhook should issue valid license token on subscription checkout', async () => {
    const webhookPayload = {
      type: 'checkout.session.completed',
      data: {
        object: {
          id: 'cs_test_stripe_session_123',
          customer: 'cust_stripe_buyer_456',
          customer_details: { email: 'buyer@company.com' },
          amount_total: 4900, // $49/mo Pro tier
        },
      },
    };

    const res = await app.request('/api/billing/stripe-webhook', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(webhookPayload),
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.fulfilled).toBe(true);
    expect(data.plan).toBe('pro');
    expect(data.licenseKey).toMatch(/^aegis_lic_/);

    // Verify the newly generated license key with verify endpoint
    const verifyRes = await app.request('/api/license/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ licenseKey: data.licenseKey }),
    });

    const verifyData = await verifyRes.json();
    expect(verifyData.valid).toBe(true);
    expect(verifyData.active).toBe(true);
    expect(verifyData.tier).toBe('pro');
    expect(verifyData.payload?.features).toContain('hipaa_guard');
  });
});
