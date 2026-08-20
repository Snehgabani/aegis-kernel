import { describe, it, expect, beforeEach } from 'vitest';
import { createGatewayApp } from '../src/index.js';
import type { AegisEvent } from '@aegis-kernel/core';

describe('Aegis Cloud Gateway Service', () => {
  let app: ReturnType<typeof createGatewayApp>;

  beforeEach(() => {
    app = createGatewayApp({
      AEGIS_LICENSE_SECRET: 'test_gateway_secret_key_123',
      STRIPE_WEBHOOK_SECRET: 'whsec_test_secret_456',
    });
  });

  it('GET /health should return 200 OK', async () => {
    const res = await app.request('/health');
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.status).toBe('ok');
    expect(data.service).toBe('aegis-gateway');
  });

  it('GET /health/deep should return 200 with engine diagnostic probe', async () => {
    const res = await app.request('/health/deep');
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.status).toBe('healthy');
    expect(data.probe).toBeDefined();
    expect(data.probe.healthy).toBe(true);
    expect(data.probe.checkersTested).toBeGreaterThanOrEqual(5);
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

    const rawBody = JSON.stringify(webhookPayload);
    const timestamp = Math.floor(Date.now() / 1000);
    const crypto = await import('node:crypto');
    const signature = crypto.createHmac('sha256', 'whsec_test_secret_456')
      .update(`${timestamp}.${rawBody}`)
      .digest('hex');

    // Test rejection without signature
    const unsignedRes = await app.request('/api/billing/stripe-webhook', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: rawBody,
    });
    expect(unsignedRes.status).toBe(401);

    // Test success with valid signature
    const res = await app.request('/api/billing/stripe-webhook', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'stripe-signature': `t=${timestamp},v1=${signature}`,
      },
      body: rawBody,
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

  // ─────────────────────────────────────────────────────────────────────────────
  // FAIL-CLOSED LICENSE SECURITY (regression tests for hardcoded-secret defect)
  // Fixed 2026-08-20: the gateway previously fell back to a hardcoded HMAC
  // secret, letting anyone who read the MIT source forge enterprise licenses.
  // ─────────────────────────────────────────────────────────────────────────────

  it('SEC-1: license forged with the OLD hardcoded secret must be REJECTED when AEGIS_LICENSE_SECRET is unset', async () => {
    const unconfigured = createGatewayApp({ STRIPE_WEBHOOK_SECRET: 'whsec_test_secret_456' });
    const crypto = await import('node:crypto');

    // Attack: forge an enterprise license using the historically hardcoded secret
    const OLD_HARDCODED_SECRET = 'aegis_enterprise_lic_verification_secret_v1_deterministic';
    const forgedPayload = Buffer.from(
      JSON.stringify({
        customerId: 'cust_attacker',
        customerEmail: 'attacker@evil.example',
        plan: 'enterprise',
        issuedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(),
        features: ['soc2_guard', 'custom_packs'],
        maxMonthlyChecks: 'unlimited',
        algorithm: 'hmac-sha256',
      }),
      'utf8'
    ).toString('base64url');
    const forgedSig = crypto.createHmac('sha256', OLD_HARDCODED_SECRET).update(forgedPayload).digest('hex');
    const forgedLicense = `aegis_lic_${forgedPayload}.${forgedSig}`;

    const res = await unconfigured.request('/api/license/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ licenseKey: forgedLicense }),
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.valid).toBe(false);
    expect(data.active).toBe(false);
    expect(data.tier).toBe('community');
  });

  it('SEC-2: Stripe license issuance must fail CLOSED (503) when AEGIS_LICENSE_SECRET is unset', async () => {
    const unconfigured = createGatewayApp({ STRIPE_WEBHOOK_SECRET: 'whsec_test_secret_456' });
    const crypto = await import('node:crypto');

    const webhookPayload = {
      type: 'checkout.session.completed',
      data: { object: { id: 'cs_x', customer: 'cust_x', amount_total: 49900 } },
    };
    const rawBody = JSON.stringify(webhookPayload);
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = crypto
      .createHmac('sha256', 'whsec_test_secret_456')
      .update(`${timestamp}.${rawBody}`)
      .digest('hex');

    const res = await unconfigured.request('/api/billing/stripe-webhook', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'stripe-signature': `t=${timestamp},v1=${signature}`,
      },
      body: rawBody,
    });
    expect(res.status).toBe(503);
    const data = await res.json();
    expect(data.error).toContain('disabled');
    expect(data.licenseKey).toBeUndefined();
  });

  it('SEC-3: Ed25519 asymmetric licenses must still verify with no secret configured', async () => {
    const unconfigured = createGatewayApp({ STRIPE_WEBHOOK_SECRET: 'whsec_test_secret_456' });
    const crypto = await import('node:crypto');

    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const compiledPublicKey = (
      await import('@aegis-kernel/core')
    ).DEFAULT_AEGIS_PUBLIC_KEY_PEM;

    // Issue with a vendor private key against the compiled-in public key is the
    // real issuer flow; for the test we inject the matching public key instead.
    const gatewayWithVendorKey = createGatewayApp({
      STRIPE_WEBHOOK_SECRET: 'whsec_test_secret_456',
      AEGIS_PUBLIC_KEY: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    });

    const payload = Buffer.from(
      JSON.stringify({
        customerId: 'cust_legit',
        customerEmail: 'buyer@corp.example',
        plan: 'enterprise',
        issuedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString(),
        features: ['soc2_guard'],
        maxMonthlyChecks: 'unlimited',
        algorithm: 'ed25519',
      }),
      'utf8'
    ).toString('base64url');
    const sig = crypto.sign(null, Buffer.from(payload, 'utf8'), privateKey).toString('hex');
    const license = `aegis_lic_ed25519_${payload}.${sig}`;

    const res = await gatewayWithVendorKey.request('/api/license/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ licenseKey: license }),
    });
    const data = await res.json();
    expect(data.valid).toBe(true);
    expect(data.tier).toBe('enterprise');

    // Tampered token must fail even with the same key configured
    const tampered = `aegis_lic_ed25519_${payload}.${'0'.repeat(128)}`;
    const badRes = await gatewayWithVendorKey.request('/api/license/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ licenseKey: tampered }),
    });
    const badData = await badRes.json();
    expect(badData.valid).toBe(false);

    // Default app (compiled-in key) must reject keys from a foreign vendor keypair
    const foreignRes = await unconfigured.request('/api/license/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ licenseKey: license }),
    });
    const foreignData = await foreignRes.json();
    expect(foreignData.valid).toBe(false);

    // Silence unused-var lint: compiled key exists for real deployments
    expect(typeof compiledPublicKey).toBe('string');
  });

  it('SEC-4: AEGIS_ALLOW_UNSAFE_LICENSE=1 must be refused in production boot', () => {
    expect(() =>
      createGatewayApp({
        NODE_ENV: 'production',
        AEGIS_ALLOW_UNSAFE_LICENSE: '1',
        STRIPE_WEBHOOK_SECRET: 'whsec_test_secret_456',
      })
    ).toThrow(/not permitted in production/);
  });
});
