import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { AegisLicenseManager, type AegisEvent, type LicensePayload } from '@aegis-kernel/core';

export interface GatewayEnv {
  AEGIS_LICENSE_SECRET?: string;
  STRIPE_WEBHOOK_SECRET?: string;
}

export function createGatewayApp(env?: GatewayEnv) {
  const app = new Hono();
  const secretKey = env?.AEGIS_LICENSE_SECRET || 'aegis_enterprise_lic_verification_secret_v1_deterministic';
  const licenseManager = new AegisLicenseManager(secretKey);

  // In-memory audit event store (backed by Cloudflare D1 / PostgreSQL in production)
  const auditEvents: AegisEvent[] = [];

  app.use('*', cors());

  // Health check
  app.get('/health', (c) => c.json({ status: 'ok', service: 'aegis-gateway', timestamp: new Date().toISOString() }));

  // 1. Ingest telemetry proofs from client engines
  app.post('/api/telemetry', async (c) => {
    const authHeader = c.req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ error: 'Missing or unauthorized Bearer API key' }, 401);
    }

    const body = await c.req.json<{ events?: AegisEvent[] }>();
    if (!body.events || !Array.isArray(body.events)) {
      return c.json({ error: 'Invalid payload: events array required' }, 400);
    }

    // Ingest into audit store
    for (const evt of body.events) {
      auditEvents.push(evt);
    }

    // Keep bounded in-memory buffer for serverless runtime
    if (auditEvents.length > 10000) {
      auditEvents.splice(0, auditEvents.length - 10000);
    }

    return c.json({ success: true, ingested: body.events.length });
  });

  // 2. Aggregated dashboard metrics
  app.get('/api/dashboard/stats', (c) => {
    const total = auditEvents.length;
    const blocked = auditEvents.filter((e) => e.verdict === 'BLOCKED').length;
    const allowed = auditEvents.filter((e) => e.verdict === 'ALLOWED').length;
    const avgLatencyMs =
      total > 0 ? auditEvents.reduce((sum, e) => sum + e.latencyMs, 0) / total : 0;

    const ruleBreakdown: Record<string, number> = {};
    for (const evt of auditEvents) {
      for (const v of evt.rulesFired) {
        ruleBreakdown[v.ruleId] = (ruleBreakdown[v.ruleId] || 0) + 1;
      }
    }

    return c.json({
      totalChecks: total,
      totalBlocked: blocked,
      totalAllowed: allowed,
      blockRatePercent: total > 0 ? ((blocked / total) * 100).toFixed(1) : '0.0',
      averageLatencyMs: Number(avgLatencyMs.toFixed(3)),
      ruleBreakdown,
      lastUpdated: new Date().toISOString(),
    });
  });

  // 3. Paginated audit log events
  app.get('/api/dashboard/events', (c) => {
    const limit = Number(c.req.query('limit') || '50');
    const offset = Number(c.req.query('offset') || '0');
    const verdictFilter = c.req.query('verdict');

    let filtered = auditEvents;
    if (verdictFilter) {
      filtered = filtered.filter((e) => e.verdict === verdictFilter);
    }

    const paginated = filtered.slice(-limit - offset, filtered.length - offset).reverse();

    return c.json({
      events: paginated,
      total: filtered.length,
      limit,
      offset,
    });
  });

  // 4. Stripe Subscription Fulfillment Webhook
  app.post('/api/billing/stripe-webhook', async (c) => {
    const payload = await c.req.json();
    const eventType = payload?.type;

    if (eventType === 'checkout.session.completed' || eventType === 'invoice.payment_succeeded') {
      const session = payload.data?.object;
      const customerEmail = session?.customer_details?.email || session?.customer_email || 'customer@aegis-kernel.dev';
      const customerId = session?.customer || `cust_${Date.now()}`;
      
      // Determine tier from amount or metadata
      const amountTotal = session?.amount_total || 4900; // default $49.00
      let plan: 'pro' | 'scale' | 'enterprise' = 'pro';
      let features = ['hipaa_guard', 'pci_dss_guard', 'cloud_telemetry'];
      let maxMonthlyChecks: number | 'unlimited' = 100000;

      if (amountTotal >= 49900) {
        plan = 'enterprise';
        features = ['hipaa_guard', 'pci_dss_guard', 'soc2_guard', 'cloud_telemetry', 'custom_packs'];
        maxMonthlyChecks = 'unlimited';
      } else if (amountTotal >= 19900) {
        plan = 'scale';
        features = ['hipaa_guard', 'pci_dss_guard', 'soc2_guard', 'cloud_telemetry'];
        maxMonthlyChecks = 1000000;
      }

      const licensePayload: LicensePayload = {
        customerId,
        customerEmail,
        plan,
        issuedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(),
        features,
        maxMonthlyChecks,
      };

      const licenseKey = licenseManager.generateLicenseKey(licensePayload, secretKey);

      return c.json({
        received: true,
        fulfilled: true,
        customerId,
        plan,
        licenseKey,
        instructions: `Run 'npx aegis license activate ${licenseKey}' to unlock compliance packs.`,
      });
    }

    return c.json({ received: true, ignored: true });
  });

  // 5. Remote license verification endpoint
  app.post('/api/license/verify', async (c) => {
    const body = await c.req.json<{ licenseKey?: string }>();
    if (!body.licenseKey) {
      return c.json({ valid: false, error: 'Missing licenseKey parameter' }, 400);
    }
    const result = licenseManager.verifyLicenseKey(body.licenseKey);
    return c.json(result);
  });

  // 6. Stripe Customer Portal Session generator
  app.post('/api/billing/customer-portal', async (c) => {
    const body = await c.req.json<{ customerId?: string; returnUrl?: string }>();
    if (!body.customerId) {
      return c.json({ error: 'Missing customerId parameter' }, 400);
    }
    const returnUrl = body.returnUrl || 'https://aegis-kernel.dev/dashboard/';
    return c.json({
      url: `https://billing.stripe.com/p/session/test_${body.customerId}?return_url=${encodeURIComponent(returnUrl)}`,
      customerId: body.customerId,
    });
  });

  return app;
}

export const app = createGatewayApp();
export default app;
