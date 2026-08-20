import { Hono } from 'hono';
import { cors } from 'hono/cors';
import * as crypto from 'crypto';
import { AegisEngine, AegisLicenseManager, type AegisEvent, type LicensePayload } from '@aegis-kernel/core';
import { renderPrometheusMetrics } from './metrics.js';
import { createAuditStoreFromEnv, type AuditStore } from './audit-store.js';

export interface GatewayEnv {
  AEGIS_LICENSE_SECRET?: string;
  AEGIS_PUBLIC_KEY?: string;
  AEGIS_ALLOW_UNSAFE_LICENSE?: string;
  STRIPE_WEBHOOK_SECRET?: string;
  NODE_ENV?: string;
  /** Audit persistence: 'jsonl' enables the durable file store (default memory). */
  AEGIS_AUDIT_STORE?: string;
  /** JSONL store path (default ./aegis-audit.jsonl). */
  AEGIS_AUDIT_PATH?: string;
}

/**
 * @security FAIL-CLOSED LICENSE BOOTSTRAP
 *
 * Historical defect (fixed 2026-08-20): this constructor previously fell back to
 * a hardcoded HMAC secret published in the MIT-licensed source, allowing anyone
 * to forge enterprise licenses against deployments that did not set
 * AEGIS_LICENSE_SECRET.
 *
 * Current behavior:
 * - License VERIFICATION is asymmetric by default (Ed25519 public key compiled
 *   into @aegis-kernel/core). No secret is required or desired for verification.
 * - HMAC verification/issuance requires an explicitly configured
 *   AEGIS_LICENSE_SECRET. Without it, HMAC tokens are rejected and the Stripe
 *   fulfillment endpoint fails closed (503) instead of minting forgeable keys.
 * - AEGIS_ALLOW_UNSAFE_LICENSE=1 (local demos only) is refused in production.
 */
export function createGatewayApp(env?: GatewayEnv, options?: { auditStore?: AuditStore }) {
  const nodeEnv = env?.NODE_ENV || process.env.NODE_ENV;
  const isProduction = nodeEnv === 'production';
  const secretKey = env?.AEGIS_LICENSE_SECRET || process.env.AEGIS_LICENSE_SECRET || '';
  const allowUnsafe = env?.AEGIS_ALLOW_UNSAFE_LICENSE || process.env.AEGIS_ALLOW_UNSAFE_LICENSE;
  const publicKeyPem = env?.AEGIS_PUBLIC_KEY || process.env.AEGIS_PUBLIC_KEY;

  // Fail closed: the "unsafe" escape hatch is for local demos only.
  if (isProduction && allowUnsafe === '1') {
    throw new Error(
      'AEGIS_ALLOW_UNSAFE_LICENSE=1 is not permitted in production. ' +
        'Refusing to start (fail-closed licensing policy).'
    );
  }

  if (isProduction && !secretKey) {
    // Asymmetric Ed25519 verification with the compiled-in public key requires no
    // secret; HMAC license paths are disabled until a secret is configured.
    console.warn(
      '[aegis-gateway] production boot without AEGIS_LICENSE_SECRET: ' +
        'asymmetric Ed25519 license verification active (recommended); HMAC license ' +
        'verification and Stripe license issuance are DISABLED (fail-closed).'
    );
  }

  const app = new Hono();
  const licenseManager = new AegisLicenseManager(secretKey || undefined, publicKeyPem);
  const probeEngine = new AegisEngine();

  // Audit store: pluggable persistence (default: bounded in-memory buffer).
  // AEGIS_AUDIT_STORE=jsonl + AEGIS_AUDIT_PATH=... enables durable file storage.
  const auditStore: AuditStore =
    options?.auditStore ??
    createAuditStoreFromEnv({ AEGIS_AUDIT_STORE: env?.AEGIS_AUDIT_STORE, AEGIS_AUDIT_PATH: env?.AEGIS_AUDIT_PATH });

  app.use('*', cors());

  // Shallow health check (liveness)
  app.get('/health', (c) => c.json({ status: 'ok', service: 'aegis-gateway', timestamp: new Date().toISOString() }));

  // Deep health check (readiness with engine probe)
  app.get('/health/deep', (c) => {
    const probe = probeEngine.runSelfTest();
    return c.json({
      status: probe.healthy ? 'healthy' : 'degraded',
      service: 'aegis-gateway',
      timestamp: new Date().toISOString(),
      probe,
      eventsStored: auditStore.count(),
    }, probe.healthy ? 200 : 503);
  });

  // Prometheus Golden Signals metrics exporter
  app.get('/metrics', (c) => {
    return c.text(renderPrometheusMetrics(), 200, {
      'Content-Type': 'text/plain; version=0.0.4; charset=utf-8',
    });
  });

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

    // Ingest into audit store (memory + optional durable backend)
    auditStore.append(body.events);

    return c.json({ success: true, ingested: body.events.length });
  });

  // 2. Aggregated dashboard metrics
  app.get('/api/dashboard/stats', (c) => {
    const window = auditStore.all();
    const total = window.length;
    const blocked = window.filter((e) => e.verdict === 'BLOCKED').length;
    const allowed = window.filter((e) => e.verdict === 'ALLOWED').length;
    const avgLatencyMs =
      total > 0 ? window.reduce((sum, e) => sum + e.latencyMs, 0) / total : 0;

    const ruleBreakdown: Record<string, number> = {};
    for (const evt of window) {
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

    const { events: paginated, total: filteredTotal } = auditStore.query({ limit, offset, verdict: verdictFilter });

    return c.json({
      events: paginated,
      total: filteredTotal,
      limit,
      offset,
    });
  });

  // 4. Stripe Subscription Fulfillment Webhook
  app.post('/api/billing/stripe-webhook', async (c) => {
    const rawBody = await c.req.text();
    const sigHeader = c.req.header('stripe-signature');
    const secret = env?.STRIPE_WEBHOOK_SECRET || process.env.STRIPE_WEBHOOK_SECRET;

    if (!sigHeader || !secret) {
      return c.json({ error: 'Missing signature or secret' }, 401);
    }

    const sigParts = sigHeader.split(',').reduce((acc, part) => {
      const [key, value] = part.split('=');
      if (key && value) acc[key.trim()] = value.trim();
      return acc;
    }, {} as Record<string, string>);

    if (!sigParts.t || !sigParts.v1) {
      return c.json({ error: 'Invalid signature format' }, 401);
    }

    const expectedSig = crypto.createHmac('sha256', secret).update(`${sigParts.t}.${rawBody}`).digest('hex');

    if (expectedSig !== sigParts.v1) {
      return c.json({ error: 'Invalid signature' }, 401);
    }

    let payload;
    try {
      payload = JSON.parse(rawBody);
    } catch (e) {
      return c.json({ error: 'Invalid JSON' }, 400);
    }

    const eventType = payload?.type;

    if (eventType === 'checkout.session.completed' || eventType === 'invoice.payment_succeeded') {
      // Fail closed: never mint HMAC license keys without an explicitly configured secret.
      if (!secretKey) {
        console.error(
          '[aegis-gateway] Stripe fulfillment reached without AEGIS_LICENSE_SECRET: refusing to issue license (fail-closed).'
        );
        return c.json(
          {
            error:
              'License issuance is disabled: AEGIS_LICENSE_SECRET is not configured on the gateway. ' +
              'Configure the gateway with an Ed25519 issuer key or set AEGIS_LICENSE_SECRET to fulfill purchases.',
          },
          503
        );
      }
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

      // Automated Onboarding Email Delivery (via Resend API if configured)
      if (process.env.RESEND_API_KEY && customerEmail && !customerEmail.includes('localhost')) {
        try {
          await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
            },
            body: JSON.stringify({
              from: 'Aegis Invariant Kernel <license@aegis-kernel.dev>',
              to: [customerEmail],
              subject: `🛡️ Your Aegis ${plan.toUpperCase()} License Key & Activation Guide`,
              html: `
                <h2>Welcome to Aegis Invariant Kernel!</h2>
                <p>Thank you for upgrading to the <strong>${plan.toUpperCase()} Plan</strong>.</p>
                <p>Your offline cryptographic license token is:</p>
                <pre style="background: #111827; color: #34d399; padding: 12px; border-radius: 6px; font-family: monospace;">${licenseKey}</pre>
                <p>To activate your compliance packs and unlimited throughput, run:</p>
                <pre style="background: #111827; color: #38bdf8; padding: 12px; border-radius: 6px; font-family: monospace;">npx aegis license activate ${licenseKey}</pre>
                <p>Or configure via environment variable in your production runtime:</p>
                <pre style="background: #111827; color: #fbbf24; padding: 12px; border-radius: 6px; font-family: monospace;">AEGIS_LICENSE_KEY=${licenseKey}</pre>
              `,
            }),
          });
        } catch {
          // Log and continue gracefully
        }
      }

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
    try {
      const result = licenseManager.verifyLicenseKey(body.licenseKey);
      return c.json(result);
    } catch (err) {
      // Fail closed: e.g. HMAC token presented while no AEGIS_LICENSE_SECRET is
      // configured. Report as invalid rather than 500, and never accept it.
      return c.json(
        {
          valid: false,
          active: false,
          tier: 'community',
          error: `License verification failed (fail-closed): ${(err as Error).message}`,
        },
        200
      );
    }
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
