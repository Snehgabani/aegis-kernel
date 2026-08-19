import { describe, it, expect } from 'vitest';
import { AegisLicenseManager, AegisEngine } from '../src/index.js';

describe('Aegis Enterprise Monetization & Compliance Layer', () => {
  const secretKey = 'test_secret_key_for_aegis_enterprise_licensing';
  const licenseManager = new AegisLicenseManager(secretKey);

  describe('Cryptographic License Token Verification', () => {
    it('should generate and verify valid enterprise license tokens offline', () => {
      const payload = {
        customerId: 'cust_acme_corp',
        customerEmail: 'security@acme.com',
        plan: 'enterprise' as const,
        issuedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(),
        features: ['hipaa_guard', 'pci_dss_guard', 'soc2_guard', 'cloud_telemetry'],
        maxMonthlyChecks: 'unlimited' as const,
      };

      const token = licenseManager.generateLicenseKey(payload, secretKey);
      expect(token).toMatch(/^aegis_lic_[a-zA-Z0-9_-]+\.[a-f0-9]{64}$/);

      const verification = licenseManager.verifyLicenseKey(token);
      expect(verification.valid).toBe(true);
      expect(verification.active).toBe(true);
      expect(verification.tier).toBe('enterprise');
      expect(verification.payload?.customerId).toBe('cust_acme_corp');
    });

    it('should reject tampered or forged license tokens', () => {
      const validPayload = {
        customerId: 'cust_small_biz',
        customerEmail: 'owner@small.com',
        plan: 'pro' as const,
        issuedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(),
        features: ['soc2_guard'],
        maxMonthlyChecks: 100000,
      };

      const validToken = licenseManager.generateLicenseKey(validPayload, secretKey);
      // Tamper with payload (e.g. attempt to escalate from pro to enterprise)
      const parts = validToken.slice('aegis_lic_'.length).split('.');
      const decoded = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
      decoded.plan = 'enterprise';
      const forgedPayloadB64 = Buffer.from(JSON.stringify(decoded), 'utf8').toString('base64url');
      const forgedToken = `aegis_lic_${forgedPayloadB64}.${parts[1]}`;

      const verification = licenseManager.verifyLicenseKey(forgedToken);
      expect(verification.valid).toBe(false);
      expect(verification.active).toBe(false);
      expect(verification.error).toContain('Cryptographic signature mismatch');
    });

    it('should identify expired license tokens and apply 7-day grace period', () => {
      // 1. Expired long ago (> 7 days)
      const expiredPayload = {
        customerId: 'cust_expired',
        customerEmail: 'billing@expired.com',
        plan: 'scale' as const,
        issuedAt: '2024-01-01T00:00:00.000Z',
        expiresAt: '2024-06-01T00:00:00.000Z', // Expired long ago
        features: ['hipaa_guard', 'soc2_guard'],
        maxMonthlyChecks: 1000000,
      };

      const expiredToken = licenseManager.generateLicenseKey(expiredPayload, secretKey);
      const verification = licenseManager.verifyLicenseKey(expiredToken);
      expect(verification.valid).toBe(true);
      expect(verification.active).toBe(false);
      expect(verification.inGracePeriod).toBe(false);
      expect(verification.error).toContain('License expired');

      // 2. Expired 2 days ago (within 7-day grace period)
      const recentExpiredPayload = {
        customerId: 'cust_grace',
        customerEmail: 'billing@grace.com',
        plan: 'pro' as const,
        issuedAt: new Date(Date.now() - 30 * 24 * 3600 * 1000).toISOString(),
        expiresAt: new Date(Date.now() - 2 * 24 * 3600 * 1000).toISOString(),
        features: ['hipaa_guard'],
        maxMonthlyChecks: 100000,
      };

      const graceToken = licenseManager.generateLicenseKey(recentExpiredPayload, secretKey);
      const graceVerification = licenseManager.verifyLicenseKey(graceToken);
      expect(graceVerification.valid).toBe(true);
      expect(graceVerification.active).toBe(true); // Active during grace
      expect(graceVerification.inGracePeriod).toBe(true);
      expect(graceVerification.graceDaysRemaining).toBeGreaterThan(0);
    });
    it('should generate and verify Asymmetric Ed25519 signed license tokens offline', () => {
      const { privateKey } = require('node:crypto').generateKeyPairSync('ed25519', {
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        publicKeyEncoding: { type: 'spki', format: 'pem' },
      });

      const payload = {
        customerId: 'cust_enterprise_fintech',
        customerEmail: 'compliance@fintech.io',
        plan: 'enterprise' as const,
        issuedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(),
        features: ['iso42001_guard', 'cloud_infra_guard', 'soc2_guard'],
        maxMonthlyChecks: 'unlimited' as const,
      };

      const ed25519Token = licenseManager.generateEd25519LicenseKey(payload, privateKey);
      expect(ed25519Token).toMatch(/^aegis_lic_ed25519_[a-zA-Z0-9_-]+\.[a-f0-9]+$/);

      // Verify with matching public key
      const customManager = new AegisLicenseManager('', (require('node:crypto').createPublicKey(privateKey)).export({ type: 'spki', format: 'pem' }).toString());
      const verification = customManager.verifyLicenseKey(ed25519Token);
      expect(verification.valid).toBe(true);
      expect(verification.active).toBe(true);
      expect(verification.tier).toBe('enterprise');
      expect(verification.payload?.customerId).toBe('cust_enterprise_fintech');
    });
  });

  describe('Enterprise Compliance Rule Packs Evaluation', () => {
    const engine = new AegisEngine({
      mode: 'enforce',
      packs: [
        '@aegis/hipaa-guard',
        '@aegis/pci-dss-guard',
        '@aegis/soc2-guard',
        '@aegis/iso42001-guard',
        '@aegis/cloud-infra-guard',
      ],
    });

    it('should enforce HIPAA-001 / HIPAA-002: block NPI and DEA doctor tokens in tool calls', () => {
      // NPI test (10 digits starting with 1 or 2)
      const npiVerdict = engine.evaluate({
        tool: 'patient_sync',
        params: { doctor_npi: '1234567890', patient_notes: 'Standard checkup' },
      });
      expect(npiVerdict.allowed).toBe(false);
      expect(npiVerdict.violations.some((v) => v.ruleId === 'HIPAA-001')).toBe(true);

      // DEA test
      const deaVerdict = engine.evaluate({
        tool: 'send_prescription',
        params: { dea_number: 'AB1234567', drug: 'Amoxicillin' },
      });
      expect(deaVerdict.allowed).toBe(false);
      expect(deaVerdict.violations.some((v) => v.ruleId === 'HIPAA-002')).toBe(true);
    });

    it('should enforce PCI-DSS-001 / PCI-DSS-002: block credit cards and CVV codes', () => {
      const cvvVerdict = engine.evaluate({
        tool: 'process_payment',
        params: { note: 'Card code: cvv: 888' },
      });
      expect(cvvVerdict.allowed).toBe(false);
      expect(cvvVerdict.violations.some((v) => v.ruleId === 'PCI-002')).toBe(true);
    });

    it('should enforce SOC2-001 / SOC2-002: block system path traversal and DDL wipes', () => {
      // System file traversal
      const pathVerdict = engine.evaluate({
        tool: 'read_config_file',
        params: { path: '/etc/shadow' },
      });
      expect(pathVerdict.allowed).toBe(false);
      expect(pathVerdict.violations.some((v) => v.ruleId === 'SOC2-001')).toBe(true);

      // Destructive DDL
      const ddlVerdict = engine.evaluate({
        tool: 'db_admin',
        params: { sql: 'DROP TABLE audit_trails;' },
      });
      expect(ddlVerdict.allowed).toBe(false);
      expect(ddlVerdict.violations.some((v) => v.ruleId === 'SOC2-002')).toBe(true);
    });

    it('should enforce ISO42001-001 and CLOUD-001: block high-risk unapproved tools and kubectl delete all', () => {
      // ISO 42001 HITL requirement
      const hitlVerdict = engine.evaluate({
        tool: 'deploy_untested_model',
        params: { risk_level: 'HIGH' },
      });
      expect(hitlVerdict.allowed).toBe(false);
      expect(hitlVerdict.violations.some((v) => v.ruleId === 'ISO-001')).toBe(true);

      // Cloud Infrastructure destruction
      const k8sVerdict = engine.evaluate({
        tool: 'cluster_manager',
        params: { command: 'kubectl delete all --all' },
      });
      expect(k8sVerdict.allowed).toBe(false);
      expect(k8sVerdict.violations.some((v) => v.ruleId === 'CLOUD-001')).toBe(true);
    });
  });
});
