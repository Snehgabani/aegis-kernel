import { createHmac, timingSafeEqual } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

export type AegisPlanTier = 'community' | 'pro' | 'scale' | 'enterprise';

export interface LicensePayload {
  customerId: string;
  customerEmail: string;
  plan: AegisPlanTier;
  issuedAt: string;
  expiresAt: string; // ISO string
  features: string[]; // e.g. ['hipaa_guard', 'pci_dss_guard', 'soc2_guard', 'cloud_telemetry']
  maxMonthlyChecks: number | 'unlimited';
}

export interface LicenseVerificationResult {
  valid: boolean;
  active: boolean;
  tier: AegisPlanTier;
  inGracePeriod?: boolean;
  graceDaysRemaining?: number;
  payload?: LicensePayload;
  error?: string;
}

export class AegisLicenseManager {
  private secretKey: string;
  private cachedLicense: LicenseVerificationResult | null = null;

  constructor(secretKey?: string) {
    this.secretKey = secretKey || process.env.AEGIS_LICENSE_SECRET || '';
  }

  /**
   * Generates a signed enterprise license token (Issuer side)
   */
  public generateLicenseKey(payload: LicensePayload, secret: string = this.secretKey): string {
    if (!secret) {
      throw new Error('AEGIS_LICENSE_SECRET environment variable is required for enterprise license verification');
    }
    const jsonStr = JSON.stringify(payload);
    const payloadB64 = Buffer.from(jsonStr, 'utf8').toString('base64url');
    const signature = createHmac('sha256', secret).update(payloadB64).digest('hex');
    return `aegis_lic_${payloadB64}.${signature}`;
  }

  /**
   * Verifies an enterprise license token offline with zero network latency
   */
  public verifyLicenseKey(licenseKey: string): LicenseVerificationResult {
    if (!this.secretKey) {
      throw new Error('AEGIS_LICENSE_SECRET environment variable is required for enterprise license verification');
    }
    if (!licenseKey || typeof licenseKey !== 'string' || !licenseKey.startsWith('aegis_lic_')) {
      return {
        valid: false,
        active: false,
        tier: 'community',
        error: 'Invalid license key format (must start with aegis_lic_)',
      };
    }

    try {
      const raw = licenseKey.slice('aegis_lic_'.length);
      const parts = raw.split('.');
      if (parts.length !== 2) {
        return {
          valid: false,
          active: false,
          tier: 'community',
          error: 'Malformed license token segments',
        };
      }

      const [payloadB64, signature] = parts;
      const expectedSignature = createHmac('sha256', this.secretKey)
        .update(payloadB64)
        .digest('hex');

      const sigBuffer = Buffer.from(signature, 'hex');
      const expectedBuffer = Buffer.from(expectedSignature, 'hex');

      if (sigBuffer.length !== expectedBuffer.length || !timingSafeEqual(sigBuffer, expectedBuffer)) {
        return {
          valid: false,
          active: false,
          tier: 'community',
          error: 'Cryptographic signature mismatch: unauthorized or altered license token',
        };
      }

      const jsonStr = Buffer.from(payloadB64, 'base64url').toString('utf8');
      const payload: LicensePayload = JSON.parse(jsonStr);

      const now = new Date();
      const expiresAt = new Date(payload.expiresAt);
      const GRACE_PERIOD_MS = 7 * 24 * 3600 * 1000; // 7-day grace period
      const isExpired = now > expiresAt;
      const isWithinGrace = isExpired && now.getTime() - expiresAt.getTime() < GRACE_PERIOD_MS;

      if (isExpired) {
        if (isWithinGrace) {
          const graceDaysRemaining = Math.ceil(
            (GRACE_PERIOD_MS - (now.getTime() - expiresAt.getTime())) / (24 * 3600 * 1000)
          );
          return {
            valid: true,
            active: true, // Remains active during grace period
            inGracePeriod: true,
            graceDaysRemaining,
            tier: payload.plan,
            payload,
            error: `License expired on ${payload.expiresAt} (${graceDaysRemaining} days remaining in grace period)`,
          };
        }
        return {
          valid: true,
          active: false,
          inGracePeriod: false,
          tier: payload.plan,
          payload,
          error: `License expired on ${payload.expiresAt}`,
        };
      }

      return {
        valid: true,
        active: true,
        tier: payload.plan,
        payload,
      };
    } catch (err: any) {
      return {
        valid: false,
        active: false,
        tier: 'community',
        error: `Failed to decode license token: ${err.message}`,
      };
    }
  }

  /**
   * Loads and verifies license from local environment or .aegis/license.json
   */
  public resolveActiveLicense(customPath?: string): LicenseVerificationResult {
    if (this.cachedLicense) {
      return this.cachedLicense;
    }

    // 1. Check environment variable
    if (process.env.AEGIS_LICENSE_KEY) {
      const result = this.verifyLicenseKey(process.env.AEGIS_LICENSE_KEY);
      this.cachedLicense = result;
      return result;
    }

    // 2. Check local license file
    const licenseFilePath = customPath || path.resolve(process.cwd(), '.aegis/license.json');
    if (fs.existsSync(licenseFilePath)) {
      try {
        const fileContent = JSON.parse(fs.readFileSync(licenseFilePath, 'utf8'));
        if (fileContent.licenseKey) {
          const result = this.verifyLicenseKey(fileContent.licenseKey);
          this.cachedLicense = result;
          return result;
        }
      } catch {
        // Fall back to community
      }
    }

    // Default: Community free tier
    const communityResult: LicenseVerificationResult = {
      valid: true,
      active: true,
      tier: 'community',
      payload: {
        customerId: 'community_user',
        customerEmail: 'dev@localhost',
        plan: 'community',
        issuedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 100 * 365 * 24 * 3600 * 1000).toISOString(),
        features: ['sql_guard', 'finance_guard', 'data_guard'],
        maxMonthlyChecks: 10000,
      },
    };

    this.cachedLicense = communityResult;
    return communityResult;
  }

  /**
   * Persists an activated license token to .aegis/license.json
   */
  public saveLicense(licenseKey: string, destPath?: string): LicenseVerificationResult {
    const verified = this.verifyLicenseKey(licenseKey);
    if (!verified.valid || !verified.active) {
      return verified;
    }

    const aegisDir = destPath ? path.dirname(destPath) : path.resolve(process.cwd(), '.aegis');
    if (!fs.existsSync(aegisDir)) {
      fs.mkdirSync(aegisDir, { recursive: true });
    }

    const filePath = destPath || path.join(aegisDir, 'license.json');
    fs.writeFileSync(
      filePath,
      JSON.stringify(
        {
          licenseKey,
          tier: verified.tier,
          customerId: verified.payload?.customerId,
          expiresAt: verified.payload?.expiresAt,
          features: verified.payload?.features,
          activatedAt: new Date().toISOString(),
        },
        null,
        2
      ),
      'utf8'
    );

    this.cachedLicense = verified;
    return verified;
  }

  /**
   * Checks if an enterprise pack or capability is entitled under the active license
   */
  public isPackEntitled(packId: string, customPath?: string): boolean {
    const normalized = packId.replace(/^@aegis\//, '');
    // Community packs are always free and unlocked
    if (['sql-guard', 'finance-guard', 'data-guard'].includes(normalized)) {
      return true;
    }

    const license = this.resolveActiveLicense(customPath);
    if (!license.valid || !license.active) {
      return false;
    }

    // Enterprise tier has access to all packs
    if (license.tier === 'enterprise') {
      return true;
    }

    const featureKey = normalized.replace(/-/g, '_');
    return Boolean(license.payload?.features?.includes(featureKey));
  }
}
