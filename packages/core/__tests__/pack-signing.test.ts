import { describe, it, expect } from 'vitest';
import {
  computePackCommitment,
  canonicalJson,
  signPack,
  verifyPackSignature,
  verifyPackAgainstTrustedKeys,
  generatePackSigningKeypair,
  type PackSignatureManifest,
} from '../src/pack-signing.js';
import { RulePackLoader } from '../src/rule-loader.js';
import type { RulePack } from '../src/types.js';

/**
 * Signed rule-pack manifests — OWASP AISVS C10.1.1 (reject tampered/unsigned
 * builds), MCP Top-10 MCP03/MCP04 supply-chain controls.
 */

const PACK: RulePack = RulePackLoader.loadPack('@aegis/sql-guard')!;
const { publicKeyPem, privateKeyPem } = generatePackSigningKeypair();
const OTHER_KEYS = generatePackSigningKeypair();

describe('canonical commitment', () => {
  it('is invariant to key order and formatting (YAML↔JSON round-trips)', () => {
    const shuffled: RulePack = {
      ...PACK,
      rules: PACK.rules.map((r) => {
        const entries = Object.entries(r).reverse();
        return Object.fromEntries(entries) as typeof r;
      }),
    };
    expect(computePackCommitment(shuffled)).toBe(computePackCommitment(PACK));
  });

  it('changes on ANY semantic mutation (rule added / severity changed / version bump)', () => {
    expect(computePackCommitment({ ...PACK, version: '9.9.9' })).not.toBe(computePackCommitment(PACK));
    expect(computePackCommitment({ ...PACK, rules: [...PACK.rules, { ...PACK.rules[0], id: 'SQL-999' }] })).not.toBe(
      computePackCommitment(PACK)
    );
    expect(canonicalJson({ b: 1, a: { d: 2, c: 3 } })).toBe('{"a":{"c":3,"d":2},"b":1}');
  });
});

describe('sign → verify lifecycle', () => {
  it('a correctly signed pack verifies', () => {
    const manifest = signPack(PACK, privateKeyPem, 'aegis-release-bot');
    expect(manifest.signer).toBe('aegis-release-bot');
    const result = verifyPackSignature(PACK, manifest, publicKeyPem);
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
    expect(result.commitment).toBe(manifest.commitment);
  });

  it('TAMPERED pack content fails verification (commitment mismatch) — AISVS C10.1.1', () => {
    const manifest = signPack(PACK, privateKeyPem);
    const tampered: RulePack = {
      ...PACK,
      rules: PACK.rules.map((r) =>
        r.id === 'SQL-004' ? { ...r, when: { ...(r.when as object), params: { max_limit: 999999999 } } } : r
      ),
    };
    const result = verifyPackSignature(tampered, manifest, publicKeyPem);
    expect(result.valid).toBe(false);
    expect(result.errors.join(' ')).toContain('commitment mismatch');
  });

  it('forged manifest with wrong key fails (Ed25519 signature check)', () => {
    const manifest: PackSignatureManifest = {
      ...signPack(PACK, privateKeyPem),
      // attacker re-signs commitment with their own key but ships it
      signature: signPack(PACK, OTHER_KEYS.privateKeyPem).signature,
    };
    const result = verifyPackSignature(PACK, manifest, publicKeyPem);
    expect(result.valid).toBe(false);
    expect(result.errors.join(' ')).toContain('Ed25519 signature verification failed');
  });

  it('unknown algorithm fails closed', () => {
    const manifest = { ...signPack(PACK, privateKeyPem), algorithm: 'hmac-md5' as unknown as 'ed25519' };
    const result = verifyPackSignature(PACK, manifest, publicKeyPem);
    expect(result.valid).toBe(false);
    expect(result.errors.join(' ')).toContain('unsupported algorithm');
  });

  it('packId/version binding prevents manifest replay across packs', () => {
    const manifest = signPack(PACK, privateKeyPem);
    const otherPack = RulePackLoader.loadPack('@aegis/data-guard')!;
    const result = verifyPackSignature(otherPack, manifest, publicKeyPem);
    expect(result.valid).toBe(false);
    expect(result.errors.join(' ')).toContain('mismatch');
  });
});

describe('multi-maintainer trusted-key set', () => {
  it('valid if ANY trusted key verifies; fails with none', () => {
    const manifest = signPack(PACK, privateKeyPem);
    expect(verifyPackAgainstTrustedKeys(PACK, manifest, [OTHER_KEYS.publicKeyPem, publicKeyPem]).valid).toBe(true);
    expect(verifyPackAgainstTrustedKeys(PACK, manifest, [OTHER_KEYS.publicKeyPem]).valid).toBe(false);
    expect(verifyPackAgainstTrustedKeys(PACK, manifest, []).valid).toBe(false);
  });
});
