/**
 * @file packages/core/src/pack-signing.ts
 * @description Signed rule-pack manifests — supply-chain integrity for policy
 * artifacts (OWASP AISVS C10.1.1: "verify components using signatures/checksums…
 * rejecting tampered or unsigned builds"; MCP Top-10 MCP03/MCP04).
 *
 * Design (deliberately minimal and deterministic — the CaMeL lesson that taint
 * bugs taught generally: enforcement mechanics must be simple enough to test
 * exhaustively):
 *
 *  - computePackCommitment(pack): SHA-256 over a CANONICAL serialization of the
 *    pack (recursively key-sorted, whitespace-free). Key-order and formatting
 *    differences cannot change the commitment; any semantic change must.
 *  - signPack(pack, privateKeyPem): Ed25519 signature over the commitment hex
 *    string; emits a sidecar manifest (`<pack>.sig.json`).
 *  - verifyPackSignature(pack, manifest, publicKeyPem): FAIL-CLOSED. Recomputes
 *    the commitment from the pack AS LOADED (tamper detection), checks
 *    packId/version binding, then verifies the Ed25519 signature.
 *
 * Trust model: public keys are distributed out-of-band (docs, lock files, CI
 * env). An unsigned pack is not an error — a tampered SIGNED pack is.
 */

import { createHash, sign as edSign, verify as edVerify, generateKeyPairSync } from 'node:crypto';
import type { RulePack } from './types.js';

export const PACK_SIGNATURE_ALGORITHM = 'ed25519';

/** Deterministic, recursively key-sorted JSON (formatting/order cannot alter it). */
export function canonicalJson(value: unknown): string {
  const sortDeep = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(sortDeep);
    if (v && typeof v === 'object') {
      const entries = Object.entries(v as Record<string, unknown>)
        .filter(([, val]) => val !== undefined)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
      return Object.fromEntries(entries.map(([k, val]) => [k, sortDeep(val)]));
    }
    return v;
  };
  return JSON.stringify(sortDeep(value));
}

export function computePackCommitment(pack: RulePack): string {
  return createHash('sha256')
    .update(
      canonicalJson({
        id: pack.id,
        name: pack.name,
        version: pack.version,
        rules: pack.rules,
      }),
      'utf8'
    )
    .digest('hex');
}

export interface PackSignatureManifest {
  algorithm: typeof PACK_SIGNATURE_ALGORITHM;
  packId: string;
  packVersion: string;
  /** SHA-256 commitment of the canonical pack content. */
  commitment: string;
  /** Ed25519 signature over the commitment hex string. */
  signature: string;
  signedAt: string;
  signer?: string;
}

export interface PackVerificationResult {
  valid: boolean;
  errors: string[];
  commitment: string;
}

/** Generate an Ed25519 keypair for pack signing (issuer-side convenience). */
export function generatePackSigningKeypair(): { publicKeyPem: string; privateKeyPem: string } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
}

export function signPack(pack: RulePack, privateKeyPem: string, signer?: string): PackSignatureManifest {
  const commitment = computePackCommitment(pack);
  const signature = edSign(null, Buffer.from(commitment, 'utf8'), privateKeyPem).toString('hex');
  return {
    algorithm: PACK_SIGNATURE_ALGORITHM,
    packId: pack.id,
    packVersion: pack.version,
    commitment,
    signature,
    signedAt: new Date().toISOString(),
    ...(signer ? { signer } : {}),
  };
}

/** FAIL-CLOSED signature verification. */
export function verifyPackSignature(
  pack: RulePack,
  manifest: PackSignatureManifest,
  publicKeyPem: string
): PackVerificationResult {
  const errors: string[] = [];

  if (!manifest || typeof manifest !== 'object') {
    return { valid: false, errors: ['missing signature manifest'], commitment: '' };
  }
  if (manifest.algorithm !== PACK_SIGNATURE_ALGORITHM) {
    errors.push(`unsupported algorithm '${manifest.algorithm}' (expected ${PACK_SIGNATURE_ALGORITHM})`);
  }
  if (manifest.packId !== pack.id) {
    errors.push(`packId mismatch: manifest '${manifest.packId}' vs pack '${pack.id}'`);
  }
  if (manifest.packVersion !== pack.version) {
    errors.push(`packVersion mismatch: manifest '${manifest.packVersion}' vs pack '${pack.version}'`);
  }

  // Recompute the commitment from the loaded pack — this is the tamper check.
  const commitment = computePackCommitment(pack);
  if (manifest.commitment !== commitment) {
    errors.push(
      'commitment mismatch: pack content differs from signed content (TAMPERED or wrong manifest)'
    );
  }

  if (errors.length === 0) {
    const sigOk = edVerify(
      null,
      Buffer.from(manifest.commitment, 'utf8'),
      publicKeyPem,
      Buffer.from(manifest.signature, 'hex')
    );
    if (!sigOk) {
      errors.push('Ed25519 signature verification failed (wrong key or forged manifest)');
    }
  }

  return { valid: errors.length === 0, errors, commitment };
}

/**
 * Convenience: verify a pack against a DIRECTORY of trusted public keys —
 * valid if ANY trusted key verifies (multi-maintainer signing).
 */
export function verifyPackAgainstTrustedKeys(
  pack: RulePack,
  manifest: PackSignatureManifest,
  trustedPublicKeysPem: string[]
): PackVerificationResult {
  const errors: string[] = [];
  if (trustedPublicKeysPem.length === 0) {
    return { valid: false, errors: ['no trusted public keys provided'], commitment: computePackCommitment(pack) };
  }
  let last: PackVerificationResult | null = null;
  for (const key of trustedPublicKeysPem) {
    last = verifyPackSignature(pack, manifest, key);
    if (last.valid) return last;
    errors.push(...last.errors.map((e) => `[${key.slice(0, 40)}…] ${e}`));
  }
  return { valid: false, errors, commitment: last?.commitment ?? computePackCommitment(pack) };
}
