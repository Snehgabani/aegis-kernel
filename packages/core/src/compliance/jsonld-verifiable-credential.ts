/**
 * @file packages/core/src/compliance/jsonld-verifiable-credential.ts
 * @description W3C Verifiable Credentials (JSON-LD) engine for Human-in-the-Loop
 * (HITL) approval signatures.
 *
 * Emits credentials conformant to the W3C Verifiable Credentials Data Model 1.1
 * (`@context` `https://www.w3.org/2018/credentials/v1`) carrying an
 * `Ed25519Signature2020` Data Integrity proof. This gives the EU AI Act
 * Article 14 (Human Oversight) and SOC 2 Type II CC6.3 evidence trail a
 * cryptographically verifiable, machine-readable record that a *named human*
 * (not the agent) authorized a high-risk tool invocation.
 *
 * ── Canonicalization ─────────────────────────────────────────────────────────
 * Full URDNA2015 (RDF dataset canonicalization) requires a JSON-LD processor.
 * To keep the kernel dependency-free and deterministic, the signing input is
 * the JSON Canonicalization Scheme (JCS, RFC 8785) serialization of the
 * credential **minus** its `proof` object: recursive key sorting, UTF-8,
 * no insignificant whitespace. This is independently recomputable by an
 * auditor with any JCS library, so the proof remains third-party verifiable.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { createPublicKey, randomUUID, sign, verify } from 'node:crypto';
import type { AegisEvent } from '../types.js';

/* ────────────────────────────────────────────────────────────────────────────
 * Base58 (Bitcoin alphabet) — multibase `z` encoding for Ed25519 proof values.
 * ──────────────────────────────────────────────────────────────────────────── */

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * Multicodec prefix for an Ed25519 public key (per the EdDSA Cryptosuite:
 * `publicKeyMultibase` MUST be the multicodec encoding `0xed01` + 32-byte key,
 * formatted as multibase base58btc `z...`).
 */
export const ED25519_MULTICODEC_PREFIX = Buffer.from([0xed, 0x01]);

/**
 * Base58btc encode (exported so auditors can independently decode proof values).
 *
 * Implemented to match Bitcoin Core's EncodeBase58 (base58_tests.cpp vectors):
 * leading zero bytes → '1' each; empty input → empty string.
 */
export function toBase58(bytes: Uint8Array): string {
  let zeroes = 0;
  let begin = 0;
  while (begin < bytes.length && bytes[begin] === 0) {
    zeroes++;
    begin++;
  }

  const size = Math.max(1, Math.floor(((bytes.length - begin) * 138) / 100) + 1);
  const b58 = new Uint8Array(size);
  let length = 0;

  while (begin < bytes.length) {
    let carry = bytes[begin];
    let i = 0;
    for (let it = size - 1; (carry !== 0 || i < length) && it >= 0; it--, i++) {
      carry += 256 * b58[it];
      b58[it] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    length = i;
    begin++;
  }

  let it = size - length;
  while (it < size && b58[it] === 0) it++;

  let encoded = '1'.repeat(zeroes);
  while (it < size) encoded += BASE58_ALPHABET[b58[it++]];
  return encoded;
}

/**
 * Base58btc decode (exported so auditors can independently verify proof values).
 */
export function fromBase58(input: string): Buffer {
  if (input === '') {
    return Buffer.alloc(0);
  }
  if (!/^[1-9A-HJ-NP-Za-km-z]+$/.test(input)) {
    throw new Error('Invalid base58btc string');
  }

  let zeroes = 0;
  let begin = 0;
  while (begin < input.length && input[begin] === '1') {
    zeroes++;
    begin++;
  }

  const rest = input.slice(begin);
  const size = Math.max(1, Math.floor((rest.length * 733) / 1000) + 1);
  const b256 = new Uint8Array(size);
  let length = 0;

  for (const char of rest) {
    const value = BASE58_ALPHABET.indexOf(char);
    if (value < 0) throw new Error('Invalid base58btc character');
    let carry = value;
    let i = 0;
    for (let it = size - 1; (carry !== 0 || i < length) && it >= 0; it--, i++) {
      carry += 58 * b256[it];
      b256[it] = carry & 0xff;
      carry = Math.floor(carry / 256);
    }
    length = i;
  }

  let it = size - length;
  while (it < size && b256[it] === 0) it++;

  const out = Buffer.alloc(zeroes + (size - it));
  let o = zeroes;
  while (it < size) out[o++] = b256[it++];
  return out;
}

/* ────────────────────────────────────────────────────────────────────────────
 * JCS (RFC 8785) canonical JSON serialization.
 * ──────────────────────────────────────────────────────────────────────────── */

/**
 * Produces a deterministic, byte-for-byte canonical JSON string (RFC 8785
 * "JSON Canonicalization Scheme") for an arbitrary JSON value. Object keys are
 * sorted by UTF-16 code unit; strings use standard JSON escaping; numbers use
 * ECMAScript shortest-round-trip serialization (via JSON.stringify).
 */
export function canonicalizeJson(value: unknown): string {
  return serializeJcs(value);
}

function serializeJcs(value: unknown): string {
  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';

  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('JCS cannot serialize non-finite numbers');
    return JSON.stringify(value);
  }

  if (typeof value === 'string') {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    const elements = value.map((v) => serializeJcs(v));
    return `[${elements.join(',')}]`;
  }

  if (typeof value === 'object') {
    const keys = Object.keys(value as Record<string, unknown>).sort();
    const elements = keys.map((key) => {
      const val = (value as Record<string, unknown>)[key];
      // Drop undefined properties (JSON semantics)
      if (val === undefined) return null;
      return `${JSON.stringify(key)}:${serializeJcs(val)}`;
    });
    return `{${elements.filter((e): e is string => e !== null).join(',')}}`;
  }

  // undefined, functions, symbols — treat as absent
  throw new Error(`JCS cannot serialize ${typeof value}`);
}

/* ────────────────────────────────────────────────────────────────────────────
 * Public types.
 * ──────────────────────────────────────────────────────────────────────────── */

export interface HitlApprovalCredentialSubject {
  /** Identifier for the human-approved action record. */
  id: string;
  ticketId: string;
  agentId: string;
  toolName: string;
  /** SHA-256 of the canonicalized tool-call parameters under approval. */
  paramsHash: string;
  decision: 'APPROVED' | 'REJECTED';
  /** Named human approver (e.g. email, SSO subject, or LDAP DN). */
  approver: string;
  approverRole: string;
  reason?: string;
  evaluatedAt: string;
  /** Merkle root commitment of the audit ledger at approval time. */
  merkleRootHash: string;
  policyCommitmentHash: string;
  /** Regulatory basis for the HITL gate. */
  regulatoryBasis: string[];
}

export interface Ed25519Signature2020Proof {
  type: 'Ed25519Signature2020';
  created: string;
  verificationMethod: string;
  proofPurpose: 'assertionMethod';
  proofValue: string; // multibase `z` (base58btc) Ed25519 signature
  publicKeyMultibase?: string; // multibase `z` of the raw 32-byte public key
  cryptosuiteNote?: string;
}

export interface HitlVerifiableCredential {
  '@context': (string | Record<string, string>)[];
  id: string;
  type: ['VerifiableCredential', 'AegisHitlApprovalCredential'];
  issuer: { id: string; name?: string };
  issuanceDate: string;
  expirationDate: string;
  credentialSubject: HitlApprovalCredentialSubject;
  proof: Ed25519Signature2020Proof;
}

export interface IssueHitlCredentialOptions {
  /** Signing authority DID/URI recorded as the issuer `id`. */
  issuer: string;
  issuerName?: string;
  /** PEM-encoded Ed25519 (PKCS8) private key used to produce the proof. */
  privateKeyPem: string;
  /** Verification method URI recorded in the proof. */
  verificationMethod?: string;
  /** PEM-encoded Ed25519 (SPKI) public key, used to embed `publicKeyMultibase`. */
  publicKeyPem?: string;
  /**
   * Credential lifetime in seconds. Default 10 years (~315,576,000s): the
   * credential is *audit evidence* attesting that an approval happened, so it
   * must remain verifiable across the regulatory retention horizon. (The HITL
   * authorization *ticket* itself — in hitl/escalation.ts — carries its own
   * short TTL; that is a different, time-boxed object.)
   */
  ttlSeconds?: number;
}

/** Default credential lifetime: 10 years of evidence retention. */
export const DEFAULT_HITL_CREDENTIAL_TTL_SECONDS = 315_576_000;

export interface VcVerificationResult {
  valid: boolean;
  reason: string;
  signatureValid: boolean;
  contextValid: boolean;
  typeValid: boolean;
  subjectValid: boolean;
  notExpired: boolean;
}

/* ────────────────────────────────────────────────────────────────────────────
 * Key helpers.
 * ──────────────────────────────────────────────────────────────────────────── */

/**
 * Extracts the raw 32-byte Ed25519 public key from a PEM SPKI block.
 * The Ed25519 public key is the trailing 32 bytes of the SubjectPublicKeyInfo
 * DER structure.
 */
export function ed25519PublicKeyRawFromPem(publicKeyPem: string): Buffer {
  const key = createPublicKey(publicKeyPem);
  const der = key.export({ format: 'der', type: 'spki' });
  return der.subarray(der.length - 32);
}

function signCredentialBytes(data: Buffer, privateKeyPem: string): Buffer {
  return sign(null, data, privateKeyPem);
}

function verifyCredentialBytes(data: Buffer, signature: Buffer, publicKeyPem: string): boolean {
  try {
    return verify(null, data, publicKeyPem, signature);
  } catch {
    return false;
  }
}

/* ────────────────────────────────────────────────────────────────────────────
 * Issue & verify.
 * ──────────────────────────────────────────────────────────────────────────── */

/**
 * Issues a JSON-LD Verifiable Credential attesting a HITL approval decision.
 */
export function issueHitlVerifiableCredential(
  subject: HitlApprovalCredentialSubject,
  options: IssueHitlCredentialOptions
): HitlVerifiableCredential {
  const nowIso = new Date().toISOString();
  const ttlSeconds = options.ttlSeconds ?? DEFAULT_HITL_CREDENTIAL_TTL_SECONDS;
  const expirationDate = new Date(Date.now() + ttlSeconds * 1000).toISOString();

  const unsigned: Omit<HitlVerifiableCredential, 'proof'> = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1',
      {
        aegis: 'https://aegis-kernel.dev/vocab#',
        HitlApprovalCredential: 'aegis:HitlApprovalCredential',
        ticketId: 'aegis:ticketId',
        agentId: 'aegis:agentId',
        toolName: 'aegis:toolName',
        paramsHash: 'aegis:paramsHash',
        approver: 'aegis:approver',
        approverRole: 'aegis:approverRole',
        decision: 'aegis:decision',
        evaluatedAt: 'aegis:evaluatedAt',
        merkleRootHash: 'aegis:merkleRootHash',
        policyCommitmentHash: 'aegis:policyCommitmentHash',
        regulatoryBasis: 'aegis:regulatoryBasis',
      },
    ],
    id: `urn:uuid:${randomUUID()}`,
    type: ['VerifiableCredential', 'AegisHitlApprovalCredential'],
    issuer: { id: options.issuer, name: options.issuerName },
    issuanceDate: nowIso,
    expirationDate,
    credentialSubject: subject,
  };

  const canonical = canonicalizeJson(unsigned);
  const signatureBytes = signCredentialBytes(Buffer.from(canonical, 'utf8'), options.privateKeyPem);

  const proof: Ed25519Signature2020Proof = {
    type: 'Ed25519Signature2020',
    created: nowIso,
    verificationMethod: options.verificationMethod ?? `${options.issuer}#aegis-hitl-signing-key`,
    proofPurpose: 'assertionMethod',
    proofValue: `z${toBase58(signatureBytes)}`,
    cryptosuiteNote: 'Signing input: JCS (RFC 8785) canonicalization of the credential sans `proof`.',
  };

  if (options.publicKeyPem) {
    // multicodec 0xed01 prefix + 32-byte key, multibase `z` (base58btc) — per
    // the EdDSA Cryptosuite's publicKeyMultibase requirement.
    const raw = ed25519PublicKeyRawFromPem(options.publicKeyPem);
    proof.publicKeyMultibase = `z${toBase58(Buffer.concat([ED25519_MULTICODEC_PREFIX, raw]))}`;
  }

  return { ...unsigned, proof };
}

/**
 * Verifies a HITL Verifiable Credential's structure, expiry, and Ed25519 proof
 * against the issuer's public key. Returns a detailed, deterministic report.
 */
export function verifyHitlVerifiableCredential(
  credential: HitlVerifiableCredential,
  publicKeyPem: string
): VcVerificationResult {
  const contextValid =
    Array.isArray(credential['@context']) &&
    credential['@context'].includes('https://www.w3.org/2018/credentials/v1');

  const typeValid =
    Array.isArray(credential.type) &&
    credential.type.includes('VerifiableCredential') &&
    credential.type.includes('AegisHitlApprovalCredential');

  const subject = credential.credentialSubject;
  const subjectValid =
    typeof subject?.ticketId === 'string' &&
    typeof subject?.toolName === 'string' &&
    (subject?.decision === 'APPROVED' || subject?.decision === 'REJECTED') &&
    typeof subject?.approver === 'string' &&
    /^[a-f0-9]{64}$/i.test(subject?.paramsHash ?? '') &&
    /^[a-f0-9]{64}$/i.test(subject?.merkleRootHash ?? '');

  const notExpired = new Date(credential.expirationDate).getTime() > Date.now();

  const { proof, ...unsigned } = credential;
  let signatureValid = false;
  if (proof && proof.type === 'Ed25519Signature2020' && typeof proof.proofValue === 'string') {
    const canonical = canonicalizeJson(unsigned);
    const multibase = proof.proofValue;
    if (multibase.startsWith('z')) {
      const signatureBytes = fromBase58(multibase.slice(1));
      signatureValid = verifyCredentialBytes(
        Buffer.from(canonical, 'utf8'),
        signatureBytes,
        publicKeyPem
      );
    }
  }

  const valid = contextValid && typeValid && subjectValid && notExpired && signatureValid;

  let reason: string;
  if (!contextValid) reason = 'Missing or invalid @context (W3C credentials/v1 required).';
  else if (!typeValid) reason = 'Credential type must include VerifiableCredential and AegisHitlApprovalCredential.';
  else if (!subjectValid) reason = 'Credential subject is malformed or missing required HITL fields.';
  else if (!notExpired) reason = 'Credential has expired.';
  else if (!signatureValid) reason = 'Ed25519 proof signature verification failed (tampered or wrong key).';
  else reason = 'Credential is valid: structure, expiry, and Ed25519 proof verified.';

  return {
    valid,
    reason,
    signatureValid,
    contextValid,
    typeValid,
    subjectValid,
    notExpired,
  };
}

/**
 * Convenience: builds a HITL credential subject directly from an audited event
 * and a resolved human decision, binding the approval to the Merkle ledger.
 */
export function buildHitlCredentialSubject(
  event: AegisEvent,
  decision: 'APPROVED' | 'REJECTED',
  approver: string,
  approverRole: string,
  options: {
    ticketId?: string;
    reason?: string;
    merkleRootHash?: string;
    regulatoryBasis?: string[];
    /** Identity of the agent that requested the high-risk action. */
    agentId?: string;
  } = {}
): HitlApprovalCredentialSubject {
  return {
    id: `urn:aegis:approval:${event.id}`,
    ticketId: options.ticketId ?? `hitl-${event.id}`,
    agentId: options.agentId ?? `urn:aegis:agent:call:${event.toolCallFingerprint}`,
    toolName: event.toolName,
    paramsHash: event.toolCallFingerprint,
    decision,
    approver,
    approverRole,
    reason: options.reason,
    evaluatedAt: event.timestamp,
    merkleRootHash: options.merkleRootHash ?? event.proofHash,
    policyCommitmentHash: event.policyCommitmentHash,
    regulatoryBasis: options.regulatoryBasis ?? [
      'EU AI Act Article 14 (Human Oversight)',
      'SOC 2 Type II CC6.3 (Segregation of Duties)',
    ],
  };
}
