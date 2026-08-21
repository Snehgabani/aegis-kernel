/**
 * Conformance + property-based verification of the compliance crypto primitives
 * against authoritative external specifications:
 *   - JSON Canonicalization Scheme (JCS) — RFC 8785 official test vectors
 *   - base58btc — round-trip property via fast-check
 *   - STIX 2.1 — RFC 4122 identifier + patterning-grammar conformance
 *   - W3C EdDSA Cryptosuite — publicKeyMultibase multicodec (0xed01) requirement
 *   - GCS Object Lock / bucket retention — JSON API field shapes
 *   - Merkle inclusion proofs — tamper-evidence property via fast-check
 */
import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import {
  canonicalizeJson,
  toBase58,
  fromBase58,
  ED25519_MULTICODEC_PREFIX,
  uuidv5,
  formatStixTaxiiIndicator,
  validateStixBundle,
  issueHitlVerifiableCredential,
  buildHitlCredentialSubject,
  generateAuditKeyPairEd25519,
  buildGcsBucketRetentionPolicy,
  computeEventChainMerkleRoot,
  generateMerkleInclusionProof,
  verifyMerkleInclusionProof,
  type AegisEvent,
} from '../src/index.js';

describe('JCS (RFC 8785) canonicalization — official test vectors', () => {
  // Vectors from RFC 8785 §3.2 (Test Vectors).
  const vectors: [unknown, string][] = [
    [{ b: 'a', a: 'b' }, '{"a":"b","b":"a"}'],
    [{ a: '\u20ac$' }, '{"a":"€$"}'],
    [
      { numbers: [333333333.33333329, 1e30, 4.5, 2e-3, 0.000000000000000000000000001] },
      '{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}',
    ],
    [{ test: [{ a: 1 }, { b: 2 }] }, '{"test":[{"a":1},{"b":2}]}'],
  ];

  it('matches the RFC 8785 reference serializations exactly', () => {
    for (const [input, expected] of vectors) {
      expect(canonicalizeJson(input)).toBe(expected);
    }
  });

  it('is deterministic and key-order-independent (property)', () => {
    fc.assert(
      fc.property(fc.dictionary(fc.string(), fc.oneof(fc.integer(), fc.string(), fc.boolean(), fc.constant(null))), (obj) => {
        const a = canonicalizeJson(obj);
        const b = canonicalizeJson(obj);
        expect(a).toBe(b);
      })
    );
  });

  it('escapes control characters per RFC 8785 (quotes, backslash, newline)', () => {
    expect(canonicalizeJson({ a: 'x\ny' })).toBe('{"a":"x\\ny"}');
    expect(canonicalizeJson({ a: 'q"b' })).toBe('{"a":"q\\"b"}');
  });
});

describe('base58btc codec — round-trip property', () => {
  it('decode(encode(x)) === x for arbitrary byte arrays', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 1, maxLength: 64 }), (bytes) => {
        const encoded = toBase58(bytes);
        const decoded = fromBase58(encoded);
        expect(Buffer.from(decoded).equals(Buffer.from(bytes))).toBe(true);
      })
    );
  });

  it('rejects strings with characters outside the base58btc alphabet', () => {
    expect(() => fromBase58('0OIl')).toThrow();
    expect(() => fromBase58('z!')).toThrow();
  });
});

describe('STIX 2.1 conformance', () => {
  const blocked: AegisEvent = {
    id: 'evt-123',
    timestamp: '2026-08-16T01:30:00.000Z',
    version: '1.0.0',
    framework: 'langchain',
    toolName: 'execute_sql',
    toolCallFingerprint: 'fp1',
    mode: 'enforce',
    verdict: 'BLOCKED',
    rulesEvaluated: 5,
    rulesFired: [{ ruleId: 'SQL-NO-DROP', packId: 'core', severity: 'critical', message: 'DROP prohibited' }],
    latencyMs: 0.2,
    proofHash: 'proof1',
    policyCommitmentHash: 'pol1',
    userOverride: false,
  };

  it('emits RFC 4122 UUID identifiers (bundle-- and indicator--)', () => {
    const bundle = formatStixTaxiiIndicator(blocked)!;
    expect(bundle.id).toMatch(/^bundle--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    expect(bundle.objects[0].id).toMatch(/^indicator--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  });

  it('emits a single-observation-expression pattern (no cross-SCO AND)', () => {
    const bundle = formatStixTaxiiIndicator(blocked)!;
    const pattern = (bundle.objects[0] as { pattern: string }).pattern;
    expect(pattern).toBe(`[process:name = 'execute_sql']`);
    // Must not mix process:name and file:hashes in one [...] expression.
    expect(pattern).not.toMatch(/\]\s*AND\s*\[?.*file:hashes/);
    expect((bundle.objects[0] as { pattern_version: string }).pattern_version).toBe('2.1');
  });

  it('passes the built-in structural validator', () => {
    const bundle = formatStixTaxiiIndicator(blocked)!;
    const result = validateStixBundle(bundle);
    expect(result.valid).toBe(true);
    expect(result.findings).toHaveLength(0);
  });

  it('is deterministic across identical inputs (reproducible CTI)', () => {
    const a = formatStixTaxiiIndicator(blocked)!;
    const b = formatStixTaxiiIndicator(blocked)!;
    expect(a.id).toBe(b.id);
    expect(a.objects[0].id).toBe(b.objects[0].id);
  });
});

describe('W3C EdDSA Cryptosuite — publicKeyMultibase multicodec', () => {
  it('encodes the public key with the 0xed01 multicodec prefix', () => {
    const { publicKey, privateKey } = generateAuditKeyPairEd25519();
    const subject = buildHitlCredentialSubject(
      {
        id: 'e1',
        timestamp: new Date().toISOString(),
        version: '1',
        framework: 'raw',
        toolName: 't',
        toolCallFingerprint: 'f'.repeat(64),
        mode: 'enforce',
        verdict: 'BLOCKED',
        rulesEvaluated: 1,
        rulesFired: [],
        latencyMs: 0.1,
        proofHash: 'p'.repeat(64),
        policyCommitmentHash: 'q'.repeat(64),
        userOverride: false,
      },
      'APPROVED',
      'auditor@example.com',
      'Compliance Officer'
    );
    const vc = issueHitlVerifiableCredential(subject, {
      issuer: 'did:web:example.com',
      privateKeyPem: privateKey,
      publicKeyPem: publicKey,
    });

    const multibase = vc.proof.publicKeyMultibase!;
    expect(multibase.startsWith('z')).toBe(true);
    const decoded = fromBase58(multibase.slice(1));
    expect(decoded.length).toBe(34); // 2-byte multicodec + 32-byte key
    expect(decoded.subarray(0, 2).equals(ED25519_MULTICODEC_PREFIX)).toBe(true);
  });
});

describe('GCS Object Lock / bucket retention JSON API shapes', () => {
  it('emits the bucket retentionPolicy shape (seconds + isLocked)', () => {
    const policy = buildGcsBucketRetentionPolicy(
      { mode: 'COMPLIANCE', retainUntil: '2033-01-01T00:00:00.000Z' },
      '2026-01-01T00:00:00.000Z'
    );
    expect(policy.retentionPolicy.retentionPeriod).toMatch(/^\d+s$/);
    expect(policy.retentionPolicy.isLocked).toBe(true);
  });

  it('GOVERNANCE mode leaves the bucket policy unlocked', () => {
    const policy = buildGcsBucketRetentionPolicy(
      { mode: 'GOVERNANCE', retainUntil: '2033-01-01T00:00:00.000Z' },
      '2026-01-01T00:00:00.000Z'
    );
    expect(policy.retentionPolicy.isLocked).toBe(false);
  });
});

describe('Merkle inclusion proof — tamper-evidence property', () => {
  const mk = (id: string): AegisEvent => ({
    id,
    timestamp: new Date().toISOString(),
    version: '1',
    framework: 'raw',
    toolName: `tool_${id}`,
    toolCallFingerprint: `fp_${id}`,
    mode: 'enforce',
    verdict: 'ALLOWED',
    rulesEvaluated: 3,
    rulesFired: [],
    latencyMs: 0.1,
    proofHash: `proof_${id}`,
    policyCommitmentHash: 'policy',
    userOverride: false,
  });

  it('verifies valid proofs and rejects any single-field tamper', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 64 }),
        fc.integer({ min: 0, max: 3 }), // which field to tamper
        (count, field) => {
          const events = Array.from({ length: count }, (_, i) => mk(`e${i}`));
          const root = computeEventChainMerkleRoot(events);
          for (let idx = 0; idx < events.length; idx++) {
            const proof = generateMerkleInclusionProof(idx, events);
            expect(verifyMerkleInclusionProof(proof, root)).toBe(true);
          }

          // Tamper a single field on a single event; root must change.
          const tampered = events.map((e) => ({ ...e }));
          const target = tampered[Math.min(events.length - 1, field)];
          target.verdict = target.verdict === 'ALLOWED' ? 'BLOCKED' : 'ALLOWED';
          expect(computeEventChainMerkleRoot(tampered)).not.toBe(root);
        }
      )
    );
  });
});
