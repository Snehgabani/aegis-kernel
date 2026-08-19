import { describe, it, expect } from 'vitest';
import {
  computeEventChainMerkleRoot,
  generateMerkleInclusionProof,
  verifyMerkleInclusionProof,
  type AegisEvent,
} from '../src/index.js';

function createMockEvent(id: string, toolName: string, verdict: 'ALLOWED' | 'BLOCKED'): AegisEvent {
  return {
    id,
    timestamp: new Date().toISOString(),
    toolName,
    toolCallFingerprint: `fp_${id}`,
    mode: 'enforce',
    verdict,
    rulesEvaluated: 5,
    rulesFired: [],
    latencyMs: 0.15,
    proofHash: `proof_${id}`,
    policyCommitmentHash: `policy_${id}`,
  };
}

describe('Merkle Inclusion Proofs (SPV / Auditor Sampling)', () => {
  it('should generate and verify Merkle inclusion proof for a single-event chain', () => {
    const events: AegisEvent[] = [createMockEvent('evt_1', 'db_query', 'ALLOWED')];
    const root = computeEventChainMerkleRoot(events);

    const proof = generateMerkleInclusionProof(0, events);
    expect(proof.eventId).toBe('evt_1');
    expect(proof.leafIndex).toBe(0);
    expect(proof.merkleRoot).toBe(root);

    const isValid = verifyMerkleInclusionProof(proof, root);
    expect(isValid).toBe(true);
  });

  it('should generate and verify Merkle inclusion proofs across an 8-event chain', () => {
    const events: AegisEvent[] = Array.from({ length: 8 }, (_, i) =>
      createMockEvent(`evt_${i}`, `tool_${i}`, i % 2 === 0 ? 'ALLOWED' : 'BLOCKED')
    );
    const root = computeEventChainMerkleRoot(events);

    for (let i = 0; i < events.length; i++) {
      const proof = generateMerkleInclusionProof(i, events);
      expect(proof.eventId).toBe(`evt_${i}`);
      expect(proof.leafIndex).toBe(i);
      expect(proof.merkleRoot).toBe(root);
      // Proof path length should be logarithmic
      expect(proof.auditPath.length).toBeGreaterThan(0);

      const isValid = verifyMerkleInclusionProof(proof, root);
      expect(isValid).toBe(true);
    }
  });

  it('should generate and verify Merkle inclusion proofs for odd event counts (e.g. 15 events)', () => {
    const events: AegisEvent[] = Array.from({ length: 15 }, (_, i) =>
      createMockEvent(`evt_${i}`, `tool_${i}`, 'ALLOWED')
    );
    const root = computeEventChainMerkleRoot(events);

    // Verify sample transactions (auditor sampling)
    const samples = [0, 7, 14];
    for (const sampleIdx of samples) {
      const proof = generateMerkleInclusionProof(sampleIdx, events);
      const isValid = verifyMerkleInclusionProof(proof, root);
      expect(isValid).toBe(true);
    }
  });

  it('should reject tampered or forged Merkle inclusion proofs', () => {
    const events: AegisEvent[] = Array.from({ length: 4 }, (_, i) =>
      createMockEvent(`evt_${i}`, `tool_${i}`, 'ALLOWED')
    );
    const root = computeEventChainMerkleRoot(events);

    const validProof = generateMerkleInclusionProof(1, events);

    // 1. Tamper with leaf hash
    const tamperedLeafProof = { ...validProof, leafHash: 'a'.repeat(64) };
    expect(verifyMerkleInclusionProof(tamperedLeafProof, root)).toBe(false);

    // 2. Tamper with audit path sibling hash
    const tamperedPathProof = {
      ...validProof,
      auditPath: validProof.auditPath.map((step) => ({ ...step, hash: 'b'.repeat(64) })),
    };
    expect(verifyMerkleInclusionProof(tamperedPathProof, root)).toBe(false);

    // 3. Verify against wrong expected root
    expect(verifyMerkleInclusionProof(validProof, 'c'.repeat(64))).toBe(false);
  });
});
