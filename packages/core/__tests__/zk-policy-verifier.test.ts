import { describe, it, expect } from 'vitest';
import { PolicyCommitmentVerifier, PolicyCommitmentConstraint } from '../src/confidential/policy-commitment-verifier.js';

describe('Aegis Deterministic Policy Commitment & Attestation Suite', () => {
  const constraint: PolicyCommitmentConstraint = {
    policyId: 'policy_max_wire_transfer_10k',
    minAllowed: 0,
    maxAllowed: 10000,
  };

  it('should generate a verifiable policy commitment proof for compliant parameter', () => {
    const privateTransferAmount = 4500; // Compliant ($4,500 <= $10,000)
    const res = PolicyCommitmentVerifier.generateComplianceProof(constraint, privateTransferAmount);

    expect(res.success).toBe(true);
    expect(res.proof).toBeDefined();
    expect(res.proof?.proofType).toBe('SHA256_PolicyCommitment');
    expect(res.proof?.proofBytesHex).toHaveLength(64);

    const publicPolicyHash = PolicyCommitmentVerifier.computePolicyHash(constraint);
    expect(res.proof?.publicPolicyHash).toBe(publicPolicyHash);

    // Auditor verifies proof without knowing $4,500 private amount
    const isValid = PolicyCommitmentVerifier.verifyProof(res.proof!, publicPolicyHash);
    expect(isValid).toBe(true);
  });

  it('should reject proof generation for non-compliant parameter', () => {
    const nonCompliantAmount = 75000; // Exceeds $10,000 limit
    const res = PolicyCommitmentVerifier.generateComplianceProof(constraint, nonCompliantAmount);

    expect(res.success).toBe(false);
    expect(res.proof).toBeUndefined();
    expect(res.error).toContain('violates policy bounds');
  });

  it('should reject forged or mismatched public policy hash during auditor verification', () => {
    const res = PolicyCommitmentVerifier.generateComplianceProof(constraint, 5000);
    expect(res.success).toBe(true);

    const wrongPolicyHash = 'deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678';
    const isValid = PolicyCommitmentVerifier.verifyProof(res.proof!, wrongPolicyHash);
    expect(isValid).toBe(false);
  });
});
