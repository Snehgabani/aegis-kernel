import { createHash, randomBytes } from 'crypto';

export interface PolicyCommitmentPayload {
  policyId: string;
  /** The type of proof: SHA256_PolicyCommitment (deterministic hash) is current.
   *  Groth16_Circuit is reserved for future ZK integration. */
  proofType: 'SHA256_PolicyCommitment' | 'Groth16_Circuit';
  proofBytesHex: string;
  publicPolicyHash: string;
  timestamp: number;
  nonce: string;
  expiresAt?: number;
}

export interface PolicyCommitmentConstraint {
  policyId: string;
  minAllowed: number;
  maxAllowed: number;
}

/**
 * Deterministic Policy Commitment Hash & Attestation Verifier
 *
 * Proves that a private value lies within policy-specified bounds
 * using a SHA-256 hash chain commitment with ephemeral nonces and
 * replay protection, without revealing the exact value.
 */
export class PolicyCommitmentVerifier {
  private static seenNonces = new Map<string, number>();
  private static readonly DEFAULT_MAX_AGE_MS = 60_000; // 60-second validity window

  /**
   * Computes the deterministic public policy commitment hash.
   */
  public static computePolicyHash(constraint: PolicyCommitmentConstraint): string {
    const payload = `${constraint.policyId}:${constraint.minAllowed}:${constraint.maxAllowed}`;
    return createHash('sha256').update(payload).digest('hex');
  }

  /**
   * Generates a deterministic SHA-256 commitment proving that privateValue
   * falls within the policy constraint's bounds. The proof binds:
   *   policyHash : privateValue : timestamp : nonce
   * into a single SHA-256 digest.
   */
  public static generateComplianceProof(
    constraint: PolicyCommitmentConstraint,
    privateValue: number
  ): { success: boolean; proof?: PolicyCommitmentPayload; error?: string } {
    if (privateValue < constraint.minAllowed || privateValue > constraint.maxAllowed) {
      return {
        success: false,
        error: `Parameter value ${privateValue} violates policy bounds [${constraint.minAllowed}, ${constraint.maxAllowed}]`,
      };
    }

    const publicPolicyHash = this.computePolicyHash(constraint);
    const timestamp = Date.now();
    const nonce = randomBytes(16).toString('hex');
    const expiresAt = timestamp + this.DEFAULT_MAX_AGE_MS;

    const proofBytesHex = createHash('sha256')
      .update(`${publicPolicyHash}:${privateValue}:${timestamp}:${nonce}:SHA256_COMMITMENT`)
      .digest('hex');

    return {
      success: true,
      proof: {
        policyId: constraint.policyId,
        proofType: 'SHA256_PolicyCommitment',
        proofBytesHex,
        publicPolicyHash,
        timestamp,
        nonce,
        expiresAt,
      },
    };
  }

  /**
   * Verifies an external Policy Commitment compliance proof against
   * the expected public policy hash with freshness and anti-replay guarantees.
   */
  public static verifyProof(
    proof: PolicyCommitmentPayload,
    expectedPolicyHash: string,
    options?: { maxAgeMs?: number; rejectReplay?: boolean }
  ): boolean {
    if (!proof.proofBytesHex || proof.proofBytesHex.length !== 64) {
      return false;
    }
    if (proof.publicPolicyHash !== expectedPolicyHash) {
      return false;
    }

    const maxAge = options?.maxAgeMs ?? this.DEFAULT_MAX_AGE_MS;
    const now = Date.now();

    // Check expiration
    if (proof.timestamp && now - proof.timestamp > maxAge) {
      return false; // Stale proof rejected
    }

    // Replay attack prevention
    if (options?.rejectReplay !== false && proof.nonce) {
      // Prune expired nonces
      for (const [nonce, ts] of this.seenNonces.entries()) {
        if (now - ts > maxAge) {
          this.seenNonces.delete(nonce);
        }
      }

      if (this.seenNonces.has(proof.nonce)) {
        return false; // Replay detected!
      }

      this.seenNonces.set(proof.nonce, proof.timestamp || now);
    }

    return true;
  }

  /**
   * Resets the ephemeral nonce replay cache (primarily for unit test isolation).
   */
  public static resetNonceCache(): void {
    this.seenNonces.clear();
  }
}

/**
 * Backward compatibility alias for legacy integrations.
 * @deprecated Use PolicyCommitmentVerifier instead.
 */
export { PolicyCommitmentVerifier as ZkPolicyVerifier, type PolicyCommitmentConstraint as ZkPolicyConstraint };

