import { describe, it, expect, beforeEach } from 'vitest';
import { SqlChecker } from '../src/checkers/sql-checker.js';
import { PolicyCommitmentVerifier, PolicyCommitmentConstraint } from '../src/confidential/policy-commitment-verifier.js';
import { PiiTokenVault } from '../src/pii/token-vault.js';
import { ConversationTracker } from '../src/state/conversation-tracker.js';

describe('Aegis Catastrophic Pre-Mortem Immunity & Antifragility Suite', () => {
  beforeEach(() => {
    PolicyCommitmentVerifier.resetNonceCache();
  });

  describe('Invariant 1: AST Recursion & Parentheses Exhaustion (Anti-ReDoS/DOS)', () => {
    const checker = new SqlChecker();

    it('should reject deeply nested malicious expressions (>32 parentheses) without crashing event loop', () => {
      // 40 layers of nested parentheses
      const deepNestedSql = 'SELECT ' + '('.repeat(40) + '1' + ')'.repeat(40) + ' FROM users;';
      
      const violations = checker.evaluate(
        'RULE-SQL-AST',
        'pack-sql',
        { block_statements: ['DROP', 'TRUNCATE'] },
        { toolName: 'database_query', params: { query: deepNestedSql } },
        'critical'
      );

      expect(violations.length).toBeGreaterThan(0);
      expect(violations[0].message).toContain('exceeds safety limit (32)');
    });

    it('should allow normal queries with reasonable nested subqueries (<=32 depth)', () => {
      const normalSql = 'SELECT * FROM users WHERE id IN (SELECT user_id FROM orders WHERE amount > 100);';
      
      const violations = checker.evaluate(
        'RULE-SQL-AST',
        'pack-sql',
        { block_statements: ['DROP', 'TRUNCATE'] },
        { toolName: 'database_query', params: { query: normalSql } },
        'critical'
      );

      expect(violations.length).toBe(0);
    });
  });

  describe('Invariant 2: Zero-Knowledge Policy Commitment Replay Defense', () => {
    const constraint: PolicyCommitmentConstraint = {
      policyId: 'policy_max_transfer_5k',
      minAllowed: 0,
      maxAllowed: 5000,
    };

    it('should verify fresh proof on first presentation', () => {
      const proofRes = PolicyCommitmentVerifier.generateComplianceProof(constraint, 2500);
      expect(proofRes.success).toBe(true);
      expect(proofRes.proof?.nonce).toBeDefined();

      const publicPolicyHash = PolicyCommitmentVerifier.computePolicyHash(constraint);
      const isValid = PolicyCommitmentVerifier.verifyProof(proofRes.proof!, publicPolicyHash);
      expect(isValid).toBe(true);
    });

    it('should reject replayed proofs with the same nonce', () => {
      const proofRes = PolicyCommitmentVerifier.generateComplianceProof(constraint, 2500);
      const publicPolicyHash = PolicyCommitmentVerifier.computePolicyHash(constraint);

      // First verification: success
      const firstValid = PolicyCommitmentVerifier.verifyProof(proofRes.proof!, publicPolicyHash);
      expect(firstValid).toBe(true);

      // Second verification (Replay Attack): rejected!
      const replayValid = PolicyCommitmentVerifier.verifyProof(proofRes.proof!, publicPolicyHash);
      expect(replayValid).toBe(false);
    });

    it('should reject stale proofs exceeding maximum age window', () => {
      const proofRes = PolicyCommitmentVerifier.generateComplianceProof(constraint, 2500);
      const publicPolicyHash = PolicyCommitmentVerifier.computePolicyHash(constraint);

      // Manually backdate timestamp by 2 minutes
      proofRes.proof!.timestamp = Date.now() - 120_000;

      const isValid = PolicyCommitmentVerifier.verifyProof(proofRes.proof!, publicPolicyHash, { maxAgeMs: 60_000 });
      expect(isValid).toBe(false);
    });
  });

  describe('Invariant 3: Unicode NFKD & Zero-Width Sanitization in PII Token Vault', () => {
    it('should strip zero-width characters and normalize homoglyphs before tokenization', () => {
      const vault = new PiiTokenVault();
      
      // Inject zero-width spaces inside an SSN: 123-\u200B45-\u200B6789
      const zeroWidthSsn = 'User SSN is 123-\u200B45-\u200B6789.';
      const res = vault.tokenize(zeroWidthSsn);

      expect(res.tokensCreated).toBe(1);
      expect(res.sanitized).toContain('<US_SSN_');
      expect(res.sanitized).not.toContain('123-45-6789');

      // Detokenization restores clean SSN
      const restored = vault.detokenize(res.sanitized);
      expect(restored.tokensRestored).toBe(1);
      expect(restored.restored).toBe('User SSN is 123-45-6789.');
    });
  });

  describe('Invariant 4: Multi-Turn Crescendo Monotonic Risk Escalation Detection', () => {
    it('should quarantine conversation when monotonic risk escalation occurs across 4 turns', () => {
      const tracker = new ConversationTracker({
        driftThreshold: 0.9, // Higher threshold so cumulative doesn't trigger immediately
      });

      // Turn 1: 0.1 risk
      const v1 = tracker.addTurn({
        turnIndex: 1,
        toolName: 'read_public_docs',
        params: {},
        riskContribution: 0.1,
        timestamp: Date.now(),
      });
      expect(v1.action).toBe('CONTINUE');

      // Turn 2: 0.2 risk
      const v2 = tracker.addTurn({
        turnIndex: 2,
        toolName: 'read_user_profile',
        params: {},
        riskContribution: 0.2,
        timestamp: Date.now(),
      });
      expect(v2.action).toBe('CONTINUE');

      // Turn 3: 0.3 risk
      const v3 = tracker.addTurn({
        turnIndex: 3,
        toolName: 'query_financial_summary',
        params: {},
        riskContribution: 0.3,
        timestamp: Date.now(),
      });
      expect(v3.action).toBe('WARN');

      // Turn 4: 0.4 risk -> strictly monotonic increase: 0.1 -> 0.2 -> 0.3 -> 0.4
      const v4 = tracker.addTurn({
        turnIndex: 4,
        toolName: 'export_all_transactions',
        params: {},
        riskContribution: 0.4,
        timestamp: Date.now(),
      });
      expect(v4.action).toBe('QUARANTINE');
      expect(v4.reason).toContain('Monotonic risk escalation detected');
    });
  });
});
