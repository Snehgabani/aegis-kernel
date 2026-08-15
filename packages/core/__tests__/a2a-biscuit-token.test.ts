import { describe, it, expect } from 'vitest';
import { AegisBiscuitToken } from '../src/a2a/biscuit-token.js';
import { AgentCardValidator, AgentCard } from '../src/a2a/agent-card-validator.js';
import { DelegationRouter } from '../src/a2a/delegation-router.js';
import { sign } from 'crypto';

describe('Aegis A2A & Biscuit Capability Token Suite', () => {
  describe('AegisBiscuitToken (Ed25519 & Monotonic Attenuation)', () => {
    const { publicKey, privateKey } = AegisBiscuitToken.generateKeyPair();

    it('should create and verify a valid root capability token', () => {
      const rootToken = AegisBiscuitToken.createRootToken(
        'supervisor_agent',
        ['database:query', 'database:update'],
        [{ field: 'spend_limit', operator: '<=', value: 5000 }],
        privateKey,
        publicKey
      );

      expect(typeof rootToken).toBe('string');

      // Valid check within limits
      const validVerify = AegisBiscuitToken.verify(rootToken, 'database:query', { spend_limit: 2500 });
      expect(validVerify.valid).toBe(true);
      expect(validVerify.authorized).toBe(true);
      expect(validVerify.attenuationDepth).toBe(1);

      // Violating check (exceeds spend limit)
      const invalidVerify = AegisBiscuitToken.verify(rootToken, 'database:query', { spend_limit: 7500 });
      expect(invalidVerify.valid).toBe(true);
      expect(invalidVerify.authorized).toBe(false);
      expect(invalidVerify.reason).toContain('Caveat violated');
    });

    it('should enforce monotonic capability attenuation (child cannot expand rights)', () => {
      const rootToken = AegisBiscuitToken.createRootToken(
        'supervisor_agent',
        ['database:query'],
        [],
        privateKey,
        publicKey
      );

      // Attempting to add ungranted right 'database:drop' should throw error
      expect(() => {
        AegisBiscuitToken.attenuate(
          rootToken,
          [],
          privateKey,
          'subagent_1',
          ['database:query', 'database:drop']
        );
      }).toThrow(/Monotonic Violation/);

      // Successfully attenuate with stricter constraint
      const { privateKey: subagentKey } = AegisBiscuitToken.generateKeyPair();
      const attenuatedToken = AegisBiscuitToken.attenuate(
        rootToken,
        [{ field: 'table', operator: '==', value: 'analytics' }],
        subagentKey,
        'subagent_1'
      );

      const resValid = AegisBiscuitToken.verify(attenuatedToken, 'database:query', { table: 'analytics' });
      expect(resValid.authorized).toBe(true);
      expect(resValid.attenuationDepth).toBe(2);

      const resWrongTable = AegisBiscuitToken.verify(attenuatedToken, 'database:query', { table: 'users_passwords' });
      expect(resWrongTable.authorized).toBe(false);
      expect(resWrongTable.reason).toContain('Caveat violated');
    });
  });

  describe('AgentCardValidator (Google A2A Standard)', () => {
    const { publicKey, privateKey } = AegisBiscuitToken.generateKeyPair();
    const validator = new AgentCardValidator(['enterprise.internal']);

    it('should validate signed Agent Card from trusted organization', () => {
      const cardPayload = {
        id: 'agent_financial_analyst_01',
        name: 'Financial Analyst Agent',
        version: '1.2.0',
        description: 'Analyzes Q3 financial reports',
        organization: 'enterprise.internal',
        securityLevel: 'HIGH' as const,
        skills: [{ id: 'analyze_balance_sheet', name: 'Analyze Balance Sheet', description: 'Computes EBITDA' }],
      };

      const payloadStr = JSON.stringify(cardPayload);
      const signature = sign(null, Buffer.from(payloadStr), privateKey).toString('hex');

      const card: AgentCard = {
        ...cardPayload,
        publicKey,
        signatures: {
          issuer: 'enterprise.internal',
          signature,
        },
      };

      const result = validator.validateCard(card);
      expect(result.valid).toBe(true);
      expect(result.trusted).toBe(true);
      expect(result.securityLevel).toBe('HIGH');
      expect(result.skillsCount).toBe(1);
    });

    it('should reject Agent Card with forged signature', () => {
      const card: AgentCard = {
        id: 'forged_agent',
        name: 'Attacker Bot',
        version: '1.0.0',
        description: 'Rogue agent',
        organization: 'enterprise.internal',
        securityLevel: 'CRITICAL',
        publicKey,
        skills: [],
        signatures: {
          issuer: 'enterprise.internal',
          signature: 'deadbeef12345678',
        },
      };

      const result = validator.validateCard(card);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.toLowerCase().includes('signature'))).toBe(true);
    });
  });

  describe('DelegationRouter (Swarm Invariants & Multi-Hop Limits)', () => {
    let router: DelegationRouter;

    it('should prevent circular delegation loops and track swarm budget', () => {
      router = new DelegationRouter(3);
      router.registerSwarmCeiling('swarm_alpha', 10000);

      // Hop 1: ag1 -> ag2
      const hop1 = router.recordHop('swarm_alpha', 'ag1', 'ag2', 'tok1');
      expect(hop1.allowed).toBe(true);

      // Hop 2: ag2 -> ag3
      const hop2 = router.recordHop('swarm_alpha', 'ag2', 'ag3', 'tok2');
      expect(hop2.allowed).toBe(true);

      // Circular hop: ag3 -> ag1 (should fail)
      const circularHop = router.recordHop('swarm_alpha', 'ag3', 'ag1', 'tok3');
      expect(circularHop.allowed).toBe(false);
      expect(circularHop.reason).toContain('Circular delegation detected');

      // Spend tracking
      const spend1 = router.recordSpend('swarm_alpha', 6000);
      expect(spend1.allowed).toBe(true);
      expect(spend1.remainingBudget).toBe(4000);

      const spendExceed = router.recordSpend('swarm_alpha', 5000);
      expect(spendExceed.allowed).toBe(false);
      expect(spendExceed.reason).toContain('exceeded');
    });
  });
});
