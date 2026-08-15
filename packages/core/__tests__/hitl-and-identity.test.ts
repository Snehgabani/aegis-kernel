import { describe, it, expect, beforeEach } from 'vitest';
import { HITLEscalationManager } from '../src/hitl/escalation';
import { AgentIdentityManager } from '../src/identity/agent-identity';
import { AgentCircuitBreaker } from '../src/quarantine/circuit-breaker';

describe('Aegis Elite 2026 Capabilities Suite', () => {
  describe('Human-in-the-Loop (HITL) Escalation Engine', () => {
    let hitl: HITLEscalationManager;

    beforeEach(() => {
      hitl = new HITLEscalationManager({ ticketTtlSeconds: 300, signingSecret: 'test-secret-key-123' });
    });

    it('should create a cryptographically signed approval ticket for high-risk action', () => {
      const ticket = hitl.createTicket({
        agentId: 'agent-finance-01',
        toolName: 'execute_wire_transfer',
        params: { recipient: 'ACME Corp', amount: 50000 },
        reason: 'Financial transfer exceeds automated threshold ($10,000)'
      });

      expect(ticket.ticketId).toBeDefined();
      expect(ticket.status).toBe('PENDING');
      expect(ticket.signature).toBeDefined();
      expect(ticket.expiresAt).toBeGreaterThan(Date.now());
    });

    it('should allow authorized human approver to grant clearance', () => {
      const ticket = hitl.createTicket({
        agentId: 'agent-finance-01',
        toolName: 'execute_wire_transfer',
        params: { recipient: 'ACME Corp', amount: 50000 },
        reason: 'Financial transfer exceeds automated threshold'
      });

      const resolution = hitl.resolveTicket(ticket.ticketId, {
        decision: 'APPROVED',
        approver: 'ciso@enterprise.com',
        reason: 'Verified transaction against Invoice #INV-9821',
        signature: ticket.signature
      });

      expect(resolution.success).toBe(true);
      expect(resolution.ticket?.status).toBe('APPROVED');
      expect(resolution.ticket?.resolvedBy).toBe('ciso@enterprise.com');
    });

    it('should reject invalid or expired approval attempts', () => {
      const ticket = hitl.createTicket({
        agentId: 'agent-finance-01',
        toolName: 'execute_wire_transfer',
        params: { amount: 50000 },
        reason: 'Exceeds limit'
      });

      const badResolution = hitl.resolveTicket('non-existent-ticket-id', {
        decision: 'APPROVED',
        approver: 'hacker@adversary.com',
        signature: 'fake-signature'
      });

      expect(badResolution.success).toBe(false);
      expect(badResolution.error).toBe('Ticket not found');
    });

    it('should reject resolution with wrong signature', () => {
      const ticket = hitl.createTicket({
        agentId: 'agent-finance-01',
        toolName: 'execute_wire_transfer',
        params: { recipient: 'ACME Corp', amount: 50000 },
        reason: 'Testing wrong signature'
      });

      const resolution = hitl.resolveTicket(ticket.ticketId, {
        decision: 'APPROVED',
        approver: 'ciso@enterprise.com',
        signature: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'
      });

      expect(resolution.success).toBe(false);
      expect(resolution.error).toBe('Invalid ticket signature');
    });

    it('should reject resolution of expired ticket', () => {
      const shortHitl = new HITLEscalationManager({ ticketTtlSeconds: -1, signingSecret: 'test' });
      const ticket = shortHitl.createTicket({
        agentId: 'agent-finance-01',
        toolName: 'execute_wire_transfer',
        params: { amount: 50000 },
        reason: 'Testing expiry'
      });

      const resolution = shortHitl.resolveTicket(ticket.ticketId, {
        decision: 'APPROVED',
        approver: 'ciso@enterprise.com',
        signature: ticket.signature
      });

      expect(resolution.success).toBe(false);
      expect(resolution.error).toContain('current status is EXPIRED');
    });
  });

  describe('Non-Human Identity (NHI) & Agent Attestation', () => {
    let identityManager: AgentIdentityManager;

    beforeEach(() => {
      identityManager = new AgentIdentityManager();
    });

    it('should register an agent identity with scoped RBAC permissions and enforce boundaries', () => {
      identityManager.registerAgent({
        agentId: 'agent-support-readonly',
        role: 'read-only-support',
        allowedTools: ['search_kb', 'read_customer_ticket', 'get_status'],
        maxTransactionLimit: 0,
        allowedSqlOperations: ['SELECT']
      });

      const allowedCheck = identityManager.validateCapability('agent-support-readonly', {
        toolName: 'search_kb'
      });
      expect(allowedCheck.allowed).toBe(true);

      const unauthorizedToolCheck = identityManager.validateCapability('agent-support-readonly', {
        toolName: 'drop_database'
      });
      expect(unauthorizedToolCheck.allowed).toBe(false);
      expect(unauthorizedToolCheck.reason).toContain('Tool not permitted for agent role');
    });
  });

  describe('Automated Quarantine & Adaptive Circuit Breaker', () => {
    let circuitBreaker: AgentCircuitBreaker;

    beforeEach(() => {
      circuitBreaker = new AgentCircuitBreaker({ maxStrikes: 3, windowSeconds: 60, quarantineDurationSeconds: 300 });
    });

    it('should track security strikes and quarantine rogue agent upon exceeding threshold', () => {
      const agentId = 'rogue-crawler-99';

      expect(circuitBreaker.isQuarantined(agentId)).toBe(false);

      // Strike 1
      circuitBreaker.recordStrike(agentId, 'SQL_INJECTION_ATTEMPT');
      expect(circuitBreaker.isQuarantined(agentId)).toBe(false);

      // Strike 2
      circuitBreaker.recordStrike(agentId, 'PII_EXFILTRATION_ATTEMPT');
      expect(circuitBreaker.isQuarantined(agentId)).toBe(false);

      // Strike 3 (Quarantine triggered)
      const quarantineResult = circuitBreaker.recordStrike(agentId, 'MASS_DELETION_ATTEMPT');
      expect(quarantineResult.quarantined).toBe(true);
      expect(circuitBreaker.isQuarantined(agentId)).toBe(true);

      const status = circuitBreaker.getAgentStatus(agentId);
      expect(status.state).toBe('QUARANTINED');
      expect(status.strikeCount).toBe(3);
    });

    it('should allow security admin to manually lift quarantine', () => {
      const agentId = 'misconfigured-bot-02';
      circuitBreaker.recordStrike(agentId, 'ERROR_1');
      circuitBreaker.recordStrike(agentId, 'ERROR_2');
      circuitBreaker.recordStrike(agentId, 'ERROR_3');

      expect(circuitBreaker.isQuarantined(agentId)).toBe(true);

      circuitBreaker.liftQuarantine(agentId, 'admin@enterprise.com');
      expect(circuitBreaker.isQuarantined(agentId)).toBe(false);
    });
  });
});
