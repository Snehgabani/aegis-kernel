import { describe, it, expect, beforeEach } from 'vitest';
import { SqlChecker } from '../src/checkers/sql-checker.js';
import { StateChecker } from '../src/checkers/state-checker.js';
import { AegisBiscuitToken } from '../src/a2a/biscuit-token.js';
import { ExecutionDAG } from '../src/graph/execution-dag.js';

describe('Aegis Frontier Multi-Agent Swarm Immunity & Cascading Failure Gauntlet', () => {
  beforeEach(() => {
    StateChecker.resetAtomicStore();
  });

  describe('Pillar 1: Polyglot SQL & Dangerous Built-In Functions', () => {
    const checker = new SqlChecker();

    it('should reject postgres pg_read_file server exfiltration functions', () => {
      const sql = "SELECT pg_read_file('/etc/passwd', 0, 1000);";
      const violations = checker.evaluate(
        'RULE-SQL-AST',
        'pack-sql',
        { block_statements: ['DROP'] },
        { toolName: 'database_query', params: { query: sql } },
        'critical'
      );

      expect(violations.length).toBeGreaterThan(0);
      expect(violations[0].message).toContain('pg_read_file');
      expect(violations[0].severity).toBe('critical');
    });

    it('should reject MySQL into outfile data exfiltration attempts', () => {
      const sql = "SELECT * FROM credit_cards INTO OUTFILE '/var/www/html/dump.txt';";
      const violations = checker.evaluate(
        'RULE-SQL-AST',
        'pack-sql',
        { block_statements: ['DROP'] },
        { toolName: 'database_query', params: { query: sql } },
        'critical'
      );

      expect(violations.length).toBeGreaterThan(0);
      expect(violations[0].message.toLowerCase()).toContain('into outfile');
    });

    it('should reject MSSQL xp_cmdshell command execution attempts', () => {
      const sql = "EXEC xp_cmdshell('whoami');";
      const violations = checker.evaluate(
        'RULE-SQL-AST',
        'pack-sql',
        { block_statements: ['DROP'] },
        { toolName: 'database_query', params: { query: sql } },
        'critical'
      );

      expect(violations.length).toBeGreaterThan(0);
      expect(violations[0].message).toContain('xp_cmdshell');
    });
  });

  describe('Pillar 2: Swarm Confused-Deputy Mitigation via Attenuated Biscuit Tokens', () => {
    it('should enforce attenuated caveat ceilings on subagents across delegation chains', () => {
      const { publicKey: rootPub, privateKey: rootPriv } = AegisBiscuitToken.generateKeyPair();
      const { publicKey: subagentPub, privateKey: subagentPriv } = AegisBiscuitToken.generateKeyPair();

      // Master supervisor issues root token allowing wire transfers up to $50,000
      const rootToken = AegisBiscuitToken.createRootToken(
        'agent_supervisor',
        ['wire_transfer'],
        [{ field: 'amount', operator: '<=', value: 50000 }],
        rootPriv,
        rootPub
      );

      // Supervisor delegates to subagent, attenuating the allowance to max $500
      const attenuatedToken = AegisBiscuitToken.attenuate(
        rootToken,
        [{ field: 'amount', operator: '<=', value: 500 }],
        rootPriv,
        'agent_subagent_checkout'
      );

      // Verify compliant $300 transfer
      const resCompliant = AegisBiscuitToken.verify(
        attenuatedToken,
        'wire_transfer',
        { amount: 300 },
        'agent_subagent_checkout'
      );
      expect(resCompliant.valid).toBe(true);
      expect(resCompliant.authorized).toBe(true);

      // Verify non-compliant $2,000 transfer (Confused Deputy Escalation attempt)
      const resEscalated = AegisBiscuitToken.verify(
        attenuatedToken,
        'wire_transfer',
        { amount: 2000 },
        'agent_subagent_checkout'
      );
      expect(resEscalated.valid).toBe(true);
      expect(resEscalated.authorized).toBe(false);
      expect(resEscalated.reason).toContain('Caveat violated');
    });
  });

  describe('Pillar 3: Concurrent Swarm Atomic Compare-and-Swap State Invariants', () => {
    it('should atomically decrement state balance and reject overdraft attempts in parallel swarms', () => {
      const accountKey = 'account_balance_tenant_101';
      StateChecker.setAtomicBalance(accountKey, 10000); // Initial $10,000 balance

      // Subagent 1 requests $6,000 -> Approved (Remaining $4,000)
      const r1 = StateChecker.atomicDecrementBalance(accountKey, 6000);
      expect(r1.success).toBe(true);
      expect(r1.remaining).toBe(4000);

      // Subagent 2 requests $5,000 -> Rejected! (Exceeds available $4,000)
      const r2 = StateChecker.atomicDecrementBalance(accountKey, 5000);
      expect(r2.success).toBe(false);
      expect(r2.remaining).toBe(4000);
      expect(r2.error).toContain('exceeds available balance 4000');

      // Subagent 3 requests $4,000 -> Approved (Remaining $0)
      const r3 = StateChecker.atomicDecrementBalance(accountKey, 4000);
      expect(r3.success).toBe(true);
      expect(r3.remaining).toBe(0);
    });
  });

  describe('Pillar 4: Information Flow Control (IFC) Cascading Failure Circuit Breakers', () => {
    it('should propagate untrusted taint from web scraper and detect anomaly at sensitive sink', () => {
      const dag = new ExecutionDAG();

      // Node 1: Untrusted web scrape
      dag.addAction({
        id: 'node_scrape',
        agentId: 'agent_crawler',
        actionType: 'scrape_website',
        timestamp: Date.now(),
        securityLabel: {
          integrity: 'untrusted',
          confidentiality: 'public',
          taintSources: ['untrusted_web_input'],
        },
      });

      // Node 2: Subagent processing data
      dag.addAction({
        id: 'node_process',
        agentId: 'agent_analyst',
        actionType: 'format_payload',
        timestamp: Date.now(),
      });

      // Node 3: High-risk mutation sink
      dag.addAction({
        id: 'node_sink',
        agentId: 'agent_executor',
        actionType: 'execute_sql',
        timestamp: Date.now(),
      });

      // Connect data flow edges
      dag.addEdge({ sourceId: 'node_scrape', targetId: 'node_process', type: 'data_flow' });
      dag.addEdge({ sourceId: 'node_process', targetId: 'node_sink', type: 'data_flow' });

      // Anomaly detection flags information flow violation
      const anomalies = dag.verifyInformationFlow({
        mutationSinks: ['execute_sql', 'wire_transfer'],
        blockedMutationIntegrities: ['untrusted'],
      });

      expect(anomalies.length).toBeGreaterThan(0);
      const ifcAnomaly = anomalies.find((a) => a.type === 'InformationFlowViolation');
      expect(ifcAnomaly).toBeDefined();
      expect(ifcAnomaly?.reason).toContain('Untrusted');
    });
  });
});
