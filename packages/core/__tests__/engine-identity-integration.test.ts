import { AegisEngine } from '../src/engine.js';
import { AgentIdentityManager } from '../src/identity/agent-identity.js';
import type { ToolCall } from '../src/types.js';

describe('AegisEngine with AgentIdentityManager Integration', () => {
  let engine: AegisEngine;
  let identityManager: AgentIdentityManager;

  beforeEach(() => {
    identityManager = new AgentIdentityManager();
    identityManager.registerAgent({
      agentId: 'agent-007',
      role: 'junior-assistant',
      allowedTools: ['read_file', 'list_dir', 'make_transfer'],
      maxTransactionLimit: 500,
    });

    engine = new AegisEngine({
      mode: 'enforce',
      identityManager,
      // Provide a dummy pack to avoid loading defaults in tests
      packs: [{ id: 'dummy-pack', name: 'Dummy', version: '1.0', rules: [] }],
    });
  });

  it('ALLOWS authorized tools', () => {
    const toolCall: ToolCall = {
      tool: 'read_file',
      params: { path: '/etc/passwd' }, // RBAC only checks tool name, not arguments here
    };

    const verdict = engine.evaluate(toolCall, { callerId: 'agent-007' });
    expect(verdict.allowed).toBe(true);
    expect(verdict.violations).toHaveLength(0);
  });

  it('BLOCKS unauthorized tools', () => {
    const toolCall: ToolCall = {
      tool: 'delete_database',
      params: { db: 'prod' },
    };

    const verdict = engine.evaluate(toolCall, { callerId: 'agent-007' });
    expect(verdict.allowed).toBe(false);
    expect(verdict.violations).toHaveLength(1);
    expect(verdict.violations[0].ruleId).toBe('RBAC-001');
    expect(verdict.violations[0].message).toMatch(/Tool not permitted/);
  });

  it('BLOCKS exceeding financial limits', () => {
    const toolCall: ToolCall = {
      tool: 'make_transfer',
      params: { amount: 1000, to: 'evil-hacker' },
    };

    const verdict = engine.evaluate(toolCall, { callerId: 'agent-007' });
    expect(verdict.allowed).toBe(false);
    expect(verdict.violations).toHaveLength(1);
    expect(verdict.violations[0].ruleId).toBe('RBAC-001');
    expect(verdict.violations[0].message).toMatch(/exceeds agent role limit/i);
  });

  it('ALLOWS financial transfer within limits', () => {
    const toolCall: ToolCall = {
      tool: 'make_transfer',
      params: { amount: 200, to: 'legit-user' },
    };

    const verdict = engine.evaluate(toolCall, { callerId: 'agent-007' });
    expect(verdict.allowed).toBe(true);
    expect(verdict.violations).toHaveLength(0);
  });
  
  it('BLOCKS unregistered agent', () => {
    const toolCall: ToolCall = {
      tool: 'read_file',
      params: {},
    };

    const verdict = engine.evaluate(toolCall, { callerId: 'ghost-agent' });
    expect(verdict.allowed).toBe(false);
    expect(verdict.violations[0].message).toMatch(/not registered/i);
  });

  it('enforces Google DeepMind CaMeL quarantined worker isolation from mutating tools', () => {
    identityManager.registerAgent({
      agentId: 'quarantined-scraper-01',
      role: 'web-scraper',
      allowedTools: ['*'],
      executionRole: 'quarantined_worker',
    });

    // 1. Quarantined agent can invoke read-only tool
    const readVerdict = engine.evaluate(
      { tool: 'read_doc', params: { url: 'https://example.com' } },
      { callerId: 'quarantined-scraper-01' }
    );
    expect(readVerdict.allowed).toBe(true);

    // 2. Quarantined agent is BLOCKED from invoking mutating tool
    const mutateVerdict = engine.evaluate(
      { tool: 'database_exec', params: { query: 'SELECT 1' } },
      { callerId: 'quarantined-scraper-01' }
    );
    expect(mutateVerdict.allowed).toBe(false);
    expect(mutateVerdict.violations[0].message).toMatch(/CaMeL Invariant: Quarantined worker agent/);
  });
});
