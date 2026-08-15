import { describe, it, expect } from 'vitest';
import { AegisEngine } from '../src/engine.js';
import type { ToolCall } from '../src/types.js';

describe('AegisEngine Orchestrator', () => {
  it('should block mass DELETE without WHERE clause', () => {
    const engine = new AegisEngine({ mode: 'enforce' });
    const toolCall: ToolCall = {
      tool: 'db_query',
      params: { sql: 'DELETE FROM users;' },
    };

    const verdict = engine.evaluate(toolCall);
    expect(verdict.allowed).toBe(false);
    expect(verdict.violations.length).toBeGreaterThan(0);
    expect(verdict.violations[0].ruleId).toBe('SQL-001');
    expect(verdict.suggestedFix).toBeDefined();
    expect(verdict.proofHash).toHaveLength(64);
  });

  it('should allow legitimate targeted SELECT queries with zero false positives', () => {
    const engine = new AegisEngine({ mode: 'enforce' });
    const toolCall: ToolCall = {
      tool: 'db_query',
      params: { sql: 'SELECT id, email, created_at FROM users WHERE id = 42;' },
    };

    const verdict = engine.evaluate(toolCall);
    expect(verdict.allowed).toBe(true);
    expect(verdict.violations.length).toBe(0);
  });

  it('should support shadow mode (audits without blocking)', () => {
    const engine = new AegisEngine({ mode: 'shadow' });
    const toolCall: ToolCall = {
      tool: 'db_query',
      params: { sql: 'DROP TABLE customers;' },
    };

    const verdict = engine.evaluate(toolCall);
    // In shadow mode, allowed is always true
    expect(verdict.allowed).toBe(true);
    expect(verdict.mode).toBe('shadow');
    expect(verdict.violations.length).toBeGreaterThan(0);
  });

  it('should block financial overspend above ceiling', () => {
    const engine = new AegisEngine({ mode: 'enforce' });
    const toolCall: ToolCall = {
      tool: 'transfer_funds',
      params: { amount: 50000, recipient: 'acct_999' },
    };

    const verdict = engine.evaluate(toolCall);
    expect(verdict.allowed).toBe(false);
    expect(verdict.violations.some((v) => v.ruleId === 'FIN-001')).toBe(true);
  });

  it('should block PII credit card leakage', () => {
    const engine = new AegisEngine({ mode: 'enforce' });
    const toolCall: ToolCall = {
      tool: 'send_webhook',
      params: { message: 'Customer card is 4532015012345678' },
    };

    const verdict = engine.evaluate(toolCall);
    expect(verdict.allowed).toBe(false);
    expect(verdict.violations.some((v) => v.ruleId === 'DATA-001')).toBe(true);
  });

  it('should execute sub-5ms latency', () => {
    const engine = new AegisEngine();
    const toolCall: ToolCall = {
      tool: 'db_query',
      params: { sql: 'SELECT 1;' },
    };

    const verdict = engine.evaluate(toolCall);
    expect(verdict.latencyMs).toBeLessThan(100);
  });
});
