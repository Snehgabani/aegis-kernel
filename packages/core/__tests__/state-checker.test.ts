import { describe, it, expect } from 'vitest';
import { StateChecker } from '../src/checkers/state-checker.js';
import { AegisEngine } from '../src/engine.js';
import type { ToolCall } from '../src/types.js';

describe('StateChecker (System State Invariant Layer)', () => {
  const checker = new StateChecker();

  it('should block an action that breaches a cumulative daily spend state invariant', () => {
    const toolCall: ToolCall = {
      tool: 'transfer_funds',
      params: { amount: 15000 },
    };

    const stateContext = {
      account_status: 'active',
      spent_today: 40000,
      daily_budget: 50000,
    };

    const violations = checker.evaluate(
      'STATE-INV-1',
      'finance-guard',
      {
        precondition: "state.account_status == 'active'",
        assertion: 'state.spent_today + params.amount <= state.daily_budget',
      },
      toolCall,
      stateContext
    );

    expect(violations.length).toBe(1);
    expect(violations[0].ruleId).toBe('STATE-INV-1');
    expect(violations[0].message).toContain('System state invariant violated');
  });

  it('should allow an action when proposed transition satisfies the state invariant', () => {
    const toolCall: ToolCall = {
      tool: 'transfer_funds',
      params: { amount: 5000 },
    };

    const stateContext = {
      account_status: 'active',
      spent_today: 40000,
      daily_budget: 50000,
    };

    const violations = checker.evaluate(
      'STATE-INV-1',
      'finance-guard',
      {
        precondition: "state.account_status == 'active'",
        assertion: 'state.spent_today + params.amount <= state.daily_budget',
      },
      toolCall,
      stateContext
    );

    expect(violations.length).toBe(0);
  });

  it('should fail when system state fails a mandatory precondition', () => {
    const toolCall: ToolCall = {
      tool: 'ship_order',
      params: { order_id: 'ORD-999' },
    };

    const stateContext = {
      order_status: 'cancelled',
    };

    const violations = checker.evaluate(
      'STATE-INV-2',
      'order-guard',
      {
        precondition: "state.order_status == 'pending'",
        assertion: "params.order_id != null",
      },
      toolCall,
      stateContext
    );

    expect(violations.length).toBe(1);
    expect(violations[0].message).toContain('State precondition failed');
  });

  it('should resolve state from an async StateProvider outside agent control', async () => {
    const engine = new AegisEngine({
      stateProvider: async (_toolCall) => {
        // Simulates trusted database lookup
        return {
          account_status: 'active',
          spent_today: 45000,
          daily_budget: 50000,
        };
      },
    });

    const toolCall: ToolCall = {
      tool: 'payout',
      params: { amount: 10000 },
    };

    const verdict = await engine.evaluateAsync(toolCall);
    expect(verdict.allowed).toBe(false);
    expect(verdict.violations.some((v) => v.ruleId === 'FIN-STATE-001')).toBe(true);
  });
});
