import { describe, it, expect } from 'vitest';
import { AegisOpenAIGuard } from '../src/index.js';

describe('AegisOpenAIGuard', () => {
  it('should intercept OpenAI function call and return tool error payload', async () => {
    const guard = new AegisOpenAIGuard({ mode: 'enforce' });

    const toolCall = {
      id: 'call_12345',
      type: 'function' as const,
      function: {
        name: 'stripe_payout',
        arguments: JSON.stringify({ amount: 999999, recipient: 'acct_bad' }),
      },
    };

    let executed = false;
    const response = await guard.handleToolCall(toolCall, async () => {
      executed = true;
      return { success: true };
    });

    expect(executed).toBe(false);
    expect(response.role).toBe('tool');
    expect(response.tool_call_id).toBe('call_12345');
    expect(response.content).toContain('AEGIS_INVARIANT_VIOLATION');
    expect(response.content).toContain('FIN-001');
  });

  it('should pass through legitimate OpenAI tool call', async () => {
    const guard = new AegisOpenAIGuard({ mode: 'enforce' });

    const toolCall = {
      id: 'call_67890',
      type: 'function' as const,
      function: {
        name: 'stripe_payout',
        arguments: JSON.stringify({ amount: 50, recipient: 'acct_good' }),
      },
    };

    let executed = false;
    const response = await guard.handleToolCall(toolCall, async (args) => {
      executed = true;
      return { status: 'paid', amount: args.amount };
    });

    expect(executed).toBe(true);
    expect(response.content).toContain('paid');
  });

  it('should handle malformed JSON arguments gracefully without crashing', () => {
    const guard = new AegisOpenAIGuard({ mode: 'enforce' });

    const toolCall = {
      id: 'call_malformed',
      type: 'function' as const,
      function: {
        name: 'test_tool',
        arguments: 'NOT_VALID_JSON_}{',
      },
    };

    const verdict = guard.evaluate(toolCall);
    expect(verdict).toBeDefined();
    expect(verdict.mode).toBe('enforce');
  });

  it('should allow tool execution in shadow mode even when violations exist', async () => {
    const guard = new AegisOpenAIGuard({ mode: 'shadow' });

    const toolCall = {
      id: 'call_shadow',
      type: 'function' as const,
      function: {
        name: 'stripe_payout',
        arguments: JSON.stringify({ amount: 999999 }),
      },
    };

    let executed = false;
    const response = await guard.handleToolCall(toolCall, async () => {
      executed = true;
      return { status: 'shadow_executed' };
    });

    expect(executed).toBe(true);
    expect(response.content).toContain('shadow_executed');
  });
});

