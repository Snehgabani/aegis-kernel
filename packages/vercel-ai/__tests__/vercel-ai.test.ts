import { describe, it, expect } from 'vitest';
import { AegisVercelAIGuard, wrapVercelTool } from '../src/index.js';

describe('Aegis Vercel AI SDK Adapter', () => {
  it('should allow benign SQL queries and execute the tool', async () => {
    const dbTool = wrapVercelTool('database_exec', {
      description: 'Execute SQL queries on database',
      execute: async ({ query }: { query: string }) => {
        return { success: true, data: [{ id: 1, name: 'Alice' }] };
      },
    });

    const result: any = await dbTool.execute?.({ query: 'SELECT * FROM users WHERE id = 1 LIMIT 10' });
    expect(result.success).toBe(true);
    expect(result.data).toHaveLength(1);
  });

  it('should block destructive DELETE without WHERE and return self-healing error', async () => {
    const dbTool = wrapVercelTool('database_exec', {
      description: 'Execute SQL queries on database',
      execute: async ({ query }: { query: string }) => {
        return { success: true, message: 'Executed' };
      },
    });

    const result: any = await dbTool.execute?.({ query: 'DELETE FROM users' });
    expect(result.error).toBe(true);
    expect(result.status).toBe('BLOCKED');
    expect(result.message).toContain('Aegis Safety Invariant Violation');
    expect(result.violations.length).toBeGreaterThan(0);
    expect(result.proofHash).toBeDefined();
  });

  it('should block financial transfer exceeding limits', async () => {
    const transferTool = wrapVercelTool('payment', {
      description: 'Execute corporate wire transfer',
      execute: async ({ total, recipient }: { total: number; recipient: string }) => {
        return { success: true, txnId: 'txn_999' };
      },
    });

    const result: any = await transferTool.execute?.({ total: 999999, recipient: 'attacker_wallet' });
    expect(result.error).toBe(true);
    expect(result.status).toBe('BLOCKED');
  });

  it('should support custom onViolation handler', async () => {
    const guard = new AegisVercelAIGuard();
    const tool = guard.wrapTool(
      'database_exec',
      {
        execute: async () => ({ status: 'executed' }),
      },
      {
        onViolation: (verdict) => {
          return { intercepted: true, rule: verdict.violations[0]?.ruleId };
        },
      }
    );

    const result: any = await tool.execute?.({ query: 'DROP TABLE users' });
    expect(result.intercepted).toBe(true);
    expect(result.rule).toBe('SQL-002');
  });
});
