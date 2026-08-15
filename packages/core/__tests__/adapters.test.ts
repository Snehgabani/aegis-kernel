import { describe, it, expect } from 'vitest';
import { wrapLlamaIndexTool, wrapCrewAITool, AegisEngine } from '../src/index.js';

describe('Aegis LlamaIndex & CrewAI Native Tool Adapters', () => {
  const engine = new AegisEngine();

  describe('wrapLlamaIndexTool', () => {
    it('should allow legitimate tool calls through LlamaIndex wrapper', async () => {
      const originalTool = {
        name: 'execute_sql',
        description: 'Run safe database query',
        call: async (params: { query: string }) => `Results for ${params.query}`,
      };

      const guardedTool = wrapLlamaIndexTool(originalTool, engine);
      const result = await guardedTool.call({ query: 'SELECT id, username FROM users WHERE id = 1;' });
      expect(result).toContain('Results for SELECT');
    });

    it('should reject and throw error on destructive tool call in LlamaIndex', async () => {
      const originalTool = {
        name: 'execute_sql',
        description: 'Run SQL query',
        call: async (params: { query: string }) => `Executed: ${params.query}`,
      };

      const guardedTool = wrapLlamaIndexTool(originalTool, engine);
      await expect(guardedTool.call({ query: 'DELETE FROM accounts WHERE 1=1;' })).rejects.toThrow(
        /Aegis Clearance Denied/
      );
    });
  });

  describe('wrapCrewAITool', () => {
    it('should return successful execution on safe parameters in CrewAI', async () => {
      const originalCrewTool = {
        name: 'stripe_charge',
        description: 'Charge customer card',
        func: async (input: { amount: number }) => `Charged $${input.amount}`,
      };

      const guardedCrewTool = wrapCrewAITool(originalCrewTool, engine);
      const result = await guardedCrewTool.func({ amount: 150 });
      expect(result).toBe('Charged $150');
    });

    it('should intercept financial overspend in CrewAI and return structured error', async () => {
      const originalCrewTool = {
        name: 'stripe_charge',
        description: 'Charge customer card',
        func: async (input: { amount: number }) => `Charged $${input.amount}`,
      };

      const guardedCrewTool = wrapCrewAITool(originalCrewTool, engine);
      const result = await guardedCrewTool.func({ amount: 85000 });
      expect(result).toContain('ERROR: Aegis Invariant Clearance Denied');
      expect(result).toContain('FIN-001');
    });
  });
});
