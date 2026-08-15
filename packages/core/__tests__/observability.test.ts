import { describe, it, expect } from 'vitest';
import { formatLangfuseEvent, formatArizePhoenixEvent, AegisEngine } from '../src/index.js';
import type { ToolCall } from '../src/types.js';

describe('Aegis Enterprise Observability Integrations', () => {
  const engine = new AegisEngine();

  it('should format Langfuse observation payload for cleared tool call', () => {
    const toolCall: ToolCall = {
      tool: 'query_db',
      params: { query: 'SELECT name FROM items WHERE id = 5;' },
    };
    const verdict = engine.evaluate(toolCall);
    const langfuseEvent = formatLangfuseEvent(toolCall, verdict);

    expect(langfuseEvent.type).toBe('GUARDRAIL');
    expect(langfuseEvent.level).toBe('DEFAULT');
    expect(langfuseEvent.statusMessage).toBe('CLEARED');
    expect(langfuseEvent.metadata.verdict).toBe('ALLOWED');
    expect(langfuseEvent.metadata.proofHash).toBeDefined();
    expect(langfuseEvent.metadata.violationsCount).toBe(0);
  });

  it('should format Langfuse observation payload for blocked tool call with suggestedFix', () => {
    const toolCall: ToolCall = {
      tool: 'send_payout',
      params: { amount: 999999 },
    };
    const verdict = engine.evaluate(toolCall);
    const langfuseEvent = formatLangfuseEvent(toolCall, verdict);

    expect(langfuseEvent.type).toBe('GUARDRAIL');
    expect(langfuseEvent.level).toBe('ERROR');
    expect(langfuseEvent.metadata.verdict).toBe('BLOCKED');
    expect(langfuseEvent.metadata.violationsCount).toBeGreaterThan(0);
    expect(langfuseEvent.metadata.violatedRules).toContain('FIN-001');
    expect(langfuseEvent.metadata.suggestedFix).toBeDefined();
  });

  it('should format Arize Phoenix evaluation record correctly', () => {
    const toolCall: ToolCall = {
      tool: 'query_db',
      params: { query: 'DROP TABLE production_orders;' },
    };
    const verdict = engine.evaluate(toolCall);
    const phoenixEvent = formatArizePhoenixEvent(toolCall, verdict);

    expect(phoenixEvent.eval_name).toBe('aegis_tool_clearance');
    expect(phoenixEvent.score).toBe(0.0);
    expect(phoenixEvent.label).toBe('unsafe');
    expect(phoenixEvent.explanation).toContain('SQL-002');
    expect(phoenixEvent.metadata.tool).toBe('query_db');
  });
});
