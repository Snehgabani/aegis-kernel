import { describe, it, expect } from 'vitest';
import { AegisSanitizer, AegisEngine } from '../src/index.js';
import type { ToolCall } from '../src/types.js';

describe('Aegis In-Flight Parameter Sanitizer', () => {
  const engine = new AegisEngine();

  it('should strip zero-width unicode characters from parameter strings', () => {
    const toolCall: ToolCall = {
      tool: 'send_message',
      params: { message: 'Hello\u200B World\uFEFF!' },
    };

    const res = AegisSanitizer.sanitize(toolCall);
    expect(res.wasModified).toBe(true);
    expect(res.sanitized.params.message).toBe('Hello World!');
    expect(res.modifications).toContain('Stripped hidden zero-width unicode evasion characters');
  });

  it('should mask credit cards and SSNs in parameters', () => {
    const toolCall: ToolCall = {
      tool: 'log_data',
      params: {
        text: 'User card: 4111-2222-3333-4444 and SSN: 000-12-3456',
      },
    };

    const res = AegisSanitizer.sanitize(toolCall);
    expect(res.wasModified).toBe(true);
    expect(res.sanitized.params.text).toContain('[REDACTED_CREDIT_CARD]');
    expect(res.sanitized.params.text).toContain('[REDACTED_SSN]');
  });

  it('should automatically inject LIMIT 100 into unbound SELECT queries', () => {
    const toolCall: ToolCall = {
      tool: 'query_db',
      params: { query: 'SELECT * FROM users' },
    };

    const res = engine.sanitize(toolCall);
    expect(res.wasModified).toBe(true);
    expect(res.sanitized.params.query).toBe('SELECT * FROM users LIMIT 100;');
  });

  it('should leave safe and already-bounded tool calls untouched', () => {
    const toolCall: ToolCall = {
      tool: 'query_db',
      params: { query: 'SELECT id, name FROM users LIMIT 10;' },
    };

    const res = engine.sanitize(toolCall);
    expect(res.wasModified).toBe(false);
    expect(res.sanitized.params.query).toBe('SELECT id, name FROM users LIMIT 10;');
  });
});
