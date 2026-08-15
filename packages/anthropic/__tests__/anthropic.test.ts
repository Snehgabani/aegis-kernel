import { describe, it, expect } from 'vitest';
import { AegisAnthropicGuard } from '../src/index.js';

describe('AegisAnthropicGuard', () => {
  it('should intercept Claude tool_use and return tool_result error block', async () => {
    const guard = new AegisAnthropicGuard({ mode: 'enforce' });

    const toolUse = {
      type: 'tool_use' as const,
      id: 'toolu_01ABC',
      name: 'send_http_request',
      input: {
        url: 'https://api.external.com/log',
        body: 'Leaked SSN: 000-12-3456',
      },
    };

    let executed = false;
    const result = await guard.handleToolUse(toolUse, async () => {
      executed = true;
      return { status: 200 };
    });

    expect(executed).toBe(false);
    expect(result.type).toBe('tool_result');
    expect(result.tool_use_id).toBe('toolu_01ABC');
    expect(result.is_error).toBe(true);
    expect(result.content).toContain('AEGIS_INVARIANT_VIOLATION');
    expect(result.content).toContain('DATA-001');
  });

  it('should pass through legitimate Claude tool_use', async () => {
    const guard = new AegisAnthropicGuard({ mode: 'enforce' });

    const toolUse = {
      type: 'tool_use' as const,
      id: 'toolu_02DEF',
      name: 'send_http_request',
      input: {
        url: 'https://api.external.com/log',
        body: 'Safe operational status: OK',
      },
    };

    let executed = false;
    const result = await guard.handleToolUse(toolUse, async (input) => {
      executed = true;
      return { status: 200, received: input.body };
    });

    expect(executed).toBe(true);
    expect(result.is_error).toBeFalsy();
    expect(result.content).toContain('Safe operational status');
  });

  it('should capture underlying executor execution failure into tool_result error format', async () => {
    const guard = new AegisAnthropicGuard({ mode: 'enforce' });

    const toolUse = {
      type: 'tool_use' as const,
      id: 'toolu_03ERR',
      name: 'send_http_request',
      input: { url: 'https://api.external.com/log', body: 'Safe content' },
    };

    const result = await guard.handleToolUse(toolUse, async () => {
      throw new Error('Network socket timeout');
    });

    expect(result.type).toBe('tool_result');
    expect(result.is_error).toBe(true);
    expect(result.content).toContain('Tool execution failed: Network socket timeout');
  });

  it('should allow tool execution in shadow mode even when violations are present', async () => {
    const guard = new AegisAnthropicGuard({ mode: 'shadow' });

    const toolUse = {
      type: 'tool_use' as const,
      id: 'toolu_04SHADOW',
      name: 'send_http_request',
      input: { url: 'https://api.external.com/log', body: 'SSN: 000-12-3456' },
    };

    let executed = false;
    const result = await guard.handleToolUse(toolUse, async () => {
      executed = true;
      return { status: 200 };
    });

    expect(executed).toBe(true);
    expect(result.is_error).toBeFalsy();
  });
});

