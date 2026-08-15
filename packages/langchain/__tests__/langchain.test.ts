import { describe, it, expect } from 'vitest';
import { AegisLangChainGuard } from '../src/index.js';

describe('AegisLangChainGuard', () => {
  it('should wrap a LangChain tool and throw on invariant violation', async () => {
    const guard = new AegisLangChainGuard({ mode: 'enforce' });

    let toolExecuted = false;
    const mockTool = {
      name: 'database_tool',
      description: 'Executes database commands',
      invoke: async (input: any) => {
        toolExecuted = true;
        return 'executed';
      },
      call: async (input: any) => {
        toolExecuted = true;
        return 'executed';
      },
    };

    const protectedTool = guard.wrap(mockTool);

    // Call with dangerous input
    await expect(
      protectedTool.invoke({ sql: 'DROP TABLE production_db;' })
    ).rejects.toThrow('Aegis Safety Violation');

    expect(toolExecuted).toBe(false);
  });

  it('should allow legitimate tool execution through wrapped proxy', async () => {
    const guard = new AegisLangChainGuard({ mode: 'enforce' });

    let toolExecuted = false;
    const mockTool = {
      name: 'database_tool',
      description: 'Executes database commands',
      invoke: async (input: any) => {
        toolExecuted = true;
        return 'rows: 5';
      },
      call: async (input: any) => {
        toolExecuted = true;
        return 'rows: 5';
      },
    };

    const protectedTool = guard.wrap(mockTool);
    const result = await protectedTool.invoke({ sql: 'SELECT * FROM users WHERE active = true;' });

    expect(toolExecuted).toBe(true);
    expect(result).toBe('rows: 5');
  });

  it('should wrap multiple tools via wrapAll', async () => {
    const guard = new AegisLangChainGuard({ mode: 'enforce' });

    const tool1 = {
      name: 'tool_one',
      description: 'First tool',
      invoke: async () => 'one_res',
      call: async () => 'one_res',
    };
    const tool2 = {
      name: 'tool_two',
      description: 'Second tool',
      invoke: async () => 'two_res',
      call: async () => 'two_res',
    };

    const wrapped = guard.wrapAll([tool1, tool2]);
    expect(wrapped.length).toBe(2);

    const res1 = await wrapped[0].invoke({ param: 1 });
    const res2 = await wrapped[1].invoke({ param: 2 });
    expect(res1).toBe('one_res');
    expect(res2).toBe('two_res');
  });

  it('should handle primitive string arguments in wrapped tools gracefully', async () => {
    const guard = new AegisLangChainGuard({ mode: 'enforce' });

    const echoTool = {
      name: 'echo',
      description: 'Echoes string',
      invoke: async (input: string) => `echo:${input}`,
      call: async (input: string) => `echo:${input}`,
    };

    const wrapped = guard.wrap(echoTool);
    const res = await wrapped.invoke('hello world');
    expect(res).toBe('echo:hello world');
  });

  it('should allow tool execution in shadow mode even when violation occurs', async () => {
    const guard = new AegisLangChainGuard({ mode: 'shadow' });

    let executed = false;
    const dangerousTool = {
      name: 'database_tool',
      description: 'Database tool',
      invoke: async () => {
        executed = true;
        return 'shadow_success';
      },
      call: async () => {
        executed = true;
        return 'shadow_success';
      },
    };

    const wrapped = guard.wrap(dangerousTool);
    const res = await wrapped.invoke({ sql: 'DROP TABLE prod;' });
    expect(executed).toBe(true);
    expect(res).toBe('shadow_success');
  });
});

