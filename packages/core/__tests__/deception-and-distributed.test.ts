import { describe, it, expect, vi } from 'vitest';
import {
  HoneytokenManager,
  DistributedCircuitBreaker,
  InMemoryStorageAdapter,
} from '../src/index.js';
import type { ToolCall } from '../src/types.js';

describe('AI Agent Honeytoken & Deception Engine', () => {
  it('should initialize default canary tools', () => {
    const manager = new HoneytokenManager();
    const canaries = manager.getCanaryToolDefinitions();
    expect(canaries.length).toBeGreaterThanOrEqual(3);
    expect(manager.isCanaryTool('system_execute_privileged_shell')).toBe(true);
    expect(manager.isCanaryTool('vault_export_root_secrets')).toBe(true);
    expect(manager.isCanaryTool('bypass_safety_guardrails')).toBe(true);
    expect(manager.isCanaryTool('normal_database_query')).toBe(false);
  });

  it('should trigger critical breach alert when canary tool is invoked', () => {
    const manager = new HoneytokenManager();
    const breachCallback = vi.fn();
    manager.onBreach(breachCallback);

    const maliciousToolCall: ToolCall = {
      tool: 'system_execute_privileged_shell',
      params: { cmd: 'rm -rf / --no-preserve-root' },
    };

    const alert = manager.evaluateCanaryInvocation(maliciousToolCall, 'agent-rogue-007');
    expect(alert).not.toBeNull();
    expect(alert?.confidence).toBe(1.0);
    expect(alert?.severity).toBe('CRITICAL_BREACH');
    expect(alert?.canaryTool).toBe('system_execute_privileged_shell');
    expect(alert?.agentId).toBe('agent-rogue-007');
    expect(alert?.mitreTechnique).toBe('AML.T0053');
    expect(breachCallback).toHaveBeenCalledWith(alert);
  });

  it('should return null when clean legitimate tool is invoked', () => {
    const manager = new HoneytokenManager();
    const cleanToolCall: ToolCall = {
      tool: 'execute_sql',
      params: { query: 'SELECT 1' },
    };
    const alert = manager.evaluateCanaryInvocation(cleanToolCall);
    expect(alert).toBeNull();
  });
});

describe('Distributed Circuit Breaker & Multi-Node Quarantine', () => {
  it('should record strikes and quarantine agent across distributed storage', async () => {
    const storage = new InMemoryStorageAdapter();
    const breaker = new DistributedCircuitBreaker({
      maxStrikes: 3,
      windowSeconds: 60,
      storage,
    });

    const agent = 'worker-fleet-node-42';

    const strike1 = await breaker.recordStrike(agent, 'SQL_INJECTION');
    expect(strike1.strikes).toBe(1);
    expect(strike1.quarantined).toBe(false);
    expect(strike1.remainingStrikes).toBe(2);

    const strike2 = await breaker.recordStrike(agent, 'PII_LEAK');
    expect(strike2.strikes).toBe(2);
    expect(strike2.quarantined).toBe(false);

    const strike3 = await breaker.recordStrike(agent, 'UNAUTHORIZED_ACCESS');
    expect(strike3.strikes).toBe(3);
    expect(strike3.quarantined).toBe(true);
    expect(strike3.remainingStrikes).toBe(0);

    // Agent is now quarantined
    expect(await breaker.isQuarantined(agent)).toBe(true);

    // Release agent
    await breaker.releaseAgent(agent);
    expect(await breaker.isQuarantined(agent)).toBe(false);
  });
});
