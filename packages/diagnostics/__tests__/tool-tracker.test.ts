import { describe, it, expect } from 'vitest';
import { ToolUsageTracker } from '../src/tool-usage-tracker.js';

describe('ToolUsageTracker', () => {
  it('should track tool invocation frequency and compute guard coverage', () => {
    const tracker = new ToolUsageTracker(['execute_sql', 'send_slack', 'disburse_payout', 'unused_tool']);

    tracker.attachRule('execute_sql', 'SQL-001');
    tracker.attachRule('disburse_payout', 'FIN-001');

    // Safe and blocked calls
    tracker.recordInvocation('execute_sql', true);
    tracker.recordInvocation('execute_sql', false);
    tracker.recordInvocation('disburse_payout', true);
    tracker.recordInvocation('send_slack', true); // Unguarded!

    const report = tracker.generateCoverageReport();

    expect(report.totalDeclaredTools).toBe(4);
    expect(report.totalInvokedTools).toBe(3);
    expect(report.guardedToolsCount).toBe(2);
    expect(report.unguardedToolsCount).toBe(1);
    expect(report.coveragePercentage).toBe(66.7);
    expect(report.unusedTools).toContain('unused_tool');
    expect(report.shadowTools.some((t) => t.toolName === 'send_slack')).toBe(true);
  });

  it('should flag CRITICAL LLM escape risk when unregistered shadow tool is called', () => {
    const tracker = new ToolUsageTracker(['execute_sql']);
    tracker.attachRule('execute_sql', 'SQL-001');

    // LLM attempts to call an un-declared tool
    tracker.recordInvocation('raw_system_shell', true);

    const report = tracker.generateCoverageReport();
    expect(report.llmEscapeRiskLevel).toBe('CRITICAL');
    expect(report.shadowTools.some((t) => t.toolName === 'raw_system_shell')).toBe(true);
  });
});
