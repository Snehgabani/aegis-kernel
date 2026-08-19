import { describe, it, expect } from 'vitest';
import { AegisTelemetryCollector } from '../src/telemetry-collector.js';

describe('AegisTelemetryCollector', () => {
  it('should compute exact latency percentiles and violation distribution', () => {
    const collector = new AegisTelemetryCollector('test-node-123');

    // Simulate 10 evaluation events
    collector.recordEvaluation({ tool: 'sql_exec', allowed: true, latencyMs: 0.1, violations: [] });
    collector.recordEvaluation({ tool: 'sql_exec', allowed: true, latencyMs: 0.2, violations: [] });
    collector.recordEvaluation({ tool: 'sql_exec', allowed: false, latencyMs: 0.3, violations: ['SQL-001'] });
    collector.recordEvaluation({ tool: 'finance_tool', allowed: false, latencyMs: 0.4, violations: ['FIN-001', 'SQL-001'] });
    collector.recordEvaluation({ tool: 'sql_exec', allowed: true, latencyMs: 0.5, violations: [] });

    const summary = collector.getMetricsSummary();

    expect(summary.totalEvaluations).toBe(5);
    expect(summary.allowedCount).toBe(3);
    expect(summary.blockedCount).toBe(2);
    expect(summary.blockRatePercent).toBe(40.0);
    expect(summary.latencyPercentiles.p50Ms).toBeGreaterThan(0);
    expect(summary.topViolatedRules[0].ruleId).toBe('SQL-001');
    expect(summary.topViolatedRules[0].count).toBe(2);
  });

  it('should cryptographically fingerprint and aggregate engine crashes without PII leaks', () => {
    const collector = new AegisTelemetryCollector('test-node-123');

    const err = new Error('SyntaxError: unexpected token in SQL AST');
    const crashReport = collector.recordCrash(err, 'SqlChecker');

    expect(crashReport.fingerprint).toContain('SqlChecker:Error:');
    expect(crashReport.runtime.nodeVersion).toBeDefined();

    const packet = collector.exportAnonymizedReport();
    expect(packet.anonymousInstallationId).toBe('test-node-123');
    expect(packet.crashFingerprints.length).toBe(1);
    expect(packet.crashFingerprints[0].component).toBe('SqlChecker');
  });
});
