import { describe, it, expect } from 'vitest';
import { AegisEngine } from '../src/engine.js';
import { StepDiagnosticCollector } from '../src/diagnostics/forensic-trace.js';

describe('Forensic Diagnostic Layer', () => {
  it('should capture micro-stage execution traces with high resolution timings', () => {
    const collector = new StepDiagnosticCollector('diag-123');

    collector.startStage('NORMALIZATION');
    collector.endStage('NORMALIZATION', 'PASSED', { tokens: 5 });

    collector.startStage('INVARIANT_EVALUATION');
    collector.endStage('INVARIANT_EVALUATION', 'FAILED', { reason: 'Missing WHERE' }, {
      ruleId: 'SQL-01',
      reason: 'Unconstrained mutation',
    });

    const trace = collector.finalize({
      failureCategory: 'SECURITY_VIOLATION',
      primaryCulpritRule: 'SQL-01',
      triggeringPayloadSnippet: 'DELETE FROM users',
      remediationAction: 'ATTACH_WHERE_CLAUSE',
    });

    expect(trace.evaluationId).toBe('diag-123');
    expect(trace.stages.length).toBe(2);
    expect(trace.stages[0].stageName).toBe('NORMALIZATION');
    expect(trace.stages[1].status).toBe('FAILED');
    expect(trace.rootCauseAnalysis?.failureCategory).toBe('SECURITY_VIOLATION');
    expect(trace.totalDurationUs).toBeGreaterThanOrEqual(0);
  });

  it('should attach forensic diagnostic trace to AegisVerdict when enableDiagnostics is true', () => {
    const engine = new AegisEngine({
      mode: 'enforce',
      packs: ['@aegis/sql-guard'],
    });

    const verdict = engine.evaluate(
      {
        tool: 'database_exec',
        params: { query: 'DELETE FROM accounts' },
      },
      { enableDiagnostics: true }
    );

    expect(verdict.allowed).toBe(false);
    expect(verdict.diagnosticTrace).toBeDefined();
    expect(verdict.diagnosticTrace?.stages.length).toBeGreaterThanOrEqual(4);
    expect(verdict.diagnosticTrace?.rootCauseAnalysis?.failureCategory).toBe('SECURITY_VIOLATION');
    expect(verdict.diagnosticTrace?.rootCauseAnalysis?.primaryCulpritRule).toBe('SQL-001');
  });
});
