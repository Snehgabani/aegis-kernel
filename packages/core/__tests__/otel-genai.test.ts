import { describe, it, expect } from 'vitest';
import {
  formatGenAiSpanName,
  formatGenAiExecuteToolSpan,
  formatGenAiDurationObservation,
  AEGIS_GENAI_ATTRIBUTES,
  formatOtelSpanAttributes,
} from '../src/telemetry/otel.js';
import { AegisEngine } from '../src/engine.js';

/* Test helpers: build verdicts through the real engine so shapes stay honest. */
function engineWithPacks() {
  return new AegisEngine({ mode: 'enforce', packs: ['@aegis/sql-guard'] });
}

const MALICIOUS_CALL = {
  tool: 'sql_query',
  params: { query: "SELECT * FROM users WHERE name='admin' OR '1'='1'; DROP TABLE users;--" },
};

const BENIGN_CALL = {
  tool: 'sql_query',
  params: { query: 'SELECT id, name FROM products WHERE price < 100' },
};

describe('OTel GenAI semantic conventions — span formatting', () => {
  it('span name follows the "{operation} {resource}" convention', () => {
    expect(formatGenAiSpanName('sql_query')).toBe('execute_tool sql_query');
  });

  it('emits required gen_ai.* attributes (operation, provider, tool, call id)', () => {
    const engine = engineWithPacks();
    const verdict = engine.evaluate(MALICIOUS_CALL);
    const span = formatGenAiExecuteToolSpan(MALICIOUS_CALL, verdict);
    expect(span.attributes[AEGIS_GENAI_ATTRIBUTES.OPERATION_NAME]).toBe('execute_tool');
    expect(span.attributes[AEGIS_GENAI_ATTRIBUTES.PROVIDER_NAME]).toBe('aegis');
    expect(span.attributes[AEGIS_GENAI_ATTRIBUTES.TOOL_NAME]).toBe('sql_query');
    expect(typeof span.attributes[AEGIS_GENAI_ATTRIBUTES.TOOL_CALL_ID]).toBe('string');
    expect((span.attributes[AEGIS_GENAI_ATTRIBUTES.TOOL_CALL_ID] as string).length).toBeGreaterThan(0);
  });

  it('blocked verdict → STATUS_CODE_ERROR + error.type + content-free violation events', () => {
    const engine = engineWithPacks();
    const verdict = engine.evaluate(MALICIOUS_CALL);
    expect(verdict.allowed).toBe(false);
    const span = formatGenAiExecuteToolSpan(MALICIOUS_CALL, verdict);
    expect(span.status.code).toBe('STATUS_CODE_ERROR');
    expect(String(span.attributes[AEGIS_GENAI_ATTRIBUTES.ERROR_TYPE])).toMatch(/^aegis_policy_violation:/);
    expect(span.events.length).toBe(verdict.violations.length);
    for (const ev of span.events) {
      expect(ev.name).toBe('aegis.rule.violation');
      expect(ev.attributes).toBeDefined();
      expect(ev.attributes!['aegis.rule.id']).toBeDefined();
    }
  });

  it('allowed verdict → STATUS_CODE_OK, no error.type, no events', () => {
    const engine = engineWithPacks();
    const verdict = engine.evaluate(BENIGN_CALL);
    expect(verdict.allowed).toBe(true);
    const span = formatGenAiExecuteToolSpan(BENIGN_CALL, verdict);
    expect(span.status.code).toBe('STATUS_CODE_OK');
    expect(span.attributes[AEGIS_GENAI_ATTRIBUTES.ERROR_TYPE]).toBeUndefined();
    expect(span.events).toHaveLength(0);
  });

  it('ZERO CONTENT CAPTURE: tool params never appear anywhere in the span (PII-safe)', () => {
    const engine = engineWithPacks();
    const verdict = engine.evaluate(MALICIOUS_CALL);
    const span = formatGenAiExecuteToolSpan(MALICIOUS_CALL, verdict);
    const serialized = JSON.stringify(span);
    // Distinctive payload tokens (values) must be absent …
    expect(serialized).not.toContain('DROP TABLE');
    expect(serialized).not.toContain('admin');
    expect(serialized).not.toContain("'1'='1'");
    // … and no params object/key structure is captured at all
    expect(serialized).not.toContain('"params"');
    expect(Object.keys(span.attributes).some((k) => k.startsWith('aegis.tool.params'))).toBe(false);
  });

  it('end - start equals verdict latency within rounding', () => {
    const engine = engineWithPacks();
    const verdict = engine.evaluate(BENIGN_CALL);
    const span = formatGenAiExecuteToolSpan(BENIGN_CALL, verdict);
    const durationMs = Number(BigInt(span.endTimeUnixNano) - BigInt(span.startTimeUnixNano)) / 1_000_000;
    expect(Math.abs(durationMs - verdict.latencyMs)).toBeLessThanOrEqual(0.001);
  });

  it('duration observation is in SECONDS with semconv metric name and unit', () => {
    const engine = engineWithPacks();
    const verdict = engine.evaluate(BENIGN_CALL);
    const span = formatGenAiExecuteToolSpan(BENIGN_CALL, verdict);
    const obs = formatGenAiDurationObservation(span);
    expect(obs.metric).toBe('gen_ai.client.operation.duration');
    expect(obs.unit).toBe('s');
    expect(obs.valueSeconds).toBeGreaterThan(0);
    expect(obs.valueSeconds).toBeLessThan(1); // sub-millisecond-ish work stays sub-second
  });

  it('legacy aegis.* attribute formatter still works (backward compat)', () => {
    const engine = engineWithPacks();
    const verdict = engine.evaluate(MALICIOUS_CALL);
    const attrs = formatOtelSpanAttributes(MALICIOUS_CALL, verdict);
    expect(attrs['aegis.verdict.allowed']).toBe(false);
    expect(attrs['aegis.violations.count']).toBeGreaterThan(0);
  });
});

describe('OTel GenAI — engine opt-in emission', () => {
  it('sink receives one GenAi span per evaluation when observability.onSpan is set', () => {
    const spans: unknown[] = [];
    const engine = new AegisEngine({
      mode: 'enforce',
      packs: ['@aegis/sql-guard'],
      observability: {
        agentName: 'billing-agent',
        onSpan: (span) => spans.push(span),
      },
    });
    engine.evaluate(BENIGN_CALL);
    engine.evaluate(MALICIOUS_CALL);
    expect(spans).toHaveLength(2);
    const s1 = spans[0] as { name: string; attributes: Record<string, unknown> };
    const s2 = spans[1] as { name: string; status: { code: string } };
    expect(s1.name).toBe('execute_tool sql_query');
    expect(s1.attributes['gen_ai.agent.name']).toBe('billing-agent');
    expect(s2.status.code).toBe('STATUS_CODE_ERROR');
  });

  it('a throwing sink must NOT break evaluation (verdict still returned)', () => {
    const engine = new AegisEngine({
      mode: 'enforce',
      packs: ['@aegis/sql-guard'],
      observability: {
        onSpan: () => {
          throw new Error('sink down');
        },
      },
    });
    expect(() => engine.evaluate(BENIGN_CALL)).not.toThrow();
    const verdict = engine.evaluate(MALICIOUS_CALL);
    expect(verdict.allowed).toBe(false);
  });

  it('default (no observability config) changes nothing', () => {
    const engine = engineWithPacks();
    const verdict = engine.evaluate(BENIGN_CALL);
    expect(verdict.allowed).toBe(true);
    expect(verdict.latencyMs).toBeGreaterThanOrEqual(0);
  });
});
