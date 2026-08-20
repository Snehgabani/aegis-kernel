/**
 * Aegis Invariant Kernel - OpenTelemetry (OTel) Semantic Conventions
 *
 * Provides standardized OpenTelemetry trace attributes and span formatting
 * for integration with Datadog, Grafana, Dynatrace, Langfuse, and Arize Phoenix.
 */

import type { AegisVerdict, ToolCall } from '../types.js';
import { computeToolCallFingerprint } from '../verdict.js';

export const AEGIS_OTEL_ATTRIBUTES = {
  SYSTEM: 'aegis.system',
  TOOL_NAME: 'aegis.tool.name',
  VERDICT_ALLOWED: 'aegis.verdict.allowed',
  MODE: 'aegis.verdict.mode',
  LATENCY_MS: 'aegis.evaluation.latency_ms',
  PROOF_HASH: 'aegis.proof.hash',
  VIOLATIONS_COUNT: 'aegis.violations.count',
  VIOLATIONS_RULE_IDS: 'aegis.violations.rule_ids',
  FINGERPRINT: 'aegis.fingerprint',
} as const;

export function formatOtelSpanAttributes(
  toolCall: ToolCall,
  verdict: AegisVerdict
): Record<string, string | number | boolean | string[]> {
  return {
    [AEGIS_OTEL_ATTRIBUTES.SYSTEM]: 'aegis-invariant-kernel',
    [AEGIS_OTEL_ATTRIBUTES.TOOL_NAME]: toolCall.tool,
    [AEGIS_OTEL_ATTRIBUTES.VERDICT_ALLOWED]: verdict.allowed,
    [AEGIS_OTEL_ATTRIBUTES.MODE]: verdict.mode,
    [AEGIS_OTEL_ATTRIBUTES.LATENCY_MS]: verdict.latencyMs,
    [AEGIS_OTEL_ATTRIBUTES.PROOF_HASH]: verdict.proofHash,
    [AEGIS_OTEL_ATTRIBUTES.VIOLATIONS_COUNT]: verdict.violations.length,
    [AEGIS_OTEL_ATTRIBUTES.VIOLATIONS_RULE_IDS]: verdict.violations.map((v) => v.ruleId),
    [AEGIS_OTEL_ATTRIBUTES.FINGERPRINT]: computeToolCallFingerprint(toolCall),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// OpenTelemetry GenAI Semantic Conventions (added 2026-08-20)
//
// Follows the GenAI semconv shape that all major backends (Datadog, Grafana,
// Langfuse, Arize, Braintrust) ingest natively in 2026:
//   span name:  "execute_tool {tool}"        (operation + resource name)
//   required:   gen_ai.operation.name, gen_ai.provider.name
//   recommended: gen_ai.tool.name, gen_ai.tool.call.id, error.type
//   metric:     gen_ai.client.operation.duration (histogram, unit "s")
//
// SECURITY INVARIANTS OF THIS FORMATTER:
//   1. ZERO CONTENT CAPTURE — tool params never appear in span attributes or
//      events (GenAI semconv keeps content in opt-in events; Aegis omits it
//      entirely: deterministic verdicts need no payload sampling, and params
//      are exactly where PII lives).
//   2. ZERO EGRESS — formatting only; export is the deployer's responsibility
//      via their own sink (see AegisConfig.observability.onSpan).
// ─────────────────────────────────────────────────────────────────────────────

export const AEGIS_GENAI_ATTRIBUTES = {
  OPERATION_NAME: 'gen_ai.operation.name',
  PROVIDER_NAME: 'gen_ai.provider.name',
  TOOL_NAME: 'gen_ai.tool.name',
  TOOL_CALL_ID: 'gen_ai.tool.call.id',
  AGENT_NAME: 'gen_ai.agent.name',
  ERROR_TYPE: 'error.type',
} as const;

/** OTLP span kind (numeric per OTLP JSON): 1 = INTERNAL, 2 = SERVER, 3 = CLIENT. */
export type OtlpSpanKind = 1 | 2 | 3;

export interface GenAiSpanEvent {
  name: string;
  timeUnixNano: string;
  attributes?: Record<string, string | number | boolean>;
}

export interface GenAiSpan {
  /** OTLP-JSON shaped traceable span (single-span resourceSpans element). */
  traceId: string;
  spanId: string;
  name: string;
  kind: OtlpSpanKind;
  startTimeUnixNano: string;
  endTimeUnixNano: string;
  attributes: Record<string, string | number | boolean | string[]>;
  events: GenAiSpanEvent[];
  status: { code: 'STATUS_CODE_UNSET' | 'STATUS_CODE_OK' | 'STATUS_CODE_ERROR' };
}

export interface GenAiDurationObservation {
  /** gen_ai.client.operation.duration histogram observation — seconds, per semconv. */
  metric: 'gen_ai.client.operation.duration';
  unit: 's';
  valueSeconds: number;
  attributes: Record<string, string>;
}

/** Span name per GenAI semconv naming pattern: "{operation} {resource}". */
export function formatGenAiSpanName(toolName: string): string {
  return `execute_tool ${toolName}`;
}

function toUnixNano(iso: string): string {
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? String(BigInt(ms) * 1_000_000n) : String(Date.now() * 1_000_000);
}

function randomHexBytes(bytes: number): string {
  let out = '';
  for (let i = 0; i < bytes; i++) {
    out += Math.floor(Math.random() * 256).toString(16).padStart(2, '0');
  }
  return out;
}

export interface GenAiSpanOptions {
  agentName?: string;
  /** Deterministic ids for tests/reproducibility. */
  traceId?: string;
  spanId?: string;
  /** Evaluation timestamp (ISO); defaults to now, minus verdict latency. */
  evaluationTimeIso?: string;
}

/**
 * Formats a complete GenAI-conformant `execute_tool` span for one Aegis
 * evaluation. Content-free by construction (params never included).
 */
export function formatGenAiExecuteToolSpan(
  toolCall: ToolCall,
  verdict: AegisVerdict,
  options?: GenAiSpanOptions
): GenAiSpan {
  const endTimeIso = options?.evaluationTimeIso ?? new Date().toISOString();
  const endUnixNano = toUnixNano(endTimeIso);
  const startUnixNano = String(BigInt(endUnixNano) - BigInt(Math.max(0, Math.round(verdict.latencyMs * 1_000_000))));
  const blocked = !verdict.allowed;

  const attributes: Record<string, string | number | boolean | string[]> = {
    [AEGIS_GENAI_ATTRIBUTES.OPERATION_NAME]: 'execute_tool',
    [AEGIS_GENAI_ATTRIBUTES.PROVIDER_NAME]: 'aegis',
    [AEGIS_GENAI_ATTRIBUTES.TOOL_NAME]: toolCall.tool,
    [AEGIS_GENAI_ATTRIBUTES.TOOL_CALL_ID]: computeToolCallFingerprint(toolCall),
    ...formatOtelSpanAttributes(toolCall, verdict),
  };
  if (options?.agentName) {
    attributes[AEGIS_GENAI_ATTRIBUTES.AGENT_NAME] = options.agentName;
  }
  if (blocked) {
    attributes[AEGIS_GENAI_ATTRIBUTES.ERROR_TYPE] = `aegis_policy_violation:${
      verdict.violations[0]?.ruleId ?? 'unknown'
    }`;
  }

  const events: GenAiSpanEvent[] = verdict.violations.map((v) => ({
    name: 'aegis.rule.violation',
    timeUnixNano: endUnixNano,
    attributes: {
      'aegis.rule.id': v.ruleId,
      'aegis.rule.severity': v.severity,
    },
  }));

  return {
    traceId: options?.traceId ?? randomHexBytes(16),
    spanId: options?.spanId ?? randomHexBytes(8),
    name: formatGenAiSpanName(toolCall.tool),
    kind: 1,
    startTimeUnixNano: startUnixNano,
    endTimeUnixNano: endUnixNano,
    attributes,
    events,
    status: { code: blocked ? 'STATUS_CODE_ERROR' : 'STATUS_CODE_OK' },
  };
}

/** Histogram observation for gen_ai.client.operation.duration (seconds). */
export function formatGenAiDurationObservation(span: GenAiSpan): GenAiDurationObservation {
  const durationNs = Number(BigInt(span.endTimeUnixNano) - BigInt(span.startTimeUnixNano));
  return {
    metric: 'gen_ai.client.operation.duration',
    unit: 's',
    valueSeconds: Math.round((durationNs / 1_000_000_000) * 1e6) / 1e6,
    attributes: {
      [AEGIS_GENAI_ATTRIBUTES.OPERATION_NAME]: 'execute_tool',
      [AEGIS_GENAI_ATTRIBUTES.PROVIDER_NAME]: 'aegis',
    },
  };
}
