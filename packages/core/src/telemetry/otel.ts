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
