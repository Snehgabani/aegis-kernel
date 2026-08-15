/**
 * Aegis Invariant Kernel — Observability Integrations
 *
 * Direct payload formatters and export hooks for Langfuse, Arize Phoenix,
 * and Datadog APM tracing dashboards.
 */

import type { AegisVerdict, ToolCall } from '../types.js';

export interface LangfuseObservationMetadata {
  name: string;
  type: 'GUARDRAIL';
  level: 'DEFAULT' | 'WARNING' | 'ERROR';
  statusMessage: string;
  metadata: {
    toolName: string;
    verdict: 'ALLOWED' | 'BLOCKED';
    latencyMs: number;
    violationsCount: number;
    violatedRules: string[];
    suggestedFix?: string;
    proofHash: string;
  };
}

export function formatLangfuseEvent(toolCall: ToolCall, verdict: AegisVerdict): LangfuseObservationMetadata {
  return {
    name: `aegis-guardrail:${toolCall.tool}`,
    type: 'GUARDRAIL',
    level: verdict.allowed ? 'DEFAULT' : 'ERROR',
    statusMessage: verdict.allowed ? 'CLEARED' : `BLOCKED: ${verdict.violations.map((v) => v.ruleId).join(', ')}`,
    metadata: {
      toolName: toolCall.tool,
      verdict: verdict.allowed ? 'ALLOWED' : 'BLOCKED',
      latencyMs: verdict.latencyMs,
      violationsCount: verdict.violations.length,
      violatedRules: verdict.violations.map((v) => v.ruleId),
      suggestedFix: verdict.suggestedFix,
      proofHash: verdict.proofHash,
    },
  };
}

export interface ArizePhoenixEvaluationEvent {
  eval_name: 'aegis_tool_clearance';
  score: number; // 1.0 = safe/allowed, 0.0 = blocked violation
  label: 'safe' | 'unsafe';
  explanation: string;
  latency_ms: number;
  metadata: Record<string, unknown>;
}

export function formatArizePhoenixEvent(toolCall: ToolCall, verdict: AegisVerdict): ArizePhoenixEvaluationEvent {
  return {
    eval_name: 'aegis_tool_clearance',
    score: verdict.allowed ? 1.0 : 0.0,
    label: verdict.allowed ? 'safe' : 'unsafe',
    explanation: verdict.allowed
      ? 'All deterministic AST and state invariants satisfied.'
      : `Violations: ${verdict.violations.map((v) => `[${v.ruleId}] ${v.message}`).join('; ')}`,
    latency_ms: verdict.latencyMs,
    metadata: {
      tool: toolCall.tool,
      proofHash: verdict.proofHash,
      violations: verdict.violations,
    },
  };
}
