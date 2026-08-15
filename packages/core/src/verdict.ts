import { createHash } from 'node:crypto';
import type { AegisMode, AegisVerdict, AegisViolation, RulePack, ToolCall } from './types.js';

export function computeToolCallFingerprint(toolCall: ToolCall): string {
  const cache = new Set();
  const json = JSON.stringify({
    tool: toolCall.tool,
    params: toolCall.params,
  }, (_key, value) => {
    if (typeof value === 'bigint') {
      return value.toString();
    }
    if (typeof value === 'object' && value !== null) {
      if (cache.has(value)) {
        return '[Circular]';
      }
      cache.add(value);
    }
    return value;
  });
  return createHash('sha256').update(json).digest('hex');
}

export function computePolicyCommitmentHash(packs: RulePack[]): string {
  const payload = packs
    .map((p) => `${p.id}@${p.version}:${p.rules.map((r) => r.id).sort().join(',')}`)
    .sort()
    .join('|');
  return createHash('sha256').update(payload).digest('hex');
}

export function computeProofHash(
  verdict: 'ALLOWED' | 'BLOCKED',
  toolCallFingerprint: string,
  policyCommitmentHash: string,
  timestamp: string,
  violationIds: string[]
): string {
  const payload = `${verdict}:${toolCallFingerprint}:${policyCommitmentHash}:${timestamp}:${violationIds.sort().join(',')}`;
  return createHash('sha256').update(payload).digest('hex');
}

export function createVerdict(
  violations: AegisViolation[],
  latencyMs: number,
  mode: AegisMode,
  toolCallFingerprint: string,
  policyCommitmentHash: string,
  timestamp: string,
  options?: { trustedContext?: boolean; warning?: string }
): AegisVerdict {
  const hasCritical = violations.some((v) => v.severity === 'critical');
  const allowed = mode === 'shadow' ? true : !hasCritical;

  const proofVerdict = hasCritical ? 'BLOCKED' : 'ALLOWED';
  const proofHash = computeProofHash(
    proofVerdict,
    toolCallFingerprint,
    policyCommitmentHash,
    timestamp,
    violations.map((v) => v.ruleId)
  );

  // If untrusted context (e.g. prompt injection suspect), return terse non-actionable fix to prevent information disclosure
  let suggestedFix: string | undefined;
  if (options?.trustedContext === false) {
    suggestedFix = hasCritical ? 'Action rejected per security policy.' : undefined;
  } else {
    suggestedFix = violations.find((v) => v.suggestedFix)?.suggestedFix;
  }

  return {
    allowed,
    violations,
    proofHash,
    latencyMs,
    mode,
    suggestedFix,
    warning: options?.warning,
  };
}
