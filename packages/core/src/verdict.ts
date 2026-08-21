import { createHash } from 'node:crypto';
import type { AegisMode, AegisVerdict, AegisViolation, RulePack, ToolCall } from './types.js';

/**
 * Hot-path fingerprint serialization.
 *
 * The overwhelmingly common case (plain JSON data: strings/numbers/booleans/
 * null, nested objects & arrays — no BigInt, no circular references) is served
 * by native `JSON.stringify` with NO replacer callback and NO per-call `Set`
 * allocation. `JSON.stringify` throws on BigInt and circular structures; only
 * then do we fall back to the replacer-based canonical serializer (identical
 * semantics to the historical implementation, used by the vast majority of
 * callers for whom the fast path applies).
 *
 * The output is byte-identical to the previous implementation for every input
 * that does not throw, so proof hashes and committed fingerprints are
 * unchanged on benign traffic (pure-function property is preserved: same input
 * ⇒ same hash; different canonical JSON ⇒ different hash).
 */
const CIRCULAR_REPLACER = (_key: string, value: unknown): unknown => {
  if (typeof value === 'bigint') {
    return value.toString();
  }
  return value;
};

export function computeToolCallFingerprint(toolCall: ToolCall): string {
  let json: string;
  try {
    json = JSON.stringify({ tool: toolCall.tool, params: toolCall.params });
  } catch {
    // BigInt or circular structure → historical replacer semantics.
    const cache = new Set<object>();
    json = JSON.stringify(
      { tool: toolCall.tool, params: toolCall.params },
      (key, value) => {
        if (typeof value === 'object' && value !== null) {
          if (cache.has(value)) {
            return '[Circular]';
          }
          cache.add(value);
        }
        return CIRCULAR_REPLACER(key, value);
      }
    );
  }
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
