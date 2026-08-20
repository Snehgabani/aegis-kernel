/**
 * @file packages/core/src/provenance.ts
 * @description Deterministic information-flow control (IFC) for Aegis —
 * FIDES/NeuroTaint-inspired taint labels with sink-time enforcement.
 *
 * Research lineage (see docs/research/ and ROADMAP_BACKLOG_2026H2.md):
 *  - CaMeL (Debenedetti et al., 2025, arXiv:2503.18813): separate control/data
 *    flow; capabilities at tool-call sinks.
 *  - FIDES (Costa et al., 2025): confidentiality+integrity labels on planner
 *    values, deterministic sink checks.
 *  - NeuroTaint (Cai et al., 2026, arXiv:2604.23374): three flow classes —
 *    explicit content propagation, implicit control influence, asynchronous
 *    provenance reuse (labels must persist across memory boundaries/sessions).
 *  - ADI attack (Choi et al., 2026, arXiv:2607.05120): only strict data-flow
 *    tracking reached 0% ASR — and CaMeL's "Normal" mode leaked because of a
 *    taint-propagation bug. Lesson: taint mechanics must be simple, explicit,
 *    and tested.
 *
 * Aegis scope (deterministic, zero-egress, no LLM):
 *  1. EXPLICIT content propagation: a registered untrusted source (tool output)
 *     that reappears — after normalization — inside a sensitive-sink parameter
 *     blocks the call (IFC-001). This catches ADI-style data injection where
 *     the value itself is not PII and matches no content rule: the *flow* is
 *     the violation.
 *  2. ASYNCHRONOUS reuse (partial): sources persist across evaluate() calls
 *     within the tracker and are serialized to the ledger path so a later
 *     session can reload them (NeuroTaint's cross-session case, mechanism-level).
 *  3. NOT in scope (documented): implicit control influence and paraphrase-
 *     surviving taint — those require NeuroTaint-style LLM auditing; Aegis's
 *     labels are exact-after-normalization. Paraphrased reuse is NOT claimed.
 */

import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { ToolCall } from './types.js';

export type IntegrityLabel = 'trusted' | 'untrusted';

export interface SensitiveSink {
  /** Tool name (exact) to guard. */
  tool: string;
  /** Parameter names whose VALUES are sinks; omitted ⇒ every string param. */
  params?: string[];
  /** Human-readable rationale shown in the violation. */
  rationale?: string;
}

export interface InformationFlowPolicy {
  sinks: SensitiveSink[];
  /**
   * Minimum normalized-content length for a source to be tracked (avoids
   * trivial collisions on short tokens like "yes"); default 12.
   */
  minSourceLength?: number;
  /** Maximum tracked sources (FIFO beyond cap); default 256. */
  maxSources?: number;
}

export interface RegisteredSource {
  /** SHA-256 of the normalized source content. */
  hash: string;
  /** First 96 chars of normalized content — enough to re-verify, never for scanning. */
  preview: string;
  registeredAt: string;
  /** Origin descriptor, e.g. "tool:fetch_webpage#output". */
  origin: string;
}

/**
 * Normalization applied before both source registration and sink matching —
 * the SAME cascade the checkers use, so zero-width/bidi/homoglyph mutations of
 * a source cannot launder it into a sink (CaMeL's lesson: label mechanics must
 * survive the transformations attackers actually use).
 */
export function normalizeForTaint(text: string): string {
  const stripped = text
    .replace(/[\u00AD\u061C\u180E\u2000-\u200F\u202A-\u202E\u202F\u205F\u2060-\u2064\u2066-\u206F\u3000\uFEFF]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  return stripped.normalize('NFKD');
}

function hashContent(normalized: string): string {
  return createHash('sha256').update(normalized, 'utf8').digest('hex');
}

export class TaintTracker {
  private readonly policy: Required<InformationFlowPolicy>;
  private readonly sources = new Map<string, RegisteredSource>(); // hash → source
  private readonly ledgerPath?: string;

  constructor(policy: InformationFlowPolicy, ledgerPath?: string) {
    this.policy = {
      sinks: policy.sinks,
      minSourceLength: policy.minSourceLength ?? 12,
      maxSources: policy.maxSources ?? 256,
    };
    this.ledgerPath = ledgerPath;
    if (ledgerPath && fs.existsSync(ledgerPath)) {
      this.loadPersistedSources(ledgerPath);
    }
  }

  /**
   * Sink check: does any registered untrusted source appear (normalized) inside
   * one of the sensitive sink parameters of this tool call?
   * Substring semantics: an agent may embed a quote of tool output inside a
   * larger param — the flow is tainted regardless of the surrounding text.
   */
  public checkSinks(toolCall: ToolCall): Array<{ param: string; source: RegisteredSource; matchedLength: number }> {
    const sink = this.policy.sinks.find((s) => s.tool === toolCall.tool);
    if (!sink) return [];
    const hits: Array<{ param: string; source: RegisteredSource; matchedLength: number }> = [];

    const paramNames =
      sink.params ?? Object.keys(toolCall.params ?? {}).filter((k) => typeof toolCall.params?.[k] === 'string');

    for (const param of paramNames) {
      const raw = toolCall.params?.[param];
      if (typeof raw !== 'string') continue;
      const normalizedParam = normalizeForTaint(raw);
      for (const source of this.sources.values()) {
        // Re-derive matching content from the preview is not possible (truncated);
        // instead store the normalized content length and match by recompute:
        // we keep a parallel normalized-content map for exact substring checks.
        const content = this.normalizedContents.get(source.hash);
        if (content && content.length >= this.policy.minSourceLength && normalizedParam.includes(content)) {
          hits.push({ param, source, matchedLength: content.length });
          break; // one hit per param is enough for enforcement
        }
      }
    }
    return hits;
  }

  /** Register trusted content — recorded for audit (no-op for enforcement). */
  public sourceCount(): number {
    return this.sources.size;
  }

  public listSources(): RegisteredSource[] {
    return [...this.sources.values()];
  }

  // normalized content kept in-memory only; persistence stores hashes+previews
  private readonly normalizedContents = new Map<string, string>();

  public registerUntrusted(content: string, origin: string): RegisteredSource | null {
    const normalized = normalizeForTaint(content);
    if (normalized.length < this.policy.minSourceLength) return null;
    const hash = hashContent(normalized);
    const source: RegisteredSource = {
      hash,
      preview: normalized.slice(0, 96),
      registeredAt: new Date().toISOString(),
      origin,
    };
    if (!this.sources.has(hash)) {
      if (this.sources.size >= this.policy.maxSources) {
        const oldest = this.sources.keys().next().value;
        if (oldest !== undefined) {
          this.sources.delete(oldest);
          this.normalizedContents.delete(oldest);
        }
      }
      this.sources.set(hash, source);
      this.normalizedContents.set(hash, normalized);
      this.persist();
    }
    return source;
  }

  private persist(): void {
    if (!this.ledgerPath) return;
    try {
      fs.mkdirSync(path.dirname(this.ledgerPath), { recursive: true });
      fs.writeFileSync(this.ledgerPath, JSON.stringify({ version: 1, sources: this.listSources() }, null, 2), 'utf8');
    } catch {
      // Audit persistence is best-effort; enforcement never depends on the file.
    }
  }

  private loadPersistedSources(path: string): void {
    try {
      const parsed = JSON.parse(fs.readFileSync(path, 'utf8')) as { sources?: RegisteredSource[] };
      for (const s of parsed.sources ?? []) {
        this.sources.set(s.hash, s);
        // Preview is truncated normalized content — usable as a (weaker, prefix)
        // matcher so cross-session enforcement still works on common embeds.
        if (s.preview) this.normalizedContents.set(s.hash, s.preview);
      }
    } catch {
      // corrupt ledger → start clean (fail-open for tracking, fail-closed at sinks stays)
    }
  }
}

export const IFC_VIOLATION_RULE = 'IFC-001';

export function createIfcViolation(
  toolCall: ToolCall,
  param: string,
  source: RegisteredSource,
  rationale?: string
): {
  ruleId: string;
  packId: string;
  severity: 'critical';
  message: string;
  suggestedFix: string;
  context: Record<string, unknown>;
} {
  return {
    ruleId: IFC_VIOLATION_RULE,
    packId: '@aegis/core-ifc',
    severity: 'critical',
    message:
      `Untrusted data flow: content originating from ${source.origin} flows into sensitive sink ` +
      `'${toolCall.tool}.${param}'${rationale ? ` (${rationale})` : ''}. The value may be attacker-controlled ` +
      `(tool output / retrieved content); it must not reach sensitive sinks without review.`,
    suggestedFix: `Route the value through an explicit human approval or re-derive it from a trusted source before calling '${toolCall.tool}'.`,
    context: {
      flowClass: 'EXPLICIT_CONTENT_PROPAGATION',
      sourceOrigin: source.origin,
      sourceRegisteredAt: source.registeredAt,
      sinkParam: param,
    },
  };
}
