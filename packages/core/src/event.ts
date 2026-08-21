import * as fs from 'node:fs';
import * as path from 'node:path';
import { randomUUID } from 'node:crypto';
import type { AegisEvent, AegisFramework, AegisMode, AegisViolation } from './types.js';

// Pre-compiled high-recall patterns for in-flight telemetry redaction.
// CARD patterns are separator-tolerant (spaces AND dashes) so formatted
// PANs never reach the audit log.
const REDACTION_PATTERNS = [
  { name: 'SSN', regex: /\b\d{3}-\d{2}-\d{4}\b/g, replacement: '[REDACTED_SSN]' },
  {
    name: 'CARD',
    regex: /\b(?:\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}|\d{16}|4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/g,
    replacement: '[REDACTED_CARD]',
  },
  { name: 'KEY', regex: /\b(?:sk-[a-zA-Z0-9_-]{20,}|ghp_[a-zA-Z0-9]{36,}|AKIA[0-9A-Z]{16})\b/g, replacement: '[REDACTED_SECRET]' },
  { name: 'EMAIL', regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, replacement: '[REDACTED_EMAIL]' },
];

export function redactPiiString(input: string): string {
  // Normalize first (NFKD fullwidth/homoglyph collapse + strip zero-width &
  // bidi controls) so obfuscated secrets are redacted too — same policy as
  // AegisSanitizer. Audit logs must not leak what the hot path would mask.
  const normalized = input
    .normalize('NFKD')
    .replace(/[\u200b-\u200d\u200e\u200f\u2060\uFEFF\u202a-\u202e\u00ad]/g, '');
  let result = normalized;
  for (const { regex, replacement } of REDACTION_PATTERNS) {
    result = result.replace(regex, replacement);
  }
  return result;
}

export function redactViolations(violations: AegisViolation[]): AegisViolation[] {
  if (violations.length === 0) return violations;
  return violations.map((v) => ({
    ...v,
    message: redactPiiString(v.message),
    suggestedFix: v.suggestedFix ? redactPiiString(v.suggestedFix) : undefined,
  }));
}

export class AegisEventLogger {
  private logPath: string;
  private enabled: boolean;
  private maxFileSizeMb: number;
  private version: string;

  // --- Hot-path write batching -------------------------------------------------
  // Every evaluate() previously issued `fs.statSync` + `fs.appendFileSync`
  // (plus a JSON serialization) per event — the dominant cost of audit logging.
  // Events are now buffered in memory and flushed OFF the hot path:
  //   • a 20ms unref'd timer flushes in real event-loop applications;
  //   • a high-water mark triggers an ASYNC append (never blocks the caller);
  //   • reads merge buffered + on-disk events (no flush required);
  //   • `beforeExit` drains the write chain so no event is lost and ordering
  //     is preserved (a synchronous `exit` hook covers the pathological case
  //     where the loop cannot unwind).
  // All appends are serialized through a promise chain (strict FIFO ordering).
  private pendingLines: string[] = [];
  private pendingCount = 0;
  private flushTimer: NodeJS.Timeout | null = null;
  private writeChain: Promise<unknown> = Promise.resolve();
  private asyncWritesInFlight = 0;
  private lifecycleHooksRegistered = false;
  private static readonly FLUSH_INTERVAL_MS = 20;
  // High-water mark for the ASYNC append path. Generous on purpose: the timer
  // covers real event-loop apps (buffer stays tiny); a fully synchronous hot
  // loop should not pay a per-batch join cost more than ~12× per 50k calls
  // (i.e. outside the P99 tail). Worst-case buffering is bounded at
  // THRESHOLD × ~350 B ≈ 1.4 MB per logger.
  private static readonly FLUSH_THRESHOLD = 4096;
  // Chunks handed to the OS as ONE write() syscall (O_APPEND ⇒ atomic across
  // concurrent writers). If a batch were written as one large buffer, libuv
  // would split it into multiple syscalls and two processes sharing the same
  // audit file could splice two events mid-line. Chunking keeps every event
  // line whole even when multiple processes write the same log.
  private static readonly MAX_WRITE_CHUNK_BYTES = 48 * 1024;

  constructor(options?: {
    enabled?: boolean;
    path?: string;
    maxFileSizeMb?: number;
    version?: string;
  }) {
    this.enabled = options?.enabled ?? true;
    this.logPath = options?.path ?? '.aegis/events.jsonl';
    this.maxFileSizeMb = options?.maxFileSizeMb ?? 50;
    this.version = options?.version ?? '1.0.0';

    if (this.enabled) {
      this.ensureDirExists();
    }
  }

  private ensureDirExists(): void {
    try {
      const dir = path.dirname(this.logPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    } catch {
      // Fail-safe in restricted environments
    }
  }

  public logEvent(data: {
    framework?: AegisFramework;
    toolName: string;
    toolCallFingerprint: string;
    mode: AegisMode;
    verdict: 'ALLOWED' | 'BLOCKED';
    rulesEvaluated: number;
    rulesFired: AegisViolation[];
    latencyMs: number;
    proofHash: string;
    policyCommitmentHash: string;
    userOverride?: boolean;
    overrideReason?: string;
    feedbackTag?: 'true_positive' | 'false_positive' | 'unsure';
    engineError?: string;
    engineErrorStack?: string;
    timestamp?: string; // hot-path: engine already rendered an ISO timestamp
  }): AegisEvent {
    const timestamp = data.timestamp ?? new Date().toISOString();
    // Apply structured in-flight PII redaction before writing to telemetry log.
    // Empty violation lists short-circuit (no map/closure allocations).
    const sanitizedViolations = redactViolations(data.rulesFired);

    const event: AegisEvent = {
      id: randomUUID(),
      timestamp,
      version: this.version,
      framework: data.framework ?? 'raw',
      toolName: data.toolName,
      toolCallFingerprint: data.toolCallFingerprint,
      mode: data.mode,
      verdict: data.verdict,
      rulesEvaluated: data.rulesEvaluated,
      rulesFired: sanitizedViolations,
      latencyMs: data.latencyMs,
      proofHash: data.proofHash,
      policyCommitmentHash: data.policyCommitmentHash,
      userOverride: data.userOverride ?? false,
      overrideReason: data.overrideReason ? redactPiiString(data.overrideReason) : undefined,
      feedbackTag: data.feedbackTag,
      engineError: data.engineError,
      engineErrorStack: data.engineErrorStack,
    };

    if (this.enabled) {
      this.queueEvent(event);
    }

    return event;
  }

  private queueEvent(event: AegisEvent): void {
    this.pendingLines.push(JSON.stringify(event) + '\n');
    this.pendingCount++;
    if (this.pendingCount >= AegisEventLogger.FLUSH_THRESHOLD) {
      // High-water mark: dispatch an ASYNC append — the hot path never blocks.
      this.flushAsync();
      return;
    }
    if (!this.flushTimer) {
      this.flushTimer = setTimeout(() => {
        this.flushTimer = null;
        this.flushAsync();
      }, AegisEventLogger.FLUSH_INTERVAL_MS);
      if (typeof (this.flushTimer as any).unref === 'function') {
        (this.flushTimer as any).unref();
      }
    }
    this.registerLifecycleHooks();
  }

  private registerLifecycleHooks(): void {
    if (this.lifecycleHooksRegistered) return;
    this.lifecycleHooksRegistered = true;
    // beforeExit: keep the loop alive until the serialized write chain drains
    // (ordering-preserving durability). exit: best-effort synchronous drain for
    // the pathological case where the loop cannot unwind.
    process.on('beforeExit', () => this.drainOnExit());
    process.on('exit', () => {
      if (this.pendingCount === 0) return;
      try {
        this.rotateIfNeeded();
        fs.appendFileSync(this.logPath, this.pendingLines.join(''), 'utf8');
      } catch {
        // Fail-safe
      }
      this.pendingLines = [];
      this.pendingCount = 0;
    });
  }

  private drainOnExit(): void {
    if (this.pendingCount > 0) this.flushAsync();
    if (this.asyncWritesInFlight > 0 || this.pendingCount > 0) {
      setImmediate(() => this.drainOnExit());
    }
  }

  /** Move the current buffer onto the serialized async append chain. */
  private flushAsync(): void {
    if (this.pendingCount === 0) return;
    const data = this.pendingLines.join('');
    this.pendingLines = [];
    this.pendingCount = 0;
    const maxBytes = this.maxFileSizeMb * 1024 * 1024;
    this.asyncWritesInFlight++;
    this.writeChain = this.writeChain
      .then(async () => {
        try {
          // Rotation check (async — off the hot path).
          const stats = await fs.promises.stat(this.logPath);
          if (stats.size >= maxBytes) {
            const rotatedPath = `${this.logPath}.${Date.now()}.bak`;
            await fs.promises.rename(this.logPath, rotatedPath);
          }
        } catch {
          // No file yet or stat race — append will create it.
        }
        // Split into single-syscall chunks (≤ MAX_WRITE_CHUNK_BYTES) so
        // concurrent processes can never interleave mid-line.
        for (let offset = 0; offset < data.length; offset += AegisEventLogger.MAX_WRITE_CHUNK_BYTES) {
          await fs.promises.appendFile(
            this.logPath,
            data.slice(offset, offset + AegisEventLogger.MAX_WRITE_CHUNK_BYTES),
            'utf8'
          );
        }
      })
      .catch(() => {
        // Fail-safe: a failed append must never crash the process.
      })
      .finally(() => {
        this.asyncWritesInFlight--;
      });
  }

  private rotateIfNeeded(): void {
    try {
      if (!fs.existsSync(this.logPath)) return;
      const stats = fs.statSync(this.logPath);
      const maxBytes = this.maxFileSizeMb * 1024 * 1024;
      if (stats.size >= maxBytes) {
        const rotatedPath = `${this.logPath}.${Date.now()}.bak`;
        fs.renameSync(this.logPath, rotatedPath);
      }
    } catch {
      // Fail-safe
    }
  }

  public readRecentEvents(limit: number = 100): AegisEvent[] {
    try {
      // Merge on-disk events with the still-buffered tail so callers observe a
      // consistent audit trail WITHOUT forcing a synchronous flush. Malformed
      // lines (e.g. a torn line from a concurrent writer in another process)
      // are skipped, never fatal.
      const all: AegisEvent[] = [];
      if (fs.existsSync(this.logPath)) {
        const content = fs.readFileSync(this.logPath, 'utf8');
        const lines = content.split('\n');
        for (const raw of lines) {
          const l = raw.trim();
          if (!l) continue;
          try {
            all.push(JSON.parse(l) as AegisEvent);
          } catch {
            // Skip torn/corrupt line — never fail the whole read.
          }
        }
      }
      for (const line of this.pendingLines) {
        try {
          all.push(JSON.parse(line) as AegisEvent);
        } catch {
          // Skip malformed buffered line (should never happen)
        }
      }
      return all.slice(-limit);
    } catch {
      return [];
    }
  }
}
