import * as fs from 'node:fs';
import * as path from 'node:path';
import { randomUUID } from 'node:crypto';
import type { AegisEvent, AegisFramework, AegisMode, AegisViolation } from './types.js';

// Pre-compiled high-recall patterns for in-flight telemetry redaction
const REDACTION_PATTERNS = [
  { name: 'SSN', regex: /\b\d{3}-\d{2}-\d{4}\b/g, replacement: '[REDACTED_SSN]' },
  { name: 'CARD', regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/g, replacement: '[REDACTED_CARD]' },
  { name: 'KEY', regex: /\b(?:sk-[a-zA-Z0-9_-]{20,}|ghp_[a-zA-Z0-9]{36,}|AKIA[0-9A-Z]{16})\b/g, replacement: '[REDACTED_SECRET]' },
  { name: 'EMAIL', regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, replacement: '[REDACTED_EMAIL]' },
];

export function redactPiiString(input: string): string {
  let result = input;
  for (const { regex, replacement } of REDACTION_PATTERNS) {
    result = result.replace(regex, replacement);
  }
  return result;
}

export function redactViolations(violations: AegisViolation[]): AegisViolation[] {
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
  }): AegisEvent {
    const timestamp = new Date().toISOString();
    // Apply structured in-flight PII redaction before writing to telemetry log
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
      this.writeEvent(event);
    }

    return event;
  }

  private writeEvent(event: AegisEvent): void {
    try {
      this.rotateIfNeeded();
      const line = JSON.stringify(event) + '\n';
      fs.appendFileSync(this.logPath, line, 'utf8');
    } catch {
      // Fail-safe
    }
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
      if (!fs.existsSync(this.logPath)) return [];
      const content = fs.readFileSync(this.logPath, 'utf8');
      const lines = content.trim().split('\n').filter(Boolean);
      return lines
        .slice(-limit)
        .map((l) => JSON.parse(l) as AegisEvent);
    } catch {
      return [];
    }
  }
}
