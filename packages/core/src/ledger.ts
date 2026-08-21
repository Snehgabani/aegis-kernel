import * as fs from 'node:fs';
import * as path from 'node:path';
import type { AegisEvent, LearningLedger } from './types.js';

export class LearningLedgerManager {
  private ledgerPath: string;
  private ledger: LearningLedger;
  private saveTimeout: NodeJS.Timeout | null = null;
  private isDirty = false;

  constructor(ledgerPath?: string) {
    this.ledgerPath = ledgerPath ?? '.aegis/learning-ledger.json';
    this.ledger = this.loadLedger();
  }

  private loadLedger(): LearningLedger {
    try {
      if (fs.existsSync(this.ledgerPath)) {
        const raw = fs.readFileSync(this.ledgerPath, 'utf8');
        const parsed = JSON.parse(raw) as LearningLedger;

        // Clean migration of legacy fields if present
        if (parsed.rulePerformance) {
          for (const ruleId of Object.keys(parsed.rulePerformance)) {
            const r = parsed.rulePerformance[ruleId];
            r.overridesCount = r.overridesCount ?? 0;
            r.timesFired = r.timesFired ?? 0;
            r.overrideRatio = r.timesFired > 0 ? r.overridesCount / r.timesFired : 0;
            r.triageStatus = r.triageStatus ?? 'healthy';
          }
        }
        return parsed;
      }
    } catch {
      // Return clean ledger on error
    }

    return {
      totalEventsProcessed: 0,
      totalBlocked: 0,
      totalAllowed: 0,
      totalOverrides: 0,
      rulePerformance: {},
      uncoveredTools: {},
      lastUpdated: new Date().toISOString(),
    };
  }

  public recordEvent(event: AegisEvent): void {
    this.ledger.totalEventsProcessed += 1;
    if (event.verdict === 'BLOCKED') {
      this.ledger.totalBlocked += 1;
    } else {
      this.ledger.totalAllowed += 1;
    }

    // Reuse the event timestamp (already rendered ISO string) — the ledger
    // update is logically the same instant; avoids a second toISOString() on
    // every hot-path evaluation.
    if (event.timestamp) {
      this.ledger.lastUpdated = event.timestamp;
    }

    if (event.userOverride) {
      this.ledger.totalOverrides += 1;
    }

    // Track rules operational performance
    for (const violation of event.rulesFired) {
      const ruleId = violation.ruleId;
      if (!this.ledger.rulePerformance[ruleId]) {
        this.ledger.rulePerformance[ruleId] = {
          timesEvaluated: 0,
          timesFired: 0,
          overridesCount: 0,
          overrideRatio: 0.0,
          averageLatencyMs: event.latencyMs,
          triageStatus: 'healthy',
          lastFired: event.timestamp,
        };
      }

      const perf = this.ledger.rulePerformance[ruleId];
      perf.timesFired += 1;
      perf.lastFired = event.timestamp;
      perf.averageLatencyMs = (perf.averageLatencyMs + event.latencyMs) / 2;

      if (event.userOverride) {
        perf.overridesCount = (perf.overridesCount ?? 0) + 1;
      }

      // Override Ratio: bounded [0.0, 1.0] representing friction / override frequency
      const overrides = perf.overridesCount ?? 0;
      perf.overrideRatio = perf.timesFired > 0 ? overrides / perf.timesFired : 0;

      // Status triaging based on override frequency (high overrides = needs review)
      if (perf.overrideRatio > 0.30 && perf.timesFired >= 5) {
        perf.triageStatus = 'review_needed';
      } else if (perf.overrideRatio > 0.60 && perf.timesFired >= 10) {
        perf.triageStatus = 'quarantined';
      } else {
        perf.triageStatus = 'healthy';
      }
    }

    // Track uncovered tool calls for policy gaps
    if (event.rulesEvaluated === 0) {
      this.ledger.uncoveredTools[event.toolName] =
        (this.ledger.uncoveredTools[event.toolName] ?? 0) + 1;
    }

    this.isDirty = true;
    this.schedulePersist();
  }

  public recordOverride(
    _proofHash: string,
    _override: { reason?: string; tag?: 'true_positive' | 'false_positive' | 'unsure' }
  ): void {
    this.ledger.totalOverrides += 1;
    this.ledger.lastUpdated = new Date().toISOString();
    this.isDirty = true;
    this.schedulePersist();
  }

  public getSummary(): LearningLedger {
    return { ...this.ledger };
  }

  private schedulePersist(): void {
    if (this.saveTimeout) return;
    this.saveTimeout = setTimeout(() => {
      this.saveTimeout = null;
      this.flushSync();
    }, 100);
    if (typeof (this.saveTimeout as any).unref === 'function') {
      (this.saveTimeout as any).unref();
    }
  }

  public flushSync(): void {
    if (!this.isDirty) return;
    this.isDirty = false;
    try {
      const dir = path.dirname(this.ledgerPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      // Auto-compact uncovered tools dictionary if it exceeds 1,000 unique tools
      const toolKeys = Object.keys(this.ledger.uncoveredTools);
      if (toolKeys.length > 1000) {
        // Keep top 500 most frequently called uncovered tools
        const sorted = toolKeys.sort(
          (a, b) => this.ledger.uncoveredTools[b] - this.ledger.uncoveredTools[a]
        );
        const compacted: Record<string, number> = {};
        for (const key of sorted.slice(0, 500)) {
          compacted[key] = this.ledger.uncoveredTools[key];
        }
        this.ledger.uncoveredTools = compacted;
      }

      const serialized = JSON.stringify(this.ledger, null, 2);
      fs.writeFileSync(this.ledgerPath, serialized, 'utf8');
    } catch {
      // Fail-safe
    }
  }
}
