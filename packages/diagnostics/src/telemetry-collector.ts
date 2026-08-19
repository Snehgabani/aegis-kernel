/**
 * Aegis Invariant Kernel — Privacy-Preserving Telemetry & Crash Intelligence Engine
 *
 * Inspired by Sentry and Datadog architectures:
 * - Deterministic error fingerprinting
 * - Sub-millisecond latency percentile histograms (P50, P95, P99)
 * - Zero-egress local aggregation
 * - Anonymized aggregate diagnostic report generation
 */

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

export interface EvaluationEvent {
  tool: string;
  allowed: boolean;
  latencyMs: number;
  violations: string[];
  timestamp?: number;
}

export interface CrashReport {
  id: string;
  timestamp: number;
  fingerprint: string;
  errorName: string;
  errorMessage: string;
  component: string;
  stackTraceHash: string;
  runtime: {
    nodeVersion: string;
    platform: string;
    arch: string;
  };
}

export interface TelemetryMetricsReport {
  totalEvaluations: number;
  allowedCount: number;
  blockedCount: number;
  blockRatePercent: number;
  latencyPercentiles: {
    p50Ms: number;
    p95Ms: number;
    p99Ms: number;
    avgMs: number;
  };
  topViolatedRules: Array<{ ruleId: string; count: number }>;
  toolDistribution: Array<{ tool: string; count: number }>;
  totalCrashes: number;
  uptimeSeconds: number;
}

export interface AnonymizedTelemetryPacket {
  version: string;
  anonymousInstallationId: string;
  metrics: TelemetryMetricsReport;
  crashFingerprints: Array<{ fingerprint: string; count: number; component: string }>;
  generatedAt: string;
}

export class AegisTelemetryCollector {
  private events: EvaluationEvent[] = [];
  private crashes: CrashReport[] = [];
  private startTime = Date.now();
  private installationId: string;

  constructor(installationId?: string) {
    this.installationId = installationId || this.getOrCreateInstallationId();
  }

  private getOrCreateInstallationId(): string {
    return crypto.createHash('sha256').update(os.hostname() + os.homedir()).digest('hex').slice(0, 16);
  }

  /**
   * Record an invariant evaluation event into local ring buffer
   */
  public recordEvaluation(event: EvaluationEvent): void {
    this.events.push({
      ...event,
      timestamp: event.timestamp || Date.now(),
    });

    // Ring-buffer ceiling to preserve memory (< 10,000 events)
    if (this.events.length > 10000) {
      this.events.shift();
    }
  }

  /**
   * Record an unhandled engine crash or AST parsing anomaly with cryptographic fingerprint
   */
  public recordCrash(error: Error, component = 'core'): CrashReport {
    const stackHash = crypto
      .createHash('sha256')
      .update(error.stack || error.message)
      .digest('hex')
      .slice(0, 12);

    const fingerprint = `${component}:${error.name}:${stackHash}`;

    const report: CrashReport = {
      id: crypto.randomUUID(),
      timestamp: Date.now(),
      fingerprint,
      errorName: error.name,
      errorMessage: error.message,
      component,
      stackTraceHash: stackHash,
      runtime: {
        nodeVersion: process.version,
        platform: os.platform(),
        arch: os.arch(),
      },
    };

    this.crashes.push(report);
    return report;
  }

  /**
   * Compute comprehensive mathematical percentiles and operational metrics
   */
  public getMetricsSummary(): TelemetryMetricsReport {
    const total = this.events.length;
    if (total === 0) {
      return {
        totalEvaluations: 0,
        allowedCount: 0,
        blockedCount: 0,
        blockRatePercent: 0,
        latencyPercentiles: { p50Ms: 0, p95Ms: 0, p99Ms: 0, avgMs: 0 },
        topViolatedRules: [],
        toolDistribution: [],
        totalCrashes: this.crashes.length,
        uptimeSeconds: Math.floor((Date.now() - this.startTime) / 1000),
      };
    }

    const allowed = this.events.filter((e) => e.allowed).length;
    const blocked = total - allowed;
    const latencies = this.events.map((e) => e.latencyMs).sort((a, b) => a - b);
    const sum = latencies.reduce((acc, v) => acc + v, 0);

    const p50 = latencies[Math.floor(total * 0.5)] || 0;
    const p95 = latencies[Math.floor(total * 0.95)] || latencies[total - 1];
    const p99 = latencies[Math.floor(total * 0.99)] || latencies[total - 1];
    const avg = sum / total;

    // Rule frequency mapping
    const ruleCounts: Record<string, number> = {};
    for (const event of this.events) {
      for (const rule of event.violations) {
        ruleCounts[rule] = (ruleCounts[rule] || 0) + 1;
      }
    }

    const topViolatedRules = Object.entries(ruleCounts)
      .map(([ruleId, count]) => ({ ruleId, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    // Tool distribution mapping
    const toolCounts: Record<string, number> = {};
    for (const event of this.events) {
      toolCounts[event.tool] = (toolCounts[event.tool] || 0) + 1;
    }

    const toolDistribution = Object.entries(toolCounts)
      .map(([tool, count]) => ({ tool, count }))
      .sort((a, b) => b.count - a.count);

    return {
      totalEvaluations: total,
      allowedCount: allowed,
      blockedCount: blocked,
      blockRatePercent: Number(((blocked / total) * 100).toFixed(2)),
      latencyPercentiles: {
        p50Ms: Number(p50.toFixed(3)),
        p95Ms: Number(p95.toFixed(3)),
        p99Ms: Number(p99.toFixed(3)),
        avgMs: Number(avg.toFixed(3)),
      },
      topViolatedRules,
      toolDistribution,
      totalCrashes: this.crashes.length,
      uptimeSeconds: Math.floor((Date.now() - this.startTime) / 1000),
    };
  }

  /**
   * Export an air-gapped, privacy-compliant diagnostic packet (zero PII)
   */
  public exportAnonymizedReport(): AnonymizedTelemetryPacket {
    const fingerprintCounts: Record<string, { count: number; component: string }> = {};
    for (const crash of this.crashes) {
      if (!fingerprintCounts[crash.fingerprint]) {
        fingerprintCounts[crash.fingerprint] = { count: 0, component: crash.component };
      }
      fingerprintCounts[crash.fingerprint].count++;
    }

    const crashFingerprints = Object.entries(fingerprintCounts).map(([fingerprint, data]) => ({
      fingerprint,
      count: data.count,
      component: data.component,
    }));

    return {
      version: '1.0.1',
      anonymousInstallationId: this.installationId,
      metrics: this.getMetricsSummary(),
      crashFingerprints,
      generatedAt: new Date().toISOString(),
    };
  }

  /**
   * Persist diagnostic snapshot to local disk (~/.aegis/telemetry)
   */
  public persistLocalSnapshot(storageDir?: string): string {
    const targetDir = storageDir || path.join(os.homedir(), '.aegis', 'telemetry');
    if (!fs.existsSync(targetDir)) {
      fs.mkdirSync(targetDir, { recursive: true });
    }

    const filePath = path.join(targetDir, `telemetry-snapshot-${Date.now()}.json`);
    const packet = this.exportAnonymizedReport();
    fs.writeFileSync(filePath, JSON.stringify(packet, null, 2), 'utf8');
    return filePath;
  }
}
