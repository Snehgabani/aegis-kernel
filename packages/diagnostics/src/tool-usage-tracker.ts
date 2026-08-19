/**
 * Aegis Invariant Kernel — Tool Invariant Usage & LLM Escape Detector
 *
 * Tracks:
 * 1. Invocation counts per tool (Allowed vs Blocked)
 * 2. Invariant guard coverage (Guarded vs Unguarded)
 * 3. Shadow / Unregistered tools invoked by LLMs
 * 4. Dormant / Unused tools in catalog
 * 5. LLM Escape Risk Score
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

export interface ToolUsageRecord {
  toolName: string;
  totalInvocations: number;
  allowedCount: number;
  blockedCount: number;
  activeInvariantRules: string[];
  isGuarded: boolean;
  isRegisteredInCatalog: boolean;
  lastInvokedAt?: number;
}

export interface ToolCoverageReport {
  timestamp: number;
  totalDeclaredTools: number;
  totalInvokedTools: number;
  guardedToolsCount: number;
  unguardedToolsCount: number;
  coveragePercentage: number;
  llmEscapeRiskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  activeTools: ToolUsageRecord[];
  shadowTools: ToolUsageRecord[];
  unusedTools: string[];
}

export class ToolUsageTracker {
  private declaredCatalog: Set<string> = new Set();
  private toolInvariants: Map<string, Set<string>> = new Map();
  private toolUsage: Map<string, ToolUsageRecord> = new Map();

  constructor(declaredTools: string[] = []) {
    for (const tool of declaredTools) {
      this.registerDeclaredTool(tool);
    }
  }

  /**
   * Register a tool declared in agent/MCP tool manifest
   */
  public registerDeclaredTool(toolName: string, invariantRules: string[] = []): void {
    this.declaredCatalog.add(toolName);
    if (!this.toolInvariants.has(toolName)) {
      this.toolInvariants.set(toolName, new Set());
    }
    for (const rule of invariantRules) {
      this.toolInvariants.get(toolName)!.add(rule);
    }

    if (!this.toolUsage.has(toolName)) {
      this.toolUsage.set(toolName, {
        toolName,
        totalInvocations: 0,
        allowedCount: 0,
        blockedCount: 0,
        activeInvariantRules: Array.from(this.toolInvariants.get(toolName) || []),
        isGuarded: (this.toolInvariants.get(toolName)?.size || 0) > 0,
        isRegisteredInCatalog: true,
      });
    }
  }

  /**
   * Associate an invariant rule to a tool
   */
  public attachRule(toolName: string, ruleId: string): void {
    if (!this.toolInvariants.has(toolName)) {
      this.toolInvariants.set(toolName, new Set());
    }
    this.toolInvariants.get(toolName)!.add(ruleId);

    const record = this.toolUsage.get(toolName);
    if (record) {
      record.activeInvariantRules = Array.from(this.toolInvariants.get(toolName)!);
      record.isGuarded = true;
    }
  }

  /**
   * Record a tool invocation by an LLM agent
   */
  public recordInvocation(toolName: string, allowed: boolean): ToolUsageRecord {
    const isDeclared = this.declaredCatalog.has(toolName);
    const rules = this.toolInvariants.get(toolName) || new Set();

    let record = this.toolUsage.get(toolName);
    if (!record) {
      record = {
        toolName,
        totalInvocations: 0,
        allowedCount: 0,
        blockedCount: 0,
        activeInvariantRules: Array.from(rules),
        isGuarded: rules.size > 0,
        isRegisteredInCatalog: isDeclared,
      };
      this.toolUsage.set(toolName, record);
    }

    record.totalInvocations++;
    if (allowed) {
      record.allowedCount++;
    } else {
      record.blockedCount++;
    }
    record.lastInvokedAt = Date.now();

    return record;
  }

  /**
   * Compute Tool Invariant Coverage & LLM Escape Analysis
   */
  public generateCoverageReport(): ToolCoverageReport {
    const allRecorded = Array.from(this.toolUsage.values());
    const invokedTools = allRecorded.filter((r) => r.totalInvocations > 0);

    const activeTools = invokedTools.filter((r) => r.isRegisteredInCatalog);
    const shadowTools = invokedTools.filter((r) => !r.isRegisteredInCatalog || !r.isGuarded);

    const guardedCount = invokedTools.filter((r) => r.isGuarded).length;
    const unguardedCount = invokedTools.length - guardedCount;

    const totalInvoked = invokedTools.length;
    const coveragePercentage = totalInvoked === 0 ? 100.0 : Number(((guardedCount / totalInvoked) * 100).toFixed(1));

    const unusedTools = Array.from(this.declaredCatalog).filter(
      (tool) => !this.toolUsage.has(tool) || this.toolUsage.get(tool)!.totalInvocations === 0
    );

    let llmEscapeRiskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
    if (shadowTools.some((t) => !t.isRegisteredInCatalog)) {
      llmEscapeRiskLevel = 'CRITICAL';
    } else if (unguardedCount > 0 && coveragePercentage < 70) {
      llmEscapeRiskLevel = 'HIGH';
    } else if (unguardedCount > 0) {
      llmEscapeRiskLevel = 'MEDIUM';
    }

    return {
      timestamp: Date.now(),
      totalDeclaredTools: this.declaredCatalog.size,
      totalInvokedTools: totalInvoked,
      guardedToolsCount: guardedCount,
      unguardedToolsCount: unguardedCount,
      coveragePercentage,
      llmEscapeRiskLevel,
      activeTools,
      shadowTools,
      unusedTools,
    };
  }

  /**
   * Persist report snapshot to disk
   */
  public persistSnapshot(storageDir?: string): string {
    const targetDir = storageDir || path.join(os.homedir(), '.aegis', 'telemetry');
    if (!fs.existsSync(targetDir)) {
      fs.mkdirSync(targetDir, { recursive: true });
    }

    const filePath = path.join(targetDir, `tool-coverage-${Date.now()}.json`);
    const report = this.generateCoverageReport();
    fs.writeFileSync(filePath, JSON.stringify(report, null, 2), 'utf8');
    return filePath;
  }
}
