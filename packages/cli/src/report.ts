import { LearningLedgerManager } from '@aegis-kernel/core';

// Lightweight, zero-dependency ANSI styling helper
const c = {
  cyan: (s: string | number) => `\x1b[36m${s}\x1b[0m`,
  green: (s: string | number) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s: string | number) => `\x1b[33m${s}\x1b[0m`,
  red: (s: string | number) => `\x1b[31m${s}\x1b[0m`,
  gray: (s: string | number) => `\x1b[90m${s}\x1b[0m`,
  white: (s: string | number) => `\x1b[37m${s}\x1b[0m`,
  bold: (s: string | number) => `\x1b[1m${s}\x1b[0m`,
  dim: (s: string | number) => `\x1b[2m${s}\x1b[0m`,
};

export async function runReport(options?: { ledgerPath?: string }): Promise<void> {
  const manager = new LearningLedgerManager(options?.ledgerPath);
  const ledger = manager.getSummary();

  console.log(c.bold(c.cyan('\n📊  Aegis Policy & Invariant Clearance: Telemetry & Triage Report\n')));
  console.log(c.gray('═'.repeat(65)));
  console.log(`  Total Tool Actions Evaluated:    ${c.bold(c.white(ledger.totalEventsProcessed))}`);
  console.log(`  Total Invariant Blocks:          ${c.bold(c.red(ledger.totalBlocked))}`);
  console.log(`  Total Cleared Safe Actions:      ${c.bold(c.green(ledger.totalAllowed))}`);
  console.log(`  Total Developer Overrides:       ${c.bold(c.yellow(ledger.totalOverrides))}`);
  console.log(`  Last Ledger Synchronization:     ${c.gray(ledger.lastUpdated)}`);
  console.log(c.gray('═'.repeat(65)));

  const ruleKeys = Object.keys(ledger.rulePerformance);
  if (ruleKeys.length === 0) {
    console.log(c.dim('\n  No rules triggered yet. Run `aegis test` to execute synthetic testbed.'));
    return;
  }

  console.log(c.bold(c.white('\n🛡️  Active Policy Rules Operational Status:')));
  for (const ruleId of ruleKeys) {
    const perf = ledger.rulePerformance[ruleId];
    const statusColor =
      perf.triageStatus === 'healthy'
        ? c.green('[HEALTHY]')
        : perf.triageStatus === 'review_needed'
        ? c.yellow('[REVIEW NEEDED]')
        : c.red('[QUARANTINED]');

    const overridePct = (perf.overrideRatio * 100).toFixed(1);
    console.log(`  • ${c.bold(c.white(ruleId))}: ${statusColor}`);
    console.log(
      `    Fired: ${c.cyan(perf.timesFired)} | Overrides: ${c.yellow(perf.overridesCount)} (${overridePct}%) | Status: ${perf.triageStatus} | Avg Latency: ${perf.averageLatencyMs.toFixed(2)}ms`
    );
  }

  const uncoveredKeys = Object.keys(ledger.uncoveredTools);
  if (uncoveredKeys.length > 0) {
    console.log(c.bold(c.yellow('\n⚠️  Uncovered Tool Invocations (Policy Gaps):')));
    for (const tool of uncoveredKeys) {
      console.log(`  • ${c.yellow(tool)}: ${ledger.uncoveredTools[tool]} invocations without matching rules`);
    }
  }

  console.log('\n');
}
