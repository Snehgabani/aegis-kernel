import * as fs from 'node:fs';
import * as path from 'node:path';
import pc from 'picocolors';
import { TrickyBenchmarkRunner } from '@aegis-kernel/evals';
import {
  compareToBaseline,
  formatBenchmarkTable,
  runFullBenchmark,
  type BaselineEntry,
} from '@aegis-kernel/evals';

export interface BenchmarkCliOptions {
  tricky?: boolean;
  compare?: boolean;
  json?: string; // path for evidence JSON output
  saveBaseline?: boolean;
  quick?: boolean; // shorter runs for CI smoke
}

const BASELINE_PATH = path.resolve(process.cwd(), '.benchmark', 'baseline.json');

export function runBenchmark(options?: BenchmarkCliOptions): number {
  if (options?.tricky) {
    console.log(pc.bold(pc.cyan('\n🛡️   Aegis 100-Vector Adversarial & Tricky Testbed (internal curated dataset)')));
    console.log(pc.gray('═'.repeat(70)));

    const results = TrickyBenchmarkRunner.run();

    console.log(pc.bold(pc.white('═══════════════════════════════════════════════════════════════')));
    console.log(pc.bold(pc.cyan('             100-VECTOR ADVERSARIAL STRESS REPORT             ')));
    console.log(pc.bold(pc.white('═══════════════════════════════════════════════════════════════')));
    console.log(`  Total Vectors:        ${pc.bold(results.totalVectors)}`);
    console.log(`  Malicious Evaluated:  ${pc.bold(results.maliciousCount)}`);
    console.log(`  Benign Evaluated:     ${pc.bold(results.benignCount)}`);
    console.log(`  Malicious Block Rate: ${pc.green(results.maliciousBlockRate)} (${results.truePositives}/${results.maliciousCount} blocked)`);
    console.log(`  Benign Pass Rate:     ${pc.green(results.benignPassRate)} (${results.trueNegatives}/${results.benignCount} passed)`);
    console.log(`  Empirical F1 Score:   ${pc.green(results.f1Score)}`);
    console.log(`  P50 Latency:          ${pc.cyan(results.p50LatencyMs + ' ms')}`);
    console.log(`  P95 Latency:          ${pc.cyan(results.p95LatencyMs + ' ms')}`);
    console.log(`  P99 Latency:          ${pc.cyan(results.p99LatencyMs + ' ms')}`);
    console.log(pc.bold(pc.white('═══════════════════════════════════════════════════════════════\n')));
    return results.failures.length === 0 ? 0 : 1;
  }

  console.log(pc.bold(pc.cyan('\n🔬  Aegis Statistical Benchmark Harness')));
  console.log(pc.gray('═'.repeat(70)));
  console.log(pc.dim('Methodology: warmup + 3 rounds w/ GC between rounds, full percentiles, throughput.\n'));

  const opts = options?.quick
    ? { warmupMs: 300, durationMs: 500, rounds: 2 }
    : { warmupMs: 750, durationMs: 1250, rounds: 3 };

  const report = runFullBenchmark(opts);

  let exitCode = 0;
  if (options?.compare) {
    if (fs.existsSync(BASELINE_PATH)) {
      const baseline = JSON.parse(fs.readFileSync(BASELINE_PATH, 'utf8')) as Record<string, BaselineEntry>;
      const compared = compareToBaseline(report, baseline);
      report.regressions = compared.regressions;
      report.verdict = compared.verdict;
      console.log(pc.bold(pc.cyan('  Baseline Regression Gate')));
      if (compared.regressions.length === 0) {
        console.log(pc.green('  ✅ No regressions vs baseline'));
      } else {
        exitCode = 1;
        for (const r of compared.regressions) {
          console.log(pc.red(`  ❌ [${r.profile}] ${r.metric}: ${r.current.toFixed(3)}ms vs baseline ${r.baseline.toFixed(3)}ms`));
        }
      }
    } else {
      console.log(pc.yellow('  ⚠️  No baseline found — run with --save-baseline first'));
    }
  }

  console.log(pc.bold(pc.cyan('\n  Workload Profiles (ms, lower is better)')));
  console.log(formatBenchmarkTable(report));
  console.log(pc.dim(`  generatedAt=${report.generatedAt} git=${report.gitSha} node=${report.nodeVersion} platform=${report.platform}\n`));

  if (options?.json) {
    const p = path.resolve(process.cwd(), options.json);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, JSON.stringify(report, null, 2));
    console.log(pc.dim(`  Evidence written: ${p}`));
  }
  if (options?.saveBaseline) {
    const baseline: Record<string, BaselineEntry> = {};
    for (const prof of report.profiles) {
      baseline[prof.id] = { p50Ms: prof.p50Ms, p95Ms: prof.p95Ms, samples: prof.samples };
    }
    fs.mkdirSync(path.dirname(BASELINE_PATH), { recursive: true });
    fs.writeFileSync(BASELINE_PATH, JSON.stringify(baseline, null, 2));
    console.log(pc.dim(`  Baseline saved: ${BASELINE_PATH}`));
  }

  return exitCode;
}
