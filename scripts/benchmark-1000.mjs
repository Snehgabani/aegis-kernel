#!/usr/bin/env node
/**
 * @file scripts/benchmark-1000.mjs
 * @description Runs canonical scale N=1,000 double-blind benchmark across all 10 OWASP Agentic AI threat categories.
 */

import { AegisEngine } from '../packages/core/dist/index.js';
import { generate1000OwaspBenchmarkDataset } from '../packages/evals/dist/index.js';
import { wilsonInterval } from '../packages/evals/dist/index.js';

console.log('═══════════════════════════════════════════════════════════════════════════');
console.log('🔬 AEGIS CANONICAL N=1,000 OWASP AGENTIC AI BENCHMARK (ASI01–ASI10)');
console.log('═══════════════════════════════════════════════════════════════════════════');

const dataset = generate1000OwaspBenchmarkDataset();
console.log(`Loaded dataset: ${dataset.length} samples (500 malicious / 500 benign)\n`);

const engine = new AegisEngine({
  mode: 'enforce',
  failPolicy: 'fail-closed',
  packs: ['@aegis/sql-guard', '@aegis/finance-guard', '@aegis/data-guard', '@aegis/cloud-infra-guard'],
});

// Warmup
for (let i = 0; i < 20; i++) {
  engine.evaluate({ tool: 'sql_query', params: { query: 'SELECT 1' } });
}

let malBlocked = 0;
let malTotal = 0;
let benAllowed = 0;
let benTotal = 0;
const catStats = {};
const latencies = [];

const totalStart = performance.now();

for (const s of dataset) {
  if (!catStats[s.category]) {
    catStats[s.category] = { name: s.name, malBlocked: 0, malTotal: 0, benAllowed: 0, benTotal: 0 };
  }

  engine.resetState();
  const start = performance.now();
  const verdict = engine.evaluate(s.toolCall, { sessionId: s.id });
  const elapsed = performance.now() - start;
  latencies.push(elapsed);

  if (s.isMalicious) {
    malTotal++;
    catStats[s.category].malTotal++;
    if (!verdict.allowed) {
      malBlocked++;
      catStats[s.category].malBlocked++;
    }
  } else {
    benTotal++;
    catStats[s.category].benTotal++;
    if (verdict.allowed) {
      benAllowed++;
      catStats[s.category].benAllowed++;
    }
  }
}

const totalDuration = performance.now() - totalStart;
latencies.sort((a, b) => a - b);
const p50 = latencies[Math.floor(latencies.length * 0.5)];
const p90 = latencies[Math.floor(latencies.length * 0.9)];
const p99 = latencies[Math.floor(latencies.length * 0.99)];

console.log('┌──────┬───────────────────────────────────────────┬──────────────┬──────────────┐');
console.log('│ ID   │ OWASP Agentic AI Threat Category          │ Attack Block │ Benign Pass  │');
console.log('├──────┼───────────────────────────────────────────┼──────────────┼──────────────┤');

for (const [catId, stats] of Object.entries(catStats)) {
  const malPct = ((stats.malBlocked / stats.malTotal) * 100).toFixed(1) + '%';
  const benPct = ((stats.benAllowed / stats.benTotal) * 100).toFixed(1) + '%';
  console.log(`│ ${catId.padEnd(4)} │ ${stats.name.padEnd(41).slice(0, 41)} │ ${(stats.malBlocked + '/' + stats.malTotal + ' (' + malPct + ')').padEnd(12)} │ ${(stats.benAllowed + '/' + stats.benTotal + ' (' + benPct + ')').padEnd(12)} │`);
}

console.log('└──────┴───────────────────────────────────────────┴──────────────┴──────────────┘');

const malCi = wilsonInterval(malBlocked, malTotal);
const benCi = wilsonInterval(benAllowed, benTotal);

console.log('\n📊 EMPIRICAL STATISTICAL METRICS:');
console.log(`  • Overall Attack Rejection:  ${((malBlocked / malTotal) * 100).toFixed(2)}% (${malBlocked}/${malTotal}) [95% Wilson CI: ${(malCi.lower * 100).toFixed(2)}% - ${(malCi.upper * 100).toFixed(2)}%]`);
console.log(`  • Benign Pass-Through Rate:  ${((benAllowed / benTotal) * 100).toFixed(2)}% (${benAllowed}/${benTotal}) [95% Wilson CI: ${(benCi.lower * 100).toFixed(2)}% - ${(benCi.upper * 100).toFixed(2)}%]`);
console.log(`  • Total Monorepo Execution:  ${totalDuration.toFixed(2)}ms (for 1,000 evaluations)`);
console.log(`  • Evaluation Latencies:      P50 = ${(p50 * 1000).toFixed(1)}µs | P90 = ${(p90 * 1000).toFixed(1)}µs | P99 = ${(p99 * 1000).toFixed(1)}µs`);
console.log(`  • Deterministic AST Speed:   ${Math.round(1000 / (totalDuration / 1000)).toLocaleString()} tool evaluations / sec`);
console.log('═══════════════════════════════════════════════════════════════════════════\n');
