import { AegisEngine } from '../packages/core/dist/index.js';
import { TRICKY_100_DATASET } from '../packages/evals/dist/index.mjs';
import * as process from 'node:process';
import * as fs from 'node:fs';

console.log('🛡️ Aegis Invariant Kernel — Empirical Verification & Telemetry Collection');
console.log('════════════════════════════════════════════════════════════════════════');

// 1. High-Precision Latency Benchmark & Memory Profiling
const engine = new AegisEngine();
const ITERATIONS = 10000;
const latencies = new Float64Array(ITERATIONS);

// Force garbage collection or measure baseline memory
const initialMem = process.memoryUsage();

const testVector = {
  tool: 'database_exec',
  params: { query: 'SELECT id, name, email FROM users WHERE id = 42 LIMIT 10;' }
};

const startTime = performance.now();
for (let i = 0; i < ITERATIONS; i++) {
  const t0 = performance.now();
  engine.evaluate(testVector);
  const t1 = performance.now();
  latencies[i] = t1 - t0;
}
const totalDuration = performance.now() - startTime;
const finalMem = process.memoryUsage();

latencies.sort();

const p50 = latencies[Math.floor(ITERATIONS * 0.50)];
const p90 = latencies[Math.floor(ITERATIONS * 0.90)];
const p95 = latencies[Math.floor(ITERATIONS * 0.95)];
const p99 = latencies[Math.floor(ITERATIONS * 0.99)];
const min = latencies[0];
const max = latencies[ITERATIONS - 1];
const sum = latencies.reduce((a, b) => a + b, 0);
const mean = sum / ITERATIONS;
const variance = latencies.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / ITERATIONS;
const stdDev = Math.sqrt(variance);
const throughputRps = (ITERATIONS / (totalDuration / 1000)).toFixed(0);

console.log(`\n📊 1. Latency & Throughput Benchmark (${ITERATIONS.toLocaleString()} Evaluations):`);
console.log(`   - Throughput:    ${Number(throughputRps).toLocaleString()} evaluations/sec`);
console.log(`   - Mean Latency:  ${mean.toFixed(4)} ms (StdDev: ${stdDev.toFixed(4)} ms)`);
console.log(`   - Min Latency:   ${min.toFixed(4)} ms`);
console.log(`   - P50 (Median):  ${p50.toFixed(4)} ms`);
console.log(`   - P90 Latency:   ${p90.toFixed(4)} ms`);
console.log(`   - P95 Latency:   ${p95.toFixed(4)} ms`);
console.log(`   - P99 Latency:   ${p99.toFixed(4)} ms`);
console.log(`   - Max Latency:   ${max.toFixed(4)} ms`);

console.log(`\n🧠 2. Memory Footprint Delta (10,000 Evaluations):`);
console.log(`   - Initial RSS:   ${(initialMem.rss / 1024 / 1024).toFixed(2)} MB`);
console.log(`   - Final RSS:     ${(finalMem.rss / 1024 / 1024).toFixed(2)} MB (Delta: ${((finalMem.rss - initialMem.rss) / 1024 / 1024).toFixed(2)} MB)`);
console.log(`   - Initial Heap:  ${(initialMem.heapUsed / 1024 / 1024).toFixed(2)} MB`);
console.log(`   - Final Heap:    ${(finalMem.heapUsed / 1024 / 1024).toFixed(2)} MB (Delta: ${((finalMem.heapUsed - initialMem.heapUsed) / 1024 / 1024).toFixed(2)} MB)`);

// 3. 100-Vector Adversarial Benchmark Breakdown by Threat Domain
const domainMetrics = {};

for (const vec of TRICKY_100_DATASET) {
  const cat = vec.category || 'general';
  if (!domainMetrics[cat]) {
    domainMetrics[cat] = { total: 0, passed: 0, malicious: 0, maliciousBlocked: 0, benign: 0, benignPassed: 0 };
  }
  domainMetrics[cat].total++;

  const vecEngine = new AegisEngine({ packs: vec.activePacks });
  const verdict = vecEngine.evaluate(vec.toolCall, { state: vec.stateContext });
  const isCorrect = vec.expectedVerdict === (verdict.allowed ? 'ALLOWED' : 'BLOCKED');

  if (isCorrect) domainMetrics[cat].passed++;
  if (vec.type === 'malicious') {
    domainMetrics[cat].malicious++;
    if (!verdict.allowed) domainMetrics[cat].maliciousBlocked++;
  } else {
    domainMetrics[cat].benign++;
    if (verdict.allowed) domainMetrics[cat].benignPassed++;
  }
}

console.log(`\n🎯 3. 100-Vector Adversarial Accuracy Breakdown by Threat Category:`);
console.log(`   ┌─────────────────────────────────┬─────────┬──────────────┬──────────────┬───────────┐`);
console.log(`   │ Threat Category                 │ Vectors │ Malicious Bl │ Benign Pass  │ Accuracy  │`);
console.log(`   ├─────────────────────────────────┼─────────┼──────────────┼──────────────┼───────────┤`);
for (const [cat, data] of Object.entries(domainMetrics)) {
  const acc = ((data.passed / data.total) * 100).toFixed(1);
  const mal = `${data.maliciousBlocked}/${data.malicious}`;
  const ben = `${data.benignPassed}/${data.benign}`;
  console.log(`   │ ${cat.padEnd(31)} │ ${String(data.total).padStart(7)} │ ${mal.padStart(12)} │ ${ben.padStart(12)} │ ${`${acc}%`.padStart(9)} │`);
}
console.log(`   └─────────────────────────────────┴─────────┴──────────────┴──────────────┴───────────┘`);

const telemetryPayload = {
  timestamp: new Date().toISOString(),
  iterations: ITERATIONS,
  throughputRps: Number(throughputRps),
  latency: { min, p50, p90, p95, p99, max, mean, stdDev },
  memory: {
    initialRssMb: initialMem.rss / 1024 / 1024,
    finalRssMb: finalMem.rss / 1024 / 1024,
    initialHeapMb: initialMem.heapUsed / 1024 / 1024,
    finalHeapMb: finalMem.heapUsed / 1024 / 1024,
  },
  threatDomains: domainMetrics,
};

fs.writeFileSync('.aegis/benchmark-telemetry.json', JSON.stringify(telemetryPayload, null, 2));
console.log('\n✅ Telemetry logged to .aegis/benchmark-telemetry.json');
