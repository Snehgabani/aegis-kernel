#!/usr/bin/env node
/**
 * @file scripts/run-benchmarks.mjs
 * @description Runs Aegis benchmark evaluations and writes dated, committable
 * evidence reports to benchmarks/reports/.
 *
 * Modes:
 *   node scripts/run-benchmarks.mjs              → in-tree representative corpora
 *   node scripts/run-benchmarks.mjs --canonical  → benchmarks/canonical/ datasets
 *                                                   (requires fetch-canonical-benchmarks.mjs
 *                                                   to have succeeded; fails loudly otherwise)
 *
 * Every report records: dataset source, corpus size, field-standard metrics
 * (ASR, defense rate, benign utility, risk, confusion matrix, precision/recall/F1),
 * latency distribution, environment fingerprint, and dataset SHA-256 — enough to
 * be independently reproduced and audited.
 */

import { mkdirSync, writeFileSync, existsSync, readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { createHash } from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT_DIR = join(__dirname, '..');
const REPORTS_DIR = join(ROOT_DIR, 'benchmarks', 'reports');
const CANONICAL_DIR = join(ROOT_DIR, 'benchmarks', 'canonical');

const canonical = process.argv.includes('--canonical');

const { InjecAgentAdapter, AgentDojoAdapter, MCPToxAdapter } = await import('@aegis-kernel/evals');

mkdirSync(REPORTS_DIR, { recursive: true });

const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
let failures = 0;

function summarize(name, report) {
  const m = report.metrics;
  const ld = m.latencyDistribution;
  return [
    `─ ${name}`,
    `  source=${report.datasetSource}  N=${m.totalCases}  (malicious=${m.maliciousTotal}, benign=${m.benignTotal})`,
    `  ASR=${m.attackSuccessRate}%  defenseRate=${m.defenseRate}%  benignUtility=${m.benignUtility}%  risk=${m.risk}`,
    `  accuracy=${m.accuracy}%  precision=${m.precision}%  recall=${m.recall}%  f1=${m.f1Score}%`,
    `  confusion TP/FP/TN/FN = ${m.confusionMatrix.truePositive}/${m.confusionMatrix.falsePositive}/${m.confusionMatrix.trueNegative}/${m.confusionMatrix.falseNegative}`,
    `  latency p50=${ld.p50Ms}ms p95=${ld.p95Ms}ms p99=${ld.p99Ms}ms`,
    `  dataset sha256=${report.attestationProof?.datasetSha256?.slice(0, 16) ?? 'n/a'}…`,
  ].join('\n');
}

function writeReport(slug, report) {
  const file = join(REPORTS_DIR, `${slug}-${stamp}.json`);
  writeFileSync(file, JSON.stringify(report, null, 2), 'utf8');
  console.log(summarize(report.benchmark, report) + `\n  → ${file}\n`);
  return file;
}

async function runInjecAgent() {
  const adapter = new InjecAgentAdapter();
  if (canonical) {
    const dh = join(CANONICAL_DIR, 'injecagent', 'test_cases_dh_base.json');
    const ds = join(CANONICAL_DIR, 'injecagent', 'test_cases_ds_base.json');
    const parts = [];
    if (existsSync(dh)) parts.push(adapter.evaluate(dh));
    if (existsSync(ds)) parts.push(ds);
    if (parts.length === 0) throw new Error('canonical InjecAgent files not found — run scripts/fetch-canonical-benchmarks.mjs first');
    const report = existsSync(dh) ? adapter.evaluate(dh) : null;
    const reportDs = existsSync(ds) ? adapter.evaluate(ds) : null;
    if (report) writeReport('injecagent-canonical-dh', report);
    if (reportDs) writeReport('injecagent-canonical-ds', reportDs);
    return;
  }
  const report = adapter.evaluate();
  writeReport('injecagent-in-tree', report);
}

async function runAgentDojo() {
  const adapter = new AgentDojoAdapter();
  const report = adapter.evaluate();
  writeReport('agentdojo-in-tree', report);
}

async function runMCPTox() {
  const adapter = new MCPToxAdapter();
  const report = adapter.evaluate();
  writeReport('mcptox-in-tree', report);
}

console.log(`🧪 Aegis benchmark evidence run — ${canonical ? 'CANONICAL' : 'IN-TREE'} mode`);
console.log(`   Note: in-tree corpora are representative samples (see benchmarks/EVIDENCE.md).\n`);

try {
  await runInjecAgent();
} catch (e) {
  failures++;
  console.error(`❌ InjecAgent: ${e.message}`);
}
try {
  await runAgentDojo();
} catch (e) {
  failures++;
  console.error(`❌ AgentDojo: ${e.message}`);
}
try {
  await runMCPTox();
} catch (e) {
  failures++;
  console.error(`❌ MCPTox: ${e.message}`);
}

// Latest-run pointer for tooling
writeFileSync(
  join(REPORTS_DIR, 'latest.json'),
  JSON.stringify({ stamp, mode: canonical ? 'canonical' : 'in-tree', failures }, null, 2),
  'utf8'
);

process.exitCode = failures > 0 ? 1 : 0;
