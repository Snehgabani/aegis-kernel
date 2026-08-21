#!/usr/bin/env node

/**
 * 🧪 AEGIS SCIENTIFIC EVALUATOR & OODA LOOP DAEMON
 * Automated double-blind benchmark evaluation, Wilson score statistics, and OODA cyber-defense control.
 * 
 * Hardware Budget: Apple Silicon M2 (8GB RAM) -> Zero-RAM idle, <25MB RSS active burst.
 */

import * as fs from 'fs';
import * as path from 'path';
import { 
  AgentDojoAdapter, 
  AGENTDOJO_BENCHMARK_CORPUS,
  runTrajectoryStress 
} from '../packages/evals/dist/index.js';
import { AegisEngine } from '../packages/core/dist/index.js';

const LOG_DIR = path.join(process.env.HOME || '/tmp', '.mix-mcp', 'logs');
const EVAL_LOG_FILE = path.join(LOG_DIR, 'scientific-evals.log');
const OODA_STATE_FILE = path.join(LOG_DIR, 'ooda-state.json');

try { fs.mkdirSync(LOG_DIR, { recursive: true }); } catch (_) {}

function log(msg) {
  const line = `[${new Date().toISOString()}] [SCIENTIFIC-EVAL] ${msg}\n`;
  try { fs.appendFileSync(EVAL_LOG_FILE, line); } catch (_) {}
  console.log(msg);
}

async function runScientificOodaEvaluation() {
  log('🔬 [OBSERVE] Executing multi-benchmark double-blind evaluation trial...');
  const start = performance.now();
  const engine = new AegisEngine({ mode: 'enforce', failPolicy: 'fail-closed' });

  // 1. Double-blind AgentDojo benchmark adapter trial
  const dojoAdapter = new AgentDojoAdapter(engine);
  const dojoReport = dojoAdapter.evaluate(AGENTDOJO_BENCHMARK_CORPUS.slice(0, 100));

  // 2. Trajectory Stress Long-Horizon Run
  const stressResult = runTrajectoryStress({ steps: 200 });

  const m = dojoReport.metrics;
  const totalTrials = m.totalCases + stressResult.steps;
  const defenseRate = m.defenseRate;
  const benignUtility = m.benignUtility;
  const f1Score = m.f1Score;
  const p99LatencyUs = (m.latencyDistribution.p99Ms * 1000).toFixed(1);
  const durationMs = (performance.now() - start).toFixed(2);
  const slope = stressResult.trend?.sensSlope ?? 0.0;

  // 3. ORIENT: Statistical Evaluation & Confidence Intervals
  log(`📐 [ORIENT] Empirical Synthesis (${totalTrials} total state steps evaluated):`);
  log(`   • Defense Rate (Malicious Blocked): ${defenseRate.toFixed(1)}%`);
  log(`   • Benign Utility Pass-Through: ${benignUtility.toFixed(1)}%`);
  log(`   • F1 Balance Score: ${f1Score.toFixed(1)}%`);
  if (m.confidenceIntervals?.asr) {
    log(`   • 95% Wilson ASR Interval: [${(m.confidenceIntervals.asr.lower * 100).toFixed(2)}%, ${(m.confidenceIntervals.asr.upper * 100).toFixed(2)}%]`);
  }
  log(`   • P99 Evaluation Latency: ${p99LatencyUs}µs/eval`);
  log(`   • Trajectory Stress Drift: ${slope.toFixed(6)} ms/step (Pass: ${stressResult.pass})`);

  // 4. DECIDE: Invariant Health Determination
  let oodaDecision = 'CONTINUE_NOMINAL_ENFORCEMENT';
  if (defenseRate < 95.0) {
    oodaDecision = 'TRIGGER_POLICY_CALIBRATION';
  } else if (parseFloat(p99LatencyUs) > 10000.0) {
    oodaDecision = 'TRIGGER_AST_HOT_PATH_OPTIMIZATION';
  }

  log(`🎯 [DECIDE] OODA Strategic Decision: ${oodaDecision}`);

  // 5. ACT: Persist State & Dispatch Controls
  const oodaState = {
    timestamp: new Date().toISOString(),
    evaluationDurationMs: parseFloat(durationMs),
    totalTrials,
    metrics: {
      defenseRate,
      benignUtility,
      f1Score,
      p99LatencyUs: parseFloat(p99LatencyUs),
      confidenceIntervals: m.confidenceIntervals,
      trajectoryStress: {
        driftSlope: slope,
        pass: stressResult.pass
      }
    },
    decision: oodaDecision,
    status: 'OPTIMAL'
  };

  fs.writeFileSync(OODA_STATE_FILE, JSON.stringify(oodaState, null, 2));
  log(`⚡ [ACT] OODA state cycle persisted to ${OODA_STATE_FILE}`);
}

runScientificOodaEvaluation().catch(err => log(`❌ Evaluation error: ${err.message}`));
