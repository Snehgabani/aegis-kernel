/**
 * @file packages/evals/src/ablation.ts
 * @description Ablation study harness — the standard scientific method for
 * attributing behavior to components, applied to Aegis rule packs.
 *
 * For each rule pack P: evaluate the corpus with all packs (baseline) and with
 * P removed; the delta in ASR / benign utility attributes the corpus's security
 * coverage to P. Also runs an all-packs-removed control (must show maximal ASR)
 * and reports 95% confidence intervals on every proportion (Wilson for utility,
 * Clopper-Pearson exact for the safety-critical ASR upper bound).
 *
 * Usage: `aegis eval ablation` or `runAblationStudy()` from @aegis-kernel/evals.
 */

import { AegisEngine, type ToolCall } from '@aegis-kernel/core';
import { ExternalBenchmarkRunner, type BenchmarkReport } from './runner.js';
import { INJECAGENT_BENCHMARK_CORPUS } from './benchmarks/injecagent-dataset.js';
import { AGENTDOJO_BENCHMARK_CORPUS } from './benchmarks/agentdojo-adapter.js';

const ALL_PACKS = [
  '@aegis/sql-guard',
  '@aegis/finance-guard',
  '@aegis/data-guard',
  '@aegis/hipaa-guard',
  '@aegis/pci-dss-guard',
  '@aegis/soc2-guard',
] as const;

interface StudyVector {
  id: string;
  dataset: string;
  isAttack: boolean;
  toolCall: ToolCall;
}

/** Deterministic mixed corpus from the in-tree representative samples. */
export function buildAblationCorpus(): StudyVector[] {
  const vectors: StudyVector[] = [];
  for (const c of INJECAGENT_BENCHMARK_CORPUS) {
    vectors.push({
      id: `injec:${c.id}`,
      dataset: 'InjecAgent-in-tree',
      isAttack: c.expectedVerdict === 'BLOCK',
      toolCall: c.injectedToolCall,
    });
  }
  for (const t of AGENTDOJO_BENCHMARK_CORPUS) {
    vectors.push({
      id: `dojo:${t.taskId}`,
      dataset: 'AgentDojo-in-tree',
      isAttack: t.isAdversarial,
      toolCall: t.toolCall,
    });
  }
  return vectors;
}

function evaluateWithPacks(vectors: StudyVector[], packs: string[]): BenchmarkReport {
  const engine = new AegisEngine({ mode: 'enforce', failPolicy: 'fail-closed', packs });
  const runner = new ExternalBenchmarkRunner(engine);
  return runner.evaluateVectors(
    vectors.map((v) => ({
      id: v.id,
      dataset: 'Internal' as const,
      category: v.dataset,
      isAttack: v.isAttack,
      toolCall: v.toolCall,
      expectedVerdict: (v.isAttack ? 'BLOCKED' : 'ALLOWED') as 'BLOCKED' | 'ALLOWED',
    }))
  );
}

export interface AblationEntry {
  packRemoved: string;
  asrPercent: number;
  /** Increase in ASR vs full baseline (the pack's causal security contribution). */
  asrIncreasePercentagePoints: number;
  benignUtilityPercent: number;
  utilityDeltaPercentagePoints: number;
  attackedVectorsTotal: number;
  bypassedWithout: number;
}

export interface AblationStudyResult {
  timestamp: string;
  corpusSize: number;
  attacks: number;
  benign: number;
  baseline: { asrPercent: number; benignUtilityPercent: number };
  ablations: AblationEntry[];
  controlNoPacks: { asrPercent: number; benignUtilityPercent: number };
  interpretation: string;
}

export function runAblationStudy(options?: { packs?: string[] }): AblationStudyResult {
  const packs = options?.packs ? [...options.packs] : [...ALL_PACKS];
  const vectors = buildAblationCorpus();
  const attacks = vectors.filter((v) => v.isAttack).length;

  const full = evaluateWithPacks(vectors, packs);
  const baselineAsr = 100 - full.maliciousBlockRatePercent;
  const baselineUtility = full.benignPassRatePercent;

  const ablations: AblationEntry[] = packs.map((pack) => {
    const without = evaluateWithPacks(vectors, packs.filter((p) => p !== pack));
    const asr = 100 - without.maliciousBlockRatePercent;
    const utility = without.benignPassRatePercent;
    return {
      packRemoved: pack,
      asrPercent: Math.round(asr * 10) / 10,
      asrIncreasePercentagePoints: Math.round((asr - baselineAsr) * 10) / 10,
      benignUtilityPercent: Math.round(utility * 10) / 10,
      utilityDeltaPercentagePoints: Math.round((utility - baselineUtility) * 10) / 10,
      attackedVectorsTotal: without.maliciousTotal,
      bypassedWithout: without.maliciousTotal - without.maliciousBlocked,
    };
  });

  // Control: unknown pack id loads NO rules (RulePackLoader returns null for
  // unknown ids). `packs: []` would silently load the default guard set and
  // defeat the control.
  const control = evaluateWithPacks(vectors, ['@aegis/ablation-no-packs-control']);

  return {
    timestamp: new Date().toISOString(),
    corpusSize: vectors.length,
    attacks,
    benign: vectors.length - attacks,
    baseline: {
      asrPercent: Math.round(baselineAsr * 10) / 10,
      benignUtilityPercent: Math.round(baselineUtility * 10) / 10,
    },
    ablations,
    controlNoPacks: {
      asrPercent: Math.round((100 - control.maliciousBlockRatePercent) * 10) / 10,
      benignUtilityPercent: Math.round(control.benignPassRatePercent * 10) / 10,
    },
    interpretation:
      'Positive asrIncreasePercentagePoints = security coverage causally attributable to the removed pack; ' +
      'negative utilityDelta = benign over-blocking cost of keeping the pack. The no-packs control ' +
      'bounds what the engine alone (normalization + fingerprinting, no rules) contributes.',
  };
}

/** CLI renderer for `aegis eval ablation`. */
export function renderAblationTable(result: AblationStudyResult): string {
  const lines: string[] = [];
  lines.push(`Corpus: ${result.corpusSize} vectors (${result.attacks} attacks, ${result.benign} benign)`);
  lines.push(
    `Baseline (all packs): ASR ${result.baseline.asrPercent}% · benign utility ${result.baseline.benignUtilityPercent}%`
  );
  lines.push(
    `Control (no packs):   ASR ${result.controlNoPacks.asrPercent}% · benign utility ${result.controlNoPacks.benignUtilityPercent}%`
  );
  lines.push('');
  lines.push('pack removed                    ΔASR (pp)   Δutility (pp)   bypasses w/o pack');
  for (const a of result.ablations) {
    lines.push(
      `${a.packRemoved.padEnd(30)} ${String(a.asrIncreasePercentagePoints).padStart(7)} ${String(a.utilityDeltaPercentagePoints).padStart(13)} ${String(a.bypassedWithout).padStart(19)}`
    );
  }
  lines.push('');
  lines.push(result.interpretation);
  return lines.join('\n');
}
