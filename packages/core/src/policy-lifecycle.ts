/**
 * @file packages/core/src/policy-lifecycle.ts
 * @description Policy lifecycle: shadow evaluation → gated promotion → rollback.
 *
 * The governance loop enterprises actually buy (ISO/IEC 42001 control-operation
 * records; NIST AI RMF MANAGE function): a candidate rule-pack set runs in
 * SHADOW (evaluated, never enforced) alongside the current policy; divergence
 * statistics decide promotion; promotion snapshots the old policy for instant
 * rollback.
 *
 * Promotion gate (fail-closed — default DENY promotion):
 *   1. No NEW_ALLOWS_MORE divergence on any attack vector (candidate must never
 *      be weaker on observed traffic).
 *   2. False-positive delta on benign traffic ≤ tolerance (default 0 additional
 *      FPs; configurable).
 *   3. Minimum shadow sample size reached (default 30; rule-of-three aware).
 *
 * Everything is deterministic and in-process (zero egress); snapshots are
 * serializable for durable audit.
 */

import { AegisEngine } from './engine.js';
import type { ToolCall, AegisVerdict } from './types.js';
import { computePolicyCommitmentHash } from './verdict.js';

export type LifecycleStage = 'shadow' | 'promoted' | 'rejected';

export interface SampledToolCall {
  toolCall: ToolCall;
  /** ground truth: is this an attack vector? (for divergence classification) */
  isAttack: boolean;
  /** stable id for reporting (e.g. fingerprint) */
  id?: string;
}

export type DivergenceClass = 'NEW_BLOCKS_MORE' | 'NEW_ALLOWS_MORE';

export interface Divergence {
  id: string;
  isAttack: boolean;
  classification: DivergenceClass;
  oldAllowed: boolean;
  newAllowed: boolean;
  tool: string;
}

export interface ShadowReport {
  compared: number;
  attacksCompared: number;
  benignCompared: number;
  divergences: Divergence[];
  newAllowsMoreOnAttacks: number;
  newBlocksMoreOnAttacks: number;
  newFpsOnBenign: number;
  oldFpsOnBenign: number;
}

export interface LifecycleOptions {
  currentPacks: string[];
  candidatePacks: string[];
  /** max additional benign FPs tolerated in candidate (default 0) */
  fpTolerance?: number;
  /** minimum shadow samples before promotion is allowed (default 30) */
  minShadowSamples?: number;
}

export interface SnapshotRecord {
  kind: 'current' | 'candidate';
  packs: string[];
  policyCommitmentHash: string;
  createdAt: string;
}

export class PolicyLifecycle {
  private readonly currentEngine: AegisEngine;
  private readonly candidateEngine: AegisEngine;
  private readonly options: Required<LifecycleOptions>;
  private stage: LifecycleStage = 'shadow';
  private readonly divergences: Divergence[] = [];
  private compared = 0;
  private attacksCompared = 0;
  private benignCompared = 0;
  private readonly snapshots: SnapshotRecord[];

  constructor(options: LifecycleOptions) {
    this.options = {
      currentPacks: options.currentPacks,
      candidatePacks: options.candidatePacks,
      fpTolerance: options.fpTolerance ?? 0,
      minShadowSamples: options.minShadowSamples ?? 30,
    };
    this.currentEngine = new AegisEngine({ mode: 'enforce', failPolicy: 'fail-closed', packs: this.options.currentPacks });
    this.candidateEngine = new AegisEngine({ mode: 'enforce', failPolicy: 'fail-closed', packs: this.options.candidatePacks });
    this.snapshots = [
      {
        kind: 'current',
        packs: [...this.options.currentPacks],
        policyCommitmentHash: computePolicyCommitmentHash(this.currentEngine.getActivePacks()),
        createdAt: new Date().toISOString(),
      },
      {
        kind: 'candidate',
        packs: [...this.options.candidatePacks],
        policyCommitmentHash: computePolicyCommitmentHash(this.candidateEngine.getActivePacks()),
        createdAt: new Date().toISOString(),
      },
    ];
  }

  /** Evaluate one sampled call under BOTH policies; record divergence. */
  public shadowEvaluate(sample: SampledToolCall): { oldVerdict: AegisVerdict; newVerdict: AegisVerdict; divergence?: Divergence } {
    if (this.stage !== 'shadow') {
      throw new Error(`lifecycle is in stage '${this.stage}'; shadow evaluation only allowed before promotion/rejection`);
    }
    this.currentEngine.resetState();
    this.candidateEngine.resetState();
    const oldVerdict = this.currentEngine.evaluate(sample.toolCall);
    const newVerdict = this.candidateEngine.evaluate(sample.toolCall);
    this.compared++;
    if (sample.isAttack) this.attacksCompared++;
    else this.benignCompared++;

    let divergence: Divergence | undefined;
    if (oldVerdict.allowed !== newVerdict.allowed) {
      divergence = {
        id: sample.id ?? oldVerdict.proofHash.slice(0, 16),
        isAttack: sample.isAttack,
        classification: newVerdict.allowed ? 'NEW_ALLOWS_MORE' : 'NEW_BLOCKS_MORE',
        oldAllowed: oldVerdict.allowed,
        newAllowed: newVerdict.allowed,
        tool: sample.toolCall.tool,
      };
      this.divergences.push(divergence);
    }
    return { oldVerdict, newVerdict, divergence };
  }

  public report(): ShadowReport {
    const attacks = this.divergences.filter((d) => d.isAttack);
    const oldFps = this.countOldFps();
    const newFps = this.countNewFps();
    return {
      compared: this.compared,
      attacksCompared: this.attacksCompared,
      benignCompared: this.benignCompared,
      divergences: [...this.divergences],
      newAllowsMoreOnAttacks: attacks.filter((d) => d.classification === 'NEW_ALLOWS_MORE').length,
      newBlocksMoreOnAttacks: attacks.filter((d) => d.classification === 'NEW_BLOCKS_MORE').length,
      newFpsOnBenign: newFps,
      oldFpsOnBenign: oldFps,
    };
  }

  // FP accounting requires verdict memory per sample — recomputed from divergences:
  // an OLD FP that the candidate fixes appears as NEW_ALLOWS_MORE on benign (good);
  // a NEW FP appears as NEW_BLOCKS_MORE on benign (bad). Counted accordingly.
  private countOldFps(): number {
    return this.divergences.filter((d) => !d.isAttack && d.classification === 'NEW_ALLOWS_MORE').length;
  }
  private countNewFps(): number {
    return this.divergences.filter((d) => !d.isAttack && d.classification === 'NEW_BLOCKS_MORE').length;
  }

  /** Fail-closed promotion decision. */
  public promotionGate(): { ready: boolean; blockers: string[]; report: ShadowReport } {
    const report = this.report();
    const blockers: string[] = [];
    if (this.compared < this.options.minShadowSamples) {
      blockers.push(`insufficient shadow samples: ${this.compared} < ${this.options.minShadowSamples}`);
    }
    if (report.newAllowsMoreOnAttacks > 0) {
      blockers.push(`candidate is WEAKER on ${report.newAllowsMoreOnAttacks} attack vector(s) (NEW_ALLOWS_MORE)`);
    }
    if (report.newFpsOnBenign - report.oldFpsOnBenign > this.options.fpTolerance) {
      blockers.push(
        `benign false-positive regression: +${report.newFpsOnBenign - report.oldFpsOnBenign} (tolerance ${this.options.fpTolerance})`
      );
    }
    return { ready: blockers.length === 0, blockers, report };
  }

  public promote(): { promoted: boolean; blockers: string[] } {
    const gate = this.promotionGate();
    if (!gate.ready) {
      return { promoted: false, blockers: gate.blockers };
    }
    this.stage = 'promoted';
    return { promoted: true, blockers: [] };
  }

  private rejectionReason?: string;

  public reject(reason: string): void {
    this.stage = 'rejected';
    this.rejectionReason = reason;
  }

  /** Why the lifecycle left the shadow stage (audit). */
  public getRejectionReason(): string | undefined {
    return this.rejectionReason;
  }

  public getStage(): LifecycleStage {
    return this.stage;
  }

  /** Rollback: returns the CURRENT-policy snapshot to restore after promotion. */
  public rollback(): SnapshotRecord {
    if (this.stage !== 'promoted') {
      throw new Error('rollback requires a promoted policy');
    }
    this.stage = 'rejected';
    this.rejectionReason = 'rolled back';
    return this.snapshots[0];
  }

  public getSnapshots(): SnapshotRecord[] {
    return [...this.snapshots];
  }
}
