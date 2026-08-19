/**
 * Aegis Invariant Kernel — Step-by-Step Micro-Stage Forensic Diagnostic Tracer
 *
 * Provides compiler-grade deterministic micro-stage execution tracing,
 * token-level offset localization, and root-cause failure analysis.
 */

import * as crypto from 'node:crypto';

export type EvaluationStageName =
  | 'NORMALIZATION'
  | 'SCHEMA_VALIDATION'
  | 'INVARIANT_EVALUATION'
  | 'PII_TOKENIZATION'
  | 'REMEDIATION_SYNTHESIS'
  | 'MERKLE_COMMIT';

export interface EvaluationStageTrace {
  stageName: EvaluationStageName;
  durationUs: number;
  status: 'PASSED' | 'FAILED' | 'SKIPPED';
  details: Record<string, unknown>;
  errorOrViolation?: {
    ruleId?: string;
    matchedToken?: string;
    byteOffset?: number;
    reason: string;
    remediationDiff?: string;
  };
}

export type FailureCategory =
  | 'SYNTAX_ANOMALY'
  | 'SECURITY_VIOLATION'
  | 'STATE_CONFLICT'
  | 'SCHEMA_MISMATCH'
  | 'NUMERIC_BREACH'
  | 'PII_LEAK';

export interface RootCauseAnalysis {
  failureCategory: FailureCategory;
  primaryCulpritRule?: string;
  triggeringPayloadSnippet?: string;
  suggestedFixDiff?: string;
  remediationAction: string;
}

export interface AegisForensicDiagnosticTrace {
  evaluationId: string;
  timestamp: number;
  totalDurationUs: number;
  stages: EvaluationStageTrace[];
  rootCauseAnalysis?: RootCauseAnalysis;
}

export class StepDiagnosticCollector {
  private evaluationId: string;
  private startTime: number;
  private stageStartTime: number;
  private currentStageName: EvaluationStageName | null = null;
  private stages: EvaluationStageTrace[] = [];

  constructor(evaluationId?: string) {
    this.evaluationId = evaluationId || crypto.randomUUID();
    this.startTime = performance.now();
    this.stageStartTime = this.startTime;
  }

  public getEvaluationId(): string {
    return this.evaluationId;
  }

  public getCurrentStage(): EvaluationStageName | null {
    return this.currentStageName;
  }

  /**
   * Start a micro-stage
   */
  public startStage(stageName: EvaluationStageName): void {
    this.currentStageName = stageName;
    this.stageStartTime = performance.now();
  }

  /**
   * End the current micro-stage and record execution trace
   */
  public endStage(
    stageName: EvaluationStageName,
    status: 'PASSED' | 'FAILED' | 'SKIPPED' = 'PASSED',
    details: Record<string, unknown> = {},
    errorOrViolation?: EvaluationStageTrace['errorOrViolation']
  ): void {
    const now = performance.now();
    const durationUs = Math.round((now - this.stageStartTime) * 1000);

    this.stages.push({
      stageName,
      durationUs,
      status,
      details,
      errorOrViolation,
    });
  }

  /**
   * Finalize the full forensic trace
   */
  public finalize(rootCauseAnalysis?: RootCauseAnalysis): AegisForensicDiagnosticTrace {
    const totalDurationUs = Math.round((performance.now() - this.startTime) * 1000);

    return {
      evaluationId: this.evaluationId,
      timestamp: Date.now(),
      totalDurationUs,
      stages: this.stages,
      rootCauseAnalysis,
    };
  }
}
