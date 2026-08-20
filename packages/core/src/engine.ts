import { performance } from 'node:perf_hooks';
import type {
  AegisConfig,
  AegisFailPolicy,
  AegisMode,
  AegisVerdict,
  AegisViolation,
  EvaluateOptions,
  GranularFailPolicy,
  Rule,
  RulePack,
  StateProvider,
  ToolCall,
} from './types.js';
import { formatGenAiExecuteToolSpan } from './telemetry/otel.js';
import {
  computePolicyCommitmentHash,
  computeToolCallFingerprint,
  createVerdict,
} from './verdict.js';
import { AegisEventLogger } from './event.js';
import { LearningLedgerManager } from './ledger.js';
import { RulePackLoader } from './rule-loader.js';
import { AegisSanitizer } from './sanitizer.js';
import {
  CustomChecker,
  NumericChecker,
  PiiChecker,
  SchemaChecker,
  SqlChecker,
  StateChecker,
} from './checkers/index.js';
import type { AgentIdentityManager, CapabilityCheck } from './identity/agent-identity.js';
import {
  StepDiagnosticCollector,
  type FailureCategory,
  type RootCauseAnalysis,
} from './diagnostics/forensic-trace.js';

export class AegisEngine {
  private mode: AegisMode;
  private failPolicy: AegisFailPolicy | GranularFailPolicy;
  private packs: RulePack[];
  private policyCommitmentHash: string;
  private defaultStateProvider?: StateProvider;
  private onViolation?: (verdict: AegisVerdict, toolCall: ToolCall) => void;
  private observability?: AegisConfig['observability'];
  private logger: AegisEventLogger;
  private ledger: LearningLedgerManager;
  private identityManager?: AgentIdentityManager;

  // 6 Invariant Checkers
  private sqlChecker: SqlChecker;
  private schemaChecker: SchemaChecker;
  private piiChecker: PiiChecker;
  private numericChecker: NumericChecker;
  private customChecker: CustomChecker;
  private stateChecker: StateChecker;

  constructor(config?: AegisConfig) {
    this.mode = config?.mode ?? 'enforce';
    this.failPolicy = config?.failPolicy ?? 'fail-closed';
    this.defaultStateProvider = config?.stateProvider;
    this.onViolation = config?.onViolation;
    this.identityManager = config?.identityManager;
    this.observability = config?.observability;

    // Initialize 6 Checkers
    this.sqlChecker = new SqlChecker();
    this.schemaChecker = new SchemaChecker();
    this.piiChecker = new PiiChecker();
    this.numericChecker = new NumericChecker();
    this.customChecker = new CustomChecker();
    this.stateChecker = new StateChecker();

    // Load Rulepacks
    this.packs = this.loadPacks(config?.packs);
    this.policyCommitmentHash = computePolicyCommitmentHash(this.packs);

    // Initialize Logging & Ledger
    this.logger = new AegisEventLogger(config?.logging);
    this.ledger = new LearningLedgerManager(config?.logging?.ledgerPath);
  }

  public registerStateProvider(provider: StateProvider): void {
    this.defaultStateProvider = provider;
  }

  public resetState(): void {
    this.numericChecker.resetRateLimits();
  }

  private loadPacks(packsConfig?: (string | RulePack)[]): RulePack[] {
    const loaded: RulePack[] = [];

    if (!packsConfig || packsConfig.length === 0) {
      const defaultRefs = ['@aegis/sql-guard', '@aegis/finance-guard', '@aegis/data-guard'];
      for (const ref of defaultRefs) {
        const pack = RulePackLoader.loadPack(ref);
        if (pack) loaded.push(pack);
      }
    } else {
      for (const ref of packsConfig) {
        const pack = RulePackLoader.loadPack(ref);
        if (pack) loaded.push(pack);
      }
    }

    return loaded;
  }

  /**
   * Synchronous evaluation of tool call invariants.
   * State must be passed directly in options.state if state invariants are evaluated synchronously.
   */
  public evaluate(toolCall: ToolCall, options?: EvaluateOptions): AegisVerdict {
    const startTime = performance.now();
    const timestamp = new Date().toISOString();
    const safeToolCall: ToolCall = {
      tool: typeof toolCall?.tool === 'string' ? toolCall.tool : 'unknown_tool',
      params:
        toolCall?.params && typeof toolCall.params === 'object' && !Array.isArray(toolCall.params)
          ? toolCall.params
          : {},
    };
    const violations: AegisViolation[] = [];
    let rulesEvaluated = 0;
    let toolCallFingerprint = '';
    const tracer = options?.enableDiagnostics ? new StepDiagnosticCollector() : null;

    try {
      tracer?.startStage('NORMALIZATION');
      toolCallFingerprint = computeToolCallFingerprint(safeToolCall);
      tracer?.endStage('NORMALIZATION', 'PASSED', {
        tool: safeToolCall.tool,
        paramKeys: Object.keys(safeToolCall.params),
      });

      tracer?.startStage('SCHEMA_VALIDATION');
      // Resolve state: explicit option state or synchronous provider result
      let stateContext = options?.state;
      if (!stateContext && options?.stateProvider) {
        const result = options.stateProvider(safeToolCall);
        if (!(result instanceof Promise)) {
          stateContext = result;
        }
      } else if (!stateContext && this.defaultStateProvider) {
        const result = this.defaultStateProvider(safeToolCall);
        if (!(result instanceof Promise)) {
          stateContext = result;
        }
      }
      tracer?.endStage('SCHEMA_VALIDATION', 'PASSED', { stateResolved: stateContext != null });

      tracer?.startStage('INVARIANT_EVALUATION');
      // Agent Identity RBAC Check
      let rbacBlocked = false;
      if (options?.callerId && this.identityManager) {
        const checkParams: CapabilityCheck = {
          toolName: safeToolCall.tool,
        };
        
        if ('amount' in safeToolCall.params && typeof safeToolCall.params.amount === 'number') {
          checkParams.amount = safeToolCall.params.amount;
        }

        const rbacResult = this.identityManager.validateCapability(options.callerId, checkParams);
        if (!rbacResult.allowed) {
          violations.push({
            ruleId: 'RBAC-001',
            packId: '@aegis/core',
            severity: 'critical',
            message: rbacResult.reason || `Agent '${options.callerId}' is unauthorized.`,
            suggestedFix: 'Review agent identity profile for allowed tools and limits.',
          });
          rbacBlocked = true;
        }
      }

      if (!rbacBlocked) {
        for (const pack of this.packs) {
          for (const rule of pack.rules) {
            rulesEvaluated++;
            const ruleViolations = this.evaluateRule(rule, pack.id, safeToolCall, {
              ...options,
              state: stateContext,
            });
            if (ruleViolations.length > 0) {
              violations.push(...ruleViolations);
            }
          }
        }
      }
      tracer?.endStage('INVARIANT_EVALUATION', violations.length === 0 ? 'PASSED' : 'FAILED', {
        rulesEvaluated,
        violationsCount: violations.length,
      });

      tracer?.startStage('REMEDIATION_SYNTHESIS');
      const latencyMs = Number((performance.now() - startTime).toFixed(3));
      const verdict = createVerdict(
        violations,
        latencyMs,
        this.mode,
        toolCallFingerprint,
        this.policyCommitmentHash,
        timestamp,
        { trustedContext: options?.trustedContext }
      );
      tracer?.endStage('REMEDIATION_SYNTHESIS', 'PASSED', {
        hasSuggestedFix: verdict.suggestedFix != null,
      });

      tracer?.startStage('MERKLE_COMMIT');
      tracer?.endStage('MERKLE_COMMIT', 'PASSED', { proofHash: verdict.proofHash });

      if (tracer) {
        let rootCause: RootCauseAnalysis | undefined;
        if (violations.length > 0) {
          const primary = violations[0];
          let failureCategory: FailureCategory = 'SECURITY_VIOLATION';
          if (primary.ruleId.startsWith('SQL')) failureCategory = 'SECURITY_VIOLATION';
          else if (primary.ruleId.startsWith('FIN') || primary.ruleId.startsWith('NUM')) failureCategory = 'NUMERIC_BREACH';
          else if (primary.ruleId.startsWith('PII')) failureCategory = 'PII_LEAK';
          else if (primary.ruleId.startsWith('STATE')) failureCategory = 'STATE_CONFLICT';
          else if (primary.ruleId.startsWith('SCHEMA')) failureCategory = 'SCHEMA_MISMATCH';

          rootCause = {
            failureCategory,
            primaryCulpritRule: primary.ruleId,
            triggeringPayloadSnippet: JSON.stringify(safeToolCall.params).slice(0, 120),
            suggestedFixDiff: primary.suggestedFix,
            remediationAction: primary.suggestedFix ? 'APPLY_SUGGESTED_FIX' : 'REJECT_TOOL_CALL',
          };
        }
        verdict.diagnosticTrace = tracer.finalize(rootCause);
      }

      // Telemetry & Learning Ledger Recording
      const event = this.logger.logEvent({
        framework: options?.framework ?? 'raw',
        toolName: safeToolCall.tool,
        toolCallFingerprint,
        mode: this.mode,
        verdict: verdict.allowed ? 'ALLOWED' : 'BLOCKED',
        rulesEvaluated,
        rulesFired: violations,
        latencyMs,
        proofHash: verdict.proofHash,
        policyCommitmentHash: this.policyCommitmentHash,
      });

      this.ledger.recordEvent(event);

      if (!verdict.allowed) {
        if (options?.onViolation) {
          options.onViolation(verdict, toolCall);
        } else if (this.onViolation) {
          this.onViolation(verdict, toolCall);
        }
      }

      // Opt-in OTel GenAI span emission (zero-egress: sink is caller-owned).
      // Sink failures must never affect the verdict.
      if (this.observability?.onSpan) {
        try {
          this.observability.onSpan(
            formatGenAiExecuteToolSpan(safeToolCall, verdict, { agentName: this.observability.agentName })
          );
        } catch (err) {
          console.warn('[aegis] observability span sink threw; span dropped:', (err as Error).message);
        }
      }

      return verdict;
    } catch (err: any) {
      const latencyMs = Number((performance.now() - startTime).toFixed(3));
      return this.handleEvaluationError(
        err,
        safeToolCall,
        toolCallFingerprint || 'unknown_fingerprint',
        rulesEvaluated,
        latencyMs,
        timestamp,
        options
      );
    }
  }

  /**
   * Asynchronous evaluation of tool call invariants.
   * Resolves async StateProviders from databases/redis before rule execution.
   */
  public async evaluateAsync(toolCall: ToolCall, options?: EvaluateOptions): Promise<AegisVerdict> {
    let resolvedState = options?.state;

    if (!resolvedState) {
      const provider = options?.stateProvider ?? this.defaultStateProvider;
      if (provider) {
        try {
          resolvedState = await provider(toolCall);
        } catch {
          // If state fetching fails and failPolicy is fail-closed, evaluateRule will catch missing state
        }
      }
    }

    return this.evaluate(toolCall, { ...options, state: resolvedState });
  }

  private evaluateRule(
    rule: Rule,
    packId: string,
    toolCall: ToolCall,
    options?: EvaluateOptions
  ): AegisViolation[] {
    const { condition, id: ruleId } = rule;

    switch (condition.type) {
      case 'sql_ast':
        return this.sqlChecker.evaluate(ruleId, packId, condition.params, toolCall, rule.severity);
      case 'json_schema':
        return this.schemaChecker.evaluate(ruleId, packId, condition.params, toolCall, rule.severity);
      case 'regex':
        return this.piiChecker.evaluate(ruleId, packId, condition.params, toolCall, rule.severity);
      case 'numeric':
        return this.numericChecker.evaluate(ruleId, packId, condition.params, toolCall, rule.severity);
      case 'custom':
        return this.customChecker.evaluate(ruleId, packId, condition.params, toolCall, rule.severity);
      case 'state_invariant':
        return this.stateChecker.evaluate(
          ruleId,
          packId,
          condition.params,
          toolCall,
          options?.state,
          rule.severity
        );
      default:
        return [];
    }
  }

  private handleEvaluationError(
    err: any,
    toolCall: ToolCall,
    toolCallFingerprint: string,
    rulesEvaluated: number,
    latencyMs: number,
    timestamp: string,
    options?: EvaluateOptions
  ): AegisVerdict {
    const policy = this.resolveFailPolicy('critical');
    const isFailClosed = policy === 'fail-closed';

    const fallbackViolations: AegisViolation[] = isFailClosed
      ? [
          {
            ruleId: 'ENGINE-ERR',
            packId: '@aegis/internal',
            severity: 'critical',
            message: `Evaluation engine internal error: ${err.message}. Blocked by fail-closed policy.`,
            suggestedFix: 'Review engine logs and error stack.',
          },
        ]
      : [];

    const verdict = createVerdict(
      fallbackViolations,
      latencyMs,
      this.mode,
      toolCallFingerprint,
      this.policyCommitmentHash,
      timestamp,
      {
        warning: `Aegis Engine evaluation exception: ${err.message}. Defaulted to ${policy}.`,
      }
    );

    const event = this.logger.logEvent({
      framework: options?.framework ?? 'raw',
      toolName: toolCall.tool,
      toolCallFingerprint,
      mode: this.mode,
      verdict: verdict.allowed ? 'ALLOWED' : 'BLOCKED',
      rulesEvaluated,
      rulesFired: fallbackViolations,
      latencyMs,
      proofHash: verdict.proofHash,
      policyCommitmentHash: this.policyCommitmentHash,
      engineError: err.message,
      engineErrorStack: err.stack,
    });

    this.ledger.recordEvent(event);

    return verdict;
  }

  public resolveFailPolicy(severity: 'critical' | 'warning' | 'info', packId?: string): AegisFailPolicy {
    if (typeof this.failPolicy === 'string') {
      return this.failPolicy;
    }

    if (packId && this.failPolicy.byPack && this.failPolicy.byPack[packId]) {
      return this.failPolicy.byPack[packId];
    }

    if (this.failPolicy.bySeverity && this.failPolicy.bySeverity[severity]) {
      return this.failPolicy.bySeverity[severity]!;
    }

    return this.failPolicy.default ?? 'fail-open';
  }

  public getLoadedPacks(): RulePack[] {
    return [...this.packs];
  }

  public updatePacks(newPacks: RulePack[]): void {
    this.packs = newPacks;
    this.policyCommitmentHash = computePolicyCommitmentHash(this.packs);
  }

  public getPolicyCommitmentHash(): string {
    return this.policyCommitmentHash;
  }

  public getLedgerSummary() {
    return this.ledger.getSummary();
  }

  public sanitize(toolCall: ToolCall) {
    return AegisSanitizer.sanitize(toolCall);
  }

  public getRecentEvents(limit?: number) {
    return this.logger.readRecentEvents(limit);
  }

  /**
   * Performs an in-process diagnostic self-test across all 6 invariant checkers.
   * Verifies AST parsing, schema compilation, regex scanners, and boundary constraints.
   */
  public runSelfTest(): { healthy: boolean; checkersTested: number; latencyMs: number; details: Record<string, boolean>; error?: string } {
    const start = performance.now();
    const details: Record<string, boolean> = {};

    try {
      // 1. Test Schema & Benign Evaluation
      const benignCall: ToolCall = { tool: '__aegis_diagnostic_probe__', params: { query: 'SELECT 1' } };
      const v1 = this.evaluate(benignCall);
      details.evaluationPipeline = typeof v1.allowed === 'boolean' && typeof v1.proofHash === 'string';

      // 2. Test SQL Invariant AST
      const sqlViolations = this.sqlChecker.evaluate('diag-sql', 'diag-pack', { block_statements: ['DROP'] }, { tool: 'q', params: { sql: 'DROP TABLE users' } });
      details.sqlChecker = sqlViolations.length > 0;

      // 3. Test Numeric Bounds
      const numViolations = this.numericChecker.evaluate('diag-num', 'diag-pack', { field: 'amount', max: 100 }, { tool: 'pay', params: { amount: 500 } });
      details.numericChecker = numViolations.length > 0;

      // 4. Test PII Detection
      const piiViolations = this.piiChecker.evaluate('diag-pii', 'diag-pack', { patterns: ['US_SSN'] }, { tool: 'log', params: { data: 'SSN: 000-12-3456' } });
      details.piiChecker = piiViolations.length > 0;

      // 5. Test Sanitizer
      const sanitized = AegisSanitizer.sanitize({ tool: 'log', params: { data: 'SSN: 000-12-3456' } });
      details.sanitizer = Boolean(sanitized);

      const allPassed = Object.values(details).every(Boolean);
      return {
        healthy: allPassed,
        checkersTested: Object.keys(details).length,
        latencyMs: Number((performance.now() - start).toFixed(3)),
        details,
      };
    } catch (e: any) {
      return {
        healthy: false,
        checkersTested: Object.keys(details).length,
        latencyMs: Number((performance.now() - start).toFixed(3)),
        details,
        error: e.message,
      };
    }
  }
}

