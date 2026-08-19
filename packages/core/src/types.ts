/**
 * Aegis Invariant Kernel Type Definitions
 * Deterministic, Verifiable Policy & State Invariant Enforcement Layer
 */

import type { StateInvariantCondition } from './checkers/state-checker.js';
import type { AgentIdentityManager } from './identity/agent-identity.js';

export type AegisMode = 'enforce' | 'shadow';
export type AegisSeverity = 'critical' | 'warning' | 'info';
export type AegisFailPolicy = 'fail-open' | 'fail-closed';
export type AegisFramework = 'mcp' | 'langchain' | 'openai' | 'anthropic' | 'vercel-ai' | 'llamaindex' | 'raw';

/**
 * Developer-owned State Provider function.
 * Must reside OUTSIDE agent control to prevent prompt-injection spoofing.
 */
export type StateProvider = (
  toolCall: ToolCall
) => Promise<Record<string, unknown>> | Record<string, unknown>;

export interface GranularFailPolicy {
  default: AegisFailPolicy;
  bySeverity?: {
    critical?: AegisFailPolicy;
    warning?: AegisFailPolicy;
    info?: AegisFailPolicy;
  };
  byPack?: Record<string, AegisFailPolicy>;
}

export interface AegisConfig {
  mode?: AegisMode;
  failPolicy?: AegisFailPolicy | GranularFailPolicy;
  packs?: (string | RulePack)[];
  stateProvider?: StateProvider; // Trusted system of record hook
  logging?: {
    enabled?: boolean;
    path?: string;
    ledgerPath?: string;
    maxFileSizeMb?: number;
    enablePiiRedaction?: boolean;
  };
  thresholds?: {
    maxLatencyMs?: number;
    maxOverrideRatio?: number;
  };
  onViolation?: (verdict: AegisVerdict, toolCall: ToolCall) => void;
  identityManager?: AgentIdentityManager;
}

import type { AegisForensicDiagnosticTrace } from './diagnostics/forensic-trace.js';

export interface ToolCall {
  tool: string;
  params: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface EvaluateOptions {
  framework?: AegisFramework;
  state?: Record<string, unknown>; // Explicit developer-supplied trusted state
  stateProvider?: StateProvider; // Dynamic state fetcher
  callerId?: string;
  trustedContext?: boolean; // If false, returns terse suggested fix to prevent information disclosure
  onViolation?: (verdict: AegisVerdict, toolCall: ToolCall) => void;
  enableDiagnostics?: boolean; // If true, collects microsecond stage traces and root-cause analysis
}

export interface AegisViolation {
  ruleId: string;
  packId: string;
  severity: AegisSeverity;
  message: string;
  suggestedFix?: string;
  context?: Record<string, unknown>;
}

export interface AegisVerdict {
  allowed: boolean;
  violations: AegisViolation[];
  proofHash: string; // Cryptographic commitment binding verdict + tool fingerprint + rulepack version + rule IDs
  latencyMs: number;
  mode: AegisMode;
  suggestedFix?: string;
  warning?: string;
  diagnosticTrace?: AegisForensicDiagnosticTrace;
}

export interface AegisEvent {
  id: string; // UUID v7
  timestamp: string; // ISO 8601 UTC
  version: string; // Engine version
  framework: AegisFramework;
  toolName: string;
  toolCallFingerprint: string; // SHA-256 for deduplication / correlation
  mode: AegisMode;
  verdict: 'ALLOWED' | 'BLOCKED';
  rulesEvaluated: number;
  rulesFired: AegisViolation[]; // Redacted messages before logging
  latencyMs: number;
  proofHash: string;
  policyCommitmentHash: string; // Hash binding active rule pack versions
  userOverride: boolean;
  overrideReason?: string;
  feedbackTag?: 'true_positive' | 'false_positive' | 'unsure';
  engineError?: string;
  engineErrorStack?: string;
}

export interface RulePerformance {
  timesEvaluated: number;
  timesFired: number;
  overridesCount: number;
  overrideRatio: number; // overridesCount / timesFired
  averageLatencyMs: number;
  triageStatus: 'healthy' | 'review_needed' | 'quarantined';
  lastFired?: string;
}

export interface LearningLedger {
  totalEventsProcessed: number;
  totalBlocked: number;
  totalAllowed: number;
  totalOverrides: number;
  rulePerformance: Record<string, RulePerformance>;
  uncoveredTools: Record<string, number>;
  lastUpdated: string;
}

// Condition Param Types

export interface SqlAstConditionParams {
  statements?: ('SELECT' | 'INSERT' | 'UPDATE' | 'DELETE' | 'DROP' | 'TRUNCATE' | 'ALTER')[];
  require?: 'WHERE_CLAUSE' | 'LIMIT';
  block_statements?: ('DROP' | 'TRUNCATE' | 'ALTER' | 'DELETE' | 'UPDATE')[];
  max_limit?: number;
  allowed_tables?: string[];
  blocked_tables?: string[];
  database_field?: string;
}

export interface SqlAstCondition {
  type: 'sql_ast';
  params: SqlAstConditionParams;
}

export interface JsonSchemaConditionParams {
  schema: Record<string, unknown>;
  strict?: boolean;
}

export interface JsonSchemaCondition {
  type: 'json_schema';
  params: JsonSchemaConditionParams;
}

export interface RegexConditionParams {
  patterns: string[];
  field?: string;
  targets?: ('params' | 'body' | 'url' | 'headers' | '*')[];
  match_action?: 'block' | 'warn';
}

export interface RegexCondition {
  type: 'regex';
  params: RegexConditionParams;
}

export interface NumericConditionParams {
  field: string;
  min?: number;
  max?: number;
  rate_limit?: {
    max_per_minute: number;
  };
}

export interface NumericCondition {
  type: 'numeric';
  params: NumericConditionParams;
}

export interface CustomConditionParams {
  predicate: string; // Zero-eval declarative expression
}

export interface CustomCondition {
  type: 'custom';
  params: CustomConditionParams;
}

export type RuleCondition =
  | SqlAstCondition
  | JsonSchemaCondition
  | RegexCondition
  | NumericCondition
  | CustomCondition
  | StateInvariantCondition;

export interface Rule {
  id: string;
  severity: AegisSeverity;
  description: string;
  condition: RuleCondition;
  suggestedFix?: string;
}

export interface RulePack {
  id: string;
  name: string;
  version: string;
  description?: string;
  rules: Rule[];
}
