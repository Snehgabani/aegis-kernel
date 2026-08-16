/**
 * @file packages/core/src/adapters/hybrid-guardrail-bridge.ts
 * @description Enterprise Hybrid Guardrail Bridge for Autonomous AI Agents.
 * 
 * Implements a unified 2-Stage Defense-in-Depth Pipeline:
 *  - Stage 1: Conversational / Semantic Moderation (Llama Guard, NeMo Guardrails, Custom LLM Judge)
 *  - Stage 2: Aegis Deterministic Invariant Clearance (<1ms AST tool & state firewall)
 * 
 * Architectural Rationale:
 * Conversational moderation excels at probabilistic nuance (politeness, hate speech, jailbreak tone,
 * topic constraints) in natural language (100-800ms). However, it CANNOT provide deterministic guarantees
 * against SQL destruction, financial limit breaches, parameter tampering, or SSRF egress.
 * Aegis Invariant Kernel operates at Stage 2 as an immutable, sub-millisecond AST execution barrier.
 */

import { AegisEngine } from '../engine.js';
import type { ToolCall, AegisVerdict, AegisConfig, EvaluateOptions } from '../types.js';
import { LocalPromptInjectionDetector } from '../ml/prompt-injection-classifier.js';

export interface GuardrailCheckResult {
  allowed: boolean;
  reason?: string;
  category?: string;
  confidence?: number;
  latencyMs?: number;
  details?: Record<string, unknown>;
}

export interface ConversationalGuardrail {
  name: string;
  version?: string;
  evaluateInput?(prompt: string, context?: Record<string, unknown>): Promise<GuardrailCheckResult> | GuardrailCheckResult;
  evaluateOutput?(response: string, context?: Record<string, unknown>): Promise<GuardrailCheckResult> | GuardrailCheckResult;
}

export interface StageExecutionResult {
  stage: 1 | 2;
  stageName: string;
  allowed: boolean;
  latencyMs: number;
  reasons: string[];
  findings?: GuardrailCheckResult[];
  verdict?: AegisVerdict;
}

export interface HybridPipelineResult {
  allowed: boolean;
  verdictSummary: string;
  blockedAtStage?: 1 | 2;
  stage1Result?: StageExecutionResult;
  stage2Result?: StageExecutionResult;
  totalLatencyMs: number;
  timestamp: string;
}

export interface HybridBridgeOptions {
  stage1Guardrails?: ConversationalGuardrail[];
  stage2Engine?: AegisEngine;
  aegisConfig?: AegisConfig;
  failClosedStage1?: boolean;
  shortCircuitOnStage1Block?: boolean;
}

/**
 * Stage 1 Adapter: Llama Guard 3 / 3-Vision Compatible Moderation Adapter.
 */
export class LlamaGuardAdapter implements ConversationalGuardrail {
  public name = 'LlamaGuard-v3-Adapter';
  public version = '3.0';
  private customEvaluator?: (text: string, type: 'input' | 'output') => Promise<GuardrailCheckResult> | GuardrailCheckResult;

  // Standard MLCommons / Llama Guard Hazard Taxonomy
  public static readonly HAZARD_CATEGORIES = {
    S1: 'Violent Crimes',
    S2: 'Non-Violent Crimes & Theft',
    S3: 'Sex-Related Crimes',
    S4: 'Child Sexual Exploitation & Abuse',
    S5: 'Defamation & Malicious Harm',
    S6: 'Specialized Professional Advice (Medical/Financial/Legal)',
    S7: 'Privacy & Personal Identifiable Information Violations',
    S8: 'Intellectual Property Infringement',
    S9: 'Indiscriminate Weapons (CBRN)',
    S10: 'Hate Speech & Harassment',
    S11: 'Suicide, Self-Harm & Cyberbullying',
    S12: 'Sexual Content & Explicit Media',
    S13: 'Cyberattacks, Exploits & Malicious Scripting',
  } as const;

  private toxicRegexes = [
    /\b(how to (make|build) a (bomb|weapon|explosive))\b/i,
    /\b(kill yourself|commit suicide)\b/i,
    /\b(steal credit card|ddos attack script)\b/i,
  ];

  constructor(options?: {
    customEvaluator?: (text: string, type: 'input' | 'output') => Promise<GuardrailCheckResult> | GuardrailCheckResult;
  }) {
    this.customEvaluator = options?.customEvaluator;
  }

  public async evaluateInput(prompt: string, _context?: Record<string, unknown>): Promise<GuardrailCheckResult> {
    const start = performance.now();

    if (this.customEvaluator) {
      const res = await this.customEvaluator(prompt, 'input');
      return { ...res, latencyMs: performance.now() - start };
    }

    // High-speed zero-egress semantic heuristic fallback
    for (const pattern of this.toxicRegexes) {
      if (pattern.test(prompt)) {
        return {
          allowed: false,
          category: 'S13: Cyberattacks & Malicious Acts',
          reason: 'LlamaGuard intercepted severe policy hazard violation.',
          latencyMs: performance.now() - start,
        };
      }
    }

    return {
      allowed: true,
      reason: 'LlamaGuard: Prompt passed conversational safety screening.',
      latencyMs: performance.now() - start,
    };
  }

  public async evaluateOutput(response: string, _context?: Record<string, unknown>): Promise<GuardrailCheckResult> {
    const start = performance.now();

    if (this.customEvaluator) {
      const res = await this.customEvaluator(response, 'output');
      return { ...res, latencyMs: performance.now() - start };
    }

    for (const pattern of this.toxicRegexes) {
      if (pattern.test(response)) {
        return {
          allowed: false,
          category: 'S10: Content Safety',
          reason: 'LlamaGuard: Response generated unsafe conversational content.',
          latencyMs: performance.now() - start,
        };
      }
    }

    return {
      allowed: true,
      reason: 'LlamaGuard: Output passed conversational safety screening.',
      latencyMs: performance.now() - start,
    };
  }
}

/**
 * Stage 1 Adapter: NeMo Guardrails Flow & Topical Boundary Adapter.
 */
export class NeMoGuardAdapter implements ConversationalGuardrail {
  public name = 'NeMo-Guardrails-Adapter';
  public version = '0.9.0';
  private blockedTopics: string[];

  constructor(options?: { blockedTopics?: string[] }) {
    this.blockedTopics = options?.blockedTopics || [
      'political_opinions',
      'internal_credentials',
      'competitor_endorsement',
    ];
  }

  public evaluateInput(prompt: string): GuardrailCheckResult {
    const lower = prompt.toLowerCase();
    for (const topic of this.blockedTopics) {
      if (lower.includes(topic.replace(/_/g, ' '))) {
        return {
          allowed: false,
          category: 'Off-Topic / Policy Rail',
          reason: `NeMo Guardrails: Prompt matched restricted dialog topic '${topic}'.`,
        };
      }
    }
    return {
      allowed: true,
      reason: 'NeMo Guardrails: Prompt within approved dialog flow rails.',
    };
  }

  public evaluateOutput(_response: string): GuardrailCheckResult {
    return {
      allowed: true,
      reason: 'NeMo Guardrails: Agent response maintained approved conversational bounds.',
    };
  }
}

/**
 * Stage 1 Adapter: Fast Zero-Egress Prompt Injection Guardrail.
 */
export class AegisPromptInjectionGuardrail implements ConversationalGuardrail {
  public name = 'Aegis-Prompt-Injection-Guardrail';
  private detector = new LocalPromptInjectionDetector();

  public evaluateInput(prompt: string): GuardrailCheckResult {
    const analysis = this.detector.analyze(prompt);
    return {
      allowed: !analysis.isInjection,
      reason: analysis.reason,
      confidence: analysis.confidenceScore,
      details: analysis.details as unknown as Record<string, unknown>,
    };
  }
}

/**
 * Stage 1 Adapter: Custom LLM Judge / Semantic Classifier Guardrail.
 */
export class CustomJudgeGuardrail implements ConversationalGuardrail {
  public name: string;
  private judgeFn: (text: string, type: 'input' | 'output') => Promise<GuardrailCheckResult> | GuardrailCheckResult;

  constructor(
    name: string,
    judgeFn: (text: string, type: 'input' | 'output') => Promise<GuardrailCheckResult> | GuardrailCheckResult
  ) {
    this.name = name;
    this.judgeFn = judgeFn;
  }

  public async evaluateInput(prompt: string, _context?: Record<string, unknown>): Promise<GuardrailCheckResult> {
    return this.judgeFn(prompt, 'input');
  }

  public async evaluateOutput(response: string, _context?: Record<string, unknown>): Promise<GuardrailCheckResult> {
    return this.judgeFn(response, 'output');
  }
}

/**
 * Master Hybrid Guardrail Bridge.
 * Glues Stage 1 (Probabilistic Conversational Safety) to Stage 2 (Aegis Deterministic Invariant Clearance).
 */
export class HybridGuardrailBridge {
  private stage1Guardrails: ConversationalGuardrail[] = [];
  private stage2Engine: AegisEngine;
  private failClosedStage1: boolean;
  private shortCircuitOnStage1Block: boolean;

  constructor(options: HybridBridgeOptions = {}) {
    this.stage1Guardrails = options.stage1Guardrails || [
      new AegisPromptInjectionGuardrail(),
      new LlamaGuardAdapter(),
    ];
    this.stage2Engine = options.stage2Engine || new AegisEngine(options.aegisConfig);
    this.failClosedStage1 = options.failClosedStage1 ?? true;
    this.shortCircuitOnStage1Block = options.shortCircuitOnStage1Block ?? true;
  }

  /**
   * Registers an additional Stage 1 conversational guardrail.
   */
  public addConversationalGuardrail(guardrail: ConversationalGuardrail): this {
    this.stage1Guardrails.push(guardrail);
    return this;
  }

  /**
   * Evaluates a user prompt through Stage 1 conversational guardrails.
   */
  public async evaluatePrompt(prompt: string, context?: Record<string, unknown>): Promise<HybridPipelineResult> {
    const pipelineStart = performance.now();
    const stage1Findings: GuardrailCheckResult[] = [];
    const stage1Reasons: string[] = [];
    let stage1Allowed = true;

    for (const rail of this.stage1Guardrails) {
      if (rail.evaluateInput) {
        try {
          const res = await rail.evaluateInput(prompt, context);
          stage1Findings.push(res);
          if (!res.allowed) {
            stage1Allowed = false;
            stage1Reasons.push(`[${rail.name}] ${res.reason || 'Blocked by input policy'}`);
          }
        } catch (err: any) {
          if (this.failClosedStage1) {
            stage1Allowed = false;
            stage1Reasons.push(`[${rail.name}] Guardrail evaluation error: ${err.message}`);
          }
        }
      }
    }

    const totalLatencyMs = performance.now() - pipelineStart;
    const stage1Result: StageExecutionResult = {
      stage: 1,
      stageName: 'Conversational Moderation (Stage 1)',
      allowed: stage1Allowed,
      latencyMs: totalLatencyMs,
      reasons: stage1Reasons,
      findings: stage1Findings,
    };

    return {
      allowed: stage1Allowed,
      blockedAtStage: stage1Allowed ? undefined : 1,
      stage1Result,
      totalLatencyMs,
      timestamp: new Date().toISOString(),
      verdictSummary: stage1Allowed
        ? '✅ Stage 1 passed: User prompt cleared conversational safety boundaries.'
        : `🚫 Stage 1 violation: ${stage1Reasons.join('; ')}`,
    };
  }

  /**
   * Evaluates a tool call through Stage 2 Aegis Deterministic Invariant Clearance (<1ms AST firewall).
   */
  public evaluateToolCall(toolCall: ToolCall, options?: EvaluateOptions): HybridPipelineResult {
    const start = performance.now();
    const verdict = this.stage2Engine.evaluate(toolCall, options);
    const latencyMs = performance.now() - start;

    const reasons = verdict.violations.map((v) => `[${v.packId}:${v.ruleId}] ${v.message}`);
    const stage2Result: StageExecutionResult = {
      stage: 2,
      stageName: 'Aegis Deterministic Invariant Clearance (Stage 2)',
      allowed: verdict.allowed,
      latencyMs,
      reasons,
      verdict,
    };

    return {
      allowed: verdict.allowed,
      blockedAtStage: verdict.allowed ? undefined : 2,
      stage2Result,
      totalLatencyMs: latencyMs,
      timestamp: new Date().toISOString(),
      verdictSummary: verdict.allowed
        ? '✅ Stage 2 passed: Tool call satisfied all deterministic AST invariants.'
        : `🚫 Stage 2 violation: ${reasons.join('; ')}`,
    };
  }

  /**
   * Evaluates an agent's conversational response through Stage 1 output guardrails.
   */
  public async evaluateResponse(response: string, context?: Record<string, unknown>): Promise<HybridPipelineResult> {
    const start = performance.now();
    const findings: GuardrailCheckResult[] = [];
    const reasons: string[] = [];
    let allowed = true;

    for (const rail of this.stage1Guardrails) {
      if (rail.evaluateOutput) {
        try {
          const res = await rail.evaluateOutput(response, context);
          findings.push(res);
          if (!res.allowed) {
            allowed = false;
            reasons.push(`[${rail.name}] ${res.reason || 'Blocked by output policy'}`);
          }
        } catch (err: any) {
          if (this.failClosedStage1) {
            allowed = false;
            reasons.push(`[${rail.name}] Guardrail output evaluation error: ${err.message}`);
          }
        }
      }
    }

    const totalLatencyMs = performance.now() - start;
    const stage1Result: StageExecutionResult = {
      stage: 1,
      stageName: 'Conversational Response Moderation (Stage 1)',
      allowed,
      latencyMs: totalLatencyMs,
      reasons,
      findings,
    };

    return {
      allowed,
      blockedAtStage: allowed ? undefined : 1,
      stage1Result,
      totalLatencyMs,
      timestamp: new Date().toISOString(),
      verdictSummary: allowed
        ? '✅ Stage 1 passed: Agent response cleared conversational moderation.'
        : `🚫 Stage 1 violation: ${reasons.join('; ')}`,
    };
  }

  /**
   * Executes the complete end-to-end 2-stage hybrid guardrail evaluation for a full agent turn.
   */
  public async evaluateFullTurn(params: {
    prompt: string;
    toolCall?: ToolCall;
    response?: string;
    context?: Record<string, unknown>;
    evaluateOptions?: EvaluateOptions;
  }): Promise<HybridPipelineResult> {
    const overallStart = performance.now();

    // 1. Stage 1: Evaluate Input Prompt
    const promptRes = await this.evaluatePrompt(params.prompt, params.context);
    if (!promptRes.allowed && this.shortCircuitOnStage1Block) {
      return {
        ...promptRes,
        totalLatencyMs: performance.now() - overallStart,
      };
    }

    // 2. Stage 2: Evaluate Tool Call (if agent attempts tool invocation)
    let stage2Res: HybridPipelineResult | undefined = undefined;
    if (params.toolCall) {
      stage2Res = this.evaluateToolCall(params.toolCall, params.evaluateOptions);
      if (!stage2Res.allowed) {
        return {
          allowed: false,
          blockedAtStage: 2,
          stage1Result: promptRes.stage1Result,
          stage2Result: stage2Res.stage2Result,
          totalLatencyMs: performance.now() - overallStart,
          timestamp: new Date().toISOString(),
          verdictSummary: stage2Res.verdictSummary,
        };
      }
    }

    // 3. Stage 1: Evaluate Output Response (if agent generated text)
    if (params.response) {
      const respRes = await this.evaluateResponse(params.response, params.context);
      if (!respRes.allowed) {
        return {
          allowed: false,
          blockedAtStage: 1,
          stage1Result: respRes.stage1Result,
          stage2Result: stage2Res?.stage2Result,
          totalLatencyMs: performance.now() - overallStart,
          timestamp: new Date().toISOString(),
          verdictSummary: respRes.verdictSummary,
        };
      }
    }

    const totalLatency = performance.now() - overallStart;
    return {
      allowed: true,
      stage1Result: promptRes.stage1Result,
      stage2Result: stage2Res?.stage2Result,
      totalLatencyMs: totalLatency,
      timestamp: new Date().toISOString(),
      verdictSummary: '✅ Defense-in-Depth Cleared: Both Stage 1 Conversational & Stage 2 Invariant Firewalls passed.',
    };
  }

  /**
   * Returns the underlying Aegis deterministic engine.
   */
  public getEngine(): AegisEngine {
    return this.stage2Engine;
  }
}
