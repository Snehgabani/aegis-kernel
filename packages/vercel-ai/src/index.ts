import {
  AegisEngine,
  type AegisConfig,
  type AegisVerdict,
  type ToolCall,
} from '@aegis-kernel/core';

export interface VercelAITool<TParams = any, TResult = any> {
  description?: string;
  parameters?: any;
  execute?: (args: TParams, context?: any) => Promise<TResult>;
}

export interface ProtectedVercelToolOptions {
  toolName?: string;
  config?: AegisConfig | AegisEngine;
  onViolation?: (verdict: AegisVerdict, args: any) => any;
}

export class AegisVercelAIGuard {
  private engine: AegisEngine;

  constructor(config?: AegisConfig | AegisEngine) {
    if (config instanceof AegisEngine) {
      this.engine = config;
    } else {
      this.engine = new AegisEngine(config);
    }
  }

  public evaluate(toolName: string, params: Record<string, unknown>): AegisVerdict {
    const toolCall: ToolCall = {
      tool: toolName,
      params,
    };
    return this.engine.evaluate(toolCall, { framework: 'vercel-ai' });
  }

  /**
   * Wraps a Vercel AI SDK tool definition to enforce deterministic safety invariants before execution.
   */
  public wrapTool<TParams extends Record<string, unknown> = any, TResult = any>(
    toolName: string,
    toolDef: VercelAITool<TParams, TResult>,
    options?: ProtectedVercelToolOptions
  ): VercelAITool<TParams, TResult> {
    const originalExecute = toolDef.execute;
    if (!originalExecute) {
      return toolDef;
    }

    return {
      ...toolDef,
      execute: async (args: TParams, context?: any): Promise<TResult> => {
        const verdict = this.evaluate(toolName, args);

        if (!verdict.allowed) {
          if (options?.onViolation) {
            return options.onViolation(verdict, args);
          }

          const violationSummary = verdict.violations
            .map((v) => `[${v.ruleId}]: ${v.message}`)
            .join('; ');

          const errorPayload: any = {
            error: true,
            status: 'BLOCKED',
            message: `Aegis Safety Invariant Violation: ${violationSummary}`,
            violations: verdict.violations,
            proofHash: verdict.proofHash,
            suggestedFix: verdict.suggestedFix ?? verdict.violations[0]?.suggestedFix,
          };

          return errorPayload as TResult;
        }

        return originalExecute(args, context);
      },
    };
  }
}

/**
 * 1-Liner Factory Function to wrap any Vercel AI SDK tool definition
 */
export function wrapVercelTool<TParams extends Record<string, unknown> = any, TResult = any>(
  toolName: string,
  toolDef: VercelAITool<TParams, TResult>,
  config?: AegisConfig | AegisEngine
): VercelAITool<TParams, TResult> {
  const guard = new AegisVercelAIGuard(config);
  return guard.wrapTool(toolName, toolDef);
}
