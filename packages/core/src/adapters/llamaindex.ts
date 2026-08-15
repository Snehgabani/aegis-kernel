/**
 * Aegis Invariant Kernel — LlamaIndex Tool & Agent Adapter
 *
 * Intercepts tool calls in LlamaIndex TypeScript agents (OpenAIAgent, ReActAgent)
 * and enforces deterministic AST and state invariants before tool execution.
 */

import { AegisEngine } from '../engine.js';
import type { ToolCall, AegisVerdict } from '../types.js';

export interface LlamaIndexTool<TParams = any, TResult = any> {
  name: string;
  description: string;
  call: (params: TParams) => Promise<TResult> | TResult;
}

export function wrapLlamaIndexTool<TParams extends Record<string, unknown>, TResult>(
  tool: LlamaIndexTool<TParams, TResult>,
  engine?: AegisEngine
): LlamaIndexTool<TParams, TResult> {
  const aegis = engine ?? new AegisEngine();

  return {
    name: tool.name,
    description: tool.description,
    call: async (params: TParams): Promise<TResult> => {
      const toolCall: ToolCall = {
        tool: tool.name,
        params,
      };

      const verdict: AegisVerdict = aegis.evaluate(toolCall);

      if (!verdict.allowed) {
        const violationMsg = verdict.violations.map((v) => `[${v.ruleId}] ${v.message}`).join('; ');
        throw new Error(
          `Aegis Clearance Denied: ${violationMsg}${verdict.suggestedFix ? ` (Fix: ${verdict.suggestedFix})` : ''}`
        );
      }

      return await tool.call(params);
    },
  };
}
