/**
 * Aegis Invariant Kernel — CrewAI TypeScript & Agent Tool Adapter
 *
 * Intercepts tool calls in CrewAI custom tools and agentic task runners.
 */

import { AegisEngine } from '../engine.js';
import type { ToolCall, AegisVerdict } from '../types.js';

export interface CrewAIToolSpec {
  name: string;
  description: string;
  func: (input: any) => Promise<any> | any;
}

export function wrapCrewAITool(tool: CrewAIToolSpec, engine?: AegisEngine): CrewAIToolSpec {
  const aegis = engine ?? new AegisEngine();

  return {
    name: tool.name,
    description: tool.description,
    func: async (input: any): Promise<any> => {
      const params = typeof input === 'object' && input !== null ? input : { input };
      const toolCall: ToolCall = {
        tool: tool.name,
        params,
      };

      const verdict: AegisVerdict = aegis.evaluate(toolCall);

      if (!verdict.allowed) {
        const errorDetails = verdict.violations.map((v) => `${v.ruleId}: ${v.message}`).join(' | ');
        return `ERROR: Aegis Invariant Clearance Denied (${errorDetails}). ${verdict.suggestedFix ? `Suggestion: ${verdict.suggestedFix}` : ''}`;
      }

      return await tool.func(input);
    },
  };
}
