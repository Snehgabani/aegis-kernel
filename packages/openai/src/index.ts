import {
  AegisEngine,
  type AegisConfig,
  type AegisVerdict,
  type ToolCall,
} from '@aegis-kernel/core';

export interface OpenAIFunctionToolCall {
  id: string;
  type: 'function';
  function: {
    name: string;
    arguments: string; // JSON string
  };
}

export class AegisOpenAIGuard {
  private engine: AegisEngine;

  constructor(config?: AegisConfig | AegisEngine) {
    if (config instanceof AegisEngine) {
      this.engine = config;
    } else {
      this.engine = new AegisEngine(config);
    }
  }

  /**
   * Intercept and evaluate an OpenAI tool_calls response item
   */
  public evaluate(toolCallItem: OpenAIFunctionToolCall): AegisVerdict {
    let parsedArgs: Record<string, unknown> = {};
    try {
      parsedArgs = JSON.parse(toolCallItem.function.arguments || '{}');
    } catch {
      parsedArgs = { raw: toolCallItem.function.arguments };
    }

    const toolCall: ToolCall = {
      tool: toolCallItem.function.name,
      params: parsedArgs,
    };

    return this.engine.evaluate(toolCall, { framework: 'openai' });
  }

  public evaluateToolCall(toolCallItem: OpenAIFunctionToolCall): AegisVerdict {
    return this.evaluate(toolCallItem);
  }

  /**
   * Evaluates and formats an auto-correction tool message if blocked
   */
  public handleToolCall(
    toolCallItem: OpenAIFunctionToolCall,
    executor: (args: Record<string, unknown>) => Promise<unknown>
  ): Promise<{ role: 'tool'; tool_call_id: string; content: string }> {
    const verdict = this.evaluate(toolCallItem);

    if (!verdict.allowed) {
      const primaryViolation = verdict.violations[0];
      const errorContent = JSON.stringify({
        error: 'AEGIS_INVARIANT_VIOLATION',
        rule_id: primaryViolation?.ruleId,
        severity: primaryViolation?.severity,
        reason: primaryViolation?.message,
        suggested_fix: verdict.suggestedFix,
        proof_hash: verdict.proofHash,
      });

      return Promise.resolve({
        role: 'tool',
        tool_call_id: toolCallItem.id,
        content: errorContent,
      });
    }

    let parsedArgs: Record<string, unknown> = {};
    try {
      parsedArgs = JSON.parse(toolCallItem.function.arguments || '{}');
    } catch {
      parsedArgs = {};
    }

    return executor(parsedArgs).then((result) => ({
      role: 'tool',
      tool_call_id: toolCallItem.id,
      content: typeof result === 'string' ? result : JSON.stringify(result),
    }));
  }

  public getEngine(): AegisEngine {
    return this.engine;
  }
}

export { AegisOpenAIGuard as AegisOpenAIInterceptor };
