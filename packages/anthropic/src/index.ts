import {
  AegisEngine,
  type AegisConfig,
  type AegisVerdict,
  type ToolCall,
} from '@aegis-kernel/core';

export interface ClaudeToolUseBlock {
  type: 'tool_use';
  id: string;
  name: string;
  input: Record<string, unknown>;
}

export interface ClaudeToolResultBlock {
  type: 'tool_result';
  tool_use_id: string;
  content: string;
  is_error?: boolean;
}

export class AegisAnthropicGuard {
  private engine: AegisEngine;

  constructor(config?: AegisConfig) {
    this.engine = new AegisEngine(config);
  }

  /**
   * Evaluates a Claude tool_use content block
   */
  public evaluate(toolUse: ClaudeToolUseBlock): AegisVerdict {
    const toolCall: ToolCall = {
      tool: toolUse.name,
      params: toolUse.input || {},
    };

    return this.engine.evaluate(toolCall, { framework: 'anthropic' });
  }

  /**
   * Safely executes a Claude tool use block with self-healing feedback on error
   */
  public async handleToolUse(
    toolUse: ClaudeToolUseBlock,
    executor: (input: Record<string, unknown>) => Promise<unknown>
  ): Promise<ClaudeToolResultBlock> {
    const verdict = this.evaluate(toolUse);

    if (!verdict.allowed) {
      const primaryViolation = verdict.violations[0];
      const errorPayload = JSON.stringify({
        error: 'AEGIS_INVARIANT_VIOLATION',
        rule_id: primaryViolation?.ruleId,
        severity: primaryViolation?.severity,
        reason: primaryViolation?.message,
        suggested_fix: verdict.suggestedFix,
        proof_hash: verdict.proofHash,
      });

      return {
        type: 'tool_result',
        tool_use_id: toolUse.id,
        is_error: true,
        content: `[Aegis Safety Violation]: Action was blocked by security policy.\n${errorPayload}`,
      };
    }

    try {
      const result = await executor(toolUse.input);
      return {
        type: 'tool_result',
        tool_use_id: toolUse.id,
        content: typeof result === 'string' ? result : JSON.stringify(result),
      };
    } catch (err: any) {
      return {
        type: 'tool_result',
        tool_use_id: toolUse.id,
        is_error: true,
        content: `Tool execution failed: ${err.message}`,
      };
    }
  }

  public getEngine(): AegisEngine {
    return this.engine;
  }
}
