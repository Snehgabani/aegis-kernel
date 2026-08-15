import { AegisEngine } from '../engine.js';
import { AegisVerdict, AegisViolation, ToolCall, EvaluateOptions } from '../types.js';

export interface ReaskOptions {
  maxRetries?: number;          // Default: 3
  backoffMs?: number;           // Default: 100, doubles each retry
  includeViolationDetails?: boolean; // Default: true
}

export interface ReaskResult {
  verdict: AegisVerdict;
  attempts: number;
  healed: boolean;
  history: ReaskAttempt[];
}

export interface ReaskAttempt {
  attemptNumber: number;
  toolCall: ToolCall;
  verdict: AegisVerdict;
  correctivePrompt?: string;
}

export type ReaskCallback = (
  correctiveFeedback: string,
  previousToolCall: ToolCall,
  violations: AegisViolation[]
) => Promise<ToolCall>;

export class ReaskHandler {
  private engine: AegisEngine;

  constructor(engine: AegisEngine) {
    this.engine = engine;
  }

  public async evaluateWithReask(
    toolCall: ToolCall,
    reaskCallback: ReaskCallback,
    options?: EvaluateOptions,
    reaskOptions?: ReaskOptions
  ): Promise<ReaskResult> {
    const maxRetries = reaskOptions?.maxRetries ?? 3;
    let currentBackoffMs = reaskOptions?.backoffMs ?? 100;
    const includeViolationDetails = reaskOptions?.includeViolationDetails ?? true;

    const history: ReaskAttempt[] = [];
    let currentToolCall = toolCall;
    let attempts = 0;
    
    while (attempts <= maxRetries) {
      attempts++;
      
      // Evaluate current tool call
      const verdict = await this.engine.evaluateAsync(currentToolCall, options);
      
      if (verdict.allowed) {
        history.push({
          attemptNumber: attempts,
          toolCall: currentToolCall,
          verdict,
        });
        
        return {
          verdict,
          attempts,
          healed: attempts > 1,
          history
        };
      }
      
      // Build corrective prompt
      const correctivePrompt = this.buildCorrectivePrompt(verdict.violations, includeViolationDetails);
      
      history.push({
        attemptNumber: attempts,
        toolCall: currentToolCall,
        verdict,
        correctivePrompt
      });
      
      if (attempts <= maxRetries) {
        // Wait for backoff
        if (currentBackoffMs > 0) {
          await new Promise(resolve => setTimeout(resolve, currentBackoffMs));
          currentBackoffMs *= 2; // Exponential backoff
        }
        
        // Try to reask
        try {
          currentToolCall = await reaskCallback(correctivePrompt, currentToolCall, verdict.violations);
        } catch (error) {
          // If callback throws, we stop reasking and return current state
          return {
            verdict,
            attempts,
            healed: false,
            history
          };
        }
      } else {
        // Max retries reached
        return {
          verdict,
          attempts,
          healed: false,
          history
        };
      }
    }
    
    // Should not reach here based on while condition but for safety:
    const finalVerdict = history[history.length - 1].verdict;
    return {
      verdict: finalVerdict,
      attempts,
      healed: false,
      history
    };
  }

  private buildCorrectivePrompt(violations: AegisViolation[], includeDetails: boolean): string {
    let prompt = "Your previous tool call was blocked by security policy.\nViolations:\n";
    
    if (violations.length === 0) {
      prompt += "- Unknown violation.\n";
    } else {
      for (const v of violations) {
        prompt += `- [${v.ruleId}] ${v.message}`;
        if (includeDetails && v.suggestedFix) {
          prompt += ` Suggested fix: ${v.suggestedFix}`;
        }
        prompt += "\n";
      }
    }
    
    prompt += "\nPlease regenerate the tool call with these constraints satisfied.";
    
    return prompt;
  }
}
