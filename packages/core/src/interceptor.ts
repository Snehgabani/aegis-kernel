import { AegisEngine } from './engine.js';
import type { AegisConfig, AegisFramework, AegisVerdict, ToolCall } from './types.js';

export abstract class BaseToolCallInterceptor {
  protected engine: AegisEngine;
  protected framework: AegisFramework;

  constructor(framework: AegisFramework, config?: AegisConfig) {
    this.framework = framework;
    this.engine = new AegisEngine(config);
  }

  public evaluateToolCall(toolCall: ToolCall): AegisVerdict {
    return this.engine.evaluate(toolCall, { framework: this.framework });
  }

  public getEngine(): AegisEngine {
    return this.engine;
  }
}
