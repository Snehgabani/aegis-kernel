import {
  AegisEngine,
  type AegisConfig,
  type AegisVerdict,
  type ToolCall,
} from '@aegis-kernel/core';

export interface LangChainStructuredTool {
  name: string;
  description: string;
  schema?: any;
  call: (arg: any, config?: any) => Promise<any>;
  invoke: (arg: any, config?: any) => Promise<any>;
  [key: string]: any;
}

export class AegisLangChainGuard {
  private engine: AegisEngine;

  constructor(config?: AegisConfig) {
    this.engine = new AegisEngine(config);
  }

  /**
   * Wraps a single LangChain tool with deterministic invariant validation
   */
  public wrap<T extends LangChainStructuredTool>(tool: T): T {
    const originalInvoke = tool.invoke ? tool.invoke.bind(tool) : null;
    const originalCall = tool.call ? tool.call.bind(tool) : null;
    const engine = this.engine;

    const wrappedInvoke = async (arg: any, config?: any) => {
      const params = typeof arg === 'object' && arg !== null ? arg : { input: arg };
      const toolCall: ToolCall = {
        tool: tool.name,
        params,
      };

      const verdict: AegisVerdict = engine.evaluate(toolCall, {
        framework: 'langchain',
      });

      if (!verdict.allowed) {
        const violation = verdict.violations[0];
        const error = new Error(
          `[Aegis Safety Violation] Tool '${tool.name}' blocked by rule ${violation?.ruleId}: ${violation?.message}. Fix: ${verdict.suggestedFix || 'None'}`
        );
        (error as any).aegisVerdict = verdict;
        throw error;
      }

      if (originalInvoke) {
        return originalInvoke(arg, config);
      } else if (originalCall) {
        return originalCall(arg, config);
      }
    };

    const proxy = new Proxy(tool, {
      get(target, prop, receiver) {
        if (prop === 'invoke' || prop === 'call') {
          return wrappedInvoke;
        }
        return Reflect.get(target, prop, receiver);
      },
    });

    return proxy;
  }

  /**
   * Wraps an array of LangChain tools
   */
  public wrapAll<T extends LangChainStructuredTool>(tools: T[]): T[] {
    return tools.map((t) => this.wrap(t));
  }

  public getEngine(): AegisEngine {
    return this.engine;
  }
}
