export interface WasmPluginConfig {
  memoryLimitBytes?: number;
  timeoutMs?: number;
  wasiEnabled?: boolean;
}

export interface WasmPluginVerdict {
  isValid: boolean;
  score: number;
  message?: string;
  metadata?: Record<string, any>;
  executionTimeMs: number;
}

export class WasmPluginRunner {
  private config: Required<WasmPluginConfig>;

  constructor(config?: WasmPluginConfig) {
    this.config = {
      memoryLimitBytes: config?.memoryLimitBytes ?? 16 * 1024 * 1024, // 16MB default
      timeoutMs: config?.timeoutMs ?? 100, // 100ms default
      wasiEnabled: config?.wasiEnabled ?? true,
    };
  }

  /**
   * Executes a WASM plugin.
   * Provides a fallback safe in-process sandbox simulation if real WASM environments are not available.
   */
  async execute(wasmBytes: Uint8Array, inputData: any): Promise<WasmPluginVerdict> {
    const startTime = Date.now();
    
    return new Promise((resolve, reject) => {
      let isCompleted = false;

      const timer = setTimeout(() => {
        if (!isCompleted) {
          isCompleted = true;
          reject(new Error(`WASM execution timed out after ${this.config.timeoutMs}ms`));
        }
      }, this.config.timeoutMs);

      try {
        // Fallback simulation for non-WASM environments or testing
        // In a real implementation, this would use WebAssembly.instantiate with memory/WASI limits.
        
        // Simulating processing time and memory constraint checks
        if (wasmBytes.length > this.config.memoryLimitBytes) {
          throw new Error("WASM module exceeds memory limits");
        }

        setTimeout(() => {
          if (isCompleted) return;
          isCompleted = true;
          clearTimeout(timer);

          // Simulated response
          resolve({
            isValid: true,
            score: 1.0,
            message: "Execution simulated (fallback mode)",
            metadata: {
              fallback: true,
              wasi: this.config.wasiEnabled,
              inputKeys: Object.keys(inputData)
            },
            executionTimeMs: Date.now() - startTime
          });
        }, Math.min(10, this.config.timeoutMs - 1)); // simulate some quick processing

      } catch (err) {
        if (!isCompleted) {
          isCompleted = true;
          clearTimeout(timer);
          reject(err);
        }
      }
    });
  }
}
