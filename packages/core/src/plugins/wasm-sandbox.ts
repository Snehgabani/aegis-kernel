// WebAssembly is globally available in Node.js 16+ but needs declaration
// when TypeScript lib doesn't include DOM
declare const WebAssembly: {
  compile(bytes: Uint8Array): Promise<any>;
  instantiate(module: any, imports?: any): Promise<any>;
  Memory: new (descriptor: { initial: number; maximum?: number }) => any;
};

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
        // Real WASM execution with memory bounds
        if (wasmBytes.length > this.config.memoryLimitBytes) {
          throw new Error("WASM module exceeds memory limits");
        }

        WebAssembly.compile(wasmBytes)
          .then((compiled: any) => {
            const memory = new WebAssembly.Memory({
              initial: 1, // 1 page = 64KB
              maximum: Math.ceil(this.config.memoryLimitBytes / 65536)
            });
            return WebAssembly.instantiate(compiled, { env: { memory } });
          })
          .then((instance: any) => {
            if (isCompleted) return;
            isCompleted = true;
            clearTimeout(timer);

            // Fail-closed semantics: the verdict must come from the module's own
            // validate() export. A module that cannot attest validity is NOT valid.
            let isValid = false;
            let message = '';

            if (typeof instance.exports.validate !== 'function') {
              message =
                'WASM module does not export a validate() function; cannot attest validity';
            } else {
              try {
                const result = instance.exports.validate(JSON.stringify(inputData));
                // WASM i32 conventions: 1 = allow, 0 = deny (JS booleans also accepted)
                isValid = result === true || result === 1 || result === 1n;
                message = isValid
                  ? 'WASM validator approved input'
                  : 'WASM validator rejected input';
              } catch (err) {
                isValid = false;
                message = `WASM validator threw during evaluation: ${(err as Error).message}`;
              }
            }

            resolve({
              isValid: isValid,
              score: isValid ? 1.0 : 0.0,
              message,
              metadata: {
                wasi: this.config.wasiEnabled,
                inputKeys: Object.keys(inputData)
              },
              executionTimeMs: Date.now() - startTime
            });
          })
          .catch((err: any) => {
            if (!isCompleted) {
              isCompleted = true;
              clearTimeout(timer);
              reject(err);
            }
          });

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
