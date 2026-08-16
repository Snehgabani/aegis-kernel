import { describe, it, expect } from 'vitest';
import { WasmPluginRunner } from '../src/plugins/wasm-sandbox.js';

describe('WasmPluginRunner', () => {
  it('should fail closed when a WASM module does not export validate()', async () => {
    const runner = new WasmPluginRunner();
    // Valid 8-byte WASM header (\0asm\1\0\0\0) with NO validate export
    const wasmBytes = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
    const inputData = { key: 'value' };

    const verdict = await runner.execute(wasmBytes, inputData);

    expect(verdict.isValid).toBe(false);
    expect(verdict.score).toBe(0.0);
    expect(verdict.message).toContain('validate()');
    expect(verdict.metadata?.wasi).toBe(true);
    expect(verdict.metadata?.inputKeys).toEqual(['key']);
    expect(verdict.executionTimeMs).toBeGreaterThanOrEqual(0);
  });

  it('should throw an error if memory limit is exceeded', async () => {
    const runner = new WasmPluginRunner({ memoryLimitBytes: 10 });
    const wasmBytes = new Uint8Array(20); // 20 bytes > 10 bytes limit

    await expect(runner.execute(wasmBytes, {})).rejects.toThrow(
      'WASM module exceeds memory limits'
    );
  });

  it('should reject invalid WASM bytecode', async () => {
    const runner = new WasmPluginRunner();
    const invalidWasm = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);

    await expect(runner.execute(invalidWasm, {})).rejects.toThrow();
  });
});
