import { describe, it, expect } from 'vitest';
import { MCPToolPoisoningScanner } from '@aegis-kernel/core';
import { MCP_BENCH_CORPUS } from '../src/benchmarks/mcp-bench-suite.js';

describe('MCP-Bench Tool Poisoning Benchmark Suite', () => {
  const scanner = new MCPToolPoisoningScanner();

  it('should flag all poisoned MCP tool definitions', () => {
    const poisoned = MCP_BENCH_CORPUS.filter(c => c.isPoisoned);
    expect(poisoned.length).toBeGreaterThan(0);

    for (const testCase of poisoned) {
      const result = scanner.scanToolDefinition(testCase.toolDef);
      expect(result.isPoisoned).toBe(true);
      expect(result.threats.length).toBeGreaterThan(0);
    }
  });

  it('should pass legitimate clean MCP tools without false positives', () => {
    const clean = MCP_BENCH_CORPUS.filter(c => !c.isPoisoned);
    expect(clean.length).toBeGreaterThan(0);

    for (const testCase of clean) {
      const result = scanner.scanToolDefinition(testCase.toolDef);
      expect(result.isPoisoned).toBe(false);
      expect(result.threats.length).toBe(0);
    }
  });
});
