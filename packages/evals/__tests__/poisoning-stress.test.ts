import { describe, it, expect } from 'vitest';
import {
  runPoisoningStressSuite,
  POISONING_STRESS_VECTORS,
  BENIGN_CONTROL,
} from '../src/adaptive/poisoning-stress.js';
import { MCPToolPoisoningScanner } from '@aegis-kernel/core';

describe('Tool-description poisoning stress suite', () => {
  it('contains a meaningful corpus (>= 12 vectors across >= 10 attack classes)', () => {
    expect(POISONING_STRESS_VECTORS.length).toBeGreaterThanOrEqual(12);
    const classes = new Set(POISONING_STRESS_VECTORS.map((v) => v.attackClass));
    expect(classes.size).toBeGreaterThanOrEqual(10);
  });

  it('detects every poisoning vector (a miss is a real finding)', () => {
    const result = runPoisoningStressSuite();
    expect(result.totalVectors).toBe(POISONING_STRESS_VECTORS.length);
    expect(result.missed).toEqual([]);
    expect(result.detectionRatePercent).toBe(100);
  });

  it('raises NO false positive on the benign control', () => {
    const result = runPoisoningStressSuite();
    expect(result.falsePositives).toEqual([]);
  });

  it('regression: UNBOUNDED_SCHEMA and CAPABILITY_ESCALATION classes are covered (2026-08-20 scanner gap fix)', () => {
    const result = runPoisoningStressSuite();
    expect(result.byClass['UNBOUNDED_SCHEMA'].detected).toBe(result.byClass['UNBOUNDED_SCHEMA'].total);
    expect(result.byClass['CAPABILITY_ESCALATION'].detected).toBe(result.byClass['CAPABILITY_ESCALATION'].total);
  });

  it('scanner does not fire on additionalProperties:false with typed properties', () => {
    const s = new MCPToolPoisoningScanner();
    const clean = s.scanToolDefinition(BENIGN_CONTROL.tool);
    expect(clean.isPoisoned).toBe(false);
    expect(clean.threats).toHaveLength(0);
  });
});
