import { describe, it, expect } from 'vitest';
import { mannKendall, runTrajectoryStress, renderTrajectoryStress } from '../src/adaptive/trajectory-stress.js';

describe('Mann-Kendall trend test (statistical correctness)', () => {
  it('detects a clear increasing series as significant', () => {
    const r = mannKendall(Array.from({ length: 50 }, (_, i) => i * 2 + (i % 3)));
    expect(r.trend).toBe('increasing');
    expect(r.significant).toBe(true);
    expect(r.pValue).toBeLessThan(0.05);
    expect(r.sensSlope).toBeGreaterThan(1.5); // ~2 per step
  });

  it('detects a clear decreasing series', () => {
    const r = mannKendall(Array.from({ length: 50 }, (_, i) => 100 - i * 2));
    expect(r.trend).toBe('decreasing');
    expect(r.significant).toBe(true);
    expect(r.sensSlope).toBeLessThan(-1.5);
  });

  it('finds no trend in a stationary mean-reverting series', () => {
    // deterministic sine + small alternating noise — stationary
    const r = mannKendall(Array.from({ length: 400 }, (_, i) => Math.sin(i / 7) + ((i % 2) * 0.01)));
    expect(r.significant).toBe(false);
  });

  it('handles ties without NaN (tie-corrected variance)', () => {
    const r = mannKendall([1, 1, 1, 2, 2, 3, 3, 3]);
    expect(Number.isFinite(r.z)).toBe(true);
    expect(Number.isFinite(r.varS)).toBe(true);
  });

  it('known small case: monotonic [1,2,3,4,5] has S = 10 (all pairs concordant)', () => {
    const r = mannKendall([1, 2, 3, 4, 5]);
    expect(r.s).toBe(10);
    expect(r.trend).toBe('increasing');
  });
});

describe('runTrajectoryStress (long-horizon engine stability)', () => {
  it('500-step session: no significant latency drift, attacks blocked at ALL depths, zero FPs', () => {
    const r = runTrajectoryStress({ steps: 500, seed: 42 });
    expect(r.steps).toBe(500);
    expect(r.trend.significant && r.trend.trend === 'increasing').toBe(false);
    expect(r.attacksAtDepth).toHaveLength(3);
    for (const a of r.attacksAtDepth) expect(a.blocked).toBe(true);
    expect(r.falsePositives).toBe(0);
    expect(r.falsePositiveRate.ciUpper).toBeGreaterThan(0); // CI honest even at 0 FPs
    expect(r.pass).toBe(true);
    expect(r.failures).toEqual([]);
  }, 60_000);

  it('is deterministic under a fixed seed (reproducibility)', () => {
    const a = runTrajectoryStress({ steps: 60, seed: 7 });
    const b = runTrajectoryStress({ steps: 60, seed: 7 });
    expect(a.benignSteps).toBe(b.benignSteps);
    expect(a.falsePositives).toBe(b.falsePositives);
    expect(a.attacksAtDepth.map((x) => x.blocked)).toEqual(b.attacksAtDepth.map((x) => x.blocked));
  });

  it('renderer exposes the statistics (trend, CI, depth results)', () => {
    const text = renderTrajectoryStress(runTrajectoryStress({ steps: 60, seed: 1 }));
    expect(text).toContain('Mann-Kendall');
    expect(text).toContain('95% CI');
    expect(text).toContain('PASS');
  });
});
