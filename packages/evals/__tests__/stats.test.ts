import { describe, it, expect } from 'vitest';
import {
  zForConfidence,
  wilsonInterval,
  clopperPearsonInterval,
  binomCdf,
  ruleOfThree,
  requiredSampleSize,
  formatCI,
} from '../src/stats.js';

describe('z quantiles (Acklam inverse normal)', () => {
  it('z(0.95) ≈ 1.959964, z(0.99) ≈ 2.575829, z(0.90) ≈ 1.644854', () => {
    expect(zForConfidence(0.95)).toBeCloseTo(1.959964, 5);
    expect(zForConfidence(0.99)).toBeCloseTo(2.575829, 5);
    expect(zForConfidence(0.90)).toBeCloseTo(1.644854, 5);
  });
});

describe('Wilson score interval', () => {
  it('matches the published worked example: 60/60 → [0.93983, 1]', () => {
    // stats.stackexchange Q470107: no failures in n=60 ⇒ Wilson [0.9398281, 1]
    const ci = wilsonInterval(60, 60, 0.95);
    expect(ci.lower).toBeCloseTo(0.93983, 4);
    expect(ci.upper).toBe(1);
  });

  it('never leaves [0,1] and never collapses at boundaries (unlike Wald)', () => {
    for (const [x, n] of [[0, 5], [5, 5], [0, 20], [13, 13], [1, 1]] as const) {
      const ci = wilsonInterval(x, n);
      expect(ci.lower).toBeGreaterThanOrEqual(0);
      expect(ci.upper).toBeLessThanOrEqual(1);
      expect(ci.width).toBeGreaterThan(0); // Wald would give width 0 at x=0 or x=n
    }
  });

  it('small-sample honesty: 13/13 defense rate has Wilson lower bound well below 100%', () => {
    const ci = wilsonInterval(13, 13);
    expect(ci.point).toBe(1);
    expect(ci.lower).toBeGreaterThan(0.7);
    expect(ci.lower).toBeLessThan(0.85); // ~77% — the point of statistical reporting
  });

  it('is monotone in x for fixed n (stochastically larger success counts)', () => {
    let prevLower = -1;
    for (let x = 0; x <= 30; x++) {
      const ci = wilsonInterval(x, 30);
      expect(ci.lower).toBeGreaterThanOrEqual(prevLower);
      prevLower = ci.lower;
    }
  });

  it('converges toward the point estimate as n grows', () => {
    const small = wilsonInterval(10, 20);
    const large = wilsonInterval(500, 1000);
    expect(large.width).toBeLessThan(small.width);
  });
});

describe('Exact binomial CDF (Clopper-Pearson machinery)', () => {
  it('known values: Bin(10, 0.5) CDF at 5 ≈ 0.6230; at 10 = 1; at -1 = 0', () => {
    expect(binomCdf(5, 10, 0.5)).toBeCloseTo(0.6230, 3);
    expect(binomCdf(10, 10, 0.5)).toBe(1);
    expect(binomCdf(-1, 10, 0.5)).toBe(0);
  });

  it('P(X ≤ k) is non-decreasing in k and NON-INCREASING in p (stochastic order)', () => {
    let prev = 0;
    for (let k = 0; k <= 15; k++) {
      const v = binomCdf(k, 15, 0.3);
      expect(v).toBeGreaterThanOrEqual(prev);
      prev = v;
    }
    let prevP = 1;
    for (let p = 0.05; p < 1; p += 0.05) {
      const v = binomCdf(7, 15, p);
      expect(v).toBeLessThanOrEqual(prevP + 1e-12);
      prevP = v;
    }
  });
});

describe('Clopper-Pearson exact interval', () => {
  it('x=0: upper bound solves (1-p)^n = α/2 exactly', () => {
    // n=50 at 95%: upper = 1 - 0.025^(1/50) ≈ 0.0713 (matches scipy beta.ppf(0.975, 1, 50))
    const ci = clopperPearsonInterval(0, 50);
    expect(ci.upper).toBeCloseTo(1 - Math.pow(0.025, 1 / 50), 8);
    expect(ci.upper).toBeCloseTo(0.0713, 3);
    expect(ci.lower).toBe(0);
  });

  it('x=n: lower bound solves p^n = α/2 exactly', () => {
    const ci = clopperPearsonInterval(60, 60);
    expect(ci.lower).toBeCloseTo(Math.pow(0.025, 1 / 60), 8);
    expect(ci.lower).toBeCloseTo(0.9402, 3);
    expect(ci.upper).toBe(1);
  });

  it('is conservative: always at least as wide as Wilson (coverage guarantee ≥ nominal)', () => {
    for (const [x, n] of [[0, 10], [3, 10], [5, 10], [9, 10], [10, 10], [7, 30]] as const) {
      const w = wilsonInterval(x, n);
      const cp = clopperPearsonInterval(x, n);
      expect(cp.lower).toBeLessThanOrEqual(w.lower + 1e-9);
      expect(cp.upper).toBeGreaterThanOrEqual(w.upper - 1e-9);
    }
  });

  it('valid mid-case against exact binomial identity: interval endpoints invert the CDF', () => {
    const ci = clopperPearsonInterval(7, 30, 0.95);
    // At the lower endpoint: P(X ≥ 7) = 0.025 ⇔ 1 - CDF(6) = 0.025
    expect(1 - binomCdf(6, 30, ci.lower)).toBeCloseTo(0.025, 4);
    // At the upper endpoint: P(X ≤ 7) = 0.025
    expect(binomCdf(7, 30, ci.upper)).toBeCloseTo(0.025, 4);
  });
});

describe('Rule of three & sample-size requirements (zero-event claims)', () => {
  it('0 events in n trials ⇒ 95% upper bound 3/n', () => {
    expect(ruleOfThree(100)).toBeCloseTo(0.03, 10);
    expect(ruleOfThree(300)).toBeCloseTo(0.01, 10);
    expect(ruleOfThree(500)).toBeCloseTo(0.006, 10);
  });

  it('agrees with Wilson upper bound at x=0 for large n (approximation property)', () => {
    const w = wilsonInterval(0, 300).upper;
    expect(w).toBeGreaterThan(0); // Wilson two-sided upper ≈ 0.0125; one-sided 3/300 = 0.01 — same order
    expect(w).toBeLessThan(ruleOfThree(300) * 2);
  });

  it('claiming ASR < 1% at 95% confidence requires ≥ 300 zero-success attacks', () => {
    expect(requiredSampleSize(0.01)).toBe(300);
    expect(requiredSampleSize(0.005)).toBe(600);
    expect(requiredSampleSize(0.05)).toBe(60);
  });
});

describe('report formatting', () => {
  it('formats as "p̂% [lo, hi]"', () => {
    const s = formatCI(wilsonInterval(13, 13));
    expect(s).toMatch(/^100\.0% \[\d+\.\d, 100\.0\]$/);
  });
});
