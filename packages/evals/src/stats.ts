/**
 * @file packages/evals/src/stats.ts
 * @description Statistical foundations for Aegis evaluation claims.
 *
 * Every security/utility percentage Aegis publishes must carry a confidence
 * interval — a point estimate of "100% detection" on N=13 says almost nothing
 * scientifically (its 95% Wilson lower bound is ~77%). This module implements
 * the standard toolkit for binomial proportions:
 *
 *  - Wilson score interval (Wilson 1927): the modern default; near-nominal
 *    coverage, never leaves [0,1], does not collapse at 0 or n (unlike Wald).
 *  - Clopper-Pearson exact interval (1934): guaranteed ≥ nominal coverage
 *    (conservative); used for the safety-critical bounds (ASR upper bound).
 *  - Rule of three (3/n): one-sided 95% upper bound for zero-event samples —
 *    "0 bypasses in n trials ⇒ ASR < 3/n with 95% confidence".
 *  - Zero-event sample-size requirement: to claim rate < r at 95% confidence,
 *    n ≥ 3/r trials with zero events are required (e.g. ASR < 1% needs n ≥ 300).
 *
 * References: Wilson (1927) JASA 22:41-52; Clopper & Pearson (1934) Biometrika
 * 26:404-413; Agresti & Coull (1998) TAS 52:119-126; Hanley & Lippman-Hand
 * (1983) NEJM 309:1360-1361 (rule of three); Brown, Cai & DasGupta (2001)
 * Statist. Sci. 16:101-133 (coverage comparison). AgentDojo (NeurIPS 2024)
 * reports 95% CIs on all utility/ASR figures — this module gives Aegis the same
 * discipline without external dependencies.
 */

/** Standard-normal quantile via Acklam's rational approximation (|ε| < 1.15e-9). */
export function zForConfidence(confidence: number): number {
  if (confidence <= 0 || confidence >= 1) {
    throw new Error(`confidence must be in (0,1), got ${confidence}`);
  }
  const alpha = 1 - confidence;
  // two-sided z: the (1 - α/2) quantile of the standard normal
  const p = 1 - alpha / 2;
  // Acklam's inverse normal CDF
  const a = [-3.969683028665376e1, 2.209460984245205e2, -2.759285104469687e2, 1.38357751867269e2, -3.066479806614716e1, 2.506628277459239];
  const b = [-5.447609879822406e1, 1.615858368580409e2, -1.556989798598866e2, 6.680131188771972e1, -1.328068155288572e1];
  const c = [-7.784894002430293e-3, -3.223964580411365e-1, -2.400758277161838, -2.549732539343734, 4.374664141464968, 2.938163982698783];
  const d = [7.784695709041462e-3, 3.224671290700398e-1, 2.445134137142996, 3.754408661907416];
  const pLow = 0.02425;
  let q: number, r: number;
  if (p < pLow) {
    q = Math.sqrt(-2 * Math.log(p));
    return (((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) /
      ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1);
  }
  if (p > 1 - pLow) {
    q = Math.sqrt(-2 * Math.log(1 - p));
    return -(((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) /
      ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1);
  }
  q = p - 0.5;
  r = q * q;
  return (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5]) * q /
    (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1);
}

export interface ProportionCI {
  /** point estimate x/n */
  point: number;
  lower: number;
  upper: number;
  /** (upper - lower), useful for reporting precision */
  width: number;
  method: 'wilson' | 'clopper-pearson';
  level: number;
  n: number;
  x: number;
}

/**
 * Wilson score interval for a binomial proportion.
 * Valid for all x in [0, n]; never leaves [0,1]; does not collapse at boundaries.
 */
export function wilsonInterval(x: number, n: number, confidence = 0.95): ProportionCI {
  if (!Number.isInteger(x) || !Number.isInteger(n) || n <= 0 || x < 0 || x > n) {
    throw new Error(`invalid arguments: x=${x}, n=${n}`);
  }
  const z = zForConfidence(confidence);
  const p = x / n;
  const z2 = z * z;
  const denom = 1 + z2 / n;
  const center = (p + z2 / (2 * n)) / denom;
  const spread = (z / denom) * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n));
  return {
    point: p,
    lower: Math.max(0, center - spread),
    upper: Math.min(1, center + spread),
    width: Math.min(1, center + spread) - Math.max(0, center - spread),
    method: 'wilson',
    level: confidence,
    n,
    x,
  };
}

/* ── Exact binomial machinery for Clopper-Pearson (no external deps) ────────── */

function logGamma(z: number): number {
  // Lanczos approximation (g=7, n=9 coefficients)
  const g = [
    0.99999999999980993, 676.5203681218851, -1259.1392167224028,
    771.32342877765313, -176.61502916214059, 12.507343278686905,
    -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7,
  ];
  if (z < 0.5) {
    return Math.log(Math.PI / Math.sin(Math.PI * z)) - logGamma(1 - z);
  }
  z -= 1;
  let x = g[0];
  for (let i = 1; i < 9; i++) {
    x += g[i] / (z + i);
  }
  const t = z + 7.5;
  return 0.5 * Math.log(2 * Math.PI) + (z + 0.5) * Math.log(t) - t + Math.log(x);
}

function logChoose(n: number, k: number): number {
  return logGamma(n + 1) - logGamma(k + 1) - logGamma(n - k + 1);
}

/** Binomial CDF P(X ≤ k) for X ~ Bin(n, p), numerically stable in log space. */
export function binomCdf(k: number, n: number, p: number): number {
  if (k < 0) return 0;
  if (k >= n) return 1;
  if (p <= 0) return k >= 0 ? 1 : 0;
  if (p >= 1) return k >= n ? 1 : 0;
  const logP = Math.log(p);
  const log1mP = Math.log(1 - p);
  let sum = 0;
  // sum from the smaller tail for stability
  if (k <= n / 2) {
    for (let i = 0; i <= k; i++) {
      sum += Math.exp(logChoose(n, i) + i * logP + (n - i) * log1mP);
    }
    return Math.min(1, sum);
  }
  // complement: 1 - P(X ≥ k+1)
  let upper = 0;
  for (let i = k + 1; i <= n; i++) {
    upper += Math.exp(logChoose(n, i) + i * logP + (n - i) * log1mP);
  }
  return Math.max(0, 1 - Math.min(1, upper));
}

/**
 * Clopper-Pearson exact interval (equal-tailed): guaranteed coverage ≥ 1-α.
 * Inverts the binomial CDF by bisection — conservative by design; used for
 * safety-critical claims (e.g., the ASR upper bound).
 */
export function clopperPearsonInterval(x: number, n: number, confidence = 0.95): ProportionCI {
  if (!Number.isInteger(x) || !Number.isInteger(n) || n <= 0 || x < 0 || x > n) {
    throw new Error(`invalid arguments: x=${x}, n=${n}`);
  }
  const alpha = 1 - confidence;
  const p = x / n;
  if (x === 0) {
    const upper = bisectUpper(n, alpha / 2);
    return { point: p, lower: 0, upper, width: upper, method: 'clopper-pearson', level: confidence, n, x };
  }
  if (x === n) {
    const lower = bisectLower(n, alpha / 2);
    return { point: p, lower, upper: 1, width: 1 - lower, method: 'clopper-pearson', level: confidence, n, x };
  }
  // lower: pL s.t. P(X ≥ x | pL) = α/2. P(X ≥ x) is increasing in p, so the
  // crossing is from below: condition true means mid is ABOVE pL → move hi down.
  let lo = 0, hi = 1;
  for (let i = 0; i < 200; i++) {
    const mid = (lo + hi) / 2;
    if (1 - binomCdf(x - 1, n, mid) > alpha / 2) {
      hi = mid;
    } else {
      lo = mid;
    }
  }
  const lower = (lo + hi) / 2;
  // upper: pU s.t. P(X ≤ x | pU) = α/2. P(X ≤ x) is DECREASING in p, so the
  // predicate [CDF < α/2] is false below pU and true above → true ⇒ hi = mid.
  lo = 0; hi = 1;
  for (let i = 0; i < 200; i++) {
    const mid = (lo + hi) / 2;
    if (binomCdf(x, n, mid) < alpha / 2) {
      hi = mid;
    } else {
      lo = mid;
    }
  }
  const upper = (lo + hi) / 2;
  return { point: p, lower, upper, width: upper - lower, method: 'clopper-pearson', level: confidence, n, x };
}

function bisectUpper(n: number, alpha: number): number {
  // x=0: upper solves P(X ≤ 0 | p) = α/2 ⇔ (1-p)^n = α/2 ⇔ p = 1 - α^(1/n)
  // (E.g. n=50, α=0.05: 1 - 0.025^(1/50) ≈ 0.0713 — matches scipy beta.ppf(0.975, 1, 50).)
  return 1 - Math.pow(alpha, 1 / n);
}

function bisectLower(n: number, alpha: number): number {
  // x=n: lower solves P(X ≥ n | p) = α/2 ⇔ p^n = α/2 ⇔ p = α^(1/n)
  // (E.g. n=60: 0.025^(1/60) ≈ 0.9402.)
  return Math.pow(alpha, 1 / n);
}

/**
 * Rule of three (Hanley & Lippman-Hand 1983): with zero events in n trials,
 * the 95% one-sided upper bound on the event rate is ≈ 3/n.
 */
export function ruleOfThree(n: number): number {
  if (!Number.isInteger(n) || n <= 0) {
    throw new Error(`n must be a positive integer, got ${n}`);
  }
  return 3 / n;
}

/**
 * Minimum zero-event sample size to claim event rate < maxRate at 95%
 * confidence (rule of three): n ≥ ⌈3 / maxRate⌉.
 * E.g., claiming ASR < 1% requires ≥ 300 attacks with zero successes.
 */
export function requiredSampleSize(maxRate: number): number {
  if (maxRate <= 0 || maxRate >= 1) {
    throw new Error(`maxRate must be in (0,1), got ${maxRate}`);
  }
  return Math.ceil(3 / maxRate);
}

/** Format a ProportionCI as "p̂% [lo%, hi%]" for reports. */
export function formatCI(ci: ProportionCI, digits = 1): string {
  return `${(ci.point * 100).toFixed(digits)}% [${(ci.lower * 100).toFixed(digits)}, ${(ci.upper * 100).toFixed(digits)}]`;
}
