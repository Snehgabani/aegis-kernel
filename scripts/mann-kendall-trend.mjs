#!/usr/bin/env node
/**
 * @file scripts/mann-kendall-trend.mjs
 * @description Mann-Kendall non-parametric trend test + Sen's slope estimator
 * over a latency time-series (before → after optimization), with the standard
 * tie-corrected variance. Emits machine-readable evidence.
 *
 * Methodology (Hirsch, Slack & Smith 1982):
 *   S  = Σ_{i<j} sign(x_j − x_i)
 *   Var(S) = [n(n−1)(2n+5) − Σ_p t_p(t_p−1)(2t_p+5)] / 18   (tie correction)
 *   Z  = (S − 1)/σ  (S>0), 0 (S=0), (S + 1)/σ (S<0)
 *   p  = 2·(1 − Φ(|Z|))  (two-sided)
 *   Sen slope = median{(x_j − x_i)/(j − i)}
 *
 * A negative, statistically significant trend ⇒ latency decreased.
 *
 * Usage:
 *   node scripts/mann-kendall-trend.mjs <series.json> [--json <out.json>]
 *   series.json: { "profile": [ { "run": n, "p50Ms": .., "p95Ms": .., "p99Ms": .. }, ... ] }
 */
import { readFileSync, writeFileSync } from 'node:fs';

function normCdf(z) {
  // Abramowitz & Stegun 7.1.26 (error function approximation)
  const t = 1 / (1 + 0.3275911 * Math.abs(z));
  const poly =
    t * (0.254829592 + t * (-0.284496736 + t * (1.421413741 + t * (-1.453152027 + t * 1.061405429))));
  const erf = 1 - poly * Math.exp(-z * z);
  return 0.5 * (1 + Math.sign(z) * erf);
}

function mannKendall(series) {
  const n = series.length;
  let s = 0;
  let ties = 0;
  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      const d = series[j] - series[i];
      if (d > 0) s += 1;
      else if (d < 0) s -= 1;
      else ties += 1;
    }
  }
  // tie groups for variance correction
  const sorted = [...series].sort((a, b) => a - b);
  const groups = new Map();
  for (const v of sorted) groups.set(v, (groups.get(v) ?? 0) + 1);
  let tieCorrection = 0;
  for (const t of groups.values()) {
    if (t > 1) tieCorrection += t * (t - 1) * (2 * t + 5);
  }
  const variance = (n * (n - 1) * (2 * n + 5) - tieCorrection) / 18;
  const sigma = Math.sqrt(Math.max(variance, 0.0001));
  const z = s > 0 ? (s - 1) / sigma : s < 0 ? (s + 1) / sigma : 0;
  const p = 2 * (1 - normCdf(Math.abs(z)));

  // Sen's slope: median of pairwise slopes
  const slopes = [];
  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      slopes.push((series[j] - series[i]) / (j - i));
    }
  }
  slopes.sort((a, b) => a - b);
  const mid = Math.floor(slopes.length / 2);
  const senSlope = slopes.length % 2 === 1 ? slopes[mid] : (slopes[mid - 1] + slopes[mid]) / 2;

  return { n, s, variance, z, p, senSlope, ties, direction: s < 0 ? 'decrease' : s > 0 ? 'increase' : 'none' };
}

const seriesPath = process.argv[2];
if (!seriesPath) {
  console.error('usage: node scripts/mann-kendall-trend.mjs <series.json> [--json <out.json>]');
  process.exit(2);
}
const series = JSON.parse(readFileSync(seriesPath, 'utf8'));
const jsonOutIdx = process.argv.indexOf('--json');
const jsonOut = jsonOutIdx !== -1 ? process.argv[jsonOutIdx + 1] : null;

const results = {};
const rows = [];
for (const [profile, samples] of Object.entries(series)) {
  const vals = samples.map((s) => s.p99Ms);
  const mk = mannKendall(vals);
  const first = samples[0];
  const last = samples[samples.length - 1];
  const beforeMean = vals.slice(0, Math.floor(vals.length / 2)).reduce((a, b) => a + b, 0) / Math.floor(vals.length / 2);
  const afterMean = vals.slice(Math.floor(vals.length / 2)).reduce((a, b) => a + b, 0) / (vals.length - Math.floor(vals.length / 2));
  const changePct = ((afterMean - beforeMean) / beforeMean) * 100;
  results[profile] = {
    n: mk.n,
    firstRunP99Ms: first.p99Ms,
    lastRunP99Ms: last.p99Ms,
    beforeMeanP99Ms: beforeMean,
    afterMeanP99Ms: afterMean,
    changePct,
    s: mk.s,
    z: mk.z,
    pValue: mk.p,
    senSlopeMsPerRun: mk.senSlope,
    significant: mk.p < 0.05,
    direction: mk.direction,
  };
  rows.push({
    profile,
    n: mk.n,
    S: mk.s,
    Z: mk.z.toFixed(3),
    p: mk.p.toFixed(5),
    sen: mk.senSlope.toExponential(2),
    before: beforeMean.toFixed(4),
    after: afterMean.toFixed(4),
    change: changePct.toFixed(1) + '%',
    verdict: mk.p < 0.05 ? (mk.direction === 'decrease' ? 'IMPROVED*' : 'REGRESSED*') : 'n.s.',
  });
}

console.log('Mann-Kendall trend validation (P99 latency series, run order = time)');
console.log('| profile | n | S | Z | p | Sen slope (ms/run) | before μ | after μ | Δ | verdict |');
console.log('| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- |');
for (const r of rows) {
  console.log(`| ${r.profile} | ${r.n} | ${r.S} | ${r.Z} | ${r.p} | ${r.sen} | ${r.before} | ${r.after} | ${r.change} | ${r.verdict} |`);
}
const improved = Object.values(results).filter((r) => r.significant && r.direction === 'decrease').length;
const total = Object.keys(results).length;
console.log(`\n${improved}/${total} profiles show a statistically significant (p<0.05) decreasing P99 latency trend.`);

if (jsonOut) {
  writeFileSync(jsonOut, JSON.stringify({ generatedAt: new Date().toISOString(), results }, null, 2));
  console.log(`Evidence written: ${jsonOut}`);
}
