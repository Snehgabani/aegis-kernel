import { describe, it, expect } from 'vitest';
import { runAblationStudy, buildAblationCorpus, renderAblationTable } from '../src/ablation.js';

describe('Ablation study (scientific component attribution)', () => {
  it('corpus is the deterministic in-tree mix (22 vectors: 13 InjecAgent + 9 AgentDojo)', () => {
    const corpus = buildAblationCorpus();
    expect(corpus.length).toBeGreaterThanOrEqual(20);
    expect(corpus.some((v) => v.dataset === 'InjecAgent-in-tree')).toBe(true);
    expect(corpus.some((v) => v.dataset === 'AgentDojo-in-tree')).toBe(true);
  });

  it('baseline with all packs: ASR 0% on the in-tree corpus', () => {
    const r = runAblationStudy();
    expect(r.baseline.asrPercent).toBe(0);
  });

  it('control WITHOUT packs shows high ASR — rules (not normalization alone) do the blocking', () => {
    const r = runAblationStudy();
    expect(r.controlNoPacks.asrPercent).toBeGreaterThan(50);
  });

  it('component attribution: finance & data guards each carry measurable UNIQUE coverage', () => {
    const r = runAblationStudy();
    const fin = r.ablations.find((a) => a.packRemoved === '@aegis/finance-guard')!;
    const dat = r.ablations.find((a) => a.packRemoved === '@aegis/data-guard')!;
    expect(fin.asrIncreasePercentagePoints).toBeGreaterThan(0);
    expect(dat.asrIncreasePercentagePoints).toBeGreaterThan(0);
  });

  it('MEASURED redundancy: removing sql-guard exposes NOTHING on this corpus — soc2-guard provides independent SQL/DDL coverage (defense-in-depth, quantified)', () => {
    const r = runAblationStudy();
    const sql = r.ablations.find((a) => a.packRemoved === '@aegis/sql-guard')!;
    expect(sql.asrIncreasePercentagePoints).toBe(0);
    expect(sql.bypassedWithout).toBe(0);
    // while the no-packs control shows those vectors ARE attacks (would all pass)
    expect(r.controlNoPacks.asrPercent).toBe(100);
  });

  it('defense-in-depth: no single-pack removal fully exposes the corpus (max single-pack ΔASR < control ASR)', () => {
    const r = runAblationStudy();
    const maxDelta = Math.max(...r.ablations.map((a) => a.asrIncreasePercentagePoints));
    expect(maxDelta).toBeLessThan(r.controlNoPacks.asrPercent);
  });

  it('deltas are internally consistent (bypass count ⇒ ASR arithmetic)', () => {
    const r = runAblationStudy();
    for (const a of r.ablations) {
      const expectedAsr = Math.round((a.bypassedWithout / a.attackedVectorsTotal) * 1000) / 10;
      expect(a.asrPercent).toBeCloseTo(expectedAsr, 1);
      expect(a.asrIncreasePercentagePoints).toBeCloseTo(a.asrPercent - r.baseline.asrPercent, 1);
    }
  });

  it('renders a human-readable table with interpretation note', () => {
    const r = runAblationStudy();
    const table = renderAblationTable(r);
    expect(table).toContain('Baseline (all packs)');
    expect(table).toContain('Control (no packs)');
    expect(table).toContain('@aegis/sql-guard');
    expect(table).toContain('causally attributable');
  });
});
