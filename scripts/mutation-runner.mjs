#!/usr/bin/env node
/**
 * Aegis Mutation Testing Harness
 *
 * Injects one semantic fault ("mutant") at a time into core source files and
 * checks whether the test suite KILLS it (test failure) or lets it SURVIVE.
 * Mutation score = killed / total. This measures test-suite quality — the
 * difference between "tests pass" and "tests would catch a real regression".
 *
 * Usage:
 *   node scripts/mutation-runner.mjs            # run all mutants
 *   node scripts/mutation-runner.mjs --json     # also write .benchmark/mutation.json
 *   node scripts/mutation-runner.mjs --quick    # fewer mutants (CI smoke)
 */

import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '..');

const MUTANTS = [
  // ---- sql-checker.ts -----------------------------------------------------
  {
    id: 'SQL-1',
    desc: 'tautology detection disabled for DELETE',
    file: 'packages/core/src/checkers/sql-checker.ts',
    search: "        if (stmtType === 'DELETE' || nestedMutations.includes('DELETE')) {\n          if (params.require === 'WHERE_CLAUSE') {\n            const hasWhere = Boolean((statement as any).where);\n            const isTautology = this.isTautologyWhere((statement as any).where, cleanedSql);\n\n            if (!hasWhere || isTautology) {",
    replace: "        if (stmtType === 'DELETE' || nestedMutations.includes('DELETE')) {\n          if (params.require === 'WHERE_CLAUSE') {\n            const hasWhere = Boolean((statement as any).where);\n            const isTautology = this.isTautologyWhere((statement as any).where, cleanedSql);\n\n            if (!hasWhere) {",
    tests: ['packages/core/__tests__/sql-checker.test.ts', 'packages/evals/__tests__/adversarial-fuzz.test.ts'],
  },
  {
    id: 'SQL-2',
    desc: 'blocked statement types no longer enforced',
    file: 'packages/core/src/checkers/sql-checker.ts',
    search: "if (params.block_statements && params.block_statements.includes(type as any)) {",
    replace: "if (params.block_statements && false) {",
    tests: ['packages/core/__tests__/sql-checker.test.ts', 'packages/evals/__tests__/adversarial-fuzz.test.ts'],
  },
  {
    id: 'SQL-3',
    desc: 'regex fallback disabled on parse failure (CTE/concat evasions slip)',
    file: 'packages/core/src/checkers/sql-checker.ts',
    search: 'const fallbackViolations = this.evaluateRegexFallback(ruleId, packId, params, cleanedSql);\n      violations.push(...fallbackViolations);',
    replace: 'const fallbackViolations = this.evaluateRegexFallback(ruleId, packId, params, cleanedSql);\n      // mutant: fallback disabled',
    tests: ['packages/core/__tests__/sql-checker.test.ts', 'packages/evals/__tests__/adversarial-fuzz.test.ts'],
  },
  {
    id: 'SQL-4',
    desc: 'LIMIT ceiling not enforced',
    file: 'packages/core/src/checkers/sql-checker.ts',
    search: 'if (params.max_limit && (statement as any).limit) {',
    replace: 'if (false && (statement as any).limit) {',
    tests: ['packages/core/__tests__/sql-checker.test.ts'],
  },
  {
    id: 'SQL-5',
    desc: 'unicode normalization (fullwidth/zero-width) removed',
    file: 'packages/core/src/checkers/sql-checker.ts',
    search: "  public static normalizeUnicode(sql: string): string {\n    return sql\n      .normalize('NFKD')\n      .replace(/[\\u200b-\\u200d\\u2060\\u2061\\u2062\\u2063\\u2064\\u200e\\u200f\\u202a-\\u202e\\uFEFF\\u00ad]/g, '');\n  }",
    replace: "  public static normalizeUnicode(sql: string): string {\n    return sql;\n  }",
    tests: ['packages/evals/__tests__/adversarial-fuzz.test.ts'],
  },
  {
    id: 'SQL-6',
    desc: 'SQL tool gate removed (non-DB tools parsed as SQL)',
    file: 'packages/core/src/checkers/sql-checker.ts',
    search: 'if (!SqlChecker.isSqlTool(tool)) {',
    replace: 'if (false && !SqlChecker.isSqlTool(tool)) {',
    tests: ['packages/evals/__tests__/adversarial-fuzz.test.ts'],
  },
  {
    id: 'SQL-7',
    desc: 'IS NOT NULL tautology not detected',
    file: 'packages/core/src/checkers/sql-checker.ts',
    search: "String(whereAst.operator).toUpperCase() === 'IS NOT' &&",
    replace: "String(whereAst.operator).toUpperCase() === 'IS NOT NEVER' &&",
    tests: ['packages/evals/__tests__/adversarial-fuzz.test.ts', 'packages/core/__tests__/sql-checker.test.ts'],
  },
  // ---- numeric-checker.ts -------------------------------------------------
  {
    id: 'NUM-1',
    desc: 'max ceiling off-by-one (>= instead of >)',
    file: 'packages/core/src/checkers/numeric-checker.ts',
    search: 'if (params.max !== undefined && val > params.max) {',
    replace: 'if (params.max !== undefined && val >= params.max) {',
    tests: ['packages/core/__tests__/numeric-checker.test.ts', 'packages/evals/__tests__/adversarial-fuzz.test.ts'],
  },
  {
    id: 'NUM-2',
    desc: 'min floor off-by-one (<= instead of <)',
    file: 'packages/core/src/checkers/numeric-checker.ts',
    search: 'if (effectiveMin !== undefined && val < effectiveMin) {',
    replace: 'if (effectiveMin !== undefined && val <= effectiveMin) {',
    tests: ['packages/core/__tests__/numeric-checker.test.ts', 'packages/evals/__tests__/adversarial-fuzz.test.ts'],
  },
  {
    id: 'NUM-3',
    desc: 'invalid numeric values no longer blocked (NaN passes)',
    file: 'packages/core/src/checkers/numeric-checker.ts',
    search: "if (extraction.status === 'invalid') {",
    replace: "if (extraction.status === 'invalid' && false) {",
    tests: ['packages/evals/__tests__/adversarial-fuzz.test.ts', 'packages/core/__tests__/numeric-checker.test.ts'],
  },
  {
    id: 'NUM-4',
    desc: 'rate limit off-by-one (>= instead of >)',
    file: 'packages/core/src/checkers/numeric-checker.ts',
    search: 'if (timestamps.length > params.rate_limit.max_per_minute) {',
    replace: 'if (timestamps.length >= params.rate_limit.max_per_minute) {',
    tests: ['packages/core/__tests__/numeric-checker.test.ts'],
  },
  // ---- sanitizer.ts -------------------------------------------------------
  {
    id: 'SAN-1',
    desc: 'zero-width stripping disabled',
    file: 'packages/core/src/sanitizer.ts',
    search: 'if (this.ZERO_WIDTH_REGEX.test(result)) {',
    replace: 'if (false && this.ZERO_WIDTH_REGEX.test(result)) {',
    tests: ['packages/core/__tests__/sanitizer.test.ts', 'packages/core/__tests__/properties.test.ts'],
  },
  {
    id: 'SAN-2',
    desc: 'credit-card redaction disabled',
    file: 'packages/core/src/sanitizer.ts',
    search: 'if (this.CC_REGEX.test(result)) {',
    replace: 'if (false && this.CC_REGEX.test(result)) {',
    tests: ['packages/core/__tests__/sanitizer.test.ts', 'packages/core/__tests__/properties.test.ts'],
  },
  {
    id: 'SAN-3',
    desc: 'SSN redaction disabled',
    file: 'packages/core/src/sanitizer.ts',
    search: 'if (this.SSN_REGEX.test(result)) {',
    replace: 'if (false && this.SSN_REGEX.test(result)) {',
    tests: ['packages/core/__tests__/sanitizer.test.ts', 'packages/core/__tests__/properties.test.ts'],
  },
  {
    id: 'SAN-4',
    desc: 'mandatory SELECT LIMIT injection disabled',
    file: 'packages/core/src/sanitizer.ts',
    search: "if (p.query && typeof p.query === 'string') {",
    replace: "if (false && typeof p.query === 'string') {",
    tests: ['packages/core/__tests__/sanitizer.test.ts'],
  },
  // ---- engine.ts / verdict.ts ---------------------------------------------
  {
    id: 'ENG-1',
    desc: 'default fail policy reverted to fail-open',
    file: 'packages/core/src/engine.ts',
    search: "this.failPolicy = config?.failPolicy ?? 'fail-closed';",
    replace: "this.failPolicy = config?.failPolicy ?? 'fail-open';",
    tests: ['packages/core/__tests__/engine.test.ts', 'packages/core/__tests__/hardened-features.test.ts'],
  },
  {
    id: 'ENG-2',
    desc: 'all tool calls allowed regardless of violations',
    file: 'packages/core/src/verdict.ts',
    search: "const allowed = mode === 'shadow' ? true : !hasCritical;",
    replace: "const allowed = true;",
    tests: ['packages/core/__tests__/engine.test.ts', 'packages/evals/__tests__/adversarial-fuzz.test.ts', 'packages/core/__tests__/properties.test.ts'],
  },
  // ---- event.ts -----------------------------------------------------------
  {
    id: 'EVT-1',
    desc: 'card redaction removed from audit log',
    file: 'packages/core/src/event.ts',
    search: "for (const { regex, replacement } of REDACTION_PATTERNS) {",
    replace: "for (const { name, regex, replacement } of REDACTION_PATTERNS) { if (name === 'CARD') continue;",
    tests: ['packages/core/__tests__/properties.test.ts', 'packages/core/__tests__/observability.test.ts'],
  },
];

function runVitest(tests, label) {
  const args = ['vitest', 'run', ...tests, '--reporter=dot', '--silent'];
  try {
    execFileSync('npx', args, { cwd: ROOT, stdio: 'pipe', timeout: 240_000 });
    return { killed: false, error: null };
  } catch (err) {
    return { killed: true, error: String(err.stdout || err.message || '').slice(0, 200) };
  }
}

function applyMutant(fileRel, search, replace) {
  const file = path.join(ROOT, fileRel);
  const original = fs.readFileSync(file, 'utf8');
  const occurrences = original.split(search).length - 1;
  if (occurrences !== 1) {
    return { ok: false, reason: `search matched ${occurrences} times (expected 1)` };
  }
  fs.writeFileSync(file, original.replace(search, replace));
  return { ok: true };
}

async function main() {
  const quick = process.argv.includes('--quick');
  const wantJson = process.argv.includes('--json');
  const mutants = quick ? MUTANTS.filter((_, i) => i % 2 === 0) : MUTANTS;

  const results = [];
  for (const m of mutants) {
    const file = path.join(ROOT, m.file);
    const backup = fs.readFileSync(file, 'utf8');
    const applied = applyMutant(m.file, m.search, m.replace);
    if (!applied.ok) {
      results.push({ id: m.id, desc: m.desc, status: 'SKIPPED', detail: applied.reason });
      continue;
    }
    const { killed, error } = runVitest(m.tests, m.id);
    fs.writeFileSync(file, backup); // restore
    results.push({
      id: m.id,
      desc: m.desc,
      status: killed ? 'KILLED' : 'SURVIVED',
      detail: killed ? '' : error,
    });
    process.stdout.write(`${killed ? '✗' : '○'} ${m.id} ${killed ? 'killed' : 'SURVIVED'} — ${m.desc}\n`);
  }

  const killedCount = results.filter((r) => r.status === 'KILLED').length;
  const survived = results.filter((r) => r.status === 'SURVIVED');
  const skipped = results.filter((r) => r.status === 'SKIPPED');
  const total = results.filter((r) => r.status !== 'SKIPPED').length;
  const score = total > 0 ? killedCount / total : 0;

  console.log('\n══════════════════════════════════════════════════');
  console.log(`  MUTATION SCORE: ${(score * 100).toFixed(1)}%  (${killedCount}/${total} mutants killed)`);
  if (survived.length) {
    console.log('  SURVIVING mutants (test gaps):');
    for (const s of survived) console.log(`    ○ ${s.id} ${s.desc}`);
  }
  if (skipped.length) {
    console.log('  Skipped (search did not match exactly once):');
    for (const s of skipped) console.log(`    - ${s.id} ${s.detail}`);
  }
  console.log('══════════════════════════════════════════════════\n');

  const report = {
    generatedAt: new Date().toISOString(),
    total, killedCount, scorePct: Number((score * 100).toFixed(1)),
    results,
  };
  if (wantJson) {
    const dir = path.join(ROOT, '.benchmark');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'mutation.json'), JSON.stringify(report, null, 2));
    console.log(`  Report: .benchmark/mutation.json`);
  }
  return survived.length === 0 ? 0 : 1;
}

main().then((code) => process.exit(code));
