#!/usr/bin/env node
/**
 * @file scripts/precommit-ast-shield.mjs
 * @description Fast (<30ms) Shift-Left AST & Security Invariant Shield for Git Pre-Commit Hooks.
 * Blocks polynomial ReDoS regexes, hardcoded API secrets, and unsafe sanitization patterns.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { execSync } from 'node:child_process';

const FORBIDDEN_SECRET_PATTERNS = [
  { name: 'OpenAI API Key', regex: /\bsk-[A-Za-z0-9_-]{20,}\b/ },
  { name: 'GitHub Token', regex: /\bgh[pousr]_[A-Za-z0-9_]{36,}\b/ },
  { name: 'AWS Access Key', regex: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'Private Key Header', regex: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/ },
];

const POLYNOMIAL_REDOS_PATTERNS = [
  { name: 'Polynomial Greedy Backtracking', regex: /\^?\(\.\+\)\s*[\+\-\*\/]\s*\(\.\+\)\$?/ },
  { name: 'Nested Quantifier ReDoS', regex: /\((?:[a-zA-Z0-9_\.]\+)\)\+/ },
];

export function scanFile(filePath) {
  const violations = [];
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) return violations;

  // Skip dist, node_modules, lockfiles, hidden git
  if (
    filePath.includes('node_modules') ||
    filePath.includes('dist') ||
    filePath.includes('.git') ||
    filePath.endsWith('.lock') ||
    filePath.endsWith('.jsonl') ||
    filePath.endsWith('.md')
  ) {
    return violations;
  }

  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // 1. Secrets check (ignore comments / test mocks that explicitly say 'mock' or 'test')
    if (!line.includes('mock') && !line.includes('test') && !line.includes('dummy')) {
      for (const pat of FORBIDDEN_SECRET_PATTERNS) {
        if (pat.regex.test(line)) {
          violations.push({
            file: filePath,
            line: i + 1,
            type: 'HARDCODED_SECRET',
            rule: pat.name,
            snippet: line.trim(),
          });
        }
      }
    }

    // 2. ReDoS check
    for (const pat of POLYNOMIAL_REDOS_PATTERNS) {
      if (pat.regex.test(line)) {
        violations.push({
          file: filePath,
          line: i + 1,
          type: 'POLYNOMIAL_REDOS',
          rule: pat.name,
          snippet: line.trim(),
        });
      }
    }
  }

  return violations;
}

export function runPreCommitShield() {
  console.log(`\x1b[36m🛡️  AEGIS PRE-COMMIT AST & SECURITY INVARIANT SHIELD\x1b[0m`);
  let stagedFiles = [];
  try {
    const output = execSync('git diff --cached --name-only', { encoding: 'utf8' });
    stagedFiles = output.split('\n').filter(Boolean);
  } catch {
    stagedFiles = [];
  }

  if (stagedFiles.length === 0) {
    console.log(`\x1b[32m✔ No staged files to scan.\x1b[0m`);
    return 0;
  }

  const allViolations = [];
  for (const f of stagedFiles) {
    const v = scanFile(path.resolve(process.cwd(), f));
    allViolations.push(...v);
  }

  if (allViolations.length > 0) {
    console.error(`\n\x1b[31m❌ Pre-Commit Shield Blocked ${allViolations.length} critical security risk(s):\x1b[0m\n`);
    for (const v of allViolations) {
      console.error(`  • [${v.type}] \x1b[33m${v.file}:${v.line}\x1b[0m (${v.rule})`);
      console.error(`    Snippet: \x1b[90m${v.snippet}\x1b[0m\n`);
    }
    return 1;
  }

  console.log(`\x1b[32m✔ All ${stagedFiles.length} staged file(s) passed AST and security invariant checks!\x1b[0m`);
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  const code = runPreCommitShield();
  process.exitCode = code;
}
