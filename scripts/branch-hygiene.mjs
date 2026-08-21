#!/usr/bin/env node
/**
 * @file scripts/branch-hygiene.mjs
 * @description Autonomous Git Branch Hygiene & Stale Remote Pruner daemon for Aegis Kernel.
 * Runs on a 30-minute interval via macOS launchd (0 MB idle RAM).
 */

import { execSync } from 'node:child_process';
import * as path from 'node:path';

function run() {
  const cwd = path.resolve(new URL('.', import.meta.url).pathname, '..');
  console.log(`[${new Date().toISOString()}] Running Aegis Git Branch Hygiene in ${cwd}...`);

  try {
    // 1. Prune stale tracking refs
    execSync('git fetch origin --prune', { cwd, stdio: 'inherit' });

    // 2. Find merged remote branches
    const mergedBranchesRaw = execSync('git branch -r --merged origin/main', { cwd, encoding: 'utf8' });
    const mergedBranches = mergedBranchesRaw
      .split('\n')
      .map((b) => b.trim())
      .filter((b) => b && !b.includes('origin/main') && !b.includes('origin/HEAD'));

    for (const b of mergedBranches) {
      if (b.startsWith('origin/arena/') || b.startsWith('origin/temp/') || b.startsWith('origin/patch-')) {
        const remoteBranchName = b.replace('origin/', '');
        console.log(`[aegis-hygiene] Pruning merged remote branch: ${remoteBranchName}`);
        try {
          execSync(`git push origin --delete ${remoteBranchName}`, { cwd, stdio: 'inherit' });
        } catch (e) {
          console.error(`[aegis-hygiene] Could not delete ${remoteBranchName}:`, e.message);
        }
      }
    }

    // 3. Auto-pack local repo
    execSync('git gc --auto', { cwd, stdio: 'inherit' });
    console.log(`[${new Date().toISOString()}] Git Branch Hygiene completed successfully.`);
  } catch (err) {
    console.error(`[aegis-hygiene] Execution error:`, err.message);
  }
}

run();
