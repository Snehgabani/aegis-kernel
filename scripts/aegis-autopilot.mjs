#!/usr/bin/env node

/**
 * 🛡️ AEGIS AUTOPILOT DAEMON
 * Autonomous GitHub Actions workflow approver, PR auto-fixer, and bot merge engine.
 * 
 * Hardware Budget: Apple Silicon M2 (8GB RAM) -> Zero-RAM when idle, <15MB RSS when active.
 */

import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

const REPO = 'Snehgabani/aegis-kernel';
const LOG_DIR = path.join(process.env.HOME || '/tmp', '.mix-mcp', 'logs');
const LOG_FILE = path.join(LOG_DIR, 'aegis-autopilot.log');

try {
  fs.mkdirSync(LOG_DIR, { recursive: true });
} catch (_) {}

function log(msg) {
  const line = `[${new Date().toISOString()}] ${msg}\n`;
  try {
    fs.appendFileSync(LOG_FILE, line);
  } catch (_) {}
  console.log(msg);
}

function run(cmd, silent = false) {
  try {
    return execSync(cmd, { encoding: 'utf8', stdio: 'pipe' }).trim();
  } catch (err) {
    if (!silent) log(`⚠️ Command error: ${cmd} -> ${err.message}`);
    return null;
  }
}

async function approvePendingWorkflows() {
  const jsonStr = run(`gh api repos/${REPO}/actions/runs -q '.workflow_runs[] | select(.conclusion=="action_required" or .status=="waiting") | .id'`, true);
  if (!jsonStr) return;

  const runIds = jsonStr.split('\n').map(s => s.trim()).filter(Boolean);
  for (const id of runIds) {
    log(`🔓 Approving workflow run ${id}...`);
    run(`gh api repos/${REPO}/actions/runs/${id}/approve -X POST`, true);
  }
}

async function triageAndMergeBotPRs() {
  const prsJson = run(`gh pr list --repo ${REPO} --state open --json number,title,author,mergeable,statusCheckRollup,labels`, true);
  if (!prsJson) return;

  let prs = [];
  try {
    prs = JSON.parse(prsJson);
  } catch (e) {
    return;
  }

  const TRUSTED_BOTS = [
    'github-actions',
    'app/github-actions',
    'arena-ai-coding-agent',
    'app/arena-ai-coding-agent',
    'dependabot',
    'app/dependabot'
  ];

  for (const pr of prs) {
    const authorLogin = pr.author?.login || '';
    const isTrustedBot = TRUSTED_BOTS.some(b => authorLogin.includes(b));
    if (!isTrustedBot) continue;

    log(`🔍 Inspecting bot PR #${pr.number}: "${pr.title}" by ${authorLogin}`);

    // 1. Auto-Fix PR Title Casing if needed
    const conventionalRegex = /^(feat|fix|chore|perf|refactor|docs|test|ci|style|build)(\([a-z0-9-_]+\))?:\s*([A-Z])(.*)$/;
    const match = pr.title.match(conventionalRegex);
    if (match) {
      const prefix = match[1] + (match[2] || '') + ': ';
      const correctedSubject = match[3].toLowerCase() + match[4];
      const newTitle = prefix + correctedSubject;
      log(`✏️ Auto-correcting PR #${pr.number} title casing to "${newTitle}"...`);
      run(`gh pr edit ${pr.number} --repo ${REPO} --title "${newTitle}"`, true);
    }

    // 2. Check CI Statuses
    const checks = pr.statusCheckRollup || [];
    const pendingChecks = checks.filter(c => c.status === 'IN_PROGRESS' || c.status === 'QUEUED');
    const failedChecks = checks.filter(c => c.conclusion === 'FAILURE' || c.conclusion === 'CANCELLED' || c.conclusion === 'TIMED_OUT');
    const passedChecks = checks.filter(c => c.conclusion === 'SUCCESS' || c.conclusion === 'NEUTRAL' || c.conclusion === 'SKIPPED');

    log(`   PR #${pr.number} Checks: ${passedChecks.length} Passed, ${pendingChecks.length} Pending, ${failedChecks.length} Failed`);

    if (failedChecks.length === 0 && pendingChecks.length === 0 && checks.length > 0) {
      log(`🎯 PR #${pr.number} is 100% GREEN! Executing automated approval & merge...`);
      run(`gh pr review ${pr.number} --repo ${REPO} --approve --body "🤖 [Aegis Autopilot] All ${checks.length} CI invariant checks verified green. Auto-approving."`, true);
      const mergeRes = run(`gh pr merge ${pr.number} --repo ${REPO} --squash --delete-branch --admin`, true);
      if (mergeRes !== null) {
        log(`🎉 Successfully merged PR #${pr.number} into main!`);
      }
    }
  }
}

async function cycle() {
  try {
    await approvePendingWorkflows();
    await triageAndMergeBotPRs();
  } catch (err) {
    log(`❌ Cycle exception: ${err.message}`);
  }
}

cycle();
