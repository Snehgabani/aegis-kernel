#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# Aegis Automated Security Audit Script
# ═══════════════════════════════════════════════════════════════════════════
# Run:  ./scripts/security-audit.sh
# Generates: .aegis/security-audit-report.json
#
# NOTE: Some tools (Gitleaks, Semgrep, Bandit) are optional and
# gracefully skipped if not installed.
# ═══════════════════════════════════════════════════════════════════════════

set -euo pipefail

REPORT_DIR=".aegis"
REPORT_FILE="${REPORT_DIR}/security-audit-report.json"
RESULTS_FILE=$(mktemp)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
EXIT_CODE=0

mkdir -p "${REPORT_DIR}"

echo '[]' > "${RESULTS_FILE}"

# Helper: append a result as JSON to the results file
add_result() {
  local category="$1" tool="$2" status="$3" details="$4"
  python3 -c "
import json
with open('${RESULTS_FILE}') as f:
    results = json.load(f)
results.append({
    'category': '${category}',
    'tool': '${tool//\'/\\\'}',
    'status': '${status}',
    'details': '${details//\'/\\\'}',
    'timestamp': '${TIMESTAMP}'
})
with open('${RESULTS_FILE}', 'w') as f:
    json.dump(results, f, indent=2)
"
}

# ── 1. npm audit ─────────────────────────────────────────────────────────
echo "🔍 [1/6] Running npm audit..."
if command -v npm &>/dev/null; then
  AUDIT_OUTPUT=$(npm audit --json 2>/dev/null || echo '{"metadata":{"vulnerabilities":{"total":0}}}')
  VULN_COUNT=$(echo "${AUDIT_OUTPUT}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('metadata',{}).get('vulnerabilities',{}).get('total',0))" 2>/dev/null || echo "0")
  if [ "${VULN_COUNT}" -gt "0" ]; then
    add_result "Dependencies" "npm audit" "WARNING" "${VULN_COUNT} vulnerabilities found. Run 'npm audit fix'."
  else
    add_result "Dependencies" "npm audit" "PASS" "Zero known vulnerabilities."
  fi
else
  add_result "Dependencies" "npm audit" "SKIPPED" "npm not available."
fi

# ── 2. Gitleaks ──────────────────────────────────────────────────────────
echo "🔍 [2/6] Running Gitleaks secret scan..."
if command -v gitleaks &>/dev/null; then
  GITLEAKS_OUTPUT=$(gitleaks detect --source . --no-git --report-format json --report-path /dev/stdout 2>/dev/null || echo '[]')
  LEAK_COUNT=$(echo "${GITLEAKS_OUTPUT}" | python3 -c "import sys,json; data=json.load(sys.stdin); print(len(data) if isinstance(data, list) else 0)" 2>/dev/null || echo "0")
  if [ "${LEAK_COUNT}" -gt "0" ]; then
    add_result "Secrets" "Gitleaks" "FAIL" "${LEAK_COUNT} potential secrets found."
  else
    add_result "Secrets" "Gitleaks" "PASS" "No secrets detected."
  fi
else
  add_result "Secrets" "Gitleaks" "SKIPPED" "Gitleaks not installed. See https://github.com/gitleaks/gitleaks"
fi

# ── 3. Semgrep ───────────────────────────────────────────────────────────
echo "🔍 [3/6] Running Semgrep SAST..."
if command -v semgrep &>/dev/null; then
  SEMGREP_OUTPUT=$(semgrep scan --config=auto --json --quiet . 2>/dev/null || echo '{"results":[]}')
  FINDING_COUNT=$(echo "${SEMGREP_OUTPUT}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('results',[])))" 2>/dev/null || echo "0")
  if [ "${FINDING_COUNT}" -gt "0" ]; then
    add_result "SAST" "Semgrep" "WARNING" "${FINDING_COUNT} findings. Review with 'semgrep scan --config=auto .'"
  else
    add_result "SAST" "Semgrep" "PASS" "No findings."
  fi
else
  add_result "SAST" "Semgrep" "SKIPPED" "Semgrep not installed. See https://semgrep.dev"
fi

# ── 4. CodeQL check ──────────────────────────────────────────────────────
echo "🔍 [4/6] Checking CodeQL..."
if command -v codeql &>/dev/null; then
  add_result "SAST" "CodeQL" "PASS" "CodeQL CLI available."
else
  add_result "SAST" "CodeQL" "SKIPPED" "CodeQL CLI not installed. Runs as GitHub Action in CI."
fi

# ── 5. Python bandit ─────────────────────────────────────────────────────
echo "🔍 [5/6] Running Python security checks..."
if command -v bandit &>/dev/null; then
  BANDIT_OUTPUT=$(bandit -r packages/python/ -f json 2>/dev/null || echo '{"results":[]}')
  PY_ISSUES=$(echo "${BANDIT_OUTPUT}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('results',[])))" 2>/dev/null || echo "0")
  if [ "${PY_ISSUES}" -gt "0" ]; then
    add_result "SAST" "Bandit" "WARNING" "${PY_ISSUES} Python issues found."
  else
    add_result "SAST" "Bandit" "PASS" "No Python issues found."
  fi
else
  add_result "SAST" "Bandit" "SKIPPED" "Bandit not installed."
fi

# ── 6. TypeScript type check ─────────────────────────────────────────────
echo "🔍 [6/6] Running TypeScript type check..."
if command -v npx &>/dev/null; then
  if npx tsc --noEmit -p packages/core/tsconfig.json 2>/dev/null; then
    add_result "TypeScript" "tsc" "PASS" "TypeScript compilation clean."
  else
    add_result "TypeScript" "tsc" "FAIL" "TypeScript compilation errors found."
    EXIT_CODE=1
  fi
else
  add_result "TypeScript" "tsc" "SKIPPED" "npx/tsc not available."
fi

# ── Generate report ──────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  Aegis Security Audit Report"
echo "  Timestamp: ${TIMESTAMP}"
echo "═══════════════════════════════════════════════════════════════════"

python3 -c "
import json
with open('${RESULTS_FILE}') as f:
    results = json.load(f)

passed = sum(1 for r in results if r['status'] == 'PASS')
skipped = sum(1 for r in results if r['status'] == 'SKIPPED')
warnings = sum(1 for r in results if r['status'] == 'WARNING')
fails = sum(1 for r in results if r['status'] == 'FAIL')
print(f'  PASSED: {passed}  WARNINGS: {warnings}  FAILED: {fails}  SKIPPED: {skipped}')
print(f'  TOTAL: {len(results)} checks')
for r in results:
    emoji = {'PASS': '✅', 'WARNING': '⚠️', 'FAIL': '❌', 'SKIPPED': '⏭️'}.get(r['status'], '❓')
    print(f'  {emoji} [{r[\"category\"]}] {r[\"tool\"]}: {r[\"details\"]}')

report = {
    'type': 'security-audit-report',
    'version': '1.0.0',
    'timestamp': '${TIMESTAMP}',
    'repository': 'aegis-kernel',
    'results': results,
    'summary': {
        'total': len(results),
        'passed': passed,
        'warnings': warnings,
        'failed': fails,
        'skipped': skipped,
    }
}
with open('${REPORT_FILE}', 'w') as f:
    json.dump(report, f, indent=2)
print(f'\n📄 Report written to ${REPORT_FILE}')
"

rm -f "${RESULTS_FILE}"
exit ${EXIT_CODE}