#!/usr/bin/env bash
# Install Aegis CI workflow templates into .github/workflows/.
#
# WHY THIS EXISTS: automated contributor tokens (including the one used by
# automation agents) routinely lack the `workflows` permission GitHub requires
# to create or modify .github/workflows/ files. The workflow definitions
# therefore live as versioned templates in scripts/ci-templates/ and are
# installed by a maintainer who has that permission. This keeps the pipeline
# reviewable in-repo while respecting GitHub's workflow-protection model.
#
# Usage:  bash scripts/install-ci-templates.sh [--check]
#   --check : verify installed workflows match templates (CI drift guard; no writes)

set -euo pipefail
cd "$(dirname "$0")/.."

TEMPLATES_DIR="scripts/ci-templates"
WORKFLOWS_DIR=".github/workflows"
CHECK_ONLY="${1:-}"
CHECK_FAILURES=0

install_one() {
  local name="$1"
  local src="$TEMPLATES_DIR/$name"
  local dst="$WORKFLOWS_DIR/$name"
  if [[ "$CHECK_ONLY" == "--check" ]]; then
    if [[ ! -f "$dst" ]]; then
      echo "❌ $name NOT installed (template exists at $src)"
      CHECK_FAILURES=$((CHECK_FAILURES + 1))
      return 0
    fi
    if ! diff -q "$src" "$dst" >/dev/null 2>&1; then
      echo "❌ $name DRIFTED from template"
      CHECK_FAILURES=$((CHECK_FAILURES + 1))
      return 0
    fi
    echo "✅ $name matches template"
    return 0
  fi
  mkdir -p "$WORKFLOWS_DIR"
  cp "$src" "$dst"
  echo "✅ installed $dst (from $src)"
}

# benchmark-canonical.yml — NEW: fail-loud canonical dataset fetch + evidence runs
install_one benchmark-canonical.yml
# sbom-and-grype.yml — UPDATED: release-event trigger + SBOMs attached to releases
install_one sbom-and-grype.yml
# slsa-provenance.yml — UPDATED: release-event trigger
install_one slsa-provenance.yml

if [[ "$CHECK_ONLY" == "--check" ]]; then
  echo "Drift check complete (no files written)."
  if [[ "$CHECK_FAILURES" -gt 0 ]]; then
    echo "$CHECK_FAILURES workflow(s) missing or drifted — run: bash scripts/install-ci-templates.sh"
    exit 1
  fi
else
  cat << 'EOF'

Next steps (maintainer):
  1. Review the diff:  git diff .github/workflows/
  2. Commit & push (requires workflows permission).
  3. Optionally run benchmark-canonical.yml with commit_evidence=true to
     produce the first canonical evidence PR (see benchmarks/EVIDENCE.md §2).
EOF
fi
