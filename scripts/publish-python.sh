#!/usr/bin/env bash
set -e

echo "═══════════════════════════════════════════════════════════"
echo "  🐍 Aegis Python SDK & Middleware — Automated PyPI Release"
echo "═══════════════════════════════════════════════════════════"

PYTHON_PACKAGES=(
  "packages/python"
  "packages/crewai"
  "packages/autogen"
  "packages/browser-guard"
)

echo "Installing/verifying build and twine..."
python3 -m pip install --quiet build twine

for PKG in "${PYTHON_PACKAGES[@]}"; do
  echo ""
  echo "📦 Building & Publishing $PKG..."
  (
    cd "$PKG"
    rm -rf dist build *.egg-info
    python3 -m build
    python3 -m twine upload --skip-existing dist/*
  )
  echo "   ✅ $PKG published successfully!"
done

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  🎉 All 4 Aegis Python packages published to PyPI successfully!"
echo "═══════════════════════════════════════════════════════════"
