#!/usr/bin/env bash
set -e

echo "═══════════════════════════════════════════════════════════"
echo "  🐍 Aegis Python SDK — Automated PyPI Release"
echo "═══════════════════════════════════════════════════════════"

cd packages/python
echo "Installing/verifying twine..."
python3 -m pip install --quiet twine

echo "Uploading wheel and sdist to PyPI..."
python3 -m twine upload dist/*

echo "✅ aegis-kernel published to PyPI successfully!"
