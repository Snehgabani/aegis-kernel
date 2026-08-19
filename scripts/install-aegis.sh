#!/usr/bin/env bash
# ==============================================================================
# Aegis Invariant Kernel: 1-Command Developer Installer
# Usage: curl -sSL https://raw.githubusercontent.com/Snehgabani/aegis-kernel/main/scripts/install-aegis.sh | bash
# ==============================================================================
set -euo pipefail

echo "🛡️  Installing Aegis Invariant Kernel..."

# Detect package manager
if command -v npm >/dev/null 2>&1; then
  echo "📦 Installing @aegis-kernel/cli & @aegis-kernel/core via npm..."
  npm install -g @aegis-kernel/cli || npm install --save-dev @aegis-kernel/cli @aegis-kernel/core
elif command -v pip3 >/dev/null 2>&1; then
  echo "🐍 Installing aegis-kernel via pip..."
  pip3 install aegis-kernel
elif command -v pip >/dev/null 2>&1; then
  echo "🐍 Installing aegis-kernel via pip..."
  pip install aegis-kernel
else
  echo "❌ Neither npm nor pip found. Please install Node.js (>=18) or Python (>=3.9)."
  exit 1
fi

echo "🚀 Initializing Aegis workspace security bounds..."
if command -v aegis >/dev/null 2>&1; then
  aegis init
elif command -v npx >/dev/null 2>&1; then
  npx @aegis-kernel/cli init
fi

echo "✅ Aegis Invariant Kernel successfully installed and configured!"
echo "👉 Run 'aegis scan' to audit your workspace or 'aegis test' to simulate invariant checks."
