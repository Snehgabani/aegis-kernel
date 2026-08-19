#!/usr/bin/env bash
set -e

echo "═══════════════════════════════════════════════════════════"
echo "  🚀 Aegis Invariant Kernel — Automated NPM Release"
echo "═══════════════════════════════════════════════════════════"

echo "Checking npm authentication..."
NPM_USER=$(npm whoami 2>/dev/null || true)
if [ -z "$NPM_USER" ]; then
  echo "⚠️  You are not logged in to npm."
  echo "Please run: npm login"
  exit 1
fi

echo "✅ Authenticated as: $NPM_USER"
echo ""

PACKAGES=(
  "packages/core"
  "packages/langchain"
  "packages/mcp"
  "packages/cli"
  "packages/vercel-ai"
  "packages/openai"
  "packages/anthropic"
)

for PKG in "${PACKAGES[@]}"; do
  echo "📦 Publishing $PKG..."
  (cd "$PKG" && npm publish --access public)
  echo "   ✅ $PKG published successfully!"
  echo ""
done

echo "═══════════════════════════════════════════════════════════"
echo "  🎉 All 7 Aegis packages published to npm successfully!"
echo "═══════════════════════════════════════════════════════════"
