#!/usr/bin/env bash
set -e

echo "🔧 Configuring Aegis Enterprise Git Hooks..."

chmod +x .githooks/pre-commit
chmod +x .githooks/commit-msg

git config core.hooksPath .githooks

echo "✅ Git hooks configured successfully in .githooks/!"
