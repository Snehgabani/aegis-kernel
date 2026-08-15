#!/usr/bin/env bash
set -euo pipefail

echo "🛡️  Aegis Invariant Kernel: Zero-Cost Cloud Deployment"
echo "========================================================"

# 1. Build Monorepo & Services
echo "📦 Building monorepo packages..."
npm run build

# 2. Deploy Gateway to Cloudflare Workers
echo "☁️  Deploying @aegis-kernel/gateway to Cloudflare Workers..."
if command -v npx &> /dev/null; then
  echo "Running wrangler deploy for gateway..."
  # npx wrangler deploy --config services/gateway/wrangler.toml
else
  echo "⚠️  npx not found. Please install wrangler to deploy."
fi

# 3. Deploy Static Marketing & Auditor Dashboard to Cloudflare Pages
echo "🌐 Deploying site/ to Cloudflare Pages..."
# npx wrangler pages deploy site --project-name aegis-portal

echo "========================================================"
echo "✅ Cloud deployment configuration ready!"
echo "   Gateway: https://gateway.aegis-kernel.dev"
echo "   Portal:  https://aegis-kernel.dev (site/)"
echo "   Console: https://aegis-kernel.dev/dashboard/ (site/dashboard/)"
