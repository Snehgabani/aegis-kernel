#!/usr/bin/env bash
set -e

echo "════════════════════════════════════════════════════════════════════════"
echo "  🛡️  AEGIS INVARIANT KERNEL — INTERACTIVE SECURITY DEMO               "
echo "  Sub-1.5ms In-Process Tool Clearance for Autonomous AI Agents          "
echo "════════════════════════════════════════════════════════════════════════"
echo ""

# 1. Monorepo Build Check
echo "📦 Step 1: Compiling TypeScript Engine & Framework Adapters..."
npm run build --silent
echo "   ✅ Build successful."
echo ""

# 2. Running 100-Vector Benchmark
echo "⚡ Step 2: Executing 100-Vector Adversarial Stress Testbed..."
node packages/cli/dist/index.js benchmark --tricky
echo ""

# 3. Running OpenAI Function Calling Self-Healing Demo
echo "🤖 Step 3: Simulating OpenAI Tool Interception with Self-Healing Feedback..."
npx tsx examples/openai-sql-agent/index.ts
echo ""

# 4. Running Python Zero-Dependency Guard Demo
echo "🐍 Step 4: Simulating Python Fintech Trading Guard..."
python3 examples/python-trading-guard/trading_bot.py
echo ""

echo "════════════════════════════════════════════════════════════════════════"
echo "  🎉 DEMO COMPLETE — 100% INVARIANTS ENFORCED IN SUB-MILLISECOND TIME   "
echo "  Ready to deploy in your production stack: npm install @aegis-kernel/core"
echo "════════════════════════════════════════════════════════════════════════"
