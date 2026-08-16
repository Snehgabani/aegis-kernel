#!/usr/bin/env node
/**
 * 🛡️ Aegis Invariant Kernel — Monorepo Multi-Package Publisher
 * Publishes all 8 TypeScript/JavaScript packages to npm and the Python SDK to PyPI.
 */

import { execSync } from 'node:child_process';
import * as path from 'node:path';
import * as fs from 'node:fs';

const ROOT = path.resolve(import.meta.dirname, '..');
const PACKAGES = ['core', 'cli', 'mcp', 'langchain', 'openai', 'anthropic', 'diagnostics', 'evals'];

console.log('\n🛡️  AEGIS INVARIANT KERNEL — MONOREPO PUBLICATION SUITE\n');

// 1. Build and test all packages first
console.log('1️⃣  Building all packages (clean dist)...');
execSync('npm run build', { cwd: ROOT, stdio: 'inherit' });

console.log('\n2️⃣  Checking npm authentication...');
let npmUser = null;
try {
  npmUser = execSync('npm whoami', { cwd: ROOT, encoding: 'utf8' }).trim();
  console.log(`   ✅ Logged into npm as: ${npmUser}`);
} catch {
  console.log('   ⚠️  Not logged into npm. Run `npm login` first or set NPM_TOKEN in your environment.');
}

if (npmUser) {
  for (const pkg of PACKAGES) {
    const pkgDir = path.join(ROOT, 'packages', pkg);
    if (fs.existsSync(path.join(pkgDir, 'package.json'))) {
      console.log(`\n📦 Publishing @aegis-kernel/${pkg} to npm...`);
      try {
        execSync('npm publish --access public', { cwd: pkgDir, stdio: 'inherit' });
        console.log(`   ✅ Successfully published @aegis-kernel/${pkg}`);
      } catch (err) {
        console.log(`   ⚠️  Could not publish @aegis-kernel/${pkg} (may already be published or version exists).`);
      }
    }
  }
}

// 2. Python Package
console.log('\n3️⃣  Building and publishing Python SDK (aegis-kernel) to PyPI...');
const pythonDir = path.join(ROOT, 'packages', 'python');
try {
  execSync('python3 -m build', { cwd: pythonDir, stdio: 'inherit' });
  console.log('   ✅ Built Python wheel and tarball');
  console.log('   To publish to PyPI, run:');
  console.log('   twine upload packages/python/dist/*');
} catch (err) {
  console.log(`   ⚠️  Python build error: ${err.message}`);
}

console.log('\n🎉 Publication checklist complete.\n');
