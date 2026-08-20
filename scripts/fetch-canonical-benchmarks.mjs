#!/usr/bin/env node
/**
 * @file scripts/fetch-canonical-benchmarks.mjs
 * @description Canonical academic benchmark dataset ingestion with integrity verification.
 *
 * Repairs applied 2026-08-20 (see docs/PLATFORM_UPGRADE_2026H2.md):
 *   1. FIXED SOURCE URLS. The previous URLs were dead (both returned 404):
 *      - InjecAgent publishes FOUR files (not one): test_cases_{dh,ds}_{base,enhanced}.json
 *      - AgentDojo suites live under src/agentdojo/default_suites/benchmark_suites/
 *        (the repo has no top-level data/benchmark_suites.json)
 *   2. NO SYNTHETIC FALLBACK. The previous script silently wrote a 25-vector fake
 *      "offline seed" and exited 0 on failure, which made unavailable data look
 *      like fetched data. It now fails loudly by default; pass --allow-fallback
 *      to tolerate network failure (writes nothing, exits 0) for offline CI.
 *   3. COMMITTABLE OUTPUT. Writes to benchmarks/canonical/ (committed to the repo
 *      with a SHA-256 manifest) instead of .benchmark/ (gitignored, so evidence
 *      could never be published).
 *
 * Usage:
 *   node scripts/fetch-canonical-benchmarks.mjs [--allow-fallback] [--out <dir>]
 *
 * Datasets (both MIT licensed):
 *   - UIUC InjecAgent (ACL 2024) — 1,054 test vectors (Direct Harm + Data Stealing,
 *     base + enhanced variants), 17 user tools.
 *   - ETH Zurich AgentDojo (NeurIPS 2024) — benchmark suites across Banking,
 *     Workspace, Slack, Travel (injection tasks instantiated per suite).
 */

import { existsSync, mkdirSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { createHash } from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT_DIR = join(__dirname, '..');
const DEFAULT_OUT_DIR = join(ROOT_DIR, 'benchmarks', 'canonical');

const args = process.argv.slice(2);
const allowFallback = args.includes('--allow-fallback');
const outDirIdx = args.indexOf('--out');
const OUT_DIR = outDirIdx !== -1 && args[outDirIdx + 1] ? args[outDirIdx + 1] : DEFAULT_OUT_DIR;

const INJECAGENT_BASE =
  'https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data';
const AGENTDOJO_SUITES_API =
  'https://api.github.com/repos/ethz-spylab/agentdojo/contents/src/agentdojo/default_suites/benchmark_suites';

const DATASETS = {
  injecagent: {
    name: 'UIUC InjecAgent (ACL 2024)',
    license: 'MIT',
    sourceRepo: 'https://github.com/uiuc-kang-lab/InjecAgent',
    paper: 'arXiv:2403.02691',
    files: [
      { role: 'direct-harm/base', url: `${INJECAGENT_BASE}/test_cases_dh_base.json`, file: 'injecagent/test_cases_dh_base.json' },
      { role: 'direct-harm/enhanced', url: `${INJECAGENT_BASE}/test_cases_dh_enhanced.json`, file: 'injecagent/test_cases_dh_enhanced.json' },
      { role: 'data-stealing/base', url: `${INJECAGENT_BASE}/test_cases_ds_base.json`, file: 'injecagent/test_cases_ds_base.json' },
      { role: 'data-stealing/enhanced', url: `${INJECAGENT_BASE}/test_cases_ds_enhanced.json`, file: 'injecagent/test_cases_ds_enhanced.json' },
    ],
  },
  agentdojo: {
    name: 'ETH Zurich AgentDojo (NeurIPS 2024)',
    license: 'MIT',
    sourceRepo: 'https://github.com/ethz-spylab/agentdojo',
    paper: 'arXiv:2406.13314',
    // Suite files are discovered dynamically from the GitHub contents API so the
    // script keeps working if suite files are added/renamed upstream.
    dynamic: { api: AGENTDOJO_SUITES_API, dir: 'agentdojo' },
  },
};

async function fetchText(url, headers = {}) {
  const res = await fetch(url, { headers });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} for ${url}`);
  }
  return res.text();
}

function sha256(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

function recordFailure(manifest, dataset, detail) {
  manifest.failures.push({ dataset, detail, at: new Date().toISOString() });
}

async function fetchInjecAgent(manifest) {
  const cfg = DATASETS.injecagent;
  for (const f of cfg.files) {
    const target = join(OUT_DIR, f.file);
    mkdirSync(dirname(target), { recursive: true });
    try {
      const content = await fetchText(f.url);
      JSON.parse(content); // validate
      writeFileSync(target, content, 'utf8');
      const digest = sha256(content);
      manifest.files.push({ dataset: 'injecagent', role: f.role, sourceUrl: f.url, file: f.file, sha256: digest, bytes: Buffer.byteLength(content) });
      console.log(`   ✅ injecagent ${f.role} → ${f.file} (sha256 ${digest.slice(0, 16)}…)`);
    } catch (err) {
      recordFailure(manifest, 'injecagent', `${f.role}: ${err.message}`);
      console.warn(`   ❌ injecagent ${f.role}: ${err.message}`);
    }
  }
}

async function fetchAgentDojo(manifest) {
  const cfg = DATASETS.agentdojo;
  try {
    const listing = JSON.parse(await fetchText(cfg.dynamic.api, { 'User-Agent': 'aegis-kernel-benchmark-fetcher' }));
    const suiteFiles = listing.filter((e) => e.type === 'file' && /\.(yaml|yml|json)$/i.test(e.name));
    if (suiteFiles.length === 0) {
      throw new Error(`no suite files found via ${cfg.dynamic.api}`);
    }
    for (const entry of suiteFiles) {
      const target = join(OUT_DIR, cfg.dynamic.dir, entry.name);
      mkdirSync(dirname(target), { recursive: true });
      try {
        const content = await fetchText(entry.download_url);
        writeFileSync(target, content, 'utf8');
        const digest = sha256(content);
        manifest.files.push({ dataset: 'agentdojo', role: entry.name, sourceUrl: entry.download_url, file: `${cfg.dynamic.dir}/${entry.name}`, sha256: digest, bytes: Buffer.byteLength(content) });
        console.log(`   ✅ agentdojo ${entry.name} → ${cfg.dynamic.dir}/${entry.name} (sha256 ${digest.slice(0, 16)}…)`);
      } catch (err) {
        recordFailure(manifest, 'agentdojo', `${entry.name}: ${err.message}`);
        console.warn(`   ❌ agentdojo ${entry.name}: ${err.message}`);
      }
    }
  } catch (err) {
    recordFailure(manifest, 'agentdojo', err.message);
    console.warn(`   ❌ agentdojo suite discovery failed: ${err.message}`);
  }
}

export async function fetchAllCanonicalBenchmarks() {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('  🌐 AEGIS CANONICAL BENCHMARK INGESTION (fail-loud, no synthetic fallback)');
  console.log(`  📁 output: ${OUT_DIR}${OUT_DIR === DEFAULT_OUT_DIR ? ' (committable)' : ''}`);
  console.log('═══════════════════════════════════════════════════════════════');

  const manifest = {
    generatedAt: new Date().toISOString(),
    script: 'scripts/fetch-canonical-benchmarks.mjs',
    outputDir: OUT_DIR,
    datasets: Object.fromEntries(
      Object.entries(DATASETS).map(([k, v]) => [k, { name: v.name, license: v.license, sourceRepo: v.sourceRepo, paper: v.paper }])
    ),
    files: [],
    failures: [],
  };

  await fetchInjecAgent(manifest);
  await fetchAgentDojo(manifest);

  mkdirSync(OUT_DIR, { recursive: true });
  writeFileSync(join(OUT_DIR, 'manifest.json'), JSON.stringify(manifest, null, 2), 'utf8');

  console.log('═══════════════════════════════════════════════════════════════');
  if (manifest.failures.length > 0) {
    console.warn(`  ⚠️  ${manifest.failures.length} failure(s). Manifest records them explicitly.`);
    if (!allowFallback) {
      console.error('  🚫 Exiting non-zero (fail-loud). Pass --allow-fallback to tolerate for offline CI.');
      console.log('═══════════════════════════════════════════════════════════════');
      process.exitCode = 1;
      return manifest;
    }
    console.warn('  ⚠️  --allow-fallback present: continuing (NO synthetic data was written).');
  } else {
    console.log(`  ✅ ${manifest.files.length} canonical files verified with SHA-256 manifest.`);
  }
  console.log('═══════════════════════════════════════════════════════════════');
  return manifest;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  fetchAllCanonicalBenchmarks();
}
