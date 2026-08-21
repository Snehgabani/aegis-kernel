#!/usr/bin/env node
/**
 * Distribution PR watchdog — monitors Aegis Invariant Kernel submissions to
 * community Awesome Lists and package registries.
 *
 * Usage:  node scripts/check-distribution-prs.mjs [--json]
 * Auth:   uses GITHUB_TOKEN / GH_TOKEN if present (higher rate limits).
 */

const TRACKED_PRS = [
  { repo: 'rust-unofficial/awesome-rust', number: 2718, label: 'awesome-rust (Security tools)' },
  { repo: 'e2b-dev/awesome-ai-agents', number: 1416, label: 'awesome-ai-agents' },
  { repo: 'corca-ai/awesome-llm-security', number: 296, label: 'awesome-llm-security' },
];

const TRACKED_REGISTRIES = [
  { name: 'npm @aegis-kernel/core', url: 'https://registry.npmjs.org/@aegis-kernel%2Fcore', probe: (j) => j['dist-tags']?.latest },
  { name: 'PyPI aegis-kernel', url: 'https://pypi.org/pypi/aegis-kernel/json', probe: (j) => j.info?.version },
  { name: 'PyPI aegis-kernel-crewai', url: 'https://pypi.org/pypi/aegis-kernel-crewai/json', probe: (j) => j.info?.version },
  { name: 'PyPI aegis-kernel-autogen', url: 'https://pypi.org/pypi/aegis-kernel-autogen/json', probe: (j) => j.info?.version },
  { name: 'PyPI aegis-kernel-browser-guard', url: 'https://pypi.org/pypi/aegis-kernel-browser-guard/json', probe: (j) => j.info?.version },
  { name: 'crates.io aegis-kernel', url: 'https://crates.io/api/v1/crates/aegis-kernel', probe: (j) => j.crate?.max_version },
];

const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
const ghHeaders = {
  accept: 'application/vnd.github+json',
  'user-agent': 'aegis-kernel-distribution-watchdog',
  ...(token ? { authorization: `Bearer ${token}` } : {}),
};

async function checkPr({ repo, number, label }) {
  try {
    const res = await fetch(`https://api.github.com/repos/${repo}/pulls/${number}`, { headers: ghHeaders });
    if (!res.ok) return { repo, number, label, error: `HTTP ${res.status}` };
    const pr = await res.json();

    let checks = [];
    try {
      const cres = await fetch(
        `https://api.github.com/repos/${repo}/commits/${pr.head.sha}/check-runs?per_page=50`,
        { headers: ghHeaders },
      );
      if (cres.ok) {
        const data = await cres.json();
        checks = (data.check_runs || []).map((c) => ({ name: c.name, conclusion: c.conclusion || c.status }));
      }
    } catch { /* checks are best-effort */ }

    return {
      repo,
      number,
      label,
      url: pr.html_url,
      state: pr.merged_at ? 'MERGED' : pr.state.toUpperCase(),
      mergeable: pr.mergeable_state,
      updatedAt: pr.updated_at,
      failingChecks: checks.filter((c) => ['failure', 'action_required', 'timed_out', 'cancelled'].includes(c.conclusion)),
    };
  } catch (err) {
    return { repo, number, label, error: String(err) };
  }
}

async function checkRegistry({ name, url, probe }) {
  try {
    const res = await fetch(url, { headers: { 'user-agent': 'aegis-kernel-distribution-watchdog' } });
    if (res.status === 404) return { name, published: false };
    if (!res.ok) return { name, error: `HTTP ${res.status}` };
    const version = probe(await res.json());
    return { name, published: Boolean(version), version: version || null };
  } catch (err) {
    return { name, error: String(err) };
  }
}

const [prs, registries] = await Promise.all([
  Promise.all(TRACKED_PRS.map(checkPr)),
  Promise.all(TRACKED_REGISTRIES.map(checkRegistry)),
]);

const report = { generatedAt: new Date().toISOString(), prs, registries };

if (process.argv.includes('--json')) {
  console.log(JSON.stringify(report, null, 2));
} else {
  console.log(`\nAegis Distribution Watchdog — ${report.generatedAt}\n`);
  console.log('── Awesome List PRs ─────────────────────────────────────────');
  let actionNeeded = false;
  for (const pr of prs) {
    if (pr.error) {
      console.log(`  ⚠ ${pr.label} #${pr.number}: ${pr.error}`);
      actionNeeded = true;
      continue;
    }
    const failing = pr.failingChecks.map((c) => c.name).join(', ');
    const flag = pr.state === 'MERGED' ? '✓' : failing ? '✗' : '•';
    console.log(`  ${flag} ${pr.label} #${pr.number}: ${pr.state}${failing ? ` — FAILING: ${failing}` : ''}`);
    if (failing || pr.state === 'CLOSED') actionNeeded = true;
  }
  console.log('\n── Registry Presence ────────────────────────────────────────');
  for (const reg of registries) {
    if (reg.error) console.log(`  ⚠ ${reg.name}: ${reg.error}`);
    else if (reg.published) console.log(`  ✓ ${reg.name}: v${reg.version}`);
    else {
      console.log(`  ✗ ${reg.name}: NOT PUBLISHED`);
      actionNeeded = true;
    }
  }
  console.log('');
  if (actionNeeded) {
    console.log('ACTION NEEDED — see items marked ✗/⚠ above.');
    process.exitCode = 1;
  } else {
    console.log('All distribution channels healthy.');
  }
}
