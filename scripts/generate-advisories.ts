/**
 * Programmatic Security Advisory & CVE Invariant Map Generator
 *
 * Generates structured developer security advisories documenting how Aegis Invariant Kernel
 * mitigates known autonomous agent vulnerabilities, prompt injections, and tool exfiltrations.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

export interface SecurityAdvisory {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  cveRef: string;
  affectedFrameworks: string[];
  vulnerabilityDescription: string;
  exploitVectorExample: string;
  aegisMitigationPack: string;
  aegisInvariantRule: string;
  latencyBenchmark: string;
}

export const ADVISORIES: SecurityAdvisory[] = [
  {
    id: 'AEGIS-ADV-2024-001',
    title: 'Autonomous Database Mutation via SQL AST Comment Token Splitting',
    severity: 'CRITICAL',
    cveRef: 'CWE-89 / OWASP-LLM07',
    affectedFrameworks: ['LangChain', 'CrewAI', 'AutoGen', 'Custom Function Calling'],
    vulnerabilityDescription:
      'Malicious user prompts can coerce agents into issuing mass DELETE/UPDATE database mutations where destructive keywords are split with inline C-style comments (e.g. DEL/**/ETE), bypassing naive regex guardrails.',
    exploitVectorExample: 'tool: database_exec, query: "DEL/**/ETE FROM users;"',
    aegisMitigationPack: '@aegis/sql-guard',
    aegisInvariantRule: 'SQL-001 / SQL-002 (AST-Level Tautology & DDL Prohibitor)',
    latencyBenchmark: '0.42 ms',
  },
  {
    id: 'AEGIS-ADV-2024-002',
    title: 'Zero-Width Unicode Homoglyph Credential Exfiltration in Agent Webhooks',
    severity: 'HIGH',
    cveRef: 'CWE-200 / OWASP-LLM06',
    affectedFrameworks: ['Model Context Protocol (MCP)', 'OpenAI Assistants API', 'Anthropic Claude'],
    vulnerabilityDescription:
      'Attackers embed zero-width space characters (\\u200B, \\u200C, \\uFEFF) within OpenAI API keys or Credit Card numbers. Regex pattern matchers fail to match token prefixes while remote HTTP servers normalize and consume the credentials.',
    exploitVectorExample: 'tool: post_webhook, body: "sk-proj-\\u200B1234567890..."',
    aegisMitigationPack: '@aegis/data-guard',
    aegisInvariantRule: 'DATA-001 / DATA-002 (NFKD Unicode Normalization Scanner)',
    latencyBenchmark: '0.18 ms',
  },
  {
    id: 'AEGIS-ADV-2024-003',
    title: 'Cross-Tenant Account Scope Tampering via Indirect Injection in MCP Tools',
    severity: 'CRITICAL',
    cveRef: 'CWE-639 / OWASP-LLM02',
    affectedFrameworks: ['MCP Server Ecosystem', 'LangGraph Multi-Tenant'],
    vulnerabilityDescription:
      'In multi-tenant SaaS environments, rogue sub-agents can be tricked by untrusted web browsing context to pass foreign tenant IDs into tool arguments, exfiltrating rival tenant confidential data.',
    exploitVectorExample: 'tool: export_customer_data, params: { tenantId: "tenant_target_corp" }',
    aegisMitigationPack: '@aegis/soc2-guard',
    aegisInvariantRule: 'SOC2-004 (Multi-Tenant Parameter vs Session State Isolation)',
    latencyBenchmark: '0.09 ms',
  },
  {
    id: 'AEGIS-ADV-2024-004',
    title: 'Financial Balance Draining via Scientific Notation & String Coercion',
    severity: 'HIGH',
    cveRef: 'CWE-1284 / OWASP-LLM08',
    affectedFrameworks: ['FinTech Automated Trading Bots', 'Stripe Billing Agents'],
    vulnerabilityDescription:
      'AI agents executing financial disbursements can be manipulated to output scientific notation numbers (e.g. 1e5 = 100,000) or numeric strings ("25000") that evade strict integer comparison logic in unhardened handlers.',
    exploitVectorExample: 'tool: send_payout, params: { amount: 1e5 }',
    aegisMitigationPack: '@aegis/finance-guard',
    aegisInvariantRule: 'FIN-001 / FIN-STATE-001 (Numeric Limit & Finite Coercion)',
    latencyBenchmark: '0.08 ms',
  },
];

export function generateAdvisoryFiles(outDir: string): void {
  if (!fs.existsSync(outDir)) {
    fs.mkdirSync(outDir, { recursive: true });
  }

  for (const adv of ADVISORIES) {
    const filePath = path.join(outDir, `${adv.id}.md`);
    const md = `# Security Advisory: ${adv.id}
## ${adv.title}

- **Severity**: **${adv.severity}**
- **Vulnerability Standard**: \`${adv.cveRef}\`
- **Affected Frameworks**: ${adv.affectedFrameworks.map((f) => `\`${f}\``).join(', ')}
- **Aegis Mitigation Pack**: \`${adv.aegisMitigationPack}\`
- **Enforced Invariant Rule**: \`${adv.aegisInvariantRule}\`
- **Mitigation Latency**: **${adv.latencyBenchmark}**

---

### 1. Threat Overview & Root Cause
${adv.vulnerabilityDescription}

---

### 2. Exploit Vector Example
\`\`\`json
${adv.exploitVectorExample}
\`\`\`

---

### 3. Aegis Mathematical Invariant Defense
Aegis intercepts this payload in-process before network or database dispatch:
1. Normalizes unicode characters and AST syntax trees in pure WebAssembly.
2. Evaluates state bounds, regex signatures, and schema constraints in <${adv.latencyBenchmark}.
3. Returns a deterministic rejection with self-healing feedback to the calling model.

\`\`\`bash
# Test this vector with Aegis CLI
npx aegis test
npx aegis benchmark --tricky
\`\`\`
`;
    fs.writeFileSync(filePath, md, 'utf8');
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const targetDir = path.resolve(process.cwd(), 'docs/advisories');
  generateAdvisoryFiles(targetDir);
  console.log(`✅ Generated ${ADVISORIES.length} security advisories in ${targetDir}`);
}
