/**
 * @file packages/cli/src/mcp-inventory.ts
 * @description MCP server inventory security auditor — `aegis scan mcp`.
 *
 * Addresses the 2026 MCP attack surface (OWASP MCP Top 10 #3 Tool Poisoning;
 * industry scans found 41–100% of listed MCP servers lacking authentication):
 *
 *  1. AUTH: flags HTTP/SSE MCP servers registered without any credential
 *     material (Authorization header or token/key env var).
 *  2. TRANSPORT: flags plaintext http:// server URLs.
 *  3. SUPPLY CHAIN: flags `npx`/`uvx` server commands that do not pin a
 *     package version (silent tool substitution risk).
 *  4. LOCK / DRIFT: `--pin` writes an `aegis-mcp-lock.json` manifest of
 *     SHA-256 commitments per server; `--lock` verifies the live inventory
 *     against it and reports ADDED / REMOVED / CHANGED servers (detects
 *     rug-pulls and silent reconfiguration).
 *  5. TOOL POISONING: scans any embedded tool definitions with the
 *     core MCPToolPoisoningScanner.
 *
 * SECURITY INVARIANT: env VALUES and header VALUES are never persisted,
 * hashed, logged, or included in findings — only KEY NAMES participate in
 * commitments and output.
 */

import fs from 'fs';
import path from 'path';
import { createHash } from 'node:crypto';
import { MCPToolPoisoningScanner, type MCPToolDefinition } from '@aegis-kernel/mcp';

export type McpTransport = 'stdio' | 'http' | 'sse' | 'unknown';

export interface McpServerEntry {
  name: string;
  transport: McpTransport;
  command?: string;
  args?: string[];
  url?: string;
  envKeys: string[];
  headerKeys: string[];
  hasAuthMaterial: boolean;
}

export type McpFindingType =
  | 'MCP_NO_AUTH'
  | 'MCP_INSECURE_TRANSPORT'
  | 'MCP_UNPINNED_PACKAGE'
  | 'MCP_LOCK_DRIFT'
  | 'POISONED_TOOL'
  | 'MCP_CONFIG_ERROR';

export interface McpInventoryFinding {
  file: string;
  server: string;
  type: McpFindingType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  details: string;
}

/** Well-known MCP client inventory file locations (relative to scan root). */
export const MCP_INVENTORY_FILES = [
  'mcp.json',
  '.cursor/mcp.json',
  '.vscode/mcp.json',
  'claude_desktop_config.json',
  '.claude/mcp.json',
] as const;

const AUTH_ENV_PATTERN = /(TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL|AUTH)/i;
const AUTH_HEADER_PATTERN = /^(authorization|api-key|apikey|x-api-key|x-auth-token)$/i;

/** Package-manager runners whose args should carry a pinned version. */
const RUNNER_COMMANDS = new Set(['npx', 'pnpx', 'uvx', 'bunx', 'deno run', 'pipx']);

export function parseMcpInventory(filePath: string, content: string): McpServerEntry[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return [];
  }
  if (!parsed || typeof parsed !== 'object') return [];
  const obj = parsed as Record<string, unknown>;

  // Canonical shape: { "mcpServers": { name: {...} } } (Claude Desktop, Cursor, VS Code).
  // Files without an explicit mcpServers/servers map are NOT inventories (e.g. a
  // package-style mcp.json with name/description/capabilities must be ignored).
  const serversRaw = (obj.mcpServers ?? obj.servers) as Record<string, unknown> | undefined;
  if (!serversRaw || typeof serversRaw !== 'object') return [];

  const entries: McpServerEntry[] = [];
  for (const [name, raw] of Object.entries(serversRaw)) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) continue;
    const cfg = raw as Record<string, unknown>;

    const command = typeof cfg.command === 'string' ? cfg.command : undefined;
    const args = Array.isArray(cfg.args) ? (cfg.args as unknown[]).filter((a) => typeof a === 'string') as string[] : undefined;
    const url = typeof cfg.url === 'string' ? cfg.url : undefined;
    const transport: McpTransport = url
      ? (/^https?:\/\//i.test(url) ? 'http' : 'unknown')
      : command
        ? 'stdio'
        : ('type' in cfg && typeof cfg.type === 'string' ? (cfg.type as McpTransport) : 'unknown');

    // Skip non-server entries: an entry with no command, no url, and no known
    // transport is configuration noise, not an MCP server registration.
    if (!command && !url && transport === 'unknown') continue;

    const envKeys = cfg.env && typeof cfg.env === 'object' ? Object.keys(cfg.env as object) : [];
    const headerKeys = cfg.headers && typeof cfg.headers === 'object' ? Object.keys(cfg.headers as object) : [];

    const hasAuthMaterial =
      headerKeys.some((h) => AUTH_HEADER_PATTERN.test(h)) ||
      envKeys.some((k) => AUTH_ENV_PATTERN.test(k)) ||
      Boolean(cfg.oauth) ||
      Boolean(cfg['x-aegis-verified-auth']);

    entries.push({ name, transport, command, args, url, envKeys, headerKeys, hasAuthMaterial });
  }
  return entries;
}

export function auditMcpServerEntry(entry: McpServerEntry): McpInventoryFinding[] {
  const findings: McpInventoryFinding[] = [];

  // 1. Authentication (remote servers only — stdio locals authenticate out-of-band)
  if ((entry.transport === 'http' || entry.transport === 'sse') && !entry.hasAuthMaterial) {
    findings.push({
      file: '',
      server: entry.name,
      type: 'MCP_NO_AUTH',
      severity: 'high',
      details: `Remote MCP server '${entry.name}' (${entry.transport}) registered without any credential material (no Authorization/api-key header, no token/key env var). Industry scans in 2026 found 41–100% of listed MCP servers lack auth; unauthenticated tool servers are the primary tool-poisoning on-ramp.`,
    });
  }

  // 2. Transport security
  if (entry.url && /^http:\/\//i.test(entry.url)) {
    findings.push({
      file: '',
      server: entry.name,
      type: 'MCP_INSECURE_TRANSPORT',
      severity: 'medium',
      details: `Server '${entry.name}' uses plaintext http:// — tool traffic (and any credentials) is interceptable. Use https:// or a local stdio transport.`,
    });
  }

  // 3. Supply chain: unpinned runner packages
  if (entry.command && RUNNER_COMMANDS.has(entry.command) && entry.args) {
    const pkgArg = entry.args.find((a) => !a.startsWith('-') && a !== entry.command);
    if (pkgArg && !/@|\d+\.\d+/i.test(pkgArg)) {
      findings.push({
        file: '',
        server: entry.name,
        type: 'MCP_UNPINNED_PACKAGE',
        severity: 'high',
        details: `Server '${entry.name}' runs '${entry.command} ${pkgArg}' without a pinned version. Unpinned runner packages can silently fetch a compromised or rug-pulled release. Pin an exact version or digest (e.g. ${pkgArg}@1.2.3) and verify with aegis-mcp-lock.json.`,
      });
    }
  }

  return findings;
}

/**
 * SHA-256 commitment for one server entry. Canonical JSON over KEY NAMES only
 * (env/header values never enter the hash — they are secrets).
 */
export function serverCommitment(entry: McpServerEntry): string {
  const canonical = JSON.stringify({
    name: entry.name,
    transport: entry.transport,
    command: entry.command ?? null,
    args: entry.args ?? null,
    url: entry.url ?? null,
    envKeys: [...entry.envKeys].sort(),
    headerKeys: [...entry.headerKeys].sort(),
  });
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

export interface McpLockManifest {
  version: 1;
  pinnedAt: string;
  /** file path (relative to scan root) → server name → sha256 */
  servers: Record<string, Record<string, string>>;
}

export function buildLockManifest(
  inventories: Array<{ file: string; entries: McpServerEntry[] }>
): McpLockManifest {
  const servers: Record<string, Record<string, string>> = {};
  for (const inv of inventories) {
    servers[inv.file] = {};
    for (const entry of inv.entries) {
      servers[inv.file][entry.name] = serverCommitment(entry);
    }
  }
  return { version: 1, pinnedAt: new Date().toISOString(), servers };
}

export function verifyAgainstLock(
  inventories: Array<{ file: string; entries: McpServerEntry[] }>,
  lock: McpLockManifest
): McpInventoryFinding[] {
  const findings: McpInventoryFinding[] = [];
  for (const inv of inventories) {
    const pinned = lock.servers[inv.file] ?? {};
    const live = new Set(inv.entries.map((e) => e.name));

    for (const [name, hash] of Object.entries(pinned)) {
      if (!live.has(name)) {
        findings.push({
          file: inv.file,
          server: name,
          type: 'MCP_LOCK_DRIFT',
          severity: 'medium',
          details: `Pinned server '${name}' is MISSING from '${inv.file}' (removed or renamed).`,
        });
        continue;
      }
      const entry = inv.entries.find((e) => e.name === name)!;
      const liveHash = serverCommitment(entry);
      if (liveHash !== hash) {
        findings.push({
          file: inv.file,
          server: name,
          type: 'MCP_LOCK_DRIFT',
          severity: 'critical',
          details: `Server '${name}' CHANGED since pinning (command/args/url/env-shape differ). This is the rug-pull / silent-substitution signal: verify the change is intentional, then re-pin.`,
        });
      }
    }
    for (const entry of inv.entries) {
      if (!(entry.name in pinned)) {
        findings.push({
          file: inv.file,
          server: entry.name,
          type: 'MCP_LOCK_DRIFT',
          severity: 'high',
          details: `Server '${entry.name}' is NOT in the pinned manifest (newly added to '${inv.file}'). Unknown tool servers must be reviewed before use.`,
        });
      }
    }
  }
  return findings;
}

/** Scan embedded tool definitions (some inventories/registries carry them). */
export function scanEmbeddedTools(filePath: string, content: string): McpInventoryFinding[] {
  const findings: McpInventoryFinding[] = [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return findings;
  }
  const walk = (node: unknown): void => {
    if (Array.isArray(node)) {
      node.forEach(walk);
      return;
    }
    if (node && typeof node === 'object') {
      const obj = node as Record<string, unknown>;
      if (typeof obj.name === 'string' && ('description' in obj || 'inputSchema' in obj)) {
        const scanner = new MCPToolPoisoningScanner();
        const result = scanner.scanToolDefinition(obj as unknown as MCPToolDefinition);
        if (result.isPoisoned) {
          findings.push({
            file: filePath,
            server: result.toolName,
            type: 'POISONED_TOOL',
            severity: 'critical',
            details: `Tool '${result.toolName}' definition is poisoned: ${result.threats.join(', ')}`,
          });
        }
      }
      Object.values(obj).forEach(walk);
    }
  };
  walk(parsed);
  return findings;
}

export interface McpScanResult {
  inventoriesFound: string[];
  serversAudited: number;
  findings: McpInventoryFinding[];
}

export function runMcpInventoryScan(
  rootPath: string,
  options?: { lockPath?: string; pinPath?: string }
): McpScanResult {
  const root = path.resolve(rootPath);
  const inventories: Array<{ file: string; entries: McpServerEntry[] }> = [];
  const findings: McpInventoryFinding[] = [];

  for (const rel of MCP_INVENTORY_FILES) {
    const abs = path.join(root, rel);
    if (!fs.existsSync(abs)) continue;
    let content: string;
    try {
      content = fs.readFileSync(abs, 'utf8');
    } catch {
      continue;
    }
    const entries = parseMcpInventory(abs, content);
    if (entries.length === 0) continue;
    inventories.push({ file: rel, entries });
    for (const entry of entries) {
      for (const f of auditMcpServerEntry(entry)) {
        findings.push({ ...f, file: rel });
      }
    }
    findings.push(...scanEmbeddedTools(rel, content));
  }

  if (options?.pinPath) {
    const lock = buildLockManifest(inventories);
    fs.mkdirSync(path.dirname(path.resolve(options.pinPath)), { recursive: true });
    fs.writeFileSync(path.resolve(options.pinPath), JSON.stringify(lock, null, 2), 'utf8');
  }

  if (options?.lockPath) {
    const lockAbs = path.resolve(options.lockPath);
    if (!fs.existsSync(lockAbs)) {
      findings.push({
        file: options.lockPath,
        server: '-',
        type: 'MCP_CONFIG_ERROR',
        severity: 'medium',
        details: `Lock manifest not found at ${options.lockPath}. Generate one with \`aegis scan mcp --pin\` and commit it.`,
      });
    } else {
      try {
        const lock = JSON.parse(fs.readFileSync(lockAbs, 'utf8')) as McpLockManifest;
        findings.push(...verifyAgainstLock(inventories, lock));
      } catch {
        findings.push({
          file: options.lockPath,
          server: '-',
          type: 'MCP_CONFIG_ERROR',
          severity: 'high',
          details: 'Lock manifest is not valid JSON.',
        });
      }
    }
  }

  return {
    inventoriesFound: inventories.map((i) => i.file),
    serversAudited: inventories.reduce((n, i) => n + i.entries.length, 0),
    findings,
  };
}

/** CLI renderer for `aegis scan-mcp` (kept here so the logic stays testable). */
import pc from 'picocolors';

export function printMcpScanResult(result: McpScanResult): void {
  console.log(pc.bold(pc.cyan('\n🔌 AEGIS MCP SERVER INVENTORY AUDIT')));
  if (result.inventoriesFound.length === 0) {
    console.log(pc.yellow('\n  No MCP inventory files found (mcp.json, .cursor/mcp.json, .vscode/mcp.json, claude_desktop_config.json).'));
    console.log(pc.gray('  Nothing to audit.\n'));
    return;
  }
  console.log(pc.gray(`\n  Inventories: ${result.inventoriesFound.join(', ')}`));
  console.log(pc.gray(`  Servers audited: ${result.serversAudited}\n`));

  if (result.findings.length === 0) {
    console.log(pc.green('  ✅ All MCP servers pass auth, transport, pinning, and lock checks.\n'));
    return;
  }

  for (const f of result.findings) {
    const badge =
      f.severity === 'critical'
        ? pc.bgRed(pc.white(' CRITICAL '))
        : f.severity === 'high'
          ? pc.bgRed(pc.black(' HIGH '))
          : f.severity === 'medium'
            ? pc.bgYellow(pc.black(' MEDIUM '))
            : pc.bgBlue(pc.white(' LOW '));
    console.log(`  ${badge} ${pc.bold(f.type)}  ${pc.cyan(`${f.file} :: ${f.server}`)}`);
    console.log(`     ${pc.gray(f.details)}\n`);
  }
  const blocking = result.findings.filter((f) => f.severity === 'critical' || f.severity === 'high');
  if (blocking.length > 0) {
    console.log(pc.bold(pc.red(`  ⚠️  ${blocking.length} high/critical finding(s) — exit code 1.`)));
  }
  console.log('');
}
