import fs from 'fs';
import path from 'path';
import pc from 'picocolors';
import { LocalPromptInjectionDetector } from '@aegis-kernel/core';
import { MCPToolPoisoningScanner } from '@aegis-kernel/mcp';

export interface ScanFinding {
  file: string;
  line?: number;
  type: 'PROMPT_INJECTION' | 'POISONED_TOOL' | 'HARDCODED_SECRET' | 'UNPINNED_MCP';
  severity: 'low' | 'medium' | 'high' | 'critical';
  details: string;
}

export function runScan(targetPath: string = '.'): ScanFinding[] {
  console.log(pc.bold(pc.cyan('\n🔍 AEGIS SHIFT-LEFT INVARIANT & THREAT SCANNER')));
  console.log(pc.gray(`Scanning target: ${path.resolve(targetPath)}...\n`));

  const findings: ScanFinding[] = [];
  const injectionDetector = new LocalPromptInjectionDetector();
  const mcpScanner = new MCPToolPoisoningScanner();

  function scanFile(filePath: string) {
    const ext = path.extname(filePath).toLowerCase();
    if (!['.json', '.yaml', '.yml', '.ts', '.js', '.py', '.md', '.txt'].includes(ext)) {
      return;
    }

    let content: string;
    try {
      content = fs.readFileSync(filePath, 'utf8');
    } catch {
      return;
    }

    const lines = content.split('\n');

    // 1. JSON / YAML MCP Tool Scan
    if (ext === '.json' && (filePath.includes('mcp') || filePath.includes('tool'))) {
      try {
        const parsed = JSON.parse(content);
        const tools = Array.isArray(parsed) ? parsed : (parsed.tools || [parsed]);
        for (const tool of tools) {
          if (tool && tool.name && tool.description) {
            const scan = mcpScanner.scanToolDefinition(tool);
            if (scan.isPoisoned) {
              findings.push({
                file: filePath,
                type: 'POISONED_TOOL',
                severity: 'critical',
                details: `Tool '${tool.name}' has threats: ${scan.threats.join(', ')}`,
              });
            }
          }
        }
      } catch {
        // Not a pure JSON tool schema
      }
    }

    // 2. Line-by-line inspection for prompt injection patterns and secret patterns
    lines.forEach((line, idx) => {
      // Secret check
      if (/(AIza[0-9A-Za-z-_]{30,}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,})/.test(line)) {
        findings.push({
          file: filePath,
          line: idx + 1,
          type: 'HARDCODED_SECRET',
          severity: 'critical',
          details: 'Potential hardcoded API token/secret detected',
        });
      }

      // Prompt injection check on markdown/prompts
      if (line.length > 20 && (filePath.includes('prompt') || filePath.includes('template') || ext === '.md')) {
        const injection = injectionDetector.analyze(line);
        if (injection.isInjection && injection.confidenceScore >= 0.7) {
          findings.push({
            file: filePath,
            line: idx + 1,
            type: 'PROMPT_INJECTION',
            severity: 'high',
            details: `Prompt injection pattern detected (confidence: ${(injection.confidenceScore * 100).toFixed(0)}%)`,
          });
        }
      }
    });
  }

  function walk(currentPath: string) {
    if (!fs.existsSync(currentPath)) return;
    const stat = fs.statSync(currentPath);
    if (stat.isDirectory()) {
      if (['node_modules', '.git', 'dist', '.turbo', '.next'].includes(path.basename(currentPath))) return;
      const entries = fs.readdirSync(currentPath);
      for (const entry of entries) {
        walk(path.join(currentPath, entry));
      }
    } else {
      scanFile(currentPath);
    }
  }

  walk(targetPath);

  if (findings.length === 0) {
    console.log(pc.green('✅ No invariant violations or latent security threats found!'));
  } else {
    console.log(pc.bold(pc.red(`⚠️  Found ${findings.length} potential security issues:\n`)));
    for (const f of findings) {
      const loc = f.line ? `${f.file}:${f.line}` : f.file;
      const badge = f.severity === 'critical' ? pc.bgRed(pc.white(' CRITICAL ')) : pc.bgYellow(pc.black(' HIGH '));
      console.log(`  ${badge} ${pc.bold(f.type)} at ${pc.cyan(loc)}`);
      console.log(`     ${pc.gray(f.details)}\n`);
    }
  }

  return findings;
}
