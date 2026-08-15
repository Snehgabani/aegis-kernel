/**
 * @file packages/mcp/src/scanner.ts
 * @description MCP Tool Poisoning Scanner & Schema Rug-Pull Detector.
 */

import { createHash } from 'node:crypto';

export interface MCPToolDefinition {
  name: string;
  description?: string;
  inputSchema?: Record<string, any>;
  metadata?: Record<string, any>;
}

export interface ToolScanResult {
  toolName: string;
  isPoisoned: boolean;
  threats: ('INVISIBLE_UNICODE_CHARACTERS' | 'INDIRECT_PROMPT_INJECTION' | 'OBFUSCATED_BASE64' | 'UNBOUNDED_PROPERTIES' | 'HOMOGLYPH_SPOOFING')[];
  sanitizedDescription?: string;
}

export class MCPToolPoisoningScanner {
  // Regex detecting zero-width, non-printing, and bidi-override characters
  private invisibleUnicodeRegex = /[\u200B-\u200D\uFEFF\u202A-\u202E\u2060-\u206F]/;

  // Prompt injection heuristic patterns inside tool descriptions
  private promptInjectionKeywords = [
    /ignore\s+(previous|prior)\s+(instructions|directives|rules)/i,
    /system\s*:\s*(ignore|override|execute)/i,
    /exfiltrate\s+(database|keys|passwords|tokens|pii)/i,
    /bypass\s+(guardrail|safety|security|policy)/i
  ];

  private base64Regex = /\b[A-Za-z0-9+\/]{20,}={0,2}\b/;
  private homoglyphRegex = /[аеорсх]/;
  private excessiveWhitespaceRegex = /\s{10,}/;

  /**
   * Scans a tool definition for indirect prompt injection or metadata poisoning.
   */
  public scanToolDefinition(tool: MCPToolDefinition): ToolScanResult {
    const threats: ToolScanResult['threats'] = [];
    const textToScan = `${tool.name} ${tool.description ?? ''} ${JSON.stringify(tool.inputSchema ?? {})}`;

    // 1. Invisible Unicode / Zero-Width Detection
    if (this.invisibleUnicodeRegex.test(textToScan)) {
      threats.push('INVISIBLE_UNICODE_CHARACTERS');
    }

    // 2. Indirect Prompt Injection Keywords in Description
    for (const pattern of this.promptInjectionKeywords) {
      if (pattern.test(textToScan)) {
        threats.push('INDIRECT_PROMPT_INJECTION');
        break;
      }
    }

    // 3. Excessive whitespace in description
    if (tool.description && this.excessiveWhitespaceRegex.test(tool.description)) {
      if (!threats.includes('INDIRECT_PROMPT_INJECTION')) {
        threats.push('INDIRECT_PROMPT_INJECTION');
      }
    }

    // 4. Base64 encoded payload in description
    if (tool.description && this.base64Regex.test(tool.description)) {
      threats.push('OBFUSCATED_BASE64');
    }

    // 5. Homoglyph / Tool name spoofing
    if (this.homoglyphRegex.test(textToScan)) {
      threats.push('HOMOGLYPH_SPOOFING');
    }

    return {
      toolName: tool.name,
      isPoisoned: threats.length > 0,
      threats,
      sanitizedDescription: tool.description?.replace(this.invisibleUnicodeRegex, '').replace(this.excessiveWhitespaceRegex, ' ').trim()
    };
  }
}

export class SchemaRugPullDetector {
  private registeredFingerprints: Map<string, string> = new Map();

  /**
   * Computes a canonical SHA-256 fingerprint for a tool definition.
   */
  public computeFingerprint(tool: MCPToolDefinition): string {
    const payload = JSON.stringify({
      name: tool.name,
      description: tool.description ?? '',
      inputSchema: tool.inputSchema ?? {}
    });
    return createHash('sha256').update(payload).digest('hex');
  }

  /**
   * Registers a tool's initial baseline fingerprint at session connection.
   */
  public registerTool(tool: MCPToolDefinition): void {
    const hash = this.computeFingerprint(tool);
    this.registeredFingerprints.set(tool.name, hash);
  }

  /**
   * Verifies that the tool schema has not mutated mid-session (prevents rug-pulls).
   */
  public verifyTool(tool: MCPToolDefinition): { isValid: boolean; reason?: string } {
    const initialHash = this.registeredFingerprints.get(tool.name);
    if (!initialHash) {
      // First time seeing tool, auto-register
      this.registerTool(tool);
      return { isValid: true };
    }

    const currentHash = this.computeFingerprint(tool);
    if (currentHash !== initialHash) {
      return {
        isValid: false,
        reason: `Schema rug-pull detected! Tool '${tool.name}' metadata or schema was mutated after initial connection.`
      };
    }

    return { isValid: true };
  }
}
