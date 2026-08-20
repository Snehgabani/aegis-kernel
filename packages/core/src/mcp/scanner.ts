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
  threats: ('INVISIBLE_UNICODE_CHARACTERS' | 'INDIRECT_PROMPT_INJECTION' | 'OBFUSCATED_BASE64' | 'UNBOUNDED_PROPERTIES' | 'HOMOGLYPH_SPOOFING' | 'CAPABILITY_ESCALATION')[];
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

  private base64Regex = /\b[A-Za-z0-9+\/]{20,}={0,2}\b/g;
  private excessiveWhitespaceRegex = /\s{10,}/;
  private hexEncodedRegex = /\\x([0-9A-Fa-f]{2})/g;
  private urlEncodedRegex = /%([0-9A-Fa-f]{2})/g;

  private decodeEncodedStrings(text: string): string {
    let decoded = text.replace(this.hexEncodedRegex, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
    decoded = decoded.replace(this.urlEncodedRegex, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
    // Remove typical split string concatenators (e.g. ' + ')
    decoded = decoded.replace(/['"]\s*\+\s*['"]/g, '');
    return decoded;
  }

  /**
   * Scans a tool definition for indirect prompt injection or metadata poisoning.
   */
  public scanToolDefinition(tool: MCPToolDefinition): ToolScanResult {
    const threats: ToolScanResult['threats'] = [];
    let textToScan = `${tool.name} ${tool.description ?? ''} ${JSON.stringify(tool.inputSchema ?? {})}`;
    
    // 6. Normalize text before pattern matching
    textToScan = textToScan.normalize('NFC');
    
    // Decode hex, url-encoded and split strings
    const decodedText = this.decodeEncodedStrings(textToScan);

    // 1. Invisible Unicode / Zero-Width Detection
    if (this.invisibleUnicodeRegex.test(decodedText)) {
      threats.push('INVISIBLE_UNICODE_CHARACTERS');
    }

    // 2. Indirect Prompt Injection Keywords in Description
    for (const pattern of this.promptInjectionKeywords) {
      if (pattern.test(decodedText)) {
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
    if (tool.description) {
      const matches = tool.description.match(this.base64Regex);
      if (matches) {
        let base64Suspicious = false;
        for (const match of matches) {
          try {
            const decodedB64 = Buffer.from(match, 'base64').toString('utf8');
            for (const pattern of this.promptInjectionKeywords) {
              if (pattern.test(decodedB64)) {
                base64Suspicious = true;
                break;
              }
            }
          } catch (e) {}
        }
        
        threats.push('OBFUSCATED_BASE64');
        if (base64Suspicious && !threats.includes('INDIRECT_PROMPT_INJECTION')) {
          threats.push('INDIRECT_PROMPT_INJECTION');
        }
      }
    }

    // 5. Homoglyph / Tool name spoofing
    const broaderHomoglyphRegex = /[\u0400-\u04FF\u0370-\u03FF\u0590-\u05FF\u2150-\u218F\u00C0-\u017F]/;
    if (broaderHomoglyphRegex.test(decodedText)) {
      threats.push('HOMOGLYPH_SPOOFING');
    }

    // 6. Unbounded input schema (added 2026-08-20): a poisoned or lazy schema that
    // accepts arbitrary properties, or properties with no type constraint at all,
    // defeats downstream deterministic validation before it runs.
    if (tool.inputSchema && typeof tool.inputSchema === 'object') {
      const schema = tool.inputSchema as Record<string, unknown>;
      const isUnboundedRoot = schema.additionalProperties === true;
      let hasConstraintlessProperty = false;
      const props = schema.properties;
      if (props && typeof props === 'object' && !Array.isArray(props)) {
        for (const propSchema of Object.values(props as Record<string, unknown>)) {
          if (
            !propSchema ||
            typeof propSchema !== 'object' ||
            (!('type' in propSchema) && !('enum' in propSchema) && !('const' in propSchema) && !('$ref' in propSchema) && !('anyOf' in propSchema) && !('oneOf' in propSchema))
          ) {
            hasConstraintlessProperty = true;
            break;
          }
        }
      }
      if (isUnboundedRoot || hasConstraintlessProperty) {
        threats.push('UNBOUNDED_PROPERTIES');
      }
    }

    // 7. Capability escalation (added 2026-08-20): a tool whose NAME advertises a
    // read-only capability while its DESCRIPTION claims destructive powers is the
    // classic confused-deputy / rug-pulled-tool signal (OWASP ASI02).
    if (tool.description && tool.name) {
      const readonlyName = /^(read|get|list|search|fetch|view|peek|query)[_-]/i.test(tool.name);
      const destructiveDescription =
        /\b(delete|drop|remove|write|update|destroy|wipe|overwrite|truncate|grant|disable)\b/i.test(
          tool.description
        );
      if (readonlyName && destructiveDescription) {
        threats.push('CAPABILITY_ESCALATION');
      }
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
