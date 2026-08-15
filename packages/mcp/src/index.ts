import { createHash } from 'node:crypto';
import { AegisEngine, redactPiiString, type AegisConfig, type AegisVerdict } from '@aegis-kernel/core';

export interface MCPToolDefinition {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

export interface AegisMCPOptions {
  engine?: AegisEngine;
  config?: AegisConfig;
  sanitizeOutputs?: boolean; // Scans and redacts leaked secrets from tool outputs
  enableSchemaPinning?: boolean; // Detects tool poisoning & schema drift
  callerId?: string; // Propagates caller identity to prevent confused-deputy attacks
}

export class AegisMCPMiddleware {
  private engine: AegisEngine;
  private pinnedSchemas: Map<string, string>;
  private sanitizeOutputs: boolean;
  private enableSchemaPinning: boolean;
  private callerId?: string;

  constructor(options?: AegisMCPOptions) {
    this.engine = options?.engine ?? new AegisEngine(options?.config);
    this.pinnedSchemas = new Map();
    this.sanitizeOutputs = options?.sanitizeOutputs ?? true;
    this.enableSchemaPinning = options?.enableSchemaPinning ?? true;
    this.callerId = options?.callerId;
  }

  /**
   * Pin a tool definition schema at initialization.
   * If a tool definition changes at runtime, detects potential Tool Poisoning / Rug Pull.
   */
  public pinToolDefinition(tool: MCPToolDefinition): void {
    const hash = this.computeSchemaHash(tool);
    this.pinnedSchemas.set(tool.name, hash);
  }

  /**
   * Check if a tool definition has drifted from its pinned schema
   */
  public verifyToolSchema(tool: MCPToolDefinition): { valid: boolean; driftDetected: boolean } {
    if (!this.enableSchemaPinning) return { valid: true, driftDetected: false };

    const pinnedHash = this.pinnedSchemas.get(tool.name);
    if (!pinnedHash) {
      // Pin on first encounter
      this.pinToolDefinition(tool);
      return { valid: true, driftDetected: false };
    }

    const currentHash = this.computeSchemaHash(tool);
    const driftDetected = pinnedHash !== currentHash;

    return {
      valid: !driftDetected,
      driftDetected,
    };
  }

  private computeSchemaHash(tool: MCPToolDefinition): string {
    const json = JSON.stringify({
      name: tool.name,
      description: tool.description,
      inputSchema: tool.inputSchema,
    });
    return createHash('sha256').update(json).digest('hex');
  }

  /**
   * Wraps an MCP tool handler with Aegis deterministic pre-execution clearance
   * and post-execution output sanitization.
   */
  public wrapToolHandler<TArgs extends Record<string, unknown>, TResult>(
    tool: string | MCPToolDefinition,
    handler: (args: TArgs, context?: any) => Promise<TResult>
  ): (args: TArgs, context?: any) => Promise<TResult | { isError: boolean; content: any[] }> {
    const toolName = typeof tool === 'string' ? tool : tool.name;

    return async (args: TArgs, context?: any) => {
      // 0. Verify Schema Pinning if full tool definition object is provided
      if (typeof tool === 'object' && this.enableSchemaPinning) {
        const schemaVerification = this.verifyToolSchema(tool);
        if (!schemaVerification.valid) {
          return {
            isError: true,
            content: [
              {
                type: 'text',
                text: `[AEGIS SAFETY VIOLATION] Tool schema drift or poisoning detected for tool '${toolName}'. Execution halted by Aegis MCP Middleware.`,
              },
            ],
          };
        }
      }
      // 1. Evaluate tool call invariants before execution
      const verdict: AegisVerdict = this.engine.evaluate(
        {
          tool: toolName,
          params: args,
        },
        {
          framework: 'mcp',
          callerId: this.callerId ?? context?.callerId,
        }
      );

      if (!verdict.allowed) {
        const topViolation = verdict.violations[0];
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `[AEGIS SAFETY VIOLATION] Tool execution blocked by invariant policy: ${topViolation?.message ?? 'Security violation'}. ProofHash: ${verdict.proofHash}`,
            },
            ...(verdict.suggestedFix
              ? [
                  {
                    type: 'text',
                    text: `[AEGIS SUGGESTED FIX] ${verdict.suggestedFix}`,
                  },
                ]
              : []),
          ],
        };
      }

      // 2. Execute underlying handler
      const rawResult = await handler(args, context);

      // 3. Post-execution Tool Output Sanitization (Prevents Cross-Server Exfiltration)
      if (this.sanitizeOutputs && rawResult !== null && rawResult !== undefined) {
        return this.sanitizeToolOutput(rawResult);
      }

      return rawResult;
    };
  }

  private sanitizeToolOutput<T>(output: T): T {
    if (typeof output === 'string') {
      return redactPiiString(output) as unknown as T;
    }
    if (typeof output === 'object') {
      try {
        const json = JSON.stringify(output);
        const redacted = redactPiiString(json);
        return JSON.parse(redacted);
      } catch {
        return output;
      }
    }
    return output;
  }

  public getEngine(): AegisEngine {
    return this.engine;
  }
}

/**
 * Convenience helper to wrap a general MCP tool handler function
 */
export function wrapMcpToolHandler<TArgs extends Record<string, unknown>, TResult>(
  handler: (request: { tool: string; params: TArgs }) => Promise<TResult>,
  engine?: AegisEngine
) {
  const middleware = new AegisMCPMiddleware({ engine });
  return async (request: { tool: string; params: TArgs }) => {
    const wrapped = middleware.wrapToolHandler(request.tool, async (args) => {
      return handler({ tool: request.tool, params: args as TArgs });
    });
    const result = await wrapped(request.params);
    if (result && typeof result === 'object' && 'isError' in result && (result as any).isError) {
      const errText =
        (result as any).content?.map((c: any) => c.text).join('\n') ||
        'Blocked by Aegis Invariant Policy';
      throw new Error(errText);
    }
    return result as TResult;
  };
}
