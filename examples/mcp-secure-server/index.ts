/**
 * Aegis Invariant Kernel — Production Example: MCP Secure Tool Server
 *
 * Demonstrates Model Context Protocol (MCP) tool execution wrapped with
 * deterministic AST invariants, rate limiting, and zero-width token protection.
 */

import { AegisEngine } from '@aegis-kernel/core';
import { wrapMcpToolHandler } from '@aegis-kernel/mcp';

// Initialize the deterministic invariant engine
const engine = new AegisEngine();

// Simulated raw MCP Tool Handler
const unsafeToolHandler = async (request: { tool: string; params: any }) => {
  console.log(`[Target Service] Executing '${request.tool}' with parameters:`, request.params);
  return { status: 'success', executed: true };
};

// Wrap with Aegis Invariant Middleware
const secureMcpHandler = wrapMcpToolHandler(unsafeToolHandler, engine);

async function main() {
  console.log('🛡️  Aegis MCP Secure Tool Server Running...\n');

  // 1. Legitimate Tool Call
  console.log('Test 1: Legitimate Query');
  const safeRes = await secureMcpHandler({
    tool: 'execute_sql',
    params: { query: 'SELECT name, email FROM users WHERE id = 100;' },
  });
  console.log('Verdict:', safeRes, '\n');

  // 2. Adversarial Attack Blocked
  console.log('Test 2: SQL Evasion Attack (DEL/**/ETE FROM users)');
  try {
    await secureMcpHandler({
      tool: 'execute_sql',
      params: { query: 'DEL/**/ETE FROM users WHERE 1=1;' },
    });
  } catch (err: any) {
    console.log('🛡️  Disaster Prevented:', err.message, '\n');
  }
}

main();
