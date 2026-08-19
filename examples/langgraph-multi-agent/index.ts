/**
 * Production LangGraph Multi-Agent Workflow with Aegis Invariant Kernel
 * Demonstrates deterministic tool invariant protection, multi-tenant state checks,
 * and automated self-healing feedback loops in a stateful agent graph.
 */

import { AegisEngine } from '@aegis-kernel/core';
import { AegisLangChainGuard } from '@aegis-kernel/langchain';

// 1. Configure Aegis Invariant Engine
export const aegisEngine = new AegisEngine({
  mode: 'enforce',
  rules: [
    {
      id: 'rule-sql-firewall',
      name: 'SQL AST Injection & DDL Barrier',
      type: 'sql',
      severity: 'critical',
      action: 'block',
      enabled: true,
      params: {
        prohibitDdl: true,
        prohibitUnconstrainedDelete: true,
        prohibitTautologies: true,
        maxLimit: 500,
      },
    },
    {
      id: 'rule-financial-limit',
      name: 'Financial Disbursement Limit',
      type: 'numeric',
      severity: 'critical',
      action: 'block',
      enabled: true,
      params: {
        field: 'amount',
        min: 0,
        max: 10000,
      },
    },
    {
      id: 'rule-pii-redaction',
      name: 'PII & API Token Redaction',
      type: 'pii',
      severity: 'high',
      action: 'block',
      enabled: true,
      params: {
        detectSsn: true,
        detectCreditCard: true,
        detectTokens: true,
      },
    },
  ],
});

export const langChainGuard = new AegisLangChainGuard(aegisEngine);

// 2. Define LangChain Structured Tools with Aegis Protection
const rawDatabaseTool = {
  name: 'execute_sql_query',
  description: 'Executes SQL statements on internal customer database',
  call: async (input: { sql: string }) => {
    return { status: 'SUCCESS', rows: [{ id: 101, name: 'Acme Corp', balance: 45000 }] };
  },
  invoke: async (input: { sql: string }) => {
    return { status: 'SUCCESS', rows: [{ id: 101, name: 'Acme Corp', balance: 45000 }] };
  },
};

const rawTransferTool = {
  name: 'issue_customer_refund',
  description: 'Issues refund or wire transfer to customer',
  call: async (input: { customerId: string; amount: number }) => {
    return { status: 'SETTLED', transactionId: `txn_${Date.now()}`, amount: input.amount };
  },
  invoke: async (input: { customerId: string; amount: number }) => {
    return { status: 'SETTLED', transactionId: `txn_${Date.now()}`, amount: input.amount };
  },
};

// Wrap tools with Aegis Invariant Firewall
export const protectedDbTool = langChainGuard.wrap(rawDatabaseTool);
export const protectedTransferTool = langChainGuard.wrap(rawTransferTool);

// 3. Stateful Multi-Agent Execution Node with Self-Healing Feedback
export async function executeAgentStep(toolName: string, params: Record<string, any>) {
  const tool = toolName === 'execute_sql_query' ? protectedDbTool : protectedTransferTool;
  try {
    const result = await tool.invoke(params);
    return { success: true, result };
  } catch (err: any) {
    return {
      success: false,
      error: err.message,
      aegisVerdict: err.aegisVerdict,
      suggestedFix: err.aegisVerdict?.suggestedFix || 'Please adjust parameters to meet safety invariants.',
    };
  }
}

// 4. Example Self-Healing Agent Execution
async function main() {
  console.log('🤖 Starting LangGraph Multi-Agent Aegis Protection Demonstration...');

  // Step 1: Agent attempts destructive query (injected)
  console.log('\n[Turn 1] Agent attempts destructive query: DROP TABLE customer_data');
  const turn1 = await executeAgentStep('execute_sql_query', { sql: 'DROP TABLE customer_data;' });
  console.log('  Result:', turn1.success ? 'EXECUTED (Danger!)' : `🛑 BLOCKED: ${turn1.error}`);
  console.log('  Aegis Feedback to Agent:', turn1.suggestedFix);

  // Step 2: Agent self-heals based on Aegis feedback
  console.log('\n[Turn 2] Agent self-heals: SELECT * FROM customer_data WHERE id = 101 LIMIT 1');
  const turn2 = await executeAgentStep('execute_sql_query', { sql: 'SELECT * FROM customer_data WHERE id = 101 LIMIT 1;' });
  console.log('  Result:', turn2.success ? '✅ ALLOWED & EXECUTED' : 'BLOCKED');
  console.log('  Output:', turn2.result);

  // Step 3: Agent attempts unauthorized overspend transfer ($75,000 > $10,000 limit)
  console.log('\n[Turn 3] Agent attempts transfer of $75,000.00');
  const turn3 = await executeAgentStep('issue_customer_refund', { customerId: 'cust_42', amount: 75000 });
  console.log('  Result:', turn3.success ? 'EXECUTED (Danger!)' : `🛑 BLOCKED: ${turn3.error}`);

  // Step 4: Agent adjusts to allowable refund threshold
  console.log('\n[Turn 4] Agent submits compliant transfer of $450.00');
  const turn4 = await executeAgentStep('issue_customer_refund', { customerId: 'cust_42', amount: 450 });
  console.log('  Result:', turn4.success ? '✅ ALLOWED & EXECUTED' : 'BLOCKED');
  console.log('  Output:', turn4.result);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}
