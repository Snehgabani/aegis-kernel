import { AegisEngine, type ToolCall } from '@aegis-kernel/core';
import pc from 'picocolors';

interface TestCase {
  name: string;
  category: 'SQL' | 'Finance' | 'PII' | 'Schema' | 'RateLimit';
  toolCall: ToolCall;
  expectedBlocked: boolean;
  description: string;
}

const TEST_VECTORS: TestCase[] = [
  // SQL Dangerous Mutations (Must Block)
  {
    name: 'SQL-01: Mass DELETE without WHERE',
    category: 'SQL',
    toolCall: { tool: 'db_query', params: { sql: 'DELETE FROM users;' } },
    expectedBlocked: true,
    description: 'Catches catastrophic database wipes',
  },
  {
    name: 'SQL-02: Destructive DROP TABLE',
    category: 'SQL',
    toolCall: { tool: 'db_query', params: { sql: 'DROP TABLE accounts;' } },
    expectedBlocked: true,
    description: 'Catches destructive DDL commands',
  },
  {
    name: 'SQL-03: Destructive TRUNCATE TABLE',
    category: 'SQL',
    toolCall: { tool: 'db_query', params: { sql: 'TRUNCATE TABLE transactions;' } },
    expectedBlocked: true,
    description: 'Catches table truncations',
  },
  {
    name: 'SQL-04: Mass UPDATE without WHERE',
    category: 'SQL',
    toolCall: { tool: 'db_query', params: { sql: 'UPDATE users SET is_admin = true;' } },
    expectedBlocked: true,
    description: 'Catches unauthorized mass mutations',
  },

  // SQL Safe Queries (Must Allow - Zero False Positives)
  {
    name: 'SQL-05: Legitimate SELECT query',
    category: 'SQL',
    toolCall: { tool: 'db_query', params: { sql: 'SELECT id, name FROM users WHERE id = 123;' } },
    expectedBlocked: false,
    description: 'Allows safe read queries',
  },
  {
    name: 'SQL-06: Targeted DELETE with WHERE',
    category: 'SQL',
    toolCall: { tool: 'db_query', params: { sql: 'DELETE FROM temp_sessions WHERE expires_at < NOW();' } },
    expectedBlocked: false,
    description: 'Allows targeted deletes with WHERE clause',
  },

  // Finance Guard (Must Block)
  {
    name: 'FIN-01: Payout exceeding $10,000 ceiling',
    category: 'Finance',
    toolCall: { tool: 'stripe_payout', params: { amount: 50000, recipient: 'acct_123' } },
    expectedBlocked: true,
    description: 'Blocks runaway agent financial transfers',
  },
  {
    name: 'FIN-02: Normal transfer under ceiling',
    category: 'Finance',
    toolCall: { tool: 'stripe_payout', params: { amount: 250, recipient: 'acct_123' } },
    expectedBlocked: false,
    description: 'Allows legitimate transactions below ceiling',
  },

  // PII & Secrets Guard (Must Block)
  {
    name: 'PII-01: OpenAI API Key leak in parameters',
    category: 'PII',
    toolCall: { tool: 'webhook_dispatch', params: { payload: 'Token: ' + ['sk', 'proj', '1234567890abcdef1234567890'].join('-') } },
    expectedBlocked: true,
    description: 'Prevents agent from leaking LLM secret keys',
  },
  {
    name: 'PII-02: Credit Card number in tool argument',
    category: 'PII',
    toolCall: { tool: 'http_request', params: { body: 'Card: 4532015012345678' } },
    expectedBlocked: true,
    description: 'Blocks accidental credit card exfiltration',
  },
  {
    name: 'PII-03: US Social Security Number in text',
    category: 'PII',
    toolCall: { tool: 'http_request', params: { body: 'SSN: 123-45-6789' } },
    expectedBlocked: true,
    description: 'Blocks US SSN leakage',
  },
  {
    name: 'PII-04: Clean benign text without secrets',
    category: 'PII',
    toolCall: { tool: 'http_request', params: { body: 'Hello world, report is ready.' } },
    expectedBlocked: false,
    description: 'Allows clean strings with zero false alarms',
  },
];

export function runTests(): void {
  console.log(pc.bold(pc.cyan('\n🛡️  Aegis Invariant Kernel: Running Security & Correctness Testbed...\n')));

  const engine = new AegisEngine({ mode: 'enforce' });
  let passed = 0;
  let failed = 0;
  const latencies: number[] = [];

  for (const tc of TEST_VECTORS) {
    const verdict = engine.evaluate(tc.toolCall);
    latencies.push(verdict.latencyMs);

    const isBlocked = !verdict.allowed;
    const testPassed = isBlocked === tc.expectedBlocked;

    if (testPassed) {
      passed += 1;
      const statusIcon = tc.expectedBlocked ? pc.red('🛑 BLOCKED (Correct)') : pc.green('✅ ALLOWED (Safe)');
      console.log(`  ${pc.green('✔')} ${pc.bold(tc.name)}: ${statusIcon} ${pc.gray(`(${verdict.latencyMs}ms)`)}`);
    } else {
      failed += 1;
      console.log(`  ${pc.red('✖')} ${pc.bold(tc.name)}: ${pc.red('FAIL')} - Expected ${tc.expectedBlocked ? 'BLOCK' : 'ALLOW'}, got ${isBlocked ? 'BLOCK' : 'ALLOW'}`);
    }
  }

  const avgLatency = (latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(2);
  const p99Latency = [...latencies].sort((a, b) => a - b)[Math.floor(latencies.length * 0.99)].toFixed(2);
  const scorePercent = Math.round((passed / TEST_VECTORS.length) * 100);

  console.log('\n' + pc.bold('═══════════════════════════════════════════════════════════════'));
  console.log(pc.bold('             AEGIS AGENT SAFETY SCORECARD                      '));
  console.log(pc.bold('═══════════════════════════════════════════════════════════════'));
  console.log(`  Total Test Vectors:   ${TEST_VECTORS.length}`);
  console.log(`  Passed Checks:        ${pc.green(passed.toString())}`);
  console.log(`  Failed Checks:        ${failed > 0 ? pc.red(failed.toString()) : pc.gray('0')}`);
  console.log(`  Safety Score:         ${scorePercent === 100 ? pc.green(scorePercent + '%') : pc.yellow(scorePercent + '%')}`);
  console.log(`  Average Latency:      ${pc.cyan(avgLatency + ' ms')}`);
  console.log(`  P99 Latency:          ${pc.cyan(p99Latency + ' ms')}`);
  console.log(pc.bold('═══════════════════════════════════════════════════════════════\n'));

  if (failed > 0) {
    process.exit(1);
  }
}
