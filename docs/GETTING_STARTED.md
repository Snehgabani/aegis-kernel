# Getting Started with Aegis Invariant Kernel

A comprehensive guide on installing, starting, and integrating Aegis into autonomous AI agent workflows.

---

## 1. Installation

Aegis Invariant Kernel is available across all major agent runtimes:

### TypeScript / JavaScript (Node.js >= 18.0)
```bash
npm install @aegis-kernel/core
```

Framework adapters:
```bash
npm install @aegis-kernel/langchain    # LangChain / LangGraph / CrewAI
npm install @aegis-kernel/mcp          # Model Context Protocol (MCP) servers
npm install @aegis-kernel/vercel-ai    # Vercel AI SDK
npm install @aegis-kernel/openai       # OpenAI Function Calling
npm install @aegis-kernel/anthropic    # Anthropic Tool Use
```

### Python (Python >= 3.9, Zero Dependencies)
```bash
pip install aegis-kernel
```

### Standalone Developer CLI
```bash
npm install -g @aegis-kernel/cli
# or execute via npx
npx aegis --help
```

### Go SDK
```bash
go get github.com/Snehgabani/aegis-kernel/packages/go
```

### Rust Crate
```bash
cargo add aegis-kernel --git https://github.com/Snehgabani/aegis-kernel
```

### Docker Gateway
```bash
docker pull ghcr.io/snehgabani/aegis-gateway:latest
docker run -p 8080:8080 ghcr.io/snehgabani/aegis-gateway:latest
```

---

## 2. Starting the Software

### Quick Start: In-Process Node.js Engine
```typescript
import { AegisEngine } from '@aegis-kernel/core';

// Initialize the deterministic invariant engine
const engine = new AegisEngine({
  mode: 'enforce', // 'enforce' (block violations) or 'audit' (log only)
  packs: ['@aegis/sql-guard', '@aegis/data-guard', '@aegis/safety-guard']
});

// Evaluate a proposed tool call before executing it
const result = engine.evaluate({
  tool: 'database_query',
  params: {
    query: 'SELECT id, email FROM users WHERE id = 123'
  }
});

if (result.verdict === 'BLOCKED') {
  console.error('Tool call rejected by invariant guard:', result.violations);
} else {
  console.log('Tool call allowed, proceeding with execution.');
}
```

### Quick Start: Python Guard Decorator
```python
from aegis_kernel import aegis_guard

@aegis_guard(tool_name="database_exec")
def execute_sql(query: str):
    # This function is deterministically protected before execution
    return db.execute(query)

# Safe queries pass cleanly
execute_sql("SELECT * FROM products WHERE price < 100")

# Malicious or unbounded queries raise InvariantViolationError immediately
try:
    execute_sql("DELETE FROM products WHERE 1=1")
except Exception as e:
    print(f"Blocked by Aegis: {e}")
```

### Quick Start: Model Context Protocol (MCP) Middleware
```typescript
import { AegisMCPMiddleware } from '@aegis-kernel/mcp';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';

const middleware = new AegisMCPMiddleware({
  mode: 'enforce',
  packs: ['@aegis/sql-guard', '@aegis/data-guard']
});

// Wrap tool handler with deterministic clearance
const safeHandler = middleware.wrapToolHandler('execute_query', async (args) => {
  return await db.query(args.query);
});
```

---

## 3. Usage Tutorials with Concrete Examples

### Tutorial 1: Defending Against Destructive SQL Injections
Autonomous agents often fall prey to prompt injection where untrusted external data (such as emails or support tickets) causes the LLM to output unbounded mutations:

```typescript
import { AegisEngine } from '@aegis-kernel/core';

const engine = new AegisEngine();

// Attack: Tautological deletion hiding behind comment evasion
const adversarialPayload = {
  tool: 'execute_sql',
  params: {
    query: "DEL/**/ETE FROM accounts WHERE 'a'='a'"
  }
};

const decision = engine.evaluate(adversarialPayload);
console.log(decision.verdict); // 'BLOCKED'
console.log(decision.violations[0].message);
// "Destructive SQL operation (DELETE) contains a constant tautology in WHERE predicate ('a'='a')."
```

### Tutorial 2: Enforcing Strict Financial Spend Ceilings
Prevent agents from executing out-of-bounds wire transfers or disbursements:

```typescript
import { AegisEngine } from '@aegis-kernel/core';

const engine = new AegisEngine({
  customRules: [
    {
      id: 'finance-ceiling',
      tool: 'send_payment',
      condition: {
        field: 'amount',
        max: 5000.00,
        type: 'number'
      },
      action: 'BLOCK',
      message: 'Transaction exceeds authorized single-payment disbursement ceiling ($5,000.00).'
    }
  ]
});

// An agent attempting to transfer $7,500 is blocked deterministically
const outcome = engine.evaluate({
  tool: 'send_payment',
  params: { recipient: 'supplier_123', amount: 7500.00 }
});
console.log(outcome.verdict); // 'BLOCKED'
```

### Tutorial 3: In-Flight PII Redaction with Salted Token Vaults
Sanitize sensitive medical or financial records before sending them to external LLMs:

```typescript
import { PiiTokenVault } from '@aegis-kernel/core';

const vault = new PiiTokenVault();

// Mask patient SSN and Credit Card
const raw = "Patient John Doe (SSN: 000-12-3456, Card: 4111-2222-3333-4444) requested records.";
const { sanitized } = vault.tokenize(raw);
console.log(sanitized);
// "Patient John Doe (SSN: <SSN_a1b2c3d4>, Card: <CARD_e5f6g7h8>) requested records."

// Restore after LLM response
const restored = vault.detokenize(sanitized);
console.log(restored === raw); // true
```

---

## 4. Next Steps

- Consult the [API Reference](./API_REFERENCE.md) for full method signatures and type interfaces.
- Read the [Security User Guide](./SECURITY_USER_GUIDE.md) for security best practices, configuration guidelines, and operational dos and don'ts.
- Explore the [Supply Chain Trust & Provenance Guide](./security/SUPPLY_CHAIN_TRUST_AND_PROVENANCE.md) to cryptographically verify release artifacts.
