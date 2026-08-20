# Aegis Invariant Kernel — Public API Reference

Comprehensive reference documentation detailing the public interfaces (inputs, outputs, methods, REST endpoints, and CLI options) across all Aegis packages.

---

## 1. Core TypeScript Library (`@aegis-kernel/core`)

### Class: `AegisEngine`
The primary in-process deterministic invariant clearance engine.

#### Constructor: `new AegisEngine(options?: AegisOptions)`
**Input Options (`AegisOptions`)**:
| Property | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `mode` | `'enforce' \| 'audit'` | `'enforce'` | Execution mode. In `enforce`, invariant violations return `verdict: 'BLOCKED'`. In `audit`, violations are recorded but tool calls pass. |
| `packs` | `string[]` | `['@aegis/sql-guard', '@aegis/data-guard']` | Array of rule pack identifiers to load. |
| `customRules` | `CustomRule[]` | `[]` | Array of user-defined invariant rules. |
| `failPolicy` | `'fail-closed' \| 'fail-open'` | `'fail-closed'` | Policy when internal parsing errors occur. |
| `enablePiiVault` | `boolean` | `true` | Enable automated PII masking and session tokenization. |
| `logEvents` | `boolean` | `true` | Log evaluation events to `.aegis/events.jsonl`. |

#### Method: `evaluate(toolCall: ToolCall): AegisResult`
Evaluates a proposed tool call against all active invariants.

**Input (`ToolCall`)**:
```typescript
interface ToolCall {
  tool: string;                      // Name of the proposed tool (e.g., 'execute_sql', 'send_payment')
  params: Record<string, unknown>;   // Tool arguments/parameters
  context?: {
    userId?: string;
    sessionId?: string;
    agentId?: string;
    riskScore?: number;
  };
}
```

**Output (`AegisResult`)**:
```typescript
interface AegisResult {
  verdict: 'ALLOWED' | 'BLOCKED' | 'QUARANTINE'; // Deterministic decision
  violations: AegisViolation[];                  // Array of invariant breaches detected
  proofHash: string;                             // SHA-256 HMAC cryptographic commitment
  latencyMs: number;                             // In-process evaluation time in milliseconds
  sanitizedParams?: Record<string, unknown>;     // Parameters with PII tokens if vault enabled
}

interface AegisViolation {
  ruleId: string;                    // Identifier of the breached rule
  checker: string;                   // Checker component ('SqlChecker', 'NumericChecker', etc.)
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  message: string;                   // Human-readable diagnostic explaining the violation
  suggestedFix?: string;             // Actionable remediation guidance
  remediationDiff?: string;          // AST-level replacement diff if available
}
```

---

### Class: `PiiTokenVault`
Deterministic, salted tokenization and detokenization vault for PII, secrets, and credentials.

#### Constructor: `new PiiTokenVault(config?: PiiTokenVaultConfig)`
- `config.tokenPrefix` (*optional string*): Custom token prefix (e.g. `'PII_'`).
- `config.hashLength` (*optional number*): Token hash length (default: 16 chars).

#### Method: `tokenize(text: string): TokenizeResult`
- **Input**: Raw text string containing potential PII/secrets.
- **Output**: `{ sanitized: string, tokensCreated: number, tokenTypes: Record<string, number> }`.

#### Method: `detokenize(text: string): DetokenizeResult`
- **Input**: Sanitized text string containing tokens (e.g. `<SSN_1a2b3c4d>`).
- **Output**: `{ restored: string, tokensRestored: number }`.

---

### Class: `AegisStreamInterceptor`
Real-time streaming token interceptor for LLM SSE responses.

#### Method: `interceptChunk(chunk: string): StreamChunkVerdict`
- **Input**: In-flight token text chunk from streaming LLM.
- **Output**: `{ emit: boolean, buffer: string, intercepted: boolean, reason?: string }`.

---

## 2. Framework Adapters

### LangChain / CrewAI Adapter (`@aegis-kernel/langchain`)
```typescript
import { AegisLangChainGuard } from '@aegis-kernel/langchain';

const guard = new AegisLangChainGuard({ mode: 'enforce' });
// Wrap any DynamicStructuredTool or LangChain tool
const protectedTool = guard.wrapTool(rawTool);
```

### Model Context Protocol (MCP) Middleware (`@aegis-kernel/mcp`)
```typescript
import { AegisMCPMiddleware } from '@aegis-kernel/mcp';

const middleware = new AegisMCPMiddleware({ mode: 'enforce' });
const safeHandler = middleware.wrapToolHandler('tool_name', originalHandler);
```

---

## 3. Python SDK (`aegis-kernel`)

### Decorator: `@aegis_guard`
```python
from aegis_kernel import aegis_guard

@aegis_guard(
    tool_name="database_exec",      # Logical tool identifier
    mode="enforce",                 # "enforce" or "audit"
    packs=["@aegis/sql-guard"]      # Invariant packs
)
def run_sql(query: str) -> dict:
    return db.query(query)
```

**Exceptions**:
- `InvariantViolationError`: Raised in `enforce` mode when an invariant check fails. Contains `verdict`, `violations`, and `proof_hash`.

---

## 4. Gateway REST API (`services/gateway`)

The Aegis Gateway service exposes high-throughput HTTP endpoints for microservice architectures:

### `POST /v1/evaluate`
Evaluate a proposed tool call over HTTP.

- **Request Headers**: `Content-Type: application/json`, `Authorization: Bearer <API_KEY>`
- **Request Body**:
  ```json
  {
    "tool": "execute_query",
    "params": {
      "query": "SELECT id FROM accounts WHERE active = 1"
    },
    "mode": "enforce"
  }
  ```
- **Response (`200 OK`)**:
  ```json
  {
    "verdict": "ALLOWED",
    "violations": [],
    "proofHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "latencyMs": 0.312
  }
  ```

### `POST /v1/tokenize`
Sanitize text containing PII/secrets.
- **Request Body**: `{"text": "Patient SSN is 000-12-3456"}`
- **Response (`200 OK`)**: `{"sanitized": "Patient SSN is <SSN_a1b2c3d4>", "tokensCreated": 1}`

### `POST /v1/detokenize`
Restore previously tokenized text.
- **Request Body**: `{"text": "Patient SSN is <SSN_a1b2c3d4>"}`
- **Response (`200 OK`)**: `{"restored": "Patient SSN is 000-12-3456", "tokensRestored": 1}`

### `GET /health`
Liveness and readiness health check.
- **Response (`200 OK`)**: `{"status": "healthy", "version": "1.0.1", "uptimeSeconds": 3600}`

---

## 5. Command-Line Interface (`@aegis-kernel/cli`)

### Commands & Options

```bash
# Initialize a new Aegis configuration in the current directory
aegis init [--dir <path>]

# Evaluate a tool call simulation against local configuration
aegis test --tool <tool_name> --params '<json_params>' [--mode <enforce|audit>]

# Shift-left source code and configuration scanner for latent risks
aegis scan [--target <dir>] [--output <json|sarif|table>]

# Academic benchmark evaluation suite
aegis eval <all|injecagent|agentdojo|mcptox> [--output <path>] [--blinded]

# Performance and latency benchmark profiler
aegis benchmark [--tricky] [--iterations <number>]

# Replay historical audit logs against current invariant rules
aegis replay --log-path <path> [--diff-only]

# Manage and validate invariant rule packs
aegis pack <list|validate|inspect> [--pack-id <id>]
```
