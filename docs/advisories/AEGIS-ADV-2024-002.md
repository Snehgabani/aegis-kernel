# Security Advisory: AEGIS-ADV-2024-002
## Zero-Width Unicode Homoglyph Credential Exfiltration in Agent Webhooks

- **Severity**: **HIGH**
- **Vulnerability Standard**: `CWE-200 / OWASP-LLM06`
- **Affected Frameworks**: `Model Context Protocol (MCP)`, `OpenAI Assistants API`, `Anthropic Claude`
- **Aegis Mitigation Pack**: `@aegis/data-guard`
- **Enforced Invariant Rule**: `DATA-001 / DATA-002 (NFKD Unicode Normalization Scanner)`
- **Mitigation Latency**: **0.18 ms**

---

### 1. Threat Overview & Root Cause
Attackers embed zero-width space characters (\u200B, \u200C, \uFEFF) within OpenAI API keys or Credit Card numbers. Regex pattern matchers fail to match token prefixes while remote HTTP servers normalize and consume the credentials.

---

### 2. Exploit Vector Example
```json
tool: post_webhook, body: "sk-proj-\u200B1234567890..."
```

---

### 3. Aegis Mathematical Invariant Defense
Aegis intercepts this payload in-process before network or database dispatch:
1. Normalizes unicode characters and AST syntax trees in pure WebAssembly.
2. Evaluates state bounds, regex signatures, and schema constraints in <0.18 ms.
3. Returns a deterministic rejection with self-healing feedback to the calling model.

```bash
# Test this vector with Aegis CLI
npx aegis test
npx aegis benchmark --tricky
```
