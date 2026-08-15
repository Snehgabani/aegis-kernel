# Security Advisory: AEGIS-ADV-2024-003
## Cross-Tenant Account Scope Tampering via Indirect Injection in MCP Tools

- **Severity**: **CRITICAL**
- **Vulnerability Standard**: `CWE-639 / OWASP-LLM02`
- **Affected Frameworks**: `MCP Server Ecosystem`, `LangGraph Multi-Tenant`
- **Aegis Mitigation Pack**: `@aegis/soc2-guard`
- **Enforced Invariant Rule**: `SOC2-004 (Multi-Tenant Parameter vs Session State Isolation)`
- **Mitigation Latency**: **0.09 ms**

---

### 1. Threat Overview & Root Cause
In multi-tenant SaaS environments, rogue sub-agents can be tricked by untrusted web browsing context to pass foreign tenant IDs into tool arguments, exfiltrating rival tenant confidential data.

---

### 2. Exploit Vector Example
```json
tool: export_customer_data, params: { tenantId: "tenant_target_corp" }
```

---

### 3. Aegis Mathematical Invariant Defense
Aegis intercepts this payload in-process before network or database dispatch:
1. Normalizes unicode characters and AST syntax trees in pure WebAssembly.
2. Evaluates state bounds, regex signatures, and schema constraints in <0.09 ms.
3. Returns a deterministic rejection with self-healing feedback to the calling model.

```bash
# Test this vector with Aegis CLI
npx aegis test
npx aegis benchmark --tricky
```
