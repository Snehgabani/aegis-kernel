# 🛡️ Aegis Invariant Kernel — OWASP Agentic Top 10 (ASI 2026), OWASP LLM Top 10 (2025) & MITRE ATLAS Cross-Walk

A comprehensive compliance and threat mitigation cross-walk mapping the **OWASP Top 10 for Agentic Applications (ASI01–ASI10, announced Dec 2025)**, the **OWASP Top 10 for LLM Applications (2025)**, and **MITRE ATLAS (Adversarial Threat Landscape for AI Systems)** matrices to Aegis Invariant Kernel enforcement checkers.

---

## 🤖 OWASP Agentic AI Top 10 (ASI 2026) — primary cross-walk

The agentic taxonomy is where Aegis's tool-boundary enforcement maps most
directly: eight of ten categories are partially or fully mitigated by
deterministic invariants at the tool-call boundary. Coverage labels are honest —
Aegis is one control, not a complete agent-security program (supply-chain
vetting, sandboxing, and inter-agent transport security remain your stack's job).

| OWASP ASI 2026 | Adversarial Threat Vector | Aegis Control | Coverage |
| :--- | :--- | :--- | :--- |
| **ASI01 Agent Goal Hijack** | Attacker content redirects the agent's objective (the new indirect prompt injection) | Hijacked objectives must still execute *through tools* → SQL/PII/numeric invariants + RBAC block the damaging action even when the model is captured | ◐ Structural (blocks the harmful action, not the capture) |
| **ASI02 Tool Misuse & Exploitation** | Agent uses a legitimate, authorized tool unsafely (read tool to exfiltrate, write tool to destroy) | **Core thesis**: deterministic parameter/AST/state invariants on every tool call; per-tool capability scoping | ✅ Primary |
| **ASI03 Identity & Privilege Abuse** | Over-granted or stolen agent identities escalate | `AgentIdentityManager` per-caller RBAC, Ed25519 biscuit capability attenuation, amount-capped capabilities | ✅ Primary |
| **ASI04 Agentic Supply Chain** | Poisoned MCP servers, plugins, tool descriptions | `MCPToolPoisoningScanner` (tool-description injection detection), runtime schema pinning (`@aegis/mcp`), signed rulepacks | ◐ Detection + pinning (manifest signing: roadmap) |
| **ASI05 Unexpected Code Execution** | Agent-generated code executes outside a safe boundary | Aegis gates the *tool that executes* (deny-by-default SQL AST whitelist); sandboxing the runtime itself is out of scope | ◐ Boundary gate only |
| **ASI06 Memory & Context Poisoning** | Persistent corruption reshapes later decisions | Causal execution DAG + crescendo drift tracking flag anomalous sequences; SHA-256 state commitments detect tampering | ◐ Detection |
| **ASI07 Insecure Inter-Agent Communication** | Spoofed agent-to-agent messages | Out of Aegis scope (transport mTLS/signing); Aegis verifies the *tool consequence* of any message | ✗ Out of scope |
| **ASI08 Cascading Failures** | One compromised agent propagates through pipelines | Rate limits/velocity caps (`NumericChecker`), fail-closed policies, deterministic HALT stops chains at the first violating tool call | ◐ Blast-radius limiting |
| **ASI09 Human-Agent Trust Exploitation** | Operator deceived into approving harmful actions | Verdict explainability (`violations[]`, `suggestedFix`) gives approvers ground truth; HITL gates add friction on irreversible actions | ◐ Evidence + friction |
| **ASI10 Rogue Agents** | Agent acts outside its mandate deceptively | Policy commitment hashes + tamper-evident ledger prove what policy ran; drift detection surfaces mandate violations; kill-switch HALT | ◐ Detection + halt |

---

## 🗺️ OWASP LLM Top 10 (2025) & MITRE ATLAS Cross-Walk Matrix

| OWASP 2026 Category | MITRE ATLAS Technique ID | Adversarial Threat Vector | Aegis Invariant Checker & Pack | Enforcement Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **LLM01: Prompt Injection & Jailbreak** | `AML.T0051` / `AML.T0054` | Indirect prompt injection hijacking tool arguments into destructive database queries or payouts | **`SqlChecker`**<br>**`@aegis/sql-guard`** | AST statement type whitelist, block-comment evasion detection, tautology stripping |
| **LLM02: Sensitive Information Disclosure** | `AML.T0048` / `AML.T0053` | Exfiltration of API tokens, OpenAI keys, AWS secret tokens, SSNs, credit cards via tool arguments | **`PiiChecker`**<br>**`@aegis/data-guard`** | Zero-width unicode normalization (`\u200B`, `\uFEFF`), entropy scanning, token redaction |
| **LLM06: Excessive Agency & Tool Abuse** | `AML.T0056` | Autonomous agent making unauthorized multi-thousand dollar payouts or rogue API calls | **`NumericChecker`**<br>**`@aegis/finance-guard`** | Hard mathematical currency caps, scientific notation parsing (`1e6`), sliding-window velocity caps |
| **LLM07: System Prompt & Cross-Tenant Leakage** | `AML.T0057` | Agent bypassing tenant boundaries or accessing unauthorized customer records across partitions | **`StateChecker`**<br>**`@aegis/soc2-guard`** | Session tenant hash verification (`state.tenantId == params.tenantId`), strict boundary lock |
| **LLM08: Vector & State Memory Tampering** | `AML.T0058` | Malicious manipulation of agent context state or corrupting long-term memory | **`Ledger`**<br>**`AegisEngine`** | Cryptographic SHA-256 state commitment (`proofHash`), tamper-evident FIFO ledger |
| **LLM10: Unbounded Consumption & DoS** | `AML.T0029` | Computational exhaustion through millions of recursive tool calls or CPU-heavy payload queries | **`SqlChecker`**<br>**`CustomChecker`** | Enforces mandatory `LIMIT` clause on all `SELECT` queries; payload depth recursion limits |

---

## 🏛️ Verification & Audit Command

Enterprise security teams can verify active cross-walk protections directly in the terminal:

```bash
# Display live threat coverage across all 8 active packs
npx aegis matrix
```
