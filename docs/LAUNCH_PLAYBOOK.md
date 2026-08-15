# Aegis Invariant Kernel: Go-to-Market & Launch Playbook

---

## 1. Hacker News: Show HN Post

### Title:
> **Show HN: Aegis – Sub-2ms Deterministic Safety Clearance Gateway for AI Agents**

### Post Body:
```markdown
Hi HN, I’m building Aegis (https://github.com/aegis-kernel/aegis), an open-source, deterministic safety clearance gateway for AI agent tool calls.

### The Problem
Most AI agent guardrails (NeMo, Lakera, Guardrails AI) rely on LLM-as-a-judge classifiers or semantic embeddings to decide whether an action is safe. In production, this introduces two fatal flaws:
1. **Unacceptable Latency:** Adding 50ms–300ms on every single tool invocation destroys real-time agent loops.
2. **Probabilistic Non-Determinism:** A classifier might block `DROP TABLE users` 98% of the time, but the 2% failure rate wipes out production databases.

### How Aegis Works (<2ms Deterministic Invariants)
Aegis sits directly in-process on the tool execution hot path. Before any tool executes (database queries, financial transfers, filesystem access, API calls), Aegis evaluates deterministic AST invariants:
- **SQL AST Analysis:** Parses queries into ASTs using constant-folding to block destructive DDL (`DROP`, `TRUNCATE`), unconstrained `DELETE`/`UPDATE` operations, and tautological bypasses (`WHERE 1=1`, `WHERE id=id`).
- **PII & Secret Scanning:** In-flight regex scanning for API keys, bearer tokens, AWS credentials, SSNs, and cardholder data.
- **Numeric & Rate Limits:** Strict boundaries and sliding-window rate ceilings.
- **Zero-Eval Declarative DSL:** An arithmetic/logical AST expression evaluator with zero `eval()`, zero `new Function()`, and zero code execution surface.
- **Pre-Execution State Projection:** Pre-condition and post-condition assertions evaluated against authenticated host state before dispatch.

### Architecture & Framework Adapters
Aegis provides drop-in zero-latency wrappers for:
- **TypeScript:** `@aegis-kernel/mcp`, `@aegis-kernel/langchain`, `@aegis-kernel/openai`, `@aegis-kernel/anthropic`
- **Python:** `from aegis_kernel import aegis_guard` (zero dependencies, pure Python 3.9+)
- **Developer CLI:** `npx aegis test` and `npx aegis report`

### Benchmark Latency & Accuracy
- P50 Hot Path Latency: **1.14 ms**
- Worst-Case Multi-AST Latency (P99): **6.47 ms**
- False-Positive Override Ratio: **0.0% on clean regression suites**
- Memory Footprint: **< 15 MB in-process**

### Quickstart
```bash
npx aegis init
npx aegis test
```

Interactive live playground & auditor dashboard: https://aegis-kernel.dev/dashboard/
GitHub Repo (MIT License): https://github.com/aegis-kernel/aegis

Would love your brutal feedback on our AST constant folding and zero-eval expression DSL!
```

---

## 2. Reddit Developer Thread (r/LocalLLaMA & r/LangChain)

### Title:
> **Stop using LLMs to guard LLM tool calls. Here is a sub-2ms deterministic AST invariant gateway for agent tool execution (MIT)**

### Post Text:
```markdown
Hey everyone! One huge bottleneck we noticed building autonomous agents is how slow and unreliable probabilistic guardrails are. Calling a secondary LLM classifier or embedding model every time an agent wants to run a tool adds hundreds of milliseconds of latency and still occasionally leaks dangerous commands.

We built **Aegis** as an open-source, in-process deterministic clearance kernel. 

Instead of asking an LLM "is this SQL query safe?", Aegis parses the AST into a syntax tree, evaluates constant expressions (detecting `OR 1=1` or `WHERE id=id` tautologies), and enforces strict mathematical invariants in **1.14ms**.

Drop-in Python decorator:
```python
from aegis_kernel import aegis_guard

@aegis_guard(tool_name="stripe_payout")
def send_payout(amount: float, recipient: str):
    return stripe.Transfer.create(amount=int(amount * 100), destination=recipient)
```

TypeScript LangChain wrapper:
```typescript
import { AegisLangChainGuard } from '@aegis-kernel/langchain';
const guard = new AegisLangChainGuard({ mode: 'enforce' });
const safeTools = guard.wrapAll([dbTool, payoutTool, cliTool]);
```

- Zero `eval()` or `new Function()` execution.
- Includes pre-built packs for SQL, Finance, HIPAA, PCI-DSS, and SOC 2.
- 100% open source under MIT.

Check it out: https://github.com/aegis-kernel/aegis
Feedback and PRs welcome!
```

---

## 3. 60-Second Video Demo Script

1. **[00:00 - 00:10] The Problem:** Screen recording of an autonomous agent receiving an injected prompt and generating `DELETE FROM users WHERE 1=1`.
2. **[00:10 - 00:25] The Interception:** Aegis CLI runs. Red highlight appears: `🛑 BLOCKED in 1.14ms (SQL-001)`.
3. **[00:25 - 00:40] Self-Healing:** The Claude/OpenAI agent receives the structured `suggestedFix` block and automatically fixes its query to `DELETE FROM users WHERE id = 123`.
4. **[00:40 - 00:50] Clearance & Proof:** Aegis clears the action with green pill: `✅ ALLOWED`, emitting SHA-256 ProofHash.
5. **[00:50 - 01:00] Dashboard Export:** Click over to the Auditor Dashboard at `site/dashboard/` and click "Export Auditor CSV" to download SOC 2 proof.
