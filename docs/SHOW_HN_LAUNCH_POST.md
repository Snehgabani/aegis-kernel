# Show HN / Product Hunt Launch Manifesto

**Title**: Show HN: Aegis Invariant Kernel – Deterministic Tool-Call Safety for AI Agents in <1.5ms

**Link**: `https://github.com/Snehgabani/aegis-kernel`  
**Live Studio Demo**: `https://github.com/Snehgabani/aegis-kernel/blob/main/site/playground.html`

---

## 🎯 The Pitch

Hi HN! I built **Aegis Invariant Kernel** ([GitHub](https://github.com/Snehgabani/aegis-kernel)) — an open-source, in-process deterministic clearance kernel that protects production databases, financial APIs, and systems from rogue AI agent actions in **sub-1.5ms** with zero network egress.

### The Problem with Existing AI Guardrails

Most existing AI guardrails (Guardrails AI, NeMo, Lakera) use **probabilistic LLM-as-a-Judge classifiers** or cloud APIs. In practice, this causes three fatal production issues:

1. **Massive Latency Tax**: Calling an LLM or cloud API to verify a tool call adds 200–800ms to every agent step.
2. **Jailbreak Vulnerability**: An LLM judge can be manipulated by indirect prompt injections inside tool arguments (e.g. `DEL/**/ETE FROM users WHERE 1=1` or zero-width unicode obfuscations).
3. **Data Exfiltration & Privacy**: Sending internal tool arguments to third-party cloud APIs violates strict HIPAA, PCI-DSS, and SOC 2 data boundary controls.

### How Aegis Solves This Deterministically

Aegis takes a **zero-trust, deterministic compiler approach**:

```mermaid
flowchart TD
    subgraph INGRESS["1. Ingress & Framework Adapters"]
        direction LR
        I1["LangChain / CrewAI / AutoGen"]
        I2["OpenAI Tool Calling / Swarm"]
        I3["Anthropic Claude Tool Use"]
        I4["Model Context Protocol (JSON-RPC 2.0)"]
    end

    INGRESS -->|Raw ToolCall: tool, params, token| TIER1

    subgraph TIER1["Tier 1: Lexical Normalization & Fast-Path Intercept (<0.03ms)"]
        direction TB
        T1_1["Aho-Corasick Streaming Interceptor<br/><i>(Sliding window token secret scanner)</i>"]
        T1_2["Unicode NFKD Sanitizer<br/><i>(Homoglyph & zero-width character stripper)</i>"]
        T1_3["Zero-Egress Prompt Injection Classifier<br/><i>(Local linguistic instruction override analyzer)</i>"]
        
        T1_1 --> T1_2 --> T1_3
    end

    TIER1 -->|Sanitized Tool Payload| TIER2

    subgraph TIER2["Tier 2: Structural AST Compilers & Semantic Validation (<0.15ms)"]
        direction LR
        
        subgraph T2_SQL["SQL AST Engine"]
            S1["Multi-Dialect Parser<br/>(Postgres, MySQL, SQLite, T-SQL)"]
            S2["AST Visitor Guard<br/>(Tautological WHERE 1=1, Mutating CTEs)"]
            S1 --> S2
        end

        subgraph T2_NUM["Numeric Engine"]
            N1["Safe BigInt / Currency Normalizer"]
            N2["Finite Range & Velocity Clamping"]
            N1 --> N2
        end

        subgraph T2_PII["PII Token Vault"]
            P1["16-Byte Salt Anonymizer"]
            P2["Deterministic Reversible Mapping"]
            P1 --> P2
        end

        subgraph T2_POL["Policy & Plugins"]
            R1["Cedar / Rego Policy AST Engine"]
            R2["WASM Sandbox Validator Runner"]
            R1 --> R2
        end
    end

    TIER2 -->|Validated AST & Masked Values| TIER3

    subgraph TIER3["Tier 3: Temporal, Behavioral & Cryptographic Topology (<0.06ms)"]
        direction LR

        subgraph T3_AUTH["Identity & Tokens"]
            A1["Agent Identity & RBAC Policy Manager"]
            A2["Ed25519 Biscuit Monotonic Attenuation"]
            A1 --> A2
        end

        subgraph T3_GRAPH["Behavioral Graphs"]
            G1["Causal Execution DAG<br/><i>(Multi-step exfiltration detector)</i>"]
            G2["Crescendo Conversation Tracker<br/><i>(Exponential decay drift tracker)</i>"]
            G1 --> G2
        end

        subgraph T3_CTRL["Swarm Controls"]
            C1["Swarm Delegation Router<br/><i>(Global budget ceilings)</i>"]
            C2["Multi-Strike Circuit Breaker<br/><i>(Quarantine state machine)</i>"]
            C1 --> C2
        end
    end

    TIER3 -->|Aggregate Verification State| TIER4

    subgraph TIER4["Tier 4: Cryptographic Commitments, Explainability & GRC (<0.02ms)"]
        direction TB
        
        subgraph T4_CRYPTO["Cryptographic Integrity"]
            CR1["SHA-256 ProofHash Commitment Generator"]
            CR2["Append-Only Merkle Audit Ledger<br/><i>(Chained previousRootHash for SOC2/HIPAA)</i>"]
            CR1 --> CR2
        end

        subgraph T4_DECISION["Decision & Explainability Hub"]
            DEC{"Clearance<br/>Decision Matrix"}
            EX1["EU AI Act Art. 13 Plain-English Explainer"]
            EX2["Self-Healing AST Re-Ask Fix Generator"]
            DEC --> EX1
            DEC --> EX2
        end

        T4_CRYPTO --> T4_DECISION
    end

    DEC -->|Verdict: ALLOWED| OUT_ALLOW[("🎯 Production DB / APIs / Tool Execution<br/><i>+ SHA-256 Cryptographic Proof Receipt</i>")]
    DEC -->|Verdict: REASK / BLOCKED| OUT_BLOCK["💥 LLM Self-Healing Feedback Fix<br/><i>+ Auto-Correction Prompt & SIEM / STIX Alert</i>"]
```

1. **Multi-Dialect AST Invariants**: Compiles SQL arguments into Abstract Syntax Trees across PostgreSQL, MySQL, SQLite, and TransactSQL. Detects tautological `WHERE 1=1` constant folds, recursive mutating CTEs (`WITH deleted AS (DELETE ...)`), and comment-splitting evasion attacks (`DEL/**/ETE`).
2. **Numeric Risk Boundaries**: Enforces strict financial ceilings and velocity limits, normalizing formatted currencies (`$12,500.00`) and safely parsing `BigInt` values while explicitly rejecting `NaN` and `Infinity`.
3. **Enterprise PII & Secrets Detection**: High-throughput regex & NFKD normalization detecting JWTs, GCP Service Account keys, database URIs with passwords, IBANs, and credit cards in tool arguments and return payloads.
4. **Self-Healing LLM Feedback**: When an invariant is violated, Aegis returns a structured auto-fix suggestion (`Avoid using 'DROP'. Use targeted updates instead.`) so the agent automatically self-corrects on the next turn without failing the user session.
5. **Universal Framework Support**:
   - **TypeScript / Node.js**: `@aegis-kernel/core`, `@aegis-kernel/mcp`, `@aegis-kernel/openai`, `@aegis-kernel/anthropic`, `@aegis-kernel/langchain`.
   - **Python 3.9+**: Pure Python `aegis-kernel` package with `@aegis_guard` decorator (zero external dependencies).

---

## ⚡ Quick 5-Second Demo

```bash
# Clone & run interactive demo
git clone https://github.com/Snehgabani/aegis-kernel.git
cd aegis-kernel
npm install
./scripts/demo.sh
```

Or test in Python:
```python
from aegis_kernel import aegis_guard

@aegis_guard(tool_name="database_exec")
def execute_sql(query: str):
    # Automatically blocked if query contains mass DELETE without WHERE or DROP TABLE
    return db.execute(query)
```

---

## 📊 Empirical Benchmarks (10,000 Evaluations)

- **Throughput**: 2,861 evaluations/second (single core)
- **Median Latency (P50)**: 0.318 ms
- **95th Percentile Latency (P95)**: 0.498 ms
- **Empirical F1 Score**: 100.0% across 100 tricky adversarial vectors (10 threat domains).

All code is open-source under the MIT License on [GitHub](https://github.com/Snehgabani/aegis-kernel). We’d love to hear your feedback, bug reports, or edge-case attacks!
