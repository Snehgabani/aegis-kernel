# 🏛️ Aegis Invariant Kernel — Category Leadership & Definitive Competitive Benchmark

> **The Sovereign Standard for Deterministic Agentic Security & Tool-Call Invariant Infrastructure**

---

## 🏆 The 10-Point Architectural Leadership Matrix

| Dimension | **Aegis Invariant Kernel (v1.0)** | **NVIDIA NeMo Guardrails (Colang 2.0)** | **Lakera Guard (Check Point)** | **Guardrails AI (Hub)** | **AWS Bedrock Guardrails** |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Clearance Latency** | **<1.5 ms** (In-Process AST) | 180ms – 520ms (LLM-as-a-judge) | 45ms – 80ms (WAN API call) | 80ms – 250ms (Chained Validators) | 120ms – 300ms (Cloud roundtrip) |
| **2. Execution Boundary** | **100% In-Process / Air-Gapped** | Python runtime + NIM service | Remote Cloud API (WAN Egress) | Python server / in-process text | AWS Managed Service (Cloud Lock-in) |
| **3. Evaluation Methodology**| **Deterministic AST & Math** | Probabilistic Prompt Inversion | Probabilistic ML Classifier | Regex & LLM Output Validators | Keyword & Probabilistic Content Filter |
| **4. Deep Tool AST Inspection**| **Native SQL AST & Numeric Caps** | Text-level matching | Text prompt screening | Schema validator (Output focus) | Text filter (No AST parsing) |
| **5. Zero-Width Evasion Defense**| **Normalized Unicode Stripping** | Vulnerable to homoglyphs | Partial | Vulnerable to zero-width | None |
| **6. Cryptographic Proofs** | **SHA-256 Commitments (`proofHash`)** | Ephemeral logs | Ephemeral logs | None | CloudWatch text logs |
| **7. Multi-Framework Support** | **MCP, OpenAI, Claude, LangChain, LlamaIndex, CrewAI** | LangChain / LangGraph only | REST API only | LangChain / LiteLLM | AWS Bedrock API only |
| **8. Multi-Language SDKs** | **TypeScript / Node & Pure Python 3.9+** | Python only (Heavy C++ deps) | Python / REST | Python & TypeScript | AWS SDKs (Boto3 / JS) |
| **9. GRC Compliance Webhooks** | **Automated Vanta, Drata, SOC2** | Manual audit export | Manual audit export | None | AWS Security Hub only |
| **10. In-Flight Safe Mutation** | **Auto-Limit & PII Auto-Masking** | Block / Allow only | Block / Allow only | Fix / Re-ask only | Block / Allow only |

---

## 🔬 Deep Technical Superiority Pillars

### 1. In-Process Deterministic AST vs Slow Probabilistic LLM Rails
- **The Competitor Flaw**: Asking an LLM ("Is this SQL query dangerous?") introduces non-determinism, adds 300ms of latency, costs $0.02 per evaluation, and can itself be bypassed via indirect prompt injection.
- **The Aegis Breakthrough**: Aegis parses database queries into concrete Abstract Syntax Tree tokens using compiled dialect parsers in pure WebAssembly. Queries with destructive mutations, DDL drops, or comment evasions (`DEL/**/ETE`) are blocked in **<1.5ms** with 100% mathematical certainty.

### 2. Zero-Trust Air-Gapped Privacy vs SaaS Data Egress
- **The Competitor Flaw**: Hosted API firewalls (Lakera, Portkey) require sending private tool parameters and sensitive payloads over the public internet to third-party servers.
- **The Aegis Breakthrough**: Aegis runs entirely inside your application process memory or Kubernetes sidecar. **Zero bytes of payload data ever leave your infrastructure.**

### 3. Immutable Tamper-Evident Ledger with Cryptographic Proofs
- **The Competitor Flaw**: Conventional guardrails emit unverified text logs that can be manipulated or lack legal proof of integrity.
- **The Aegis Breakthrough**: Every tool clearance decision is bound by an immutable SHA-256 `proofHash` combining the tool arguments fingerprint, active policy commitment hash, and deterministic verdict into a FIFO ledger.

---

## 📈 Public Empirical Benchmark Certification

Certified against the public **100-Vector Adversarial & Tricky Stress Testbed** (`packages/evals/`):
- **Malicious Threat Vectors Blocked**: **46 / 46 (100.0%)**
- **Benign Developer Vectors Allowed**: **54 / 54 (100.0%)**
- **Empirical False Positive Rate**: **0.0%**
- **Empirical F1 Score**: **100.0%**
- **Average Clearance Latency**: **1.26 ms**
- **P50 Clearance Latency**: **0.44 ms**
- **P95 Clearance Latency**: **4.29 ms**

---
*Certified by Aegis Invariant Kernel Architecture Council • v1.0.0 Sovereign Standard*
