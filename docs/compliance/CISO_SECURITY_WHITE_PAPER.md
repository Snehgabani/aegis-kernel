# Aegis Invariant Kernel: Enterprise Security Architecture & Compliance White Paper

**Target Audience:** Chief Information Security Officers (CISOs), Security Architects, and Compliance Officers.

---

## 1. Executive Summary

Autonomous AI agents executing tools (SQL queries, API mutations, financial transfers, and file system commands) introduce non-deterministic operational risks. Probabilistic guardrails (LLM-as-a-judge classifiers) fail to provide formal guarantees and add 100ms+ latency.

**Aegis Invariant Kernel** is an in-process, deterministic safety clearance gateway that evaluates AST invariants and mathematical bounds on every tool call in **<2ms** with **0 network egress**, producing SHA-256 cryptographic audit proofs.

---

## 2. Regulatory Compliance Mapping

| Regulatory Standard | Requirement | Aegis Invariant Enforcement Mechanism |
| :--- | :--- | :--- |
| **SOC 2 Type II** | **CC6.1 / CC6.6** (Logical Access & Boundary Protection) | Blocks unauthorized system file traversal (`/etc/shadow`, `~/.ssh`, `.env`) and prevents unconstrained DDL wipes (`DROP`, `TRUNCATE`). |
| **HIPAA Security Rule** | **45 CFR § 164.312(a)(1)** (Technical Safeguards for ePHI) | Enforces strict regex and AST masking on National Provider Identifiers (NPI), Social Security Numbers (SSN), and DEA prescription tokens. |
| **PCI-DSS v4.0** | **Req 3.4 & 6.5** (Cardholder Data Protection & Injection Defense) | Prohibits unmasked Primary Account Numbers (PAN), CVV/CVC codes, and live payment secret keys in agent tool payloads. |
| **ISO/IEC 42001** | **Clause 8.4** (AI System Risk Management & Control Verification) | Generates immutable SHA-256 `proofHash` commitments binding tool arguments, active rule pack hashes, and timestamps for every evaluation. |

---

## 3. Cryptographic Audit Proof Architecture

For every evaluated tool invocation, Aegis computes an immutable proof hash:
$$\text{ProofHash} = \text{SHA256}(\text{ToolName} \mathbin{\Vert} \text{CanonicalJSON}(\text{Params}) \mathbin{\Vert} \text{PolicyCommitmentHash})$$

This cryptographic proof guarantees:
1. **Tamper-Evidence:** The exact tool parameters and rule state cannot be altered retroactively in audit logs.
2. **Deterministic Reproducibility:** Third-party auditors can replay the tool call against the policy hash to verify the clearance decision.
3. **Zero Data Leakage:** Audit logs store the proof hash and redacted fields without exposing sensitive customer payloads.

---

## 4. Zero-Eval Threat Model & Sandboxing

Aegis enforces a strict **Zero Dynamic Code Execution** model:
- **No `eval()`:** Absolute prohibition.
- **No `new Function()`:** Absolute prohibition.
- **No `node:vm`:** Replaced by a custom Recursive Descent AST DSL parser that only supports basic arithmetic, comparison, and boolean logic.

---

## 5. Enterprise Procurement FAQ

* **Q: Does Aegis send our agent prompts or database data to an external SaaS?**  
  * **A:** No. The Aegis kernel runs 100% in-process within your application runtime (Node.js, Python). Zero data leaves your VPC unless you explicitly configure the cloud telemetry exporter.
* **Q: What is the worst-case latency impact on our agents?**  
  * **A:** P50 is 1.14ms. P99 is under 6.5ms for complex multi-statement SQL AST parsing.
* **Q: How are enterprise license keys verified?**  
  * **A:** License keys use offline HMAC-SHA256 / Ed25519 signatures. Verification requires zero network calls during agent runtime.
