# 🛡️ Aegis Invariant Kernel — Telemetry & Collective Threat Intelligence Policy

**Last Updated:** August 2026  
**Status:** GDPR Compliant · EU AI Act Art. 13 Compliant · Zero-PII Egress Guaranteed

---

## 🌟 Why Aegis Collects Diagnostic Telemetry

Aegis Invariant Kernel collects **strictly anonymous, aggregate operational telemetry and crash error signatures** to:
1. **Detect New Prompt Injections & AST Evasion Tactics**: Identify novel SQL comment-splitting, tautology mutations, and tool poisoning attempts.
2. **Prevent Latency Regressions**: Ensure sub-0.25ms P50 tool-clearance latency across all operating systems and hardware architectures.
3. **Continuous Parser Hardening**: Automatically triage AST parser edge-cases and unhandled dialect exceptions.

---

## 🔒 The Zero-PII Invariant (What We NEVER Collect)

In adherence to zero-trust principles and GDPR Recital 26, Aegis enforces an architectural **Data Egress Barrier**:

* ❌ **NO Personal Identifiable Information (PII)**: No usernames, IP addresses, emails, SSNs, or customer records.
* ❌ **NO Tool Arguments or Payloads**: No raw database queries, SQL strings, code files, or API parameters.
* ❌ **NO API Keys or Secrets**: All credentials in `~/.config/aegis/secrets.env` are locked under Unix permissions `600` and never sent anywhere.
* ❌ **NO Conversational Context**: No system prompts, user chat messages, or model completions.

---

## 📊 What We Collect (Anonymous Operational Metrics)

```
┌────────────────────────────────────────────────────────────────────────┐
│                   ANONYMOUS TELEMETRY PACKET SCHEMA                    │
├──────────────────────────┬─────────────────────────────────────────────┤
│ Metric Category          │ Data Example                                │
├──────────────────────────┼─────────────────────────────────────────────┤
│ Evaluation Counters      │ `totalEvaluations: 1420`, `blocked: 12`     │
├──────────────────────────┼─────────────────────────────────────────────┤
│ Latency Percentiles      │ `p50Ms: 0.18`, `p95Ms: 0.85`, `p99Ms: 2.10` │
├──────────────────────────┼─────────────────────────────────────────────┤
│ Triggered Rule IDs       │ `@aegis/sql-guard:SQL-01` (Rule ID only)    │
├──────────────────────────┼─────────────────────────────────────────────┤
│ Crash Fingerprints       │ `SqlChecker:SyntaxError:a8f9c1b3` (Hash)    │
├──────────────────────────┼─────────────────────────────────────────────┤
│ Environment Metadata     │ `platform: darwin`, `node: v22.23.2`        │
└──────────────────────────┴─────────────────────────────────────────────┘
```

---

## ⚙️ Full Developer Control & Opt-Out

You maintain 100% control over your telemetry preferences.

### Via Aegis CLI:
```bash
# View current status and live metrics dashboard
aegis stats

# Disable all telemetry collection
aegis telemetry disable

# Re-enable telemetry collection
aegis telemetry enable

# Export local diagnostic packet to JSON for inspection
aegis telemetry export --output ./my-telemetry.json

# Clear local telemetry history
aegis telemetry clear
```

### Via Environment Variables:
```bash
# Globally disable telemetry in CI/CD or production containers:
export AEGIS_TELEMETRY_DISABLED=1
# or standard cross-industry flag:
export DO_NOT_TRACK=1
```

---

## ⚖️ Legal & Regulatory Compliance

* **GDPR (Regulation (EU) 2016/679)**: Information collected is truly anonymous aggregate data per Recital 26 and does not constitute personal data.
* **EU AI Act (Article 13)**: Operational statistics support transparent risk management and algorithmic accountability.
* **California Consumer Privacy Act (CCPA / CPRA)**: Aegis does not sell, share, or monetize any user or device data.
