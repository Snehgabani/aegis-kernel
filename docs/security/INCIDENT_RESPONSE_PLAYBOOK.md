# Aegis Real-World Security Incident Response & Forensics Playbook

**Target Audience:** Security Operations Center (SOC) Analysts, Incident Response (IR) Engineers, and AI Red Teams.

---

## 🚨 Incident Classification Matrix

| Severity Level | Threat Vector | Automated Invariant Action | Escalation SLA |
| :--- | :--- | :--- | :---: |
| **SEV-1 (Critical)** | Mass `DELETE WHERE 1=1`, `DROP TABLE`, or Credential Exfiltration (`sk-proj-...`, `/etc/shadow`) | **IMMEDIATE DETERMINISTIC HALT** + Cryptographic Proof Hash Logged | < 15 Minutes |
| **SEV-2 (High)** | Financial Ceiling Breach ($10,000+) or Velocity Exceeded (100 req/min) | **BLOCKED** + Self-Healing Feedback to LLM | < 1 Hour |
| **SEV-3 (Medium)** | Schema Contract Drift or Unmapped Tool Property | **BLOCKED (Fail-Closed)** or Logged (Fail-Open) | Next Business Day |

---

## 🔍 Forensic Replay & Proof Verification

When a SEV-1 blocked event occurs:

1. **Extract Proof Hash from Alert:**
   ```json
   {
     "proofHash": "60f75323387672ff86197ade1bf3146fc073774f90d473930784d4af1340dd35",
     "toolName": "database_exec",
     "firedRule": "SQL-001"
   }
   ```

2. **Replay Invariant Locally:**
   ```bash
   npx aegis repl
   aegis> database_exec {"query": "<payload_under_investigation>"}
   ```

3. **Verify Tamper-Evidence:**
   The ProofHash guarantees the exact parameter payload and active policy version cannot be altered retroactively.
