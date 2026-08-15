# Aegis Enterprise Pilot & POC Migration Playbook

**Target Audience:** Enterprise Solutions Architects, AI Security Leads, and Customer Success Engineers.

---

## 🎯 14-Day Pilot Objective

Achieve **zero-disruption policy calibration**, demonstrate **<2ms deterministic clearance** under production agent loads, and prove **100% detection of unauthorized data mutations and PII leakage** with zero false positive interrupts.

---

## 📅 14-Day Pilot Schedule

```
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │ DAY 1–3: SHADOW MODE DEPLOYMENT & BASELINE INTAKE                           │
  ├─────────────────────────────────────────────────────────────────────────────┤
  │ DAY 4–7: POLICY CALIBRATION & RULE PACK TAILORING                           │
  ├─────────────────────────────────────────────────────────────────────────────┤
  │ DAY 8–11: ACTIVE ENFORCEMENT & SELF-HEALING TRIAL                           │
  ├─────────────────────────────────────────────────────────────────────────────┤
  │ DAY 12–14: SOC 2 / HIPAA AUDITOR SIGN-OFF & ANNUAL CONTRACT CONVERSION      │
  └─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Detailed Phase Breakdown

### Phase 1 (Days 1–3): Shadow Mode Deployment
Deploy Aegis with `mode: 'shadow'`. In shadow mode, the kernel intercepts every agent tool call in-process, computes AST invariants, and logs violations to the local Learning Ledger without blocking execution.

```typescript
const aegis = new AegisEngine({
  mode: 'shadow',
  packs: ['@aegis/sql-guard', '@aegis/hipaa-guard', '@aegis/soc2-guard'],
});
```

*Success Metric:* 0ms execution interruption; 10,000+ real queries logged and benchmarked for latency overhead (target: P50 < 1.5ms).

---

### Phase 2 (Days 4–7): Policy Calibration & Custom Rules
1. Inspect the Learning Ledger report:
   ```bash
   npx aegis report
   ```
2. Adjust numerical limits or author proprietary rules in YAML:
   ```bash
   npx aegis pack validate custom-enterprise-guard.yaml
   ```
3. Enable dynamic sync using `AegisDynamicSyncManager` for zero-restart rule updates across agent clusters.

---

### Phase 3 (Days 8–11): Active Enforcement (`mode: 'enforce'`)
Switch to active enforcement. Rogue agent SQL wipes, unauthorized credit card payloads, and excessive financial payouts are deterministically blocked with structured `suggestedFix` feedback returned to the agent.

---

### Phase 4 (Days 12–14): Auditor Certification & Procurement
1. Export the tamper-evident CSV audit ledger from the Auditor Dashboard (`/dashboard/`).
2. Present the signed **CISO Security White Paper** and cryptographic proof log to Compliance.
3. Sign annual SLA and deliver air-gapped Enterprise License Tokens (`aegis_lic_...`).
