# 🛡️ Aegis Invariant Kernel — Privacy Statement

**Commitment to Openness, Security & Privacy**

Aegis Invariant Kernel is open-source security infrastructure designed for deterministic AI tool-call clearance. We believe security software should be transparent, verifiable, and respectful of user privacy.

---

## 1. Zero Network Egress on the Clearance Hot-Path
The core clearance engine (`evaluateToolCall`) operates **100% in-process with zero network calls**. Your database queries, tool payloads, and application state never leave your machine during evaluation.

## 2. Air-Gapped Secret Vaults
When running locally, secrets and authentication credentials are stored exclusively on your filesystem (`~/.config/aegis/`) with Unix permissions `600` (user read/write only).

## 3. Privacy-Preserving Collective Intelligence
To improve invariant rules against emerging zero-day prompt injection and parser bypass vectors, Aegis collects non-identifiable, aggregate operational statistics (e.g. rule violation counts, latency percentiles, error stack hashes).

* No IP addresses, usernames, or database queries are logged or transmitted.
* Full details and opt-out commands are provided in [TELEMETRY.md](./TELEMETRY.md).

## 4. Contact
For security disclosures or privacy inquiries, contact: `security@aegis-kernel.dev`.
