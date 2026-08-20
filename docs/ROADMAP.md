# 🗺️ Aegis — Public Roadmap

> **What's coming next. This is a living document — last updated 2026-08-20.**

---

## v1.1.0 (Q4 2026)

### Security & Trust
- [ ] **Canonical benchmark dataset ingestion**: Automatically download and evaluate against the official InjecAgent and AgentDojo datasets, not just generated subsets
- [ ] **Sigstore signing**: Sign all release artifacts with Sigstore/Cosign for verifiable provenance (SLSA L3)
- [ ] **SPDX SBOM generation**: Machine-readable bill of materials for every release
- [ ] **Independent red-team harness**: `aegis red-team run` with structured 100+ vector adversarial test suite
- [ ] **Cross-language CI matrix**: Full build+test+lint for Go, Rust, Python in CI (config written, awaiting runner confirmation)

### Feature Completeness
- [ ] **Real WASM plugin sandbox**: `WasmPluginRunner` actually compiles and runs WASM modules with memory limits and timeout
- [ ] **WASM plugin SDK + example**: Build a custom invariant checker in C/Rust, compile to WASM, load as Aegis pack
- [ ] **Enclave attestation**: Real AWS Nitro NSM SDK integration for production attestation reports
- [ ] **Homoglyph map unification**: All 4 languages use a single canonical map generated from `docs/HOMOGLYPH_MAP.json`

### Testing & Quality
- [ ] **Mutation testing (Stryker)**: Achieve ≥80% mutation score on core checkers
- [ ] **Fuzz testing in CI**: Grammar-aware SQL fuzzer generating random obfuscated payloads
- [ ] **Performance regression CI**: Automatic PR comment when P50/P95 latency regresses >20%

---

## v1.2.0 (Q1 2027)

### Ecosystem
- [ ] **OPA/Rego policy engine**: Alternative policy-as-code using Open Policy Agent WASM modules
- [ ] **Kubernetes admission webhook**: Helm chart + ValidatingWebhookConfiguration for k8s secret scanning
- [ ] **Rule pack registry**: `aegis pack search/install/publish` for community-contributed packs
- [ ] **VSCode extension v2**: Inline diagnostics for hardcoded secrets, SQL injection detection, CodeLens actions

### Observability
- [ ] **OpenTelemetry native spans**: Full distributed tracing for every evaluation stage
- [ ] **SIEM export**: CEF (ArcSight), LEEF (QRadar), OCSF format audit log exporters
- [ ] **mTLS gateway**: Mutual TLS between gateway and internal services

### Zero-Knowledge Proofs
- [ ] **Groth16 range proofs**: Replace SHA-256 commitments with real zk-SNARK circuits using `arkworks`
- [ ] **zkVM integration**: RISC Zero / SP1 for verifiable private policy evaluation

---

## v2.0.0 (H2 2027)

### Enterprise
- [ ] **Real ZK proof system**: Groth16/PLONK-based private policy compliance verification
- [ ] **Hardware enclave support**: AWS Nitro Attestation + Intel SGX DCAP
- [ ] **Multi-tenant control plane**: Centralized policy management, audit aggregation, license enforcement
- [ ] **SOC 2 Type II evidence export**: Automated evidence collection for SOC 2, HIPAA, ISO 42001 audits

### Platform
- [ ] **First production deployment**: Documented case study with metrics
- [ ] **Community contributions**: At least 1 non-author contributor with merged PRs
- [ ] **Published security audit**: Independent third-party penetration test report

---

## 🎯 Near-Term Quick Wins (1-2 Days)

These can be done by any contributor:

- [ ] Run `cargo generate-lockfile` to produce real `Cargo.lock` instead of the manual one
- [ ] Set up Rust toolchain in CI and verify `cargo test` passes for the crate
- [ ] Install Go toolchain in CI and verify `go test ./...` passes
- [ ] Run `pip install pytest && python -m pytest packages/python/tests/` to verify Python tests
- [ ] Add `fast-check` property tests for remaining checkers (NumericChecker, PiiChecker)
- [ ] Expand homoglyph map with the full Unicode confusables list (150+ entries)

---

> **Have a suggestion?** Open a [GitHub Discussion](https://github.com/Snehgabani/aegis-kernel/discussions) or submit a PR against `ROADMAP.md`.