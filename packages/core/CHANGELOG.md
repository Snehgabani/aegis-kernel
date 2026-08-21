# Changelog

## [1.9.0](https://github.com/Snehgabani/aegis-kernel/compare/core@vv1.8.0...core@vv1.9.0) (2026-08-21)


### 🚀 Features & Verification Engines

* **security:** eliminate 7 catastrophic failure modes with AST recursion limit, ZK replay defense, NFKD vault, and crescendo drift tracker ([7f04613](https://github.com/Snehgabani/aegis-kernel/commit/7f0461374bb2af3a95833ee06e9ad6865967b548))

## [1.8.0](https://github.com/Snehgabani/aegis-kernel/compare/core@vv1.7.0...core@vv1.8.0) (2026-08-21)


### 🚀 Features & Verification Engines

* **evals:** add SecLists / Exploit-DB real-world CVE evaluation adapter and cloud SSRF invariants ([46b9e02](https://github.com/Snehgabani/aegis-kernel/commit/46b9e027714d404e838b1270aca135a7c81cdda4))

## [1.7.0](https://github.com/Snehgabani/aegis-kernel/compare/core@vv1.6.0...core@vv1.7.0) (2026-08-21)


### 🚀 Features & Verification Engines

* **compliance:** add full OWASP Agentic AI Top 10 (ASI01-ASI10) mappings and audit verification to GRC dossier ([3bc5ab0](https://github.com/Snehgabani/aegis-kernel/commit/3bc5ab083aee41b5d42add4c827cc032062115d4))

## [1.6.0](https://github.com/Snehgabani/aegis-kernel/compare/core@vv1.5.0...core@vv1.6.0) (2026-08-21)


### 🚀 Features & Verification Engines

* **evals:** add scale N=1,000 canonical OWASP Agentic AI benchmark and CLOUD-005 filesystem destruction defense ([fc00eff](https://github.com/Snehgabani/aegis-kernel/commit/fc00eff75663ba4fb38c7c1a6af18cf0ce1a8f1c))

## [1.5.0](https://github.com/Snehgabani/aegis-kernel/compare/core@vv1.4.0...core@vv1.5.0) (2026-08-21)


### 🚀 Features & Verification Engines

* **security:** add cryptographic policy commitment CLI and autonomous branch hygiene launchd daemon ([7674b00](https://github.com/Snehgabani/aegis-kernel/commit/7674b00a4afee90c3a6138b5ab816b8d45fd3bc1))

## [1.4.0](https://github.com/Snehgabani/aegis-kernel/compare/core@vv1.3.0...core@vv1.4.0) (2026-08-21)


### 🚀 Features & Verification Engines

* **security:** embed Microsoft FIDES dual-lattice IFC and DeepMind CaMeL quarantined execution separation ([0ca8f21](https://github.com/Snehgabani/aegis-kernel/commit/0ca8f217f5bb253289e41ab3416db54d88ac2c7a))
* **synthesizer:** add OpenAPI 3.0/3.1 synthesis and wire CLI commands with 100% test coverage ([a31bc19](https://github.com/Snehgabani/aegis-kernel/commit/a31bc1965887f849a36dae5090204281e9610c7e))

## [1.3.0](https://github.com/Snehgabani/aegis-kernel/compare/core@vv1.2.1...core@vv1.3.0) (2026-08-21)


### 🚀 Features & Verification Engines

* **synthesizer:** add SchemaInvariantSynthesizer for dynamic OpenAPI and MCP invariant rule generation ([a2eef8f](https://github.com/Snehgabani/aegis-kernel/commit/a2eef8f5ce4540e367ffb94e41f3c160c1d2be10))

## [1.2.1](https://github.com/Snehgabani/aegis-kernel/compare/core@vv1.2.0...core@vv1.2.1) (2026-08-21)


### 🐛 Bug Fixes & Invariant Patches

* **security:** resolve CodeQL alerts [#96](https://github.com/Snehgabani/aegis-kernel/issues/96), [#97](https://github.com/Snehgabani/aegis-kernel/issues/97), [#98](https://github.com/Snehgabani/aegis-kernel/issues/98), and [#99](https://github.com/Snehgabani/aegis-kernel/issues/99) ([1bc7ce0](https://github.com/Snehgabani/aegis-kernel/commit/1bc7ce0e261264d467a65d1607e29b1503977145))

## [1.2.0](https://github.com/Snehgabani/aegis-kernel/compare/core@vv1.1.0...core@vv1.2.0) (2026-08-21)


### 🚀 Features & Verification Engines

* **core:** z3 symbolic verification and enterprise GRC compliance exporters ([#48](https://github.com/Snehgabani/aegis-kernel/issues/48)) ([0527c89](https://github.com/Snehgabani/aegis-kernel/commit/0527c89f210378aef1c80cdad1cb117d7c0f89ce))


### ⚡ Performance & AST Optimizations

* **hot-path:** sub-50µs P99 evaluation pipeline across TS/Rust/Go ([#49](https://github.com/Snehgabani/aegis-kernel/issues/49)) ([ff24c81](https://github.com/Snehgabani/aegis-kernel/commit/ff24c81554809e06fe3a71e3d423665ee7fec10c))

## [1.1.0](https://github.com/Snehgabani/aegis-kernel/compare/core@vv1.0.1...core@vv1.1.0) (2026-08-21)


### 🚀 Features & Verification Engines

* **a2a:** add biscuit capability tokens with monotonic attenuation and cli scan replay ([b6c3784](https://github.com/Snehgabani/aegis-kernel/commit/b6c37843de906f65d5819cf4981752214a72ae2b))
* **adapters:** add LlamaIndex and CrewAI tool adapters, CLI pack scaffolder, and production example suite ([54c20ed](https://github.com/Snehgabani/aegis-kernel/commit/54c20ed149b3204743ab176ea30c05163b4c284c))
* complete all 7 gap remediations (PII unicode normalization, async Python decorator, onViolation hook, 7-day license grace period, ledger auto-compaction, tenant isolation, and customer portal endpoint) ([24a9fb7](https://github.com/Snehgabani/aegis-kernel/commit/24a9fb7599cb3150fe23cf92391fa45ef6275a4c))
* comprehensive trust & integrity upgrade ([823c875](https://github.com/Snehgabani/aegis-kernel/commit/823c875cd872efcc0f5ca84b7156a454cfb9b13c))
* **core:** complete audit remediation and health monitoring suite ([b2b73c5](https://github.com/Snehgabani/aegis-kernel/commit/b2b73c5f1c43e01e541e187dfef5e7482aee9adf))
* **core:** harden multi-dialect AST, zero-eval DSL, numeric bounds, secrets scanning, and async state provider ([95e3ac4](https://github.com/Snehgabani/aegis-kernel/commit/95e3ac47774a630ada59da4c3ce3a1660d97f20f))
* **diagnostics:** add step-by-step micro-stage forensic tracer, unified remediation diffs, and aegis diagnose CLI ([86de15d](https://github.com/Snehgabani/aegis-kernel/commit/86de15d1cb55ec6791d659078ba0f6f0826772e8))
* **ecosystem:** add official @aegis-kernel/vercel-ai package for Vercel AI SDK Core tool protection ([25a1f36](https://github.com/Snehgabani/aegis-kernel/commit/25a1f364226d5239a390127345d5fae3f235ec57))
* **elite:** activate multi-language CI workflows, fast-check deterministic fuzzing, and benchmark ingestion kits ([f0fdf6e](https://github.com/Snehgabani/aegis-kernel/commit/f0fdf6e64efa4186eeafff41d479e73beffa15f7))
* **elite:** add Human-in-the-Loop (HITL) escalation engine, Non-Human Identity (NHI) registry, and automated adaptive circuit breaker ([f3d8548](https://github.com/Snehgabani/aegis-kernel/commit/f3d85487f92cc7a269395e54e553a085f4befb06))
* **elite:** implement Phase 2 & Phase 3 roadmap (Validator Hub, Injection Classifier, RAG Grounding, Causal DAG, Policy-as-Code, WASM Sandbox, Shadow AI Sniffer, Gateway Adapters) ([a3a7197](https://github.com/Snehgabani/aegis-kernel/commit/a3a7197580d33db7a55edeff8ff284d01cc0b818))
* **enterprise:** add live Invariant Studio playground, Kubernetes Helm chart, OpenTelemetry conventions, and platform monetization thesis ([12d0dd9](https://github.com/Snehgabani/aegis-kernel/commit/12d0dd9366449e3238643ca7c169c84cb33046f3))
* **enterprise:** enterprise SIEM telemetry, WORM GRC compliance dossier exporter, explainability engine, and SEO/marketing upgrades ([222823e](https://github.com/Snehgabani/aegis-kernel/commit/222823ec6ecd3b9b3537096cd73fe3d1c1a4d5fd))
* **evals:** add unbiased 100-vector adversarial stress testbed and engine hardenings ([ca6fd34](https://github.com/Snehgabani/aegis-kernel/commit/ca6fd3423270b5b59a78583a4388417597e3c97a))
* **evals:** implement research-grade double-blind evaluation, dynamic TAP fuzzer, and UK AISI Inspect AI adapter ([b2f777a](https://github.com/Snehgabani/aegis-kernel/commit/b2f777ad157e73631fb5504c711e57210c223df6))
* **evals:** ingest academic benchmarks and add ed25519 merkle verification ([0532c7e](https://github.com/Snehgabani/aegis-kernel/commit/0532c7ef37c2e50fd56a11c4a39c70b22e5ec900))
* **frontier:** 10-subagent comprehensive hardening across AST security, polyglot parity, benchmarks, and latency SLAs ([bab8d7c](https://github.com/Snehgabani/aegis-kernel/commit/bab8d7c24424be99fb375e938c229203f2006258))
* **frontier:** add AI Agent Honeytoken Deception Manager, Distributed Redis-backed Circuit Breaker, Turnkey Docker/Grafana stack, and pre-publish verification suite ([93778b6](https://github.com/Snehgabani/aegis-kernel/commit/93778b600638c5011e147ded07be4343008d6cc2))
* **governance:** integrate PR [#45](https://github.com/Snehgabani/aegis-kernel/issues/45) trust & integrity upgrade with backward-compatibility fixes ([6202f72](https://github.com/Snehgabani/aegis-kernel/commit/6202f726bd463d903eb23a03c779e822a69ec89d))
* **governance:** signed rule packs (AISVS C10.1.1) + fail-closed policy lifecycle — cycle 6 ([484f6d6](https://github.com/Snehgabani/aegis-kernel/commit/484f6d6cbadca6f625797162cfb6cc6e300c8d8d))
* **grc:** Merkle inclusion proofs (SPV) and pricing CLI update ([53b406d](https://github.com/Snehgabani/aegis-kernel/commit/53b406d11a7f7a450697f7802519a24404cbddd7))
* **hub:** add Aegis Hub CLI package manager, Langfuse & Arize Phoenix observability formatters, and Vanta/Drata GRC evidence webhooks ([b47bb21](https://github.com/Snehgabani/aegis-kernel/commit/b47bb2141a2efb86363be256fe366f96b279372e))
* **integrations:** add VS Code/Cursor extension manifest, Homebrew formula, PR review bot, Slack/Discord webhook bot, and Docker GHCR workflow ([3f56a3d](https://github.com/Snehgabani/aegis-kernel/commit/3f56a3da939a425e698c08a084dcc88ba8585082))
* **otel:** GenAI semantic-convention spans for every evaluation (opt-in, zero-egress, content-free) ([329241f](https://github.com/Snehgabani/aegis-kernel/commit/329241f5f341054aa68b357ea1fd3fb562178b7e))
* **provenance+trajectory:** IFC-001 information-flow control & Mann-Kendall trajectory stress — research-aligned cycle 5 ([7bc37bc](https://github.com/Snehgabani/aegis-kernel/commit/7bc37bca64819be239d9d9a5a26567bc5bcb1ac8))
* **red-team:** 'aegis red-team run' + FIX real PII layered-evasion bypass found on first live fire ([600c538](https://github.com/Snehgabani/aegis-kernel/commit/600c538033cf713efc91956daff3c0cbad35f92e))
* **release:** Aegis Invariant Kernel v1.0.0 (Production Core, Adapters, Python SDK, Cloud Gateway, & Compliance Packs) ([8beb76a](https://github.com/Snehgabani/aegis-kernel/commit/8beb76a504dbfe039cc21e7c9a4a9800123c19b9))
* **scientific-rigor:** CIs on every claim, ablation study, metamorphic properties — 2 more real engine gaps found & fixed ([1630105](https://github.com/Snehgabani/aegis-kernel/commit/16301057a4363eee069edc8c4b680b1174764361))
* **sdk:** full go and rust engines, academic benchmark adapters, cpa verification, and hybrid bridge ([0dbc20b](https://github.com/Snehgabani/aegis-kernel/commit/0dbc20b7564874d4fd464a00c3339352313f87d9))
* **security:** add MCP Tool Poisoning Scanner, Schema Rug-Pull Detector, Self-Healing Synthesizer, and Threat Intelligence Ingestion Feed ([5770cc1](https://github.com/Snehgabani/aegis-kernel/commit/5770cc1191a7f5b657765008de31ec2a4b3b9ca2))
* **security:** asymmetric Ed25519 offline license verification and ISO 42001 & Cloud Infra guard packs ([b64d542](https://github.com/Snehgabani/aegis-kernel/commit/b64d54232d1ed104694e999e7726fe532c4eb813))
* **security:** remediate P0 vulnerabilities & implement Phase 1 streaming, tracking, reask, and PII vault ([c866f87](https://github.com/Snehgabani/aegis-kernel/commit/c866f871d5a1f98efecda28af462f7856fcc9467))
* **standards:** add OWASP/MITRE ATLAS matrix CLI, in-flight AST parameter sanitizer, Prometheus /metrics endpoint, and JSON schemas ([12c9f2d](https://github.com/Snehgabani/aegis-kernel/commit/12c9f2d8db752d7ba2caad7de3b24f939fda63ff))
* **verify:** complete elite verification harness — fast-check property tests, 433-vector fuzz corpus, 100% mutation score, regression gates, and build concurrency cap ([969a0ed](https://github.com/Snehgabani/aegis-kernel/commit/969a0ed51816f2f532697f75025cffbad8fc1eef))


### 🐛 Bug Fixes & Invariant Patches

* **cli:** bundle internal monorepo packages into standalone CLI distribution ([76dca1d](https://github.com/Snehgabani/aegis-kernel/commit/76dca1d793ce5f081e168ff2bfbd120ab19f33a3))
* **core:** 8 logic bug fixes — severity propagation, schema drift alignment, CLI exit codes, telemetry property, WASM test, SQL-004 limit rule ([22797df](https://github.com/Snehgabani/aegis-kernel/commit/22797df419cf765010c731d4790b63f6d8123854))
* **deps:** migrate js-yaml default imports to namespace imports for ESM compatibility ([8131976](https://github.com/Snehgabani/aegis-kernel/commit/8131976ba07a492c3510bdabe3009c8fa536be17))
* **docs:** update funding and package homepages to live GitHub Pages documentation URL ([0fcdcfa](https://github.com/Snehgabani/aegis-kernel/commit/0fcdcfa87660c1b28f381e86c0079f1029308a30))
* **evals:** clean up unused types and enforce circular reference & prototype pollution defenses ([73df037](https://github.com/Snehgabani/aegis-kernel/commit/73df0378a1b8df52788ca80da1795c534315eac5))
* **security:** 6 critical security fixes — WASM fail-closed, engine fail-closed default, Unicode normalization bypass, PII redaction hardening, Go SDK SSN detection ([84bfbd5](https://github.com/Snehgabani/aegis-kernel/commit/84bfbd539f2eeda44281d1b26506ed60c702869e))
* **security:** address independent audit findings - HMAC verification, RBAC integration, enhanced MCP scanner, robust self-healing, threat feed persistence ([e5c4994](https://github.com/Snehgabani/aegis-kernel/commit/e5c4994c62d1f2af00fbddd8af7fe31240972b06))
* **security:** eliminate ReDoS polynomial regex in SQL checkers across TypeScript, Python, Go, and Rust (fixes CodeQL [#89](https://github.com/Snehgabani/aegis-kernel/issues/89)-[#93](https://github.com/Snehgabani/aegis-kernel/issues/93)) ([de7e6e6](https://github.com/Snehgabani/aegis-kernel/commit/de7e6e6d70b704df72e9249be5910fe0013e465e))
* **security:** remediate independent technical audit findings ([30a0ed9](https://github.com/Snehgabani/aegis-kernel/commit/30a0ed9f56fe2a9f58da487723740d522bb1fa3f))
* **security:** replace all fallback regexes with 100% deterministic zero-regex token parser (resolves CodeQL [#6](https://github.com/Snehgabani/aegis-kernel/issues/6) & [#7](https://github.com/Snehgabani/aegis-kernel/issues/7)) ([7350c0a](https://github.com/Snehgabani/aegis-kernel/commit/7350c0a402330a8bdc0cb51c333c8765c2e36aef))
* **security:** resolve CodeQL polynomial regex (ReDoS) alerts with O(n) linear comment scanner and non-backtracking patterns ([9bd3537](https://github.com/Snehgabani/aegis-kernel/commit/9bd353732c056bf03d88dfb534b6272c2cf0a180))
* **security:** resolve CodeQL ReDoS in self-healing and validator-hub, pin immutable action commit SHAs for OpenSSF Scorecard ([beda666](https://github.com/Snehgabani/aegis-kernel/commit/beda666c59ef793929838d44d00991c57e34d609))
* **security:** sanitize dummy secret test tokens and enforce least-privilege token permissions across CI workflows ([d89b675](https://github.com/Snehgabani/aegis-kernel/commit/d89b675d5ee4df711a37646b21c084085f89bdf5))
* **sql:** separate punctuation in fallback tokenizer and add 25-vector auditor reproduction test ([5c11b42](https://github.com/Snehgabani/aegis-kernel/commit/5c11b42a35e8f697b2d5755876b6b6b4b7d0a89d))


### ⚡ Performance & AST Optimizations

* optimize ledger disk persistence and calibrate CI performance bounds ([ba0ca70](https://github.com/Snehgabani/aegis-kernel/commit/ba0ca703be75edad4ceb6ea777720f409b075984))


### 📚 Documentation & Compliance

* overhaul — honest compliance self-assessment, remove inflated marketing playbooks, correct benchmark attributions, and document verification evidence ([18286a1](https://github.com/Snehgabani/aegis-kernel/commit/18286a1ae024b22db39891545a304fa3b9232625))


### 🧪 Invariant Tests & Fuzzing

* calibrate CI timing bounds in engine.test.ts and tricky-100.test.ts ([61dec00](https://github.com/Snehgabani/aegis-kernel/commit/61dec006e2f283db65f154046c8921b8bd037541))
* **observability:** add unit tests for Langfuse, Arize Phoenix, Hub CLI, and GRC evidence sync ([ab3f26d](https://github.com/Snehgabani/aegis-kernel/commit/ab3f26db111c3f47edf031fbab6245637f2c1696))


### 🔧 CI/CD & Infrastructure

* **governance:** add enterprise Git governance, pre-commit hooks, CODEOWNERS, issue forms, SECURITY policy, and PR auditing ([0675f75](https://github.com/Snehgabani/aegis-kernel/commit/0675f75f80359e2699a3d6ca8dec8f5d0489d721))
* **matrix:** harden Node.js 20.x/22.x verification matrix, npm caching, and test fixture tokens ([5f35142](https://github.com/Snehgabani/aegis-kernel/commit/5f351427722237b58b2e9eca59e037b52dc3cd74))
