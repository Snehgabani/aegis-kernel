# Changelog

## [1.1.1](https://github.com/Snehgabani/aegis-kernel/compare/aegis-kernel-go@vv1.1.0...aegis-kernel-go@vv1.1.1) (2026-08-21)


### ⚡ Performance & AST Optimizations

* **hot-path:** sub-50µs P99 evaluation pipeline across TS/Rust/Go ([#49](https://github.com/Snehgabani/aegis-kernel/issues/49)) ([ff24c81](https://github.com/Snehgabani/aegis-kernel/commit/ff24c81554809e06fe3a71e3d423665ee7fec10c))

## [1.1.0](https://github.com/Snehgabani/aegis-kernel/compare/aegis-kernel-go@vv1.0.1...aegis-kernel-go@vv1.1.0) (2026-08-21)


### 🚀 Features & Verification Engines

* **frontier:** 10-subagent comprehensive hardening across AST security, polyglot parity, benchmarks, and latency SLAs ([bab8d7c](https://github.com/Snehgabani/aegis-kernel/commit/bab8d7c24424be99fb375e938c229203f2006258))
* **sdk:** add Go SDK, Rust SDK, Terraform cloud modules (AWS ECS / GCP CloudRun), and Glama/MCP manifests ([470b5dd](https://github.com/Snehgabani/aegis-kernel/commit/470b5ddc44a92c706c3f2edee47e8a9e0560ce70))
* **sdk:** full go and rust engines, academic benchmark adapters, cpa verification, and hybrid bridge ([0dbc20b](https://github.com/Snehgabani/aegis-kernel/commit/0dbc20b7564874d4fd464a00c3339352313f87d9))
* **verify:** complete elite verification harness — fast-check property tests, 433-vector fuzz corpus, 100% mutation score, regression gates, and build concurrency cap ([969a0ed](https://github.com/Snehgabani/aegis-kernel/commit/969a0ed51816f2f532697f75025cffbad8fc1eef))


### 🐛 Bug Fixes & Invariant Patches

* **ci:** resolve rustfmt, clippy linter warnings, and go.mod version for CI matrices ([f861551](https://github.com/Snehgabani/aegis-kernel/commit/f8615511c63dcaf26d62f254d878b9d53b261323))
* **ecosystem:** synchronize polyglot package versions, import paths, and author metadata ([361a828](https://github.com/Snehgabani/aegis-kernel/commit/361a828884266b4059d1bf861b6508c823f43621))
* **go:** update Go module path to github.com/Snehgabani/aegis-kernel/packages/go ([87ace65](https://github.com/Snehgabani/aegis-kernel/commit/87ace65f4cc0e4a4afc786e9db1f37416c17abbe))
* **security:** 6 critical security fixes — WASM fail-closed, engine fail-closed default, Unicode normalization bypass, PII redaction hardening, Go SDK SSN detection ([84bfbd5](https://github.com/Snehgabani/aegis-kernel/commit/84bfbd539f2eeda44281d1b26506ed60c702869e))
* **security:** eliminate ReDoS polynomial regex in SQL checkers across TypeScript, Python, Go, and Rust (fixes CodeQL [#89](https://github.com/Snehgabani/aegis-kernel/issues/89)-[#93](https://github.com/Snehgabani/aegis-kernel/issues/93)) ([de7e6e6](https://github.com/Snehgabani/aegis-kernel/commit/de7e6e6d70b704df72e9249be5910fe0013e465e))


### 📚 Documentation & Compliance

* **packages:** add dedicated production READMEs for Go and Rust packages ([0a0c609](https://github.com/Snehgabani/aegis-kernel/commit/0a0c609662f3b10487899473c2e84f884aaefa9e))
