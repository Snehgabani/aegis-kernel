## 🛡️ Aegis Pull Request Checklist

### 1. Summary of Changes
<!-- Provide a clear description of the problem, motivation, and solution -->

### 2. Type of Change
- [ ] 🐛 Bug fix (non-breaking change fixing an engine issue or false positive)
- [ ] ✨ New feature (new checker, rule pack, or framework adapter)
- [ ] 🔒 Security fix / vulnerability remediation
- [ ] ⚡ Performance optimization (latency reduction)
- [ ] 📝 Documentation & SEO updates
- [ ] 🤖 CI/CD & Automation improvements

---

### 3. Invariant & Security Verification
- [ ] All 110+ unit & invariant tests pass locally (`npm run test`)
- [ ] 100-vector adversarial stress testbed passes (`npx aegis benchmark --tricky`)
- [ ] Python SDK test suite passes (`python -m unittest discover -s packages/python/tests`)
- [ ] Strict TypeScript compilation passes with zero warnings (`npm run lint`)
- [ ] Zero network egress introduced in core engine evaluation paths

---

### 4. Benchmark Latency Delta
| Metric | Baseline (v1.0.0) | PR Value | Delta |
| :--- | :--- | :--- | :--- |
| **Average Latency** | 0.56 ms | -- ms | -- |
| **P95 Latency** | 2.29 ms | -- ms | -- |
| **Malicious Block Rate** | 100.0% | -- % | -- |
| **Benign Pass Rate** | 100.0% | -- % | -- |

---

### 5. Conventional Commit Verification
- [ ] PR title follows [Conventional Commits](https://www.conventionalcommits.org/) (e.g. `feat(core): add cross-tenant validation`).
