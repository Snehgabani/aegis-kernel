# Contributing to Aegis Invariant Kernel

Thank you for your interest in contributing to **Aegis Invariant Kernel**! We welcome contributions from developers across the AI, security, and systems engineering communities.

---

## 🏗️ Development Setup

### Prerequisites:
- **Node.js**: >= 20.0.0 LTS
- **npm**: >= 10.0.0
- **Python**: >= 3.9 (for Python SDK development)
- **Git**: Configured with Conventional Commits

```bash
# 1. Clone the repository
git clone https://github.com/Snehgabani/aegis-kernel.git
cd aegis-kernel

# 2. Install workspace dependencies
npm install

# 3. Setup pre-commit git hooks
./scripts/setup-git-hooks.sh

# 4. Build all workspaces
npm run build

# 5. Run tests & the 100-vector adversarial benchmark
npm run test
npx aegis benchmark --tricky
```

---

## 📝 Conventional Commits Standard

We enforce the [Conventional Commits](https://www.conventionalcommits.org/) specification on all commit messages and PR titles:

```
<type>(<scope>): <short summary>

[optional body]

[optional footer(s)]
```

### Allowed Types:
- `feat`: A new feature or capability (e.g. `feat(core): add cross-tenant validation`)
- `fix`: A bug fix or false positive remediation (e.g. `fix(sql): normalize inline block comments`)
- `docs`: Documentation, SEO, or diagram changes
- `perf`: Performance or latency optimizations
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `test`: Adding or modifying test suites or benchmark vectors
- `ci`: Changes to CI/CD workflows and automated pipelines
- `chore`: Maintenance, dependencies, or tooling updates

---

## 🧪 Testing & Verification Mandate

Every PR must satisfy the following invariant criteria before merging:
1. **100% Test Pass Rate**: All unit, invariant, and integration tests must pass (`npm run test`).
2. **Zero Regressions on Adversarial Testbed**: The 100-vector tricky benchmark must maintain 100.0% F1 accuracy (`npx aegis benchmark --tricky`).
3. **Strict TypeScript Compilation**: Zero type errors or warnings (`npm run lint`).
4. **Latency Budget**: Core engine execution must remain under **2.5ms P95 latency**.
