# Contributing to Aegis Invariant Kernel

Thank you for your interest in contributing to **Aegis**! We welcome contributions from developers, security researchers, and AI builders.

---

## 🛠️ Development Setup

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/aegis-kernel/aegis.git
   cd aegis
   ```

2. **Install Dependencies:**
   ```bash
   npm install
   ```

3. **Build Monorepo:**
   ```bash
   npm run build
   ```

4. **Run Test Suites:**
   ```bash
   # TypeScript tests
   npm test

   # Python tests
   python3 packages/python/tests/test_aegis.py
   ```

---

## 📦 Authoring New Rule Packs

1. Create a new YAML file in `packages/core/packs/<pack-name>.yaml`.
2. Ensure every rule has `id`, `severity`, `description`, and a valid `condition` block.
3. Validate your pack using the CLI:
   ```bash
   npx aegis pack validate packages/core/packs/<pack-name>.yaml
   ```
4. Add unit test assertions in `packages/core/__tests__/`.

---

## 🛡️ Coding Standards

- **Zero `eval()` Policy:** All dynamic evaluation must use the `CustomChecker` AST recursive descent parser.
- **Sub-2ms Performance Invariant:** Every checker evaluation must execute in under 2ms.
- **Strict TypeScript:** All code must pass `npm run lint` (`tsc --noEmit`) with zero errors.
