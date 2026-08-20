# Release Checklist (v1.0.1 → v1.0.2)

Version alignment and release hygiene procedure. Current state (2026-08-20):
in-repo manifests = **1.0.1**; npm + PyPI still serve **1.0.0**.

## Every release

1. **Green gates**
   - [ ] `npm test` — full suite (update README badge + `npm test` comment to the
         actual count in the same PR that changes the number)
   - [ ] `npm run build`
   - [ ] `bash scripts/security-audit.sh`
   - [ ] Python: `cd examples/python-adapter && python -m pytest` (11 tests)
2. **Version bump** — single source of truth:
   - [ ] Root `package.json` + `packages/*/package.json` + `services/*/package.json`
   - [ ] `CHANGELOG.md` entry (date, sections: Security / Added / Changed / Fixed)
   - [ ] `CITATION.cff` version
3. **Evidence refresh**
   - [ ] Run the `benchmark-canonical` workflow (workflow_dispatch with
         `commit_evidence=true`) — reviews + merges the checksummed evidence PR
         (workflow template: `scripts/ci-templates/`, installed via
         `bash scripts/install-ci-templates.sh` if not yet present),
         OR locally: `node scripts/fetch-canonical-benchmarks.mjs` (needs egress;
         commit `benchmarks/canonical/manifest.json` checksums)
   - [ ] `node scripts/run-benchmarks.mjs` (+ `--canonical` if data fetched)
   - [ ] `benchmarks/EVIDENCE.md` updated with new dated reports
4. **Registries** (manual, requires maintainer credentials)
   - [ ] `npm publish` (workspaces: core, cli, evals, mcp, openai, anthropic,
         langchain, vercel-ai, diagnostics) — verify each shows the new version
   - [ ] PyPI `aegis-kernel` (sdist + wheel)
   - [ ] Go module tag `v1.0.x` (module proxy picks up tags automatically)
   - [ ] crates.io `aegis-kernel` crate (docs.rs build green)
5. **Supply chain** (automatic on `release: published` — verify, don't re-run;
   workflow templates with release wiring live in `scripts/ci-templates/`, install
   once via `bash scripts/install-ci-templates.sh`)
   - [ ] SBOMs (SPDX + CycloneDX) attached as release assets (`sbom-and-grype` attach job)
   - [ ] SLSA build provenance attestation generated for the tag (`slsa-provenance`)
   - [ ] npm publish with `--provenance` (Sigstore) succeeded for all workspaces
   - [ ] Homebrew formula bump (`Formula/`)
6. **Comms**
   - [ ] GitHub Release notes from CHANGELOG section
   - [ ] Site `site/` regenerated if version numbers appear
