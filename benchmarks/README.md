# benchmarks/ — Aegis evidence directory (committed)

Everything in this directory is **committable, verifiable evidence** — unlike the
gitignored `.benchmark/` scratch directory used for local microbenchmark runs.

```
benchmarks/
├── EVIDENCE.md      # the claims ledger: every published number traces to a file here
├── README.md        # this file
├── canonical/       # canonical academic datasets + SHA-256 manifest (via fetch script)
└── reports/         # dated evaluation reports (in-tree and canonical runs)
```

## Why this exists

Until 2026-08-20 the repo quoted benchmark percentages that could not be traced
to any committed dataset (canonical fetch URLs were dead, output went to a
gitignored directory, and a silent fallback wrote synthetic data in place of
fetched data). This directory ends that: **no number is published unless a
reproducible artifact backs it.** See `EVIDENCE.md` §3 (corrections register).

## Guarantees

1. `scripts/fetch-canonical-benchmarks.mjs` never writes synthetic data in place
   of canonical data. Failures fail loudly (non-zero exit) and are recorded in
   `canonical/manifest.json` with SHA-256 checksums for everything fetched.
2. `scripts/run-benchmarks.mjs` writes reports with field-standard metrics
   (ASR / defense rate / benign utility / risk / confusion matrix) plus dataset
   hash and environment fingerprint.
3. Reports distinguish `datasetSource`: `file` (canonical data on disk),
   `canonical` (in-tree representative corpus), `synthetic` (generated).
