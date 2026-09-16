# CI-RESULTS.md — SNOW2 Hostile Audit

**Commit:** post-`44dbbbc`
**Date:** 2025-07-21
**Revised:** 2026-09-16 — see [CI Outage](#ci-outage-2026-03-02--2026-09-16) below. The
figures originally recorded here were accurate when written but went stale, and CI
did not catch the drift because CI itself was broken.

---

## CI Outage (2026-03-02 → 2026-09-16)

CI was red on `main` for roughly six months, in two overlapping stages. Recorded here
because the second stage hid the first.

**Stage 1 — a real test failure (`72f824b`, 2026-03-02).**
`72f824b` optimized the v4 extract path to reuse the Argon2 master secret, replacing
`container.open(password, pepper, …)` with `container.open_with_key(&inner_key)` when
the inner KDF params match the outer profile. `open()` enforces the container's
`pepper_required` policy; `open_with_key()` did not — it carried an empty
`if self.header.pepper_required { }` block whose comment argued the AEAD would fail
anyway. It does fail, but with a generic authentication error, so
`pepper_required_blocks_missing_pepper_on_extract` broke. CI's **Rust Tests** job
failed at `72f824b` and `1f8d3e8`.

Not an exposure of plaintext: a missing or wrong pepper still fails the inner AEAD.
The loss was the specific diagnostic, and with it the documented reason the outer key
is password-only (see *Why Two AEAD Layers* in the README).

**Stage 2 — the failure gets hidden (`0d23249`, 2026-03-13).**
`0d23249` landed formatting that `cargo fmt --check` rejects (`src/container.rs:938`,
`src/secure_mem.rs:67`). Because `test` and `wasm` declare `needs: check`, both jobs
stopped running and reported as **skipped** rather than failed. From `0d23249` through
`48b8305` every push showed `Check=failure, Rust Tests=skipped, WASM=skipped`, so the
Stage 1 regression sat undetected. GitHub has since expired the `72f824b` / `1f8d3e8`
logs (HTTP 410), so the original failure text is not recoverable from CI; the cause
above was reproduced locally instead.

**Fixed in `48b8305`'s follow-up:** `open_with_key` now takes `pepper` and enforces the
policy exactly as `open_v4` does, so the pre-derived-key path cannot silently skip it;
`cargo fmt` applied to the two offending files.

**Lesson for this file:** a `needs:`-gated job that is skipped is not a job that
passed. Any future claim here should cite a run, not a local invocation.

### Structural fix (2026-09-16)

Restoring green was not enough — the workflow was built so that one lint could
silence everything. Changes:

- **`test`, `test-pqc` and `wasm` no longer declare `needs: check`.** A
  formatting failure can no longer skip the test suite. They run in parallel
  with `check` instead.
- **`--no-fail-fast` on the test jobs**, so one broken suite does not hide
  failures in the others (which is how the local reproduction was found).
- **New `Rust Tests (pqc feature)` job.** The `pqc` feature had never been
  built by CI at all. See below.
- **`cargo clippy --all-targets --features pqc`** added to `check`; clippy had
  never linted the PQC code paths.
- **`node web_demo/stress_test.mjs`** added to the `wasm` job. This is where the
  chi-squared and line-coverage figures quoted in the README come from, and CI
  had never run it, so those numbers were unverifiable by any automated gate.
  The same properties are now also asserted in `tests/steganalysis.rs`.

### What the missing PQC coverage was hiding

With `--features pqc` never built by CI, two failures had accumulated:

1. **The test suite did not compile.** `EmbedOptions` / `EmbedSecurityOptions`
   carry `#[cfg(feature = "pqc")]` fields, so exhaustive struct literals in the
   integration tests failed with E0063 as soon as the feature was on. Fixed by
   adding `EmbedOptions::new()` / `EmbedSecurityOptions::new()` constructors
   that fill feature-gated fields, and using them from the tests — so test code
   compiles identically with and without the feature.
2. **PQC embedding was broken end-to-end.** `embed --pqc-pk` failed with
   "Password must not be empty": `embed_with_options` wrapped every container in
   the v4 outer AEAD, which is keyed by Argon2id over the password, but PQC mode
   is keypair-based and has no password. PQC containers now take the pre-v4
   CRC-framed path; the steganographic tradeoff that implies is documented in
   the README's PQC section.

`tests/pqc_roundtrip.rs` also hardcoded `target/debug/snow2`, so it could only
pass in a debug build; it now uses `env!("CARGO_BIN_EXE_snow2")`.

---

## CI Workflow Files

### `.github/workflows/ci.yml` (NEW — added in this audit)

**Purpose:** Full Rust CI: lint, test, WASM build + test
**Trigger:** push to `main`, pull requests to `main`, manual dispatch

**Jobs:**

1. **check** — Check, Lint, Format
   - `ubuntu-latest`, Rust stable + clippy + rustfmt
   - `cargo fmt --check`
   - `cargo clippy --all-targets -- -D warnings`
   - `cargo build --release`

2. **test** — Rust Tests (needs: check)
   - `ubuntu-latest`, Rust stable
   - `cargo test -- --test-threads=2`

3. **wasm** — WASM Build + Tests (needs: check)
   - `ubuntu-latest`, Rust stable + `wasm32-unknown-unknown`
   - `wasm-pack build snow2_wasm --target web --out-dir ../web_demo/pkg`
   - `node web_demo/test_wasm.mjs` (48 tests)
   - `node web_demo/test_download_upload.mjs` (12 tests)

### `.github/workflows/pages.yml` (existing)

**Purpose:** Deploy web demo to GitHub Pages
**Trigger:** push to `main`, manual dispatch

**Jobs:**
1. **build** — Install Rust, build WASM, run `test_wasm.mjs`, upload Pages artifact
2. **deploy** — `actions/deploy-pages@v4`

---

## CI Coverage Matrix

| Check | ci.yml | pages.yml |
|---|---|---|
| `cargo fmt --check` | ✅ | — |
| `cargo clippy -- -D warnings` | ✅ | — |
| `cargo clippy --features pqc -- -D warnings` | ✅ | — |
| `cargo build --release` | ✅ | — |
| `cargo test` | ✅ | — |
| `cargo test --features pqc` | ✅ | — |
| WASM build | ✅ | ✅ |
| `test_wasm.mjs` | ✅ | ✅ |
| `test_download_upload.mjs` | ✅ | — |
| `stress_test.mjs` | ✅ | — |
| Fuzz | — | — |

**Fuzz row is blank on purpose.** `.github/workflows/fuzz.yml` exists —
scheduled daily at 04:17 UTC, 8 targets in a `fail-fast: false` matrix, 60s per
target, crash artifacts uploaded on failure — but it is **not** a PR gate, and
this row stays blank until that workflow has produced at least one completed
run. A workflow file is not coverage; a green run is.

It is deliberately off the PR path. It needs a nightly toolchain and a minute
per target, so as a required check it would be the first thing bypassed by
someone in a hurry — and a gate people route around teaches the team that red is
negotiable. That is the same class of mistake as `needs: check`: a gate that
appears to cover something while quietly not running.

Historical manual results (~6.3M runs, 0 crashes) are in FUZZ-RESULTS.md.

**All Rust quality gates are covered by CI** — but coverage is not the same as
execution. See [CI Outage](#ci-outage-2026-03-02--2026-09-16): the `needs: check`
dependency means a `cargo fmt` break silently skips every gate below it.

---

## Local Verification

Original run, 2025-07-21 (stale — retained for history):

| Check | Result |
|---|---|
| `cargo fmt --check` | PASS — 0 diffs |
| `cargo clippy --all-targets -- -D warnings` | PASS — 0 warnings |
| `cargo build --release` | PASS |
| `cargo test -- --test-threads=2` | PASS — 145 tests, 0 failed |
| WASM build | PASS |
| `node web_demo/test_wasm.mjs` | PASS — 48/48 |
| `node web_demo/test_download_upload.mjs` | PASS — 12/12 |

Re-verified 2026-09-16, after the outage fix:

| Check | Result |
|---|---|
| `cargo fmt --check` | PASS — 0 diffs |
| `cargo clippy --all-targets -- -D warnings` | PASS — 0 warnings |
| `cargo build --release` | PASS |
| `cargo test --release --no-fail-fast -- --test-threads=2` | PASS — 171 tests, 0 failed |
| WASM build | NOT RUN LOCALLY — `wasm-pack` not installed; left to CI |
| `node web_demo/test_wasm.mjs` | NOT RUN LOCALLY — requires the WASM build |
| `node web_demo/test_download_upload.mjs` | NOT RUN LOCALLY — requires the WASM build |

Per-suite breakdown of the 171: lib 3, adversarial 26, cross_platform 17,
negative_edge_cases 35, pepper_policy 25, robustness 38, roundtrip 3,
websafe_zw_platform 24. `pqc_roundtrip` reports 0 — it is gated behind
`--features pqc`, which this run did not enable.

---

## Fresh Checkout Behavior

| Check | Result |
|---|---|
| `cargo build` | PASS — builds from clean checkout |
| `cargo test` | PASS — all 145 tests pass |
| `web_demo/pkg/` exists | NO — gitignored, must be built first |
| `node web_demo/test_wasm.mjs` (no build) | FAIL — clear error message (pre-check) |
| `node web_demo/test_download_upload.mjs` (no build) | FAIL — clear error message (pre-check) |
