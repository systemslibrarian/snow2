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
| `cargo build --release` | ✅ | — |
| `cargo test` | ✅ | — |
| WASM build | ✅ | ✅ |
| `test_wasm.mjs` | ✅ | ✅ |
| `test_download_upload.mjs` | ✅ | — |
| Fuzz | — | — |

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
