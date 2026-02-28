# SNOW2 ❄️  
*A modern Rust tribute to Matthew Kwan's SNOW steganography tool.*

SNOW2 is a clean, modern reimplementation inspired by the original **SNOW** program by **Matthew Kwan** — a classic late-1990s tool that demonstrated how encrypted messages could be hidden inside ordinary-looking text using whitespace.

This project preserves the elegance and educational value of the original while upgrading the cryptography, safety, and engineering for today.

---

## Philosophy

The original SNOW was brilliant because it taught two powerful concepts quickly:

1. **Encryption** protects meaning.
2. **Steganography** hides existence.

SNOW2 keeps that same spirit:

- Small
- Understandable
- Educational
- Respectful of the original design

But cryptographically modern and safer by default.

---

## What SNOW2 Does

SNOW2 hides an encrypted payload inside a text "carrier" using whitespace-based steganography.

You provide:

- A message or file
- A password
- Optional second secret (pepper / "Signal Key")

SNOW2 produces:

- A modified text file that looks normal
- A recoverable encrypted payload embedded invisibly

Extraction requires the correct secrets. Tampering causes authenticated failure.

---

## Modern Cryptography

SNOW2 upgrades the crypto model completely.

### AEAD Encryption
- **XChaCha20-Poly1305**
  - Large nonce space
  - Misuse-resistant
  - Authenticated encryption (confidentiality + integrity)

### Password Hardening
- **Argon2id**
  - Memory-hard
  - GPU-resistant
  - Tunable parameters (`--kdf-mib`, `--kdf-iters`, `--kdf-par`)

### Optional Pepper ("Signal Key")
- A second secret never stored in the carrier
- Combined into key derivation
- If missing or incorrect → decryption fails
- Not required, but strongly encouraged

### Pepper-required policy
SNOW2 can *require* a pepper for decryption.

If enabled at embed time, the container is marked **pepper_required=true** (authenticated in the header).  
Extraction will fail if the pepper is not provided — even if the password is correct.

This is useful when you want "password + something else you know" by policy.

### Secure Memory
- **SecureVec**: mlock'd, guard-paged, zeroize-on-drop memory buffers (native targets)
- Passwords zeroized from memory after use
- On WASM targets, falls back to zeroize-on-drop Vec wrappers (no mlock available)

---

## Post-Quantum Cryptography (Optional)

SNOW2 supports **hybrid post-quantum encryption** via the optional `pqc` feature flag.

When enabled, containers use a **Version 2** format with:

- **Kyber1024** (ML-KEM) — NIST-standardized lattice-based key encapsulation
- **Dilithium5** (ML-DSA) — NIST-standardized lattice-based digital signatures
- **Hybrid encryption** — Kyber KEM shared secret → HKDF → XChaCha20-Poly1305
- **Authenticated containers** — every PQC container is signed with Dilithium5

PQC mode does not use passwords. Instead, you generate a keypair and use key files.

### Build with PQC support
```bash
cargo build --release --features pqc
```

### Generate a PQC keypair
```bash
snow2 pqc-keygen --pk-out key.pk --sk-out key.sk
```

### Embed with PQC
```bash
snow2 embed \
  --mode classic-trailing \
  --carrier carrier.txt \
  --out out.txt \
  --input secret.txt \
  --pqc-pk key.pk
```

### Extract with PQC
```bash
snow2 extract \
  --mode classic-trailing \
  --carrier out.txt \
  --out recovered.txt \
  --pqc-sk key.sk
```

> **Note:** PQC containers are significantly larger than password-based containers (~10 KB overhead for Kyber ciphertext + Dilithium signature). Ensure your carrier has enough lines.

---

## Steganography Modes

SNOW2 supports multiple embedding strategies.

### `classic-trailing`
- Trailing spaces and tabs encode bits at the end of each line
- Direct homage to original SNOW
- Most elegant
- Most fragile (subject to whitespace trimming by editors/tools)

### `websafe-zw`
- Zero-width Unicode character embedding (U+200B, U+200C, U+200D, U+FEFF)
- More copy/paste tolerant
- Better suited for browser/WASM usage
- Some platforms may strip zero-width characters

---

## Important Limitations

Whitespace steganography can be fragile.

Many tools may:
- Trim trailing spaces
- Normalize whitespace
- Rewrap lines
- Strip zero-width characters

If the carrier changes, extraction will fail — intentionally. SNOW2 treats integrity as mandatory.

Use the `scan` command to check a carrier for existing whitespace or zero-width characters before embedding.

---

## Quick Start (CLI)

### 1) Build
```bash
cargo build --release
./target/release/snow2 --help
```

### 2) Generate a carrier (recommended for demos)
`classic-trailing` embeds **1 bit per non-empty line**, so you often need thousands of lines.

A helper script is included:

```bash
chmod +x scripts/make_carrier.sh
./scripts/make_carrier.sh 6000 carrier.txt
```

### 3) Embed a message
```bash
snow2 embed \
  --mode classic-trailing \
  --carrier carrier.txt \
  --out out.txt \
  --message "hello snow2" \
  --password "pw"
```

### 4) Extract
```bash
snow2 extract \
  --mode classic-trailing \
  --carrier out.txt \
  --out recovered.bin \
  --password "pw"

cat recovered.bin
```

### 5) Scan a carrier
Inspect a carrier file for existing embedded data or whitespace anomalies:

```bash
snow2 scan --carrier carrier.txt
```

---

## Security Options (CLI)

### Pepper / Signal Key
Use a second secret:

```bash
snow2 embed \
  --mode classic-trailing \
  --carrier carrier.txt \
  --out out.txt \
  --message "hello" \
  --password "pw" \
  --pepper "signal key"
```

Extract must include the same pepper:

```bash
snow2 extract \
  --mode classic-trailing \
  --carrier out.txt \
  --out recovered.bin \
  --password "pw" \
  --pepper "signal key"
```

### Require pepper by policy
This forces "password + pepper" for anyone who tries to decrypt later:

```bash
snow2 embed \
  --mode classic-trailing \
  --carrier carrier.txt \
  --out out.txt \
  --message "hello" \
  --password "pw" \
  --pepper "signal key" \
  --pepper-required
```

If someone tries to extract without the pepper, it will fail.

### Tune Argon2id (KDF)
Defaults are reasonable for interactive use, but you can harden:

| Flag | Default | Description |
|------|---------|-------------|
| `--kdf-mib` | 64 | Memory cost in MiB |
| `--kdf-iters` | 3 | Iterations / time cost |
| `--kdf-par` | 1 | Parallelism |

Example:

```bash
snow2 embed \
  --mode classic-trailing \
  --carrier carrier.txt \
  --out out.txt \
  --message "hello" \
  --password "pw" \
  --pepper "signal key" \
  --pepper-required \
  --kdf-mib 128 \
  --kdf-iters 4 \
  --kdf-par 1
```

---

## Container Format

SNOW2 uses a self-describing binary container:

```
[MAGIC "SNOW2" (5)] [VERSION (1)] [HEADER_LEN u32 LE (4)] [HEADER_JSON] [CIPHERTEXT]
```

- **Version 1** (classic): password-based, XChaCha20-Poly1305 AEAD
- **Version 2** (PQC): hybrid Kyber1024 + XChaCha20-Poly1305, signed with Dilithium5

The header JSON is authenticated as AEAD additional data (AAD). It contains KDF parameters, salt, nonce, mode, and policy flags — all cryptographically bound to the ciphertext.

PQC containers additionally include a Dilithium5 signature over the ciphertext, with the format:

```
[MAGIC] [VERSION=2] [HEADER_LEN] [HEADER_JSON] [SIG_LEN u16 LE] [SIGNATURE] [CIPHERTEXT]
```

---

## Building

### Standard release binary
```bash
cargo build --release
```

### With PQC support
```bash
cargo build --release --features pqc
```

### Static Linux build (musl)
```bash
rustup target add x86_64-unknown-linux-musl
sudo apt-get install -y musl-tools
cargo build --release --target x86_64-unknown-linux-musl
```

### Run tests
```bash
cargo test -p snow2              # without PQC
cargo test -p snow2 --features pqc  # with PQC
```

---

## Browser / WASM Demo

SNOW2 compiles to WebAssembly for fully client-side encryption in the browser.

The `web_demo/` folder contains a static web UI that loads the SNOW2 Rust core via WASM. It uses the `websafe-zw` mode (zero-width embedding), which is more tolerant of browser copy/paste behavior.

Features:
- Fully client-side — no server-side crypto, all processing in the browser
- Configurable Argon2id KDF parameters
- Pepper / Signal Key support with optional pepper-required policy
- Carrier generation and download
- Extract with UTF-8 preview and raw binary download

### Build the WASM package
```bash
cargo install wasm-pack
cd snow2_wasm
wasm-pack build --target web --out-dir web_demo/pkg
cp -r web_demo/pkg ../web_demo/pkg
```

### Serve locally
```bash
python3 -m http.server 8000 -d web_demo
```

Then open http://localhost:8000.

> **Important:** The browser demo is convenience UI, not the security boundary. Users should understand whitespace normalization risks when copy/pasting.

---

## Project Structure

```
src/
  main.rs             CLI entry point (clap)
  lib.rs              Library API (embed / extract / embed_with_options)
  config.rs           EmbedOptions, EmbedSecurityOptions, PqKeys
  container.rs        SNOW2 container format (seal / open / serialize)
  crypto.rs           AEAD, KDF (Argon2id), random bytes
  secure_mem.rs       SecureVec (mlock + guard pages on native, zeroize on WASM)
  pqc.rs              Post-quantum crypto: Kyber1024 + Dilithium5 [optional]
  stego/
    mod.rs            Bit/byte conversion utilities
    classic_trailing.rs   Trailing whitespace steganography
    websafe_zw.rs         Zero-width Unicode steganography
snow2_wasm/           WASM crate for browser demo
  src/lib.rs          wasm-bindgen bindings
web_demo/             Static web UI (HTML/CSS/JS + WASM pkg)
tests/
  roundtrip.rs        Classic embed/extract roundtrip tests
  pepper_policy.rs    Pepper-required policy + KDF tuning tests
  pqc_roundtrip.rs    PQC keygen + embed/extract roundtrip test
scripts/
  make_carrier.sh     Helper to generate carrier files
```

---

## Tribute

Original SNOW was written by **Matthew Kwan** and released under the GNU GPL.

SNOW2 is an independent modern rewrite created in admiration of that work. It does not reuse original code but preserves the idea, the elegance, and the educational spirit.

If SNOW taught a generation how clever text-based steganography could be, SNOW2 aims to show how it can be done responsibly in 2026.

---

## License

GPL-3.0-or-later
