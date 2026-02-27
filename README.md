# SNOW2 ❄️  
*A modern Rust tribute to Matthew Kwan’s SNOW steganography tool.*

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

SNOW2 hides an encrypted payload inside a text “carrier” using whitespace-based steganography.

You provide:

- A message or file
- A password
- Optional second secret (pepper / “Signal Key”)

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
  - Tunable parameters

### Optional Pepper (“Signal Key”)
- A second secret never stored in the carrier
- Combined into key derivation
- If missing or incorrect → decryption fails
- Not required, but strongly encouraged

### Pepper-required policy
SNOW2 can *require* a pepper for decryption.

If enabled at embed time, the container is marked **pepper_required=true** (authenticated in the header).  
Extraction will fail if the pepper is not provided — even if the password is correct.

This is useful when you want “password + something else you know” by policy.

---

## Steganography Modes

SNOW2 supports multiple embedding strategies.

### `classic-trailing`
- Trailing spaces and tabs
- Direct homage to original SNOW
- Most elegant
- Most fragile (subject to whitespace trimming)

### `websafe-zw`
- Zero-width Unicode embedding
- More copy/paste tolerant
- Better suited for browser/WASM usage

---

## Important Limitations

Whitespace steganography can be fragile.

Many tools may:
- Trim trailing spaces
- Normalize whitespace
- Rewrap lines
- Strip zero-width characters

If the carrier changes, extraction will fail — intentionally. SNOW2 treats integrity as mandatory.

This project is designed primarily as:

- An educational cryptography demonstration
- A respectful tribute
- A modern reference implementation
- A nostalgic but serious rebuild

---

## Quick Start (CLI)

### 1) Build
```bash
cargo build --release
./target/release/snow2 --help
```

### 2) Generate a carrier (recommended for demos)
Right now, `classic-trailing` embeds **1 bit per non-empty line**, so you often need thousands of lines.

A helper script is included:

```bash
chmod +x scripts/make_carrier.sh
./scripts/make_carrier.sh 6000 carrier.txt
```

### 3) Embed a message
```bash
cargo run -- embed \
  --mode classic-trailing \
  --carrier carrier.txt \
  --out out.txt \
  --message "hello snow2" \
  --password "pw"
```

### 4) Extract
```bash
cargo run -- extract \
  --mode classic-trailing \
  --carrier out.txt \
  --out recovered.bin \
  --password "pw"

cat recovered.bin
```

---

## Security Options (CLI)

### Pepper / Signal Key
Use a second secret:

```bash
cargo run -- embed \
  --mode classic-trailing \
  --carrier carrier.txt \
  --out out.txt \
  --message "hello" \
  --password "pw" \
  --pepper "signal key"
```

Extract must include the same pepper:

```bash
cargo run -- extract \
  --mode classic-trailing \
  --carrier out.txt \
  --out recovered.bin \
  --password "pw" \
  --pepper "signal key"
```

### Require pepper by policy
This forces “password + pepper” for anyone who tries to decrypt later:

```bash
cargo run -- embed \
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

- `--kdf-mib` (memory cost in MiB, default 64)
- `--kdf-iters` (iterations/time cost, default 3)
- `--kdf-par` (parallelism, default 1)

Example:

```bash
cargo run -- embed \
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

## Building a single portable binary

### Standard release binary
```bash
cargo build --release
```

### Static Linux build (musl)
```bash
rustup target add x86_64-unknown-linux-musl
sudo apt-get install -y musl-tools
cargo build --release --target x86_64-unknown-linux-musl
```

This produces a portable single binary.

---

## Browser / WASM Mode (Planned)

SNOW2 core logic is designed to compile to WebAssembly.

This allows:

- Fully client-side encryption
- Static site deployment (e.g., GitHub Pages)
- No server-side crypto
- Offline capability

Important: The browser demo is convenience UI, not the security boundary. Users should understand whitespace normalization risks when copy/pasting.

---

## Tribute

Original SNOW was written by **Matthew Kwan** and released under the GNU GPL.

SNOW2 is an independent modern rewrite created in admiration of that work. It does not reuse original code but preserves the idea, the elegance, and the educational spirit.

If SNOW taught a generation how clever text-based steganography could be, SNOW2 aims to show how it can be done responsibly in 2026.

---

## License

GPL-3.0-or-later

---
