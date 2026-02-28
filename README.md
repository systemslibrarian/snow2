# SNOW2 ❄️  
*A modern Rust tribute to Matthew Kwan's SNOW steganography tool.*

**[Try the live demo →](https://systemslibrarian.github.io/snow2/)**

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

### Key Derivation (Domain-Separated)
- **Argon2id** → master secret, then **HKDF-SHA256** expansion with domain labels
  - Memory-hard, GPU-resistant
  - Tunable parameters (`--kdf-mib`, `--kdf-iters`, `--kdf-par`)
  - Domain labels: `snow2/aead-key`, `snow2/pepper-binding`
  - Pepper bound via HKDF salt — no concatenation ambiguity

### Extraction-Side KDF Bounds
- Untrusted container headers are validated **before** any expensive KDF work
- Hard limits reject absurd memory/time cost values from hostile containers
- Bounds: max 512 MiB memory, max 64 iterations, max 16 parallelism, min 8 MiB memory
- Both embedding and extraction validate KDF params — you can't create un-extractable containers

### Hardened Profile
- `KdfParams::hardened()` — 256 MiB / t=4 / p=1 for high-value secrets
- `EmbedSecurityOptions::hardened()` — hardened KDF + mandatory pepper

### Optional Pepper ("Signal Key")
- A second secret never stored in the carrier
- Cryptographically bound via HKDF domain separation (not concatenation)
- If missing or incorrect → decryption fails
- Not required, but strongly encouraged

### Pepper-required policy
SNOW2 can *require* a pepper for decryption.

If enabled at embed time, the container is marked **pepper_required=true** (authenticated in the header).  
Extraction will fail if the pepper is not provided — even if the password is correct.

This is useful when you want "password + something else you know" by policy.

### Secure Memory
- **SecureVec**: mlock'd, guard-paged, zeroize-on-drop memory buffers (native targets)
- Intermediate plaintext from AEAD decryption is zeroized after copy to SecureVec
- Passwords zeroized from memory after use
- On WASM targets, falls back to zeroize-on-drop Vec wrappers (no mlock available)

### Bitstream Integrity (CRC-32)
- Container bytes are framed with a length prefix and CRC-32 checksum before stego embedding
- Catches carrier corruption (whitespace stripping, copy-paste mangling) with a clear error
  before the container parser or AEAD sees it

---

## Post-Quantum Cryptography (Optional)

SNOW2 supports **hybrid post-quantum encryption** via the optional `pqc` feature flag.

When enabled, containers use a **Version 2** format with:

- **Kyber1024** (ML-KEM) — NIST-standardized lattice-based key encapsulation
- **Dilithium5** (ML-DSA) — NIST-standardized lattice-based digital signatures
- **Hybrid encryption** — Kyber KEM shared secret → HKDF → XChaCha20-Poly1305
- **Authenticated containers** — every PQC container is signed with Dilithium5
- **Encrypted key storage** — secret keys can be encrypted at rest with password-derived AEAD
  - Versioned format (`SNOW2EK\0` magic + version byte) for future evolution
  - Version byte authenticated as AEAD AAD to prevent downgrade attacks
- **Hardened file permissions** — secret key files written with 0o600 (Unix) via atomic rename

PQC mode does not use passwords. Instead, you generate a keypair and use key files.

### Build with PQC support
```bash
cargo build --release --features pqc
```

### Generate a PQC keypair
```bash
snow2 pqc-keygen --pk-out key.pk --sk-out key.sk
# With encrypted secret key:
snow2 pqc-keygen --pk-out key.pk --sk-out key.sk --sk-password "my password"
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
# If key is encrypted:
snow2 extract \
  --mode classic-trailing \
  --carrier out.txt \
  --out recovered.txt \
  --pqc-sk key.sk \
  --pqc-sk-password "my password"
```

> **Note:** PQC containers are significantly larger than password-based containers (~10 KB overhead for Kyber ciphertext + Dilithium signature). Ensure your carrier has enough lines.

---

## Steganography Modes

SNOW2 supports multiple embedding strategies.

> **Recommendation:** For reliable day-to-day use, prefer **`websafe-zw`** mode or work with **file-based carriers** that won't be processed by editors, mail clients, or CI tools. Reserve `classic-trailing` for educational purposes, controlled environments, or when faithfulness to the original SNOW is desired.

### `classic-trailing`
- Trailing spaces and tabs encode bits at the end of each line
- Direct homage to original SNOW
- Most elegant
- **Most fragile** — trailing whitespace is silently stripped by most text editors, Git hooks, linters, formatters, email systems, and CI pipelines. If the carrier passes through *any* of these, the payload is destroyed.

### `websafe-zw` *(recommended)*
- Zero-width Unicode character embedding (U+200B, U+200C)
- **8 bits per line** — each carrier line can hold a full byte, dramatically reducing carrier size
- Survives copy/paste, most editors, and many messaging apps
- Better suited for browser/WASM usage
- Some platforms may strip zero-width characters (Unicode normalization, clipboard sanitizers)

---

## Important Limitations

Whitespace steganography is inherently fragile. **Strong encryption does not mean perfect steganographic undetectability.**

### Trailing whitespace (`classic-trailing` mode)
- Most text editors have "trim trailing whitespace on save" enabled **by default** — VS Code, JetBrains, Vim, and others will silently destroy the payload on save
- Git can be configured to strip trailing whitespace (`core.whitespace`)
- Linters, formatters, CI tools, and email systems routinely normalize whitespace
- This is the most fragile mode, but also the most faithful to the original SNOW
- **For reliability, use `websafe-zw` mode or exchange carriers as untouched files**

### Zero-width characters (`websafe-zw` mode)
- More tolerant of copy/paste than trailing whitespace
- Survives in many browsers, rich-text editors, and messaging apps
- Can still be stripped by: Unicode normalization (NFKC/NFKD), some messaging platforms, clipboard sanitizers, or HTML rendering
- Not "bulletproof" — just "more resilient"

### General
- If the carrier changes in any way, extraction will fail — this is by design (integrity is mandatory via AEAD)
- File modification metadata (timestamps, sizes) may reveal that a file has been altered
- A forensic analyst comparing the original carrier to the modified carrier can detect embedding

Use the `scan` command to check a carrier before embedding. It reports:
- Stego capacity (raw bits and estimated payload max after container overhead)
- Line ending format (LF vs CRLF vs mixed)
- Tab character warnings (editor auto-expansion risk)
- Existing trailing whitespace or zero-width characters
- Consecutive marker run detection (signs of existing embedded data)
- CRLF normalization risk warnings
- Per-mode fragility notes

---

## Quick Start (CLI)

### 1) Build
```bash
cargo build --release
./target/release/snow2 --help
```

### 2) Generate a carrier (recommended for demos)
`classic-trailing` embeds **1 bit per non-empty line**; `websafe-zw` embeds **8 bits per line** (a full byte), so it needs far fewer lines.

A helper script is included:

```bash
chmod +x scripts/make_carrier.sh
./scripts/make_carrier.sh 6000 carrier.txt
```

### 3) Embed a message
```bash
snow2 embed \
  --mode websafe-zw \
  --carrier carrier.txt \
  --out out.txt \
  --message "hello snow2" \
  --password "pw"
```

> **Tip:** `websafe-zw` is recommended for most use cases — it survives copy/paste and editor saves far better than `classic-trailing`. Use `classic-trailing` when you want exact fidelity to the original SNOW behaviour.

### 4) Extract
```bash
snow2 extract \
  --mode websafe-zw \
  --carrier out.txt \
  --out recovered.bin \
  --password "pw"

cat recovered.bin
```

### 5) Scan a carrier
Inspect a carrier file for capacity, existing embedded data, or corruption risks:

```bash
snow2 scan --carrier carrier.txt
```

### 6) Best-effort file shredding
Overwrite and remove a file (see caveats below):

```bash
snow2 shred --path sensitive.txt --passes 3
```

> **Note:** File shredding is best-effort. On SSDs with wear-leveling, CoW filesystems (btrfs, ZFS), or journaling filesystems, overwritten data may persist in spare blocks, snapshots, or journals. For high-assurance deletion, use full-disk encryption and destroy the key.

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
| `--kdf-mib` | 64 | Memory cost in MiB (min 8, max 512) |
| `--kdf-iters` | 3 | Iterations / time cost (min 1, max 64) |
| `--kdf-par` | 1 | Parallelism (min 1, max 16) |

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

- **Version 1** (classic): password-based, Argon2id → HKDF → XChaCha20-Poly1305 AEAD
- **Version 2** (PQC): hybrid Kyber1024 + XChaCha20-Poly1305, signed with Dilithium5

The header JSON is authenticated as AEAD additional data (AAD). It contains KDF parameters, salt, nonce, mode, and policy flags — all cryptographically bound to the ciphertext.

Header length is capped at 64 KiB during parsing to prevent hostile allocation.

PQC containers additionally include a Dilithium5 signature over the ciphertext, with the format:

```
[MAGIC] [VERSION=2] [HEADER_LEN] [HEADER_JSON] [SIG_LEN u16 LE] [SIGNATURE] [CIPHERTEXT]
```

### Encrypted Secret Key Format (PQC)

```
[SNOW2EK\0 (8)] [VERSION (1)] [SALT (16)] [NONCE (24)] [AEAD CIPHERTEXT]
```

Version byte is authenticated as AEAD AAD alongside the magic, preventing downgrade attacks.

---

## Security Model

### What SNOW2 protects against
- **Passive observers**: Carrier text looks normal; payload is invisible
- **Wrong password/pepper**: AEAD authentication fails — no partial decryption
- **Carrier tampering**: CRC-32 catches stego corruption before AEAD; AEAD catches everything else
- **Header tampering**: Header JSON is AEAD AAD — any modification causes auth failure
- **KDF bounds**: Extraction-side bounds reject absurd KDF parameters from hostile containers
- **Weak KDF at embed time**: Embedding validates KDF params against the same bounds
- **Key file exposure**: PQC secret keys can be encrypted at rest with password-derived AEAD
- **File permission leaks**: Sensitive files written with restricted permissions via atomic rename

### What SNOW2 does NOT protect against
- **Active carrier modification**: If someone can modify the carrier text (trim whitespace, normalize Unicode), extraction will fail. This is by design — integrity is mandatory.
- **Traffic analysis**: SNOW2 does not hide the fact that a file has been modified (file size changes, metadata, etc.)
- **Guaranteed secure deletion**: File shredding is best-effort. SSDs, CoW filesystems, and journals may retain data.
- **WASM security boundaries**: The browser demo uses zeroize-on-drop but cannot mlock memory
- **Steganographic undetectability**: Strong crypto does not mean perfect steganographic undetectability. A motivated analyst examining trailing whitespace patterns or file diffs could detect that data has been embedded. SNOW2 hides data from casual observation, not from forensic analysis.

### Important security caveats

- **Trailing whitespace is fragile.** Most text editors (VS Code, vim, Sublime, etc.) have settings to strip trailing whitespace on save. Git hooks, linters, and formatting tools often do the same. If the carrier passes through any of these, embedded data is destroyed. This is inherent to whitespace steganography, not a SNOW2 bug.

- **Zero-width Unicode is more resilient, but not bulletproof.** Zero-width characters (U+200B, U+200C) survive copy/paste in many contexts (browsers, rich-text editors, some messaging apps). However, Unicode normalization (NFC/NFD/NFKC/NFKD), some messaging platforms (Slack, Discord), and clipboard sanitizers may strip them.

- **CRC-32 is not a cryptographic integrity check.** The CRC-32 in the bitstream framing catches accidental corruption (whitespace stripping, copy-paste mangling) early, before the container parser or AEAD sees it. It is not a security boundary — AEAD provides the actual cryptographic integrity guarantee.

- **Shred/wipe is best-effort only.** On SSDs with wear-leveling, CoW filesystems (btrfs, ZFS), or journaling filesystems, overwritten data may persist. For high-assurance deletion, use full-disk encryption and destroy the key.

- **PQC is optional and experimental.** Post-quantum crypto (Kyber1024 + Dilithium5) is available as an optional feature for users who want it. It is not the default identity of the tool. PQC containers are significantly larger (~10 KB overhead) and use different trust assumptions (keypair-based, not password-based).

- **The browser/WASM demo is not the main security boundary.** It is a convenience UI for demonstration. In WASM, `mlock` is unavailable, and JavaScript's garbage collection may leave copies of sensitive data in memory.

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

> **Important:** The browser demo is convenience UI, not the security boundary. Users should understand whitespace normalization risks when copy/pasting. The WASM environment cannot use mlock and provides weaker memory protections than native builds.

---

## What has changed vs. original SNOW

The original SNOW (by Matthew Kwan, late 1990s) was a C program that:
- Used ICE encryption (a block cipher by the same author)
- Encoded data in trailing whitespace (tabs and spaces)
- Ran on Unix and Windows
- Was simple, elegant, and educational

SNOW2 preserves the spirit but is a complete rewrite:
- **Language**: Rust (memory-safe, no buffer overflows)
- **Encryption**: XChaCha20-Poly1305 AEAD (authenticated encryption, large nonce space)
- **Key derivation**: Argon2id + HKDF-SHA256 (memory-hard, domain-separated)
- **Integrity**: AEAD authentication + CRC-32 corruption detection
- **Modes**: Classic trailing whitespace (tribute mode, 1 bit/line) + zero-width Unicode (web-friendly, 8 bits/line)
- **Optional PQC**: Hybrid Kyber1024 + Dilithium5 post-quantum crypto
- **Secure memory**: mlock'd buffers with guard pages, zeroize-on-drop

What remains the same:
- Text-steganography identity ("hide in plain sight")
- Simplicity and educational clarity
- Whitespace as the invisible channel
- Single-binary CLI tool
- The charm of hiding messages where nobody looks

---

## Project Structure

```
src/
  main.rs             CLI entry point (clap)
  lib.rs              Library API (embed / extract / embed_with_options)
  config.rs           EmbedOptions, EmbedSecurityOptions, PqKeys
  container.rs        SNOW2 container format (seal / open / serialize / parse)
  crypto.rs           AEAD, KDF (Argon2id + HKDF), extraction bounds, random bytes
  secure_mem.rs       SecureVec (mlock + guard pages on native, zeroize on WASM)
  secure_fs.rs        Atomic writes, permission hardening, best-effort shredding
  pqc.rs              Post-quantum crypto: Kyber1024 + Dilithium5 [optional]
  stego/
    mod.rs            Bit/byte conversion + CRC-32 bitstream framing
    classic_trailing.rs   Trailing whitespace steganography
    websafe_zw.rs         Zero-width Unicode steganography
snow2_wasm/           WASM crate for browser demo
  src/lib.rs          wasm-bindgen bindings
web_demo/             Static web UI (HTML/CSS/JS + WASM pkg)
tests/
  roundtrip.rs        Classic embed/extract roundtrip tests
  pepper_policy.rs    Pepper policy, KDF bounds, embed-side validation,
                      malformed container rejection tests
  pqc_roundtrip.rs    PQC keygen + embed/extract roundtrip test
  negative_edge_cases.rs  Malformed input, corruption, boundary tests
  cross_platform.rs   CRLF/LF, Unicode, platform survivability tests
fuzz/
  fuzz_targets/       Fuzz targets for container parse, bitstream, stego extract
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
