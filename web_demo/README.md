# SNOW2 Web Demo

This folder is a static web UI that loads the SNOW2 Rust core compiled to WebAssembly.

All encryption and steganography happens **entirely in the browser** — no server-side processing.

## Features

- **Embed**: Hide a message inside carrier text using `websafe-zw` (zero-width Unicode) mode
- **Extract**: Recover hidden messages from carrier text
- **Security settings**: Password, optional pepper / Signal Key, pepper-required policy
- **Tunable KDF**: Configurable Argon2id memory, iterations, and parallelism
- **Carrier tools**: Generate carrier text, download output files
- **Extract output**: UTF-8 text preview + raw binary download

## Build WASM

From repo root:

```bash
cargo install wasm-pack
cd snow2_wasm
wasm-pack build --target web --out-dir web_demo/pkg
cp -r web_demo/pkg ../web_demo/pkg
```

## Serve Locally

```bash
python3 -m http.server 8000 -d web_demo
```

Then open http://localhost:8000.

## How It Works

1. `app.js` imports `embed_websafe_zw` and `extract_websafe_zw` from the WASM package
2. The WASM module (`snow2_wasm`) wraps the snow2 Rust library with wasm-bindgen bindings
3. **Embedding** uses the v4 hardened pipeline:
   - Builds a SNOW2 v4 container (optional deflate compression → Argon2id → HKDF-SHA256 domain-separated key → XChaCha20-Poly1305 inner AEAD)
   - Pads to a constant-size bucket (multiples of 64 bytes) to mask message length
   - Outer-encrypts the padded container with a BLAKE3-derived key + XChaCha20-Poly1305
   - Converts to raw bits (no CRC framing — outer AEAD provides integrity)
   - Embeds bits into carrier lines as zero-width Unicode (U+200B = 0, U+200C = 1), **8 bits per line**
   - **Random-fills ALL remaining carrier lines** with random ZW content — eliminates statistical boundary between message and padding
4. **Extraction** tries the v4 path first (extract all bits → try outer AEAD decrypt for each bucket size → unpad → parse v4 container → inner AEAD decrypt → optional inflate). Falls back to legacy CRC-framed path for v1/v3 containers.
5. **Steg resistance**: The embedded bitstream is indistinguishable from uniform random noise (chi-squared ≈ 255 with 256/256 unique byte values). Every carrier line carries ZW content.

## File Structure

```
web_demo/
  index.html     Main page
  app.js         Application logic (embed/extract UI)
  style.css      Styling
  pkg/           WASM package (built by wasm-pack, gitignored)
```

## Limitations

- Uses `websafe-zw` mode only (best for browser copy/paste)
- Some platforms may strip zero-width characters
- No PQC support in the browser demo (PQC is CLI-only)
- KDF with high memory settings may be slow in WASM — the WASM build caps KDF at **128 MiB memory, 8 iterations, 4 parallelism** to prevent browser OOM
- WASM cannot use mlock — sensitive memory is zeroized on drop but not locked against swapping
