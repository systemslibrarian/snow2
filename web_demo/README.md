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
3. Embedding creates a SNOW2 v1 container (Argon2id → HKDF-SHA256 domain-separated key derivation → XChaCha20-Poly1305 AEAD), converts it to a CRC-32-framed bitstream, and encodes it as zero-width Unicode characters inserted into the carrier text
4. Extraction validates KDF bounds from the container header, then reverses the process: strips zero-width characters → bitstream → CRC-32 check → container bytes → AEAD decrypt

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
- KDF with high memory settings may be slow in WASM
- WASM cannot use mlock — sensitive memory is zeroized on drop but not locked against swapping
- KDF parameters must stay within extraction bounds (8–4096 MiB, 1–64 iters, 1–16 parallelism)
