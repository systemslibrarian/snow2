# SNOW2 Web Demo (GitHub Pages)

This folder is a static web UI that loads the SNOW2 Rust core compiled to WebAssembly.

## Build WASM

From repo root:

```bash
cargo install wasm-pack
wasm-pack build snow2_wasm --target web --out-dir web_demo/pkg