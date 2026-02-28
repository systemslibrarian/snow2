# Start the SNOW2 Web Demo

## Prerequisites

Build the WASM package first (from repo root):

```bash
cd snow2_wasm
wasm-pack build --target web --out-dir web_demo/pkg
cp -r web_demo/pkg ../web_demo/pkg
```

## Serve

```bash
python3 -m http.server 8000 -d web_demo
```

Then open http://localhost:8000 in your browser.
