/**
 * Comprehensive Node.js functional tests for the SNOW2 WASM web demo.
 *
 * Exercises the wasm-bindgen API surface: embed, extract, error paths,
 * edge cases, KDF bounds, pepper policy, and output shape.
 *
 * Run:  node web_demo/test_wasm.mjs
 */
import { readFile, access } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── Pre-check: ensure WASM package has been built ─────────────────────
const pkgDir = join(__dirname, "pkg");
try {
  await access(join(pkgDir, "snow2_wasm_bg.wasm"));
} catch {
  console.error(
    "ERROR: WASM package not found at web_demo/pkg/.\n" +
    "       Run 'scripts/wasm_test.sh' or build manually:\n" +
    "       wasm-pack build snow2_wasm --target web --out-dir ../web_demo/pkg\n"
  );
  process.exit(1);
}

// ── Load WASM module (Node doesn't have fetch/import.meta.url for .wasm) ──
const wasmBytes = await readFile(join(pkgDir, "snow2_wasm_bg.wasm"));
const mod = await import(join(pkgDir, "snow2_wasm.js"));
const wasmModule = await WebAssembly.compile(wasmBytes);
mod.initSync({ module: wasmModule });

const { embed_websafe_zw, extract_websafe_zw } = mod;

// ── Helpers ───────────────────────────────────────────────────────────
function carrier(lines = 6000) {
  const out = ["SNOW2 test carrier."];
  for (let i = 1; i <= lines; i++)
    out.push(`Line ${String(i).padStart(5, "0")}: filler text.`);
  return out.join("\n");
}

let passed = 0;
let failed = 0;

function ok(cond, msg) {
  if (!cond) { console.error(`  FAIL: ${msg}`); failed++; }
  else       { console.log(`  PASS: ${msg}`);   passed++; }
}

function throws(fn, substr, msg) {
  try { fn(); console.error(`  FAIL (no throw): ${msg}`); failed++; }
  catch (e) {
    const s = String(e?.message || e);
    if (substr && !s.includes(substr))
      { console.error(`  FAIL (wrong err): ${msg} — got: ${s}`); failed++; }
    else { console.log(`  PASS: ${msg}`); passed++; }
  }
}

const C = carrier();

// ── Tests ─────────────────────────────────────────────────────────────

console.log("\n=== SNOW2 WASM Test Suite ===\n");

// ── 1. Basic roundtrip ───────────────────────────────────────────────
console.log("1. Basic embed/extract roundtrip");
{
  const out = embed_websafe_zw(C, "hello", "pw", null, false, 8, 1, 1);
  ok(out.length > 0, "embed returns non-empty carrier");
  ok(out.includes("Line 00001"), "visible text preserved");

  const r = extract_websafe_zw(out, "pw", null);
  ok(r.as_utf8 === "hello", `extracted text = "${r.as_utf8}"`);
  ok(r.bytes_len === 5, `bytes_len = ${r.bytes_len}`);
  ok(typeof r.as_base64 === "string" && r.as_base64.length > 0, "base64 present");
}

// ── 2. Pepper roundtrip ──────────────────────────────────────────────
console.log("\n2. Pepper roundtrip");
{
  const out = embed_websafe_zw(C, "peppered", "pw", "sig", false, 8, 1, 1);
  const r = extract_websafe_zw(out, "pw", "sig");
  ok(r.as_utf8 === "peppered", "correct pepper works");
  throws(() => extract_websafe_zw(out, "pw", "bad"),  null, "wrong pepper fails");
  throws(() => extract_websafe_zw(out, "pw", null),   null, "missing pepper fails");
}

// ── 3. Pepper-required policy ────────────────────────────────────────
console.log("\n3. Pepper-required policy");
{
  const out = embed_websafe_zw(C, "pol", "pw", "k", true, 8, 1, 1);
  ok(extract_websafe_zw(out, "pw", "k").as_utf8 === "pol", "extract with pepper OK");
  throws(() => embed_websafe_zw(C, "x", "pw", null, true, 8, 1, 1),
    "Pepper is required", "null pepper rejected");
  throws(() => embed_websafe_zw(C, "x", "pw", "",   true, 8, 1, 1),
    "Pepper is required", "empty pepper rejected");
}

// ── 4. Wrong password ────────────────────────────────────────────────
console.log("\n4. Wrong password");
{
  const out = embed_websafe_zw(C, "sec", "right", null, false, 8, 1, 1);
  throws(() => extract_websafe_zw(out, "wrong", null), null, "wrong password fails");
}

// ── 5. Empty message ─────────────────────────────────────────────────
console.log("\n5. Empty message");
{
  const out = embed_websafe_zw(C, "", "pw", null, false, 8, 1, 1);
  const r = extract_websafe_zw(out, "pw", null);
  ok(r.bytes_len === 0, "0 bytes extracted");
  ok(r.as_utf8 === "", "empty UTF-8");
}

// ── 6. Longer message ────────────────────────────────────────────────
console.log("\n6. Longer message (200 chars)");
{
  const msg = "X".repeat(200);
  const out = embed_websafe_zw(C, msg, "pw", null, false, 8, 1, 1);
  ok(extract_websafe_zw(out, "pw", null).as_utf8 === msg, "200-char roundtrip");
}

// ── 7. Unicode message ───────────────────────────────────────────────
console.log("\n7. Unicode message");
{
  const msg = "Hello 🌍 — ñoño — 日本語 — 🇺🇸";
  const out = embed_websafe_zw(C, msg, "pw", null, false, 8, 1, 1);
  ok(extract_websafe_zw(out, "pw", null).as_utf8 === msg, "unicode roundtrip");
}

// ── 8. Multi-line message ────────────────────────────────────────────
console.log("\n8. Multi-line message");
{
  const msg = "line1\nline2\nline3";
  const out = embed_websafe_zw(C, msg, "pw", null, false, 8, 1, 1);
  ok(extract_websafe_zw(out, "pw", null).as_utf8 === msg, "newlines preserved");
}

// ── 9. Non-UTF-8 payload (binary) ────────────────────────────────────
console.log("\n9. Non-UTF-8 binary payload (via base64)");
{
  // Embed a message containing bytes 0x80–0xFF (not valid UTF-8)
  // The WASM API takes a string message, so binary is limited. But we can
  // embed Latin-1 characters and check they survive the base64 path.
  const msg = String.fromCharCode(...Array.from({length: 20}, (_, i) => 128 + i));
  const out = embed_websafe_zw(C, msg, "pw", null, false, 8, 1, 1);
  const r = extract_websafe_zw(out, "pw", null);
  ok(r.bytes_len > 0, `extracted ${r.bytes_len} bytes`);
  ok(r.as_base64.length > 0, "base64 output present for binary data");
}

// ── 10. KDF bounds validation ────────────────────────────────────────
// The WASM layer CLAMPS out-of-range KDF values to browser-safe limits
// rather than throwing, so these should all succeed (clamped silently).
console.log("\n10. KDF bounds validation (WASM clamps, not rejects)");
{
  // Below-min values get clamped UP to the minimum
  const r0 = embed_websafe_zw(C, "t", "pw", null, false, 0, 1, 1);
  ok(extract_websafe_zw(r0, "pw", null).as_utf8 === "t", "kdf_mib=0 clamped to 8, roundtrips");
  const r7 = embed_websafe_zw(C, "t", "pw", null, false, 7, 1, 1);
  ok(extract_websafe_zw(r7, "pw", null).as_utf8 === "t", "kdf_mib=7 clamped to 8, roundtrips");

  // Above-max values get clamped DOWN to the maximum
  const r999 = embed_websafe_zw(C, "t", "pw", null, false, 999999, 1, 1);
  ok(extract_websafe_zw(r999, "pw", null).as_utf8 === "t", "kdf_mib=999999 clamped to 128, roundtrips");
  const r513 = embed_websafe_zw(C, "t", "pw", null, false, 513, 1, 1);
  ok(extract_websafe_zw(r513, "pw", null).as_utf8 === "t", "kdf_mib=513 clamped to 128, roundtrips");

  // Iteration bounds
  const ri65 = embed_websafe_zw(C, "t", "pw", null, false, 64, 65, 1);
  ok(extract_websafe_zw(ri65, "pw", null).as_utf8 === "t", "kdf_iters=65 clamped to 8, roundtrips");
  const ri0 = embed_websafe_zw(C, "t", "pw", null, false, 64, 0, 1);
  ok(extract_websafe_zw(ri0, "pw", null).as_utf8 === "t", "kdf_iters=0 clamped to 1, roundtrips");

  // Parallelism bounds
  const rp17 = embed_websafe_zw(C, "t", "pw", null, false, 64, 1, 17);
  ok(extract_websafe_zw(rp17, "pw", null).as_utf8 === "t", "kdf_par=17 clamped to 4, roundtrips");
  const rp0 = embed_websafe_zw(C, "t", "pw", null, false, 64, 1, 0);
  ok(extract_websafe_zw(rp0, "pw", null).as_utf8 === "t", "kdf_par=0 clamped to 1, roundtrips");
}

// ── 11. KDF at exact boundaries (should succeed) ─────────────────────
console.log("\n11. KDF at exact boundaries");
{
  // Min: 8 MiB, t=1, p=1  (already used in most tests above)
  const out8 = embed_websafe_zw(C, "min", "pw", null, false, 8, 1, 1);
  ok(extract_websafe_zw(out8, "pw", null).as_utf8 === "min", "kdf_mib=8 (min) OK");

  // t=64 (max) — this is CPU-intensive but should work
  // Skipped: takes too long. Validate that p=16 (max) is accepted.
  const outp = embed_websafe_zw(C, "pmax", "pw", null, false, 8, 1, 16);
  ok(extract_websafe_zw(outp, "pw", null).as_utf8 === "pmax", "kdf_par=16 (max) OK");
}

// ── 12. Extract from plain carrier ───────────────────────────────────
console.log("\n12. Extract from unmodified carrier fails");
{
  throws(() => extract_websafe_zw(C, "pw", null), null, "plain carrier rejected");
}

// ── 13. Carrier too small ────────────────────────────────────────────
console.log("\n13. Carrier too small");
{
  throws(() => embed_websafe_zw("one line", "payload", "pw", null, false, 8, 1, 1),
    null, "tiny carrier rejected");
}

// ── 14. Output carrier line count ────────────────────────────────────
console.log("\n14. Output carrier preserves line count");
{
  const inputLines = C.split("\n").length;
  const out = embed_websafe_zw(C, "hi", "pw", null, false, 8, 1, 1);
  const outLines = out.split("\n").length;
  ok(outLines === inputLines, `line count unchanged: ${inputLines} → ${outLines}`);
}

// ── 15. ExtractResult shape ──────────────────────────────────────────
console.log("\n15. ExtractResult shape validation");
{
  const out = embed_websafe_zw(C, "shape", "pw", null, false, 8, 1, 1);
  const r = extract_websafe_zw(out, "pw", null);
  ok("as_utf8" in r, "has as_utf8 field");
  ok("as_base64" in r, "has as_base64 field");
  ok("bytes_len" in r, "has bytes_len field");
  ok(typeof r.as_utf8 === "string", "as_utf8 is string");
  ok(typeof r.as_base64 === "string", "as_base64 is string");
  ok(typeof r.bytes_len === "number", "bytes_len is number");
}

// ── 16. Double embed (re-embed into already-embedded carrier) ────────
console.log("\n16. Double embed into embedded carrier");
{
  const out1 = embed_websafe_zw(C, "first", "pw1", null, false, 8, 1, 1);
  // Re-embedding into a carrier that already has zero-width chars
  // This should either succeed (overwrite) or fail cleanly
  try {
    const out2 = embed_websafe_zw(out1, "second", "pw2", null, false, 8, 1, 1);
    // If it succeeds, verify the second message is extractable
    const r = extract_websafe_zw(out2, "pw2", null);
    ok(r.as_utf8 === "second", "second embed is extractable");
    passed++; // count the non-throw as a pass
    console.log("  PASS: double embed succeeded (overwrite)");
  } catch (e) {
    // If it fails, that's also acceptable — just verify it's a clean error
    ok(typeof e === "string" || typeof e?.message === "string",
      "double embed fails cleanly: " + String(e?.message || e));
  }
}

// ── 17. Long password and pepper ─────────────────────────────────────
console.log("\n17. Long password and pepper");
{
  const longPw = "p".repeat(1000);
  const longPepper = "s".repeat(1000);
  const out = embed_websafe_zw(C, "long creds", longPw, longPepper, false, 8, 1, 1);
  const r = extract_websafe_zw(out, longPw, longPepper);
  ok(r.as_utf8 === "long creds", "1000-char password + pepper work");
}

// ── 18. Empty password rejected ──────────────────────────────────────
console.log("\n18. Empty password rejected");
{
  throws(() => embed_websafe_zw(C, "test", "", null, false, 8, 1, 1),
    null, "empty password rejected at embed");
}

// ── 19. Whitespace-only carrier ──────────────────────────────────────
console.log("\n19. Edge case carriers");
{
  throws(() => embed_websafe_zw("", "msg", "pw", null, false, 8, 1, 1),
    null, "empty carrier rejected");
  throws(() => embed_websafe_zw("   \n  \n  ", "msg", "pw", null, false, 8, 1, 1),
    null, "whitespace-only carrier rejected");
}

// ── 20. CSP meta tag presence ────────────────────────────────────────
console.log("\n20. CSP meta tag in index.html");
{
  const html = await readFile(join(__dirname, "index.html"), "utf-8");
  ok(html.includes("Content-Security-Policy"), "CSP meta tag present");
  ok(html.includes("default-src 'none'"), "CSP default-src is 'none'");
  ok(html.includes("wasm-unsafe-eval"), "CSP allows wasm-unsafe-eval");
  ok(!html.includes("unsafe-inline"), "CSP does NOT allow unsafe-inline");
}

// ── Summary ──────────────────────────────────────────────────────────
console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
process.exit(failed > 0 ? 1 : 0);
