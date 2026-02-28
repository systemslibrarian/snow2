/**
 * Prove the download→upload→decrypt flow works end-to-end.
 *
 * Simulates:
 *   1. User types a secret message + password
 *   2. Clicks "Encrypt & Hide"
 *   3. Clicks "Download file" → file saved to disk
 *   4. ** Refreshes the page ** (all JS state cleared)
 *   5. Clicks "Upload file" → reads file from disk
 *   6. Enters the same password
 *   7. Clicks "Decrypt & Reveal" → original message recovered
 */

import { readFileSync, writeFileSync, unlinkSync, existsSync } from "fs";
import { fileURLToPath } from "url";
import path from "path";

// ── Pre-check: ensure WASM package has been built ─────────────────────
const pkgDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "pkg");
if (!existsSync(path.join(pkgDir, "snow2_wasm_bg.wasm"))) {
  console.error(
    "ERROR: WASM package not found at web_demo/pkg/.\n" +
    "       Run 'scripts/wasm_test.sh' or build manually:\n" +
    "       wasm-pack build snow2_wasm --target web --out-dir ../web_demo/pkg\n"
  );
  process.exit(1);
}

// ── Load WASM (same way the browser demo does) ──
const wasmBytes = readFileSync(path.join(pkgDir, "snow2_wasm_bg.wasm"));
const js = await import(path.join(pkgDir, "snow2_wasm.js"));
await js.default(wasmBytes);
const { embed_websafe_zw, extract_websafe_zw } = js;

const DOWNLOAD_PATH = "/tmp/snow2_download_test.txt";

let passed = 0;
let failed = 0;

function ok(cond, label) {
  if (cond) { console.log(`    PASS: ${label}`); passed++; }
  else      { console.log(`    FAIL: ${label}`); failed++; }
}

function throws(fn, label) {
  try { fn(); ok(false, label + " (did NOT throw)"); }
  catch { ok(true, label); }
}

// ────────────────────────────────────────────────────────────
//  Generate carrier (same as app.js)
// ────────────────────────────────────────────────────────────
function generateCarrier(n) {
  const phrases = [
    "The first real snowfall of the season blanketed the mountains overnight",
    "Polar bears roam the frozen tundra in search of seals beneath the ice",
    "Arctic foxes change their fur from brown to white as winter approaches",
    "The northern lights danced across the sky in shimmering curtains of green",
    "Fresh powder covered every rooftop and fence post in the small village",
  ];
  const out = [];
  for (let i = 0; i < n; i++) out.push(phrases[i % phrases.length]);
  return out.join("\n");
}

console.log("══════════════════════════════════════════════════════════════");
console.log(" SNOW2 Download → Upload → Decrypt  (end-to-end proof)");
console.log("══════════════════════════════════════════════════════════════\n");

// ── Test 1: Basic flow — text message ───────────────────────
console.log("TEST 1: Text message — download, clear, upload, decrypt");
{
  const SECRET  = "Meet me at the library at 8pm — bring the documents.";
  const PASSWORD = "correct-horse-battery-staple";
  const carrier  = generateCarrier(6000);

  // Step 1: Encrypt
  const stegoText = embed_websafe_zw(carrier, SECRET, PASSWORD, null, false, 8, 1, 1);
  ok(stegoText.length > 0, "encrypt produced output");

  // Step 2: "Download" — write to disk
  writeFileSync(DOWNLOAD_PATH, stegoText, "utf-8");
  const fileSize = readFileSync(DOWNLOAD_PATH).length;
  ok(fileSize > 0, `file saved to disk (${(fileSize / 1024).toFixed(1)} KB)`);

  // Step 3: "Refresh page" — forget everything
  // (We simply don't reuse any variables from above except the PASSWORD)

  // Step 4: "Upload file" — read from disk
  const uploaded = readFileSync(DOWNLOAD_PATH, "utf-8");
  ok(uploaded.length > 0, `file loaded from disk (${uploaded.length.toLocaleString()} chars)`);

  // Step 5: Enter password and decrypt
  const result = extract_websafe_zw(uploaded, PASSWORD, null);
  ok(result.as_utf8 === SECRET, `decrypted message matches original`);
  console.log(`    ↳ recovered: "${result.as_utf8}"\n`);
}

// ── Test 2: With pepper ─────────────────────────────────────
console.log("TEST 2: With pepper — download, clear, upload, decrypt");
{
  const SECRET   = "🔐 Top secret emoji message! 🚀🌍";
  const PASSWORD = "hunter2";
  const PEPPER   = "signal-key-42";
  const carrier  = generateCarrier(6000);

  const stegoText = embed_websafe_zw(carrier, SECRET, PASSWORD, PEPPER, true, 8, 1, 1);
  writeFileSync(DOWNLOAD_PATH, stegoText, "utf-8");

  // "Refresh" — read back from file
  const uploaded = readFileSync(DOWNLOAD_PATH, "utf-8");

  // Correct password + pepper
  const result = extract_websafe_zw(uploaded, PASSWORD, PEPPER);
  ok(result.as_utf8 === SECRET, "correct password + pepper → decrypted");
  console.log(`    ↳ recovered: "${result.as_utf8}"`);

  // Wrong password
  throws(() => extract_websafe_zw(uploaded, "wrong", PEPPER),
    "wrong password → rejected");

  // Wrong pepper
  throws(() => extract_websafe_zw(uploaded, PASSWORD, "wrong-pepper"),
    "wrong pepper → rejected");

  // Missing pepper (required=true was set)
  throws(() => extract_websafe_zw(uploaded, PASSWORD, null),
    "missing pepper → rejected");

  console.log();
}

// ── Test 3: Large message ───────────────────────────────────
console.log("TEST 3: Large message (2 KB) — download, upload, decrypt");
{
  const SECRET   = "A".repeat(2000);
  const PASSWORD = "big-data-password";
  const carrier  = generateCarrier(6000);

  const stegoText = embed_websafe_zw(carrier, SECRET, PASSWORD, null, false, 8, 1, 1);
  writeFileSync(DOWNLOAD_PATH, stegoText, "utf-8");

  const uploaded = readFileSync(DOWNLOAD_PATH, "utf-8");
  const result = extract_websafe_zw(uploaded, PASSWORD, null);
  ok(result.as_utf8 === SECRET, `2 KB message roundtrip OK (${result.bytes_len} bytes)`);
  console.log();
}

// ── Test 4: Multi-line with special chars ───────────────────
console.log("TEST 4: Multi-line + special chars — download, upload, decrypt");
{
  const SECRET = `Line 1: Hello
Line 2: 日本語テスト
Line 3: ñoño café
Line 4: tabs\there\tand\tthere
Line 5: "quotes" and 'apostrophes'
Line 6: <html>&amp;</html>`;

  const PASSWORD = "unicode-пароль";
  const carrier  = generateCarrier(6000);

  const stegoText = embed_websafe_zw(carrier, SECRET, PASSWORD, null, false, 8, 1, 1);
  writeFileSync(DOWNLOAD_PATH, stegoText, "utf-8");

  const uploaded = readFileSync(DOWNLOAD_PATH, "utf-8");
  const result = extract_websafe_zw(uploaded, PASSWORD, null);
  ok(result.as_utf8 === SECRET, "multi-line + unicode roundtrip OK");
  console.log(`    ↳ recovered ${result.bytes_len} bytes across ${SECRET.split("\n").length} lines\n`);
}

// ── Test 5: Wrong password after upload → then correct ──────
console.log("TEST 5: Wrong password first, then correct password");
{
  const SECRET   = "The password is swordfish.";
  const PASSWORD = "swordfish";
  const carrier  = generateCarrier(6000);

  const stegoText = embed_websafe_zw(carrier, SECRET, PASSWORD, null, false, 8, 1, 1);
  writeFileSync(DOWNLOAD_PATH, stegoText, "utf-8");

  const uploaded = readFileSync(DOWNLOAD_PATH, "utf-8");

  // First attempt: wrong password
  throws(() => extract_websafe_zw(uploaded, "wrong-guess", null),
    "wrong password attempt → rejected");

  // Second attempt: correct password (proves file isn't corrupted by failed attempt)
  const result = extract_websafe_zw(uploaded, PASSWORD, null);
  ok(result.as_utf8 === SECRET, "correct password on retry → works");
  console.log(`    ↳ recovered: "${result.as_utf8}"\n`);
}

// ── Cleanup ─────────────────────────────────────────────────
try { unlinkSync(DOWNLOAD_PATH); } catch {}

console.log("══════════════════════════════════════════════════════════════");
console.log(` RESULTS: ${passed} passed, ${failed} failed`);
if (failed === 0) {
  console.log(" ✅ DOWNLOAD → UPLOAD → DECRYPT FLOW FULLY VERIFIED");
} else {
  console.log(" ❌ SOME TESTS FAILED");
}
console.log("══════════════════════════════════════════════════════════════");
process.exit(failed > 0 ? 1 : 0);
