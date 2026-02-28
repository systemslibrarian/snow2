/**
 * SNOW2 WASM Stress Test — 20 rounds with and without pepper.
 *
 * Proves the v4 hardened pipeline works reliably across:
 * - 10 rounds WITHOUT pepper (varying messages, passwords, carrier sizes)
 * - 10 rounds WITH pepper (varying peppers, pepper-required flag)
 * - Wrong password / wrong pepper / missing pepper failure checks each round
 * - Steg resistance verification (all lines have ZW content)
 *
 * Run:  node web_demo/stress_test.mjs
 */
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));

const wasmBytes = await readFile(join(__dirname, "pkg", "snow2_wasm_bg.wasm"));
const mod = await import(join(__dirname, "pkg", "snow2_wasm.js"));
const wasmModule = await WebAssembly.compile(wasmBytes);
mod.initSync({ module: wasmModule });

const { embed_websafe_zw, extract_websafe_zw } = mod;

// ── Helpers ───────────────────────────────────────────────────────────

function carrier(lines = 6000) {
  const out = ["SNOW2 stress test carrier."];
  for (let i = 1; i <= lines; i++)
    out.push(`Line ${String(i).padStart(5, "0")}: Some filler text for the stego carrier file.`);
  return out.join("\n");
}

function randomString(len) {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
  let s = "";
  for (let i = 0; i < len; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return s;
}

const ZW0 = "\u200B";
const ZW1 = "\u200C";

function checkStegCoverage(stegoText) {
  const lines = stegoText.split("\n");
  let total = 0, withZW = 0;
  for (const line of lines) {
    if (!line) continue;
    total++;
    if (line.includes(ZW0) || line.includes(ZW1)) withZW++;
  }
  return { total, withZW, pct: total > 0 ? (withZW / total * 100).toFixed(1) : "0" };
}

function chiSquared(stegoText) {
  const lines = stegoText.split("\n");
  const zwMap = { [ZW0]: "0", [ZW1]: "1" };
  const counts = new Array(256).fill(0);
  let byteCount = 0;
  for (const line of lines) {
    if (!line) continue;
    let bits = "";
    for (const c of line) {
      if (c in zwMap) bits += zwMap[c];
    }
    if (bits.length >= 8) {
      const val = parseInt(bits.slice(0, 8), 2);
      counts[val]++;
      byteCount++;
    }
  }
  if (byteCount === 0) return { chi2: Infinity, bytes: 0, unique: 0 };
  const expected = byteCount / 256;
  let chi2 = 0;
  let unique = 0;
  for (let i = 0; i < 256; i++) {
    chi2 += (counts[i] - expected) ** 2 / expected;
    if (counts[i] > 0) unique++;
  }
  return { chi2: chi2.toFixed(1), bytes: byteCount, unique };
}

let passed = 0;
let failed = 0;

function ok(cond, msg) {
  if (!cond) { console.error(`    FAIL: ${msg}`); failed++; return false; }
  else       { console.log(`    PASS: ${msg}`);   passed++; return true; }
}

function expectThrow(fn, desc) {
  try {
    fn();
    console.error(`    FAIL (no throw): ${desc}`);
    failed++;
    return false;
  } catch (e) {
    console.log(`    PASS: ${desc} → threw: "${String(e?.message || e).slice(0, 60)}..."`);
    passed++;
    return true;
  }
}

// ── Test Data ─────────────────────────────────────────────────────────

const testMessages = [
  "hi",
  "hello world",
  "The quick brown fox jumps over the lazy dog",
  "🔐 Secret message with emoji 🌍🚀",
  "line1\nline2\nline3\nline4",
  "Short",
  "x".repeat(500),
  "Unicode: 日本語テスト — ñoño — café",
  "Spaces   tabs\tand\tnewlines\n\n\nend",
  "A".repeat(1000),
  "Mixed123!@#$%^&*()_+-=[]{}|;':\",./<>?",
  `Multi\nparagraph\n\nmessage\nwith\nempty\nlines`,
  "Single character: Z",
  "🎉🎊🎉🎊🎉🎊🎉🎊🎉🎊",
  "Binary-ish: \x01\x02\x03\x04\x05",
  "Repeated: abcabc abcabc abcabc abcabc",
  "Password-like: Tr0ub4dor&3 correct horse battery staple",
  "Very very very very very very long password test message that goes on and on and on and on",
  "Tab\there\tand\there",
  "Final test message number twenty — the big finish! 🏁",
];

const passwords = [
  "pw", "password123", "hunter2", "correcthorsebatterystaple",
  "sh0rt", "a-longer-password-with-special-chars!@#",
  "p", "12345678", "unicode-пароль-密码", "Pa$$w0rd!",
];

const peppers = [
  "signal-key", "pepper123", "my-secret-pepper", "🌶️hot",
  "a", "long-pepper-long-pepper-long-pepper", "pepper!@#$%",
  "unicode-перец", "simple", "final-pepper",
];

// ══════════════════════════════════════════════════════════════════════
// PHASE 1: 10 rounds WITHOUT pepper
// ══════════════════════════════════════════════════════════════════════
console.log("\n" + "═".repeat(70));
console.log(" SNOW2 WASM STRESS TEST — 20 ROUNDS (v4 hardened pipeline)");
console.log("═".repeat(70));

console.log("\n┌──────────────────────────────────────────────────────────┐");
console.log("│ PHASE 1: 10 rounds WITHOUT pepper                       │");
console.log("└──────────────────────────────────────────────────────────┘\n");

const C = carrier(6000);

for (let i = 0; i < 10; i++) {
  const msg = testMessages[i];
  const pw = passwords[i % passwords.length];
  const displayMsg = msg.length > 40 ? msg.slice(0, 37) + "..." : msg;

  console.log(`  Round ${i + 1}/10: msg="${displayMsg}" (${msg.length} chars), pw="${pw}"`);

  // Embed
  let stego;
  try {
    stego = embed_websafe_zw(C, msg, pw, null, false, 8, 1, 1);
  } catch (e) {
    console.error(`    FAIL: embed threw: ${e}`);
    failed++;
    continue;
  }
  ok(stego.length > 0, "embed returned non-empty carrier");

  // Extract with correct password
  let result;
  try {
    result = extract_websafe_zw(stego, pw, null);
  } catch (e) {
    console.error(`    FAIL: extract threw: ${e}`);
    failed++;
    continue;
  }
  ok(result.as_utf8 === msg, `roundtrip OK (${result.bytes_len} bytes)`);

  // Wrong password must fail
  expectThrow(
    () => extract_websafe_zw(stego, "WRONG-" + pw, null),
    "wrong password rejected"
  );

  // Steg coverage check
  const cov = checkStegCoverage(stego);
  ok(cov.pct === "100.0", `steg coverage: ${cov.withZW}/${cov.total} lines (${cov.pct}%)`);

  // Chi-squared check
  const stats = chiSquared(stego);
  const chi2Good = parseFloat(stats.chi2) < 350;
  ok(chi2Good, `chi² = ${stats.chi2}, unique bytes = ${stats.unique}/256`);

  console.log("");
}

// ══════════════════════════════════════════════════════════════════════
// PHASE 2: 10 rounds WITH pepper
// ══════════════════════════════════════════════════════════════════════
console.log("┌──────────────────────────────────────────────────────────┐");
console.log("│ PHASE 2: 10 rounds WITH pepper                          │");
console.log("└──────────────────────────────────────────────────────────┘\n");

for (let i = 0; i < 10; i++) {
  const msg = testMessages[10 + i];
  const pw = passwords[i % passwords.length];
  const pepper = peppers[i % peppers.length];
  const pepperRequired = i % 2 === 0; // alternate pepper-required on/off
  const displayMsg = msg.length > 40 ? msg.slice(0, 37) + "..." : msg;

  console.log(`  Round ${i + 1}/10: msg="${displayMsg}" (${msg.length} chars), pw="${pw}", pepper="${pepper}", required=${pepperRequired}`);

  // Embed
  let stego;
  try {
    stego = embed_websafe_zw(C, msg, pw, pepper, pepperRequired, 8, 1, 1);
  } catch (e) {
    console.error(`    FAIL: embed threw: ${e}`);
    failed++;
    continue;
  }
  ok(stego.length > 0, "embed returned non-empty carrier");

  // Extract with correct password + pepper
  let result;
  try {
    result = extract_websafe_zw(stego, pw, pepper);
  } catch (e) {
    console.error(`    FAIL: extract threw: ${e}`);
    failed++;
    continue;
  }
  ok(result.as_utf8 === msg, `roundtrip OK (${result.bytes_len} bytes)`);

  // Wrong password must fail
  expectThrow(
    () => extract_websafe_zw(stego, "WRONG-" + pw, pepper),
    "wrong password rejected"
  );

  // Wrong pepper must fail
  expectThrow(
    () => extract_websafe_zw(stego, pw, "WRONG-" + pepper),
    "wrong pepper rejected"
  );

  // Missing pepper must fail
  expectThrow(
    () => extract_websafe_zw(stego, pw, null),
    "missing pepper rejected"
  );

  // Steg coverage check
  const cov = checkStegCoverage(stego);
  ok(cov.pct === "100.0", `steg coverage: ${cov.withZW}/${cov.total} lines (${cov.pct}%)`);

  // Chi-squared check
  const stats = chiSquared(stego);
  const chi2Good = parseFloat(stats.chi2) < 350;
  ok(chi2Good, `chi² = ${stats.chi2}, unique bytes = ${stats.unique}/256`);

  console.log("");
}

// ══════════════════════════════════════════════════════════════════════
// PHASE 3: Cross-extraction sanity (no cross-talk between rounds)
// ══════════════════════════════════════════════════════════════════════
console.log("┌──────────────────────────────────────────────────────────┐");
console.log("│ PHASE 3: Cross-extraction sanity check                   │");
console.log("└──────────────────────────────────────────────────────────┘\n");

{
  // Embed two different messages with different passwords
  const stego1 = embed_websafe_zw(C, "message-ONE", "password-1", null, false, 8, 1, 1);
  const stego2 = embed_websafe_zw(C, "message-TWO", "password-2", null, false, 8, 1, 1);

  // Each extracts correctly with its own password
  const r1 = extract_websafe_zw(stego1, "password-1", null);
  ok(r1.as_utf8 === "message-ONE", "stego1 extracts with pw1");

  const r2 = extract_websafe_zw(stego2, "password-2", null);
  ok(r2.as_utf8 === "message-TWO", "stego2 extracts with pw2");

  // Cross-extraction must fail
  expectThrow(
    () => extract_websafe_zw(stego1, "password-2", null),
    "stego1 rejects pw2 (no cross-talk)"
  );
  expectThrow(
    () => extract_websafe_zw(stego2, "password-1", null),
    "stego2 rejects pw1 (no cross-talk)"
  );

  // Pepper isolation
  const stegoP1 = embed_websafe_zw(C, "pepper-msg-1", "pw", "pepper-A", false, 8, 1, 1);
  const stegoP2 = embed_websafe_zw(C, "pepper-msg-2", "pw", "pepper-B", false, 8, 1, 1);

  ok(extract_websafe_zw(stegoP1, "pw", "pepper-A").as_utf8 === "pepper-msg-1", "pepperA extracts correctly");
  ok(extract_websafe_zw(stegoP2, "pw", "pepper-B").as_utf8 === "pepper-msg-2", "pepperB extracts correctly");

  expectThrow(
    () => extract_websafe_zw(stegoP1, "pw", "pepper-B"),
    "stego-pepperA rejects pepper-B"
  );
  expectThrow(
    () => extract_websafe_zw(stegoP2, "pw", "pepper-A"),
    "stego-pepperB rejects pepper-A"
  );
}

// ══════════════════════════════════════════════════════════════════════
// PHASE 4: Different carrier sizes
// ══════════════════════════════════════════════════════════════════════
console.log("\n┌──────────────────────────────────────────────────────────┐");
console.log("│ PHASE 4: Different carrier sizes                         │");
console.log("└──────────────────────────────────────────────────────────┘\n");

for (const size of [200, 500, 1000, 3000, 6000]) {
  const c = carrier(size);
  const msg = "test-msg-" + size;
  const stego = embed_websafe_zw(c, msg, "pw", null, false, 8, 1, 1);
  const r = extract_websafe_zw(stego, "pw", null);
  ok(r.as_utf8 === msg, `carrier(${size} lines): roundtrip OK`);

  const cov = checkStegCoverage(stego);
  ok(cov.pct === "100.0", `carrier(${size} lines): 100% steg coverage`);
}

// ══════════════════════════════════════════════════════════════════════
// RESULTS
// ══════════════════════════════════════════════════════════════════════
console.log("\n" + "═".repeat(70));
console.log(` FINAL RESULTS: ${passed} passed, ${failed} failed`);
if (failed === 0) {
  console.log(" ✅ ALL TESTS PASSED — v4 hardened pipeline verified.");
} else {
  console.log(` ❌ ${failed} FAILURE(S) — investigate above.`);
}
console.log("═".repeat(70) + "\n");

process.exit(failed > 0 ? 1 : 0);
