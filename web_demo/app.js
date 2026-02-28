import init, { embed_websafe_zw, extract_websafe_zw } from "./pkg/snow2_wasm.js";

const $ = (id) => document.getElementById(id);

function status(el, kind, msg) {
  el.classList.remove("ok", "err");
  if (kind === "ok") el.classList.add("ok");
  if (kind === "err") el.classList.add("err");
  el.textContent = msg || "";
}

function downloadText(filename, text) {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function downloadBytes(filename, bytes) {
  const blob = new Blob([bytes], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function generateCarrier(lines = 6000) {
  const phrases = [
    "the quick brown fox jumps over the lazy dog",
    "nothing to see here, just ordinary text",
    "a perfectly normal line of carrier text",
    "some days the weather is sunny and warm",
    "every great journey begins with a single step",
    "the stars come out one by one at dusk",
    "a watched pot never boils, they say",
    "books lined the shelves from floor to ceiling",
    "the river runs quietly through the valley",
    "time flies when you are having fun",
  ];
  const out = [];
  for (let i = 0; i < lines; i++) {
    out.push(phrases[i % phrases.length]);
  }
  return out.join("\n");
}

function getSecurityInputs() {
  const password = $("password").value;
  const pepperRaw = $("pepper").value;
  const pepper = pepperRaw.length ? pepperRaw : null;

  const pepperRequired = $("pepperRequired").checked;

  // Clamp to browser-safe ranges (matches WASM-side limits)
  const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
  const kdfMib  = clamp(Number($("kdfMib").value  || 64), 8, 128);
  const kdfIters = clamp(Number($("kdfIters").value || 3), 1, 8);
  const kdfPar  = clamp(Number($("kdfPar").value   || 1), 1, 4);

  return { password, pepper, pepperRequired, kdfMib, kdfIters, kdfPar };
}

async function main() {
  await init();

  const embedStatus = $("embedStatus");
  const extractStatus = $("extractStatus");

  // Shared state for recovered binary data — accessible to extract, download, clear
  let recoveredB64 = null;

  $("genCarrier").addEventListener("click", () => {
    $("carrier").value = generateCarrier(6000);
    status(embedStatus, "ok", "Sample text generated (6,000 lines). Ready to embed.");
  });

  $("embedBtn").addEventListener("click", () => {
    try {
      status(embedStatus, "", "");

      const { password, pepper, pepperRequired, kdfMib, kdfIters, kdfPar } = getSecurityInputs();
      const message = $("message").value;
      const carrier = $("carrier").value;

      if (!password) throw new Error("Password is required.");
      if (!carrier.trim()) throw new Error("Carrier text is required.");
      if (!message) throw new Error("Message is required.");
      if (pepperRequired && !pepper) throw new Error("Pepper is required (policy enabled).");

      const outCarrier = embed_websafe_zw(
        carrier,
        message,
        password,
        pepper,
        pepperRequired,
        kdfMib,
        kdfIters,
        kdfPar
      );

      $("outCarrier").value = outCarrier;
      $("extractCarrier").value = outCarrier;

      status(embedStatus, "ok", "Embedded successfully (websafe-zw).");
    } catch (e) {
      status(embedStatus, "err", String(e?.message || e));
    }
  });

  $("downloadCarrier").addEventListener("click", () => {
    const text = $("outCarrier").value;
    if (!text) return;
    downloadText("snow2_carrier_out.txt", text);
  });

  $("extractBtn").addEventListener("click", () => {
    try {
      status(extractStatus, "", "");

      const { password, pepper } = getSecurityInputs();
      const carrier = $("extractCarrier").value;

      if (!password) throw new Error("Password is required.");
      if (!carrier.trim()) throw new Error("Carrier text is required.");

      const res = extract_websafe_zw(carrier, password, pepper);

      $("recoveredText").value = res.as_utf8 || "";
      $("recoveredB64").value = res.as_base64 || "";

      // Store recovered data for later download
      recoveredB64 = res.as_base64;

      status(extractStatus, "ok", `Extracted ${res.bytes_len} bytes.`);
    } catch (e) {
      status(extractStatus, "err", String(e?.message || e));
    }
  });

  $("downloadRecovered").addEventListener("click", () => {
    if (!recoveredB64) {
      status(extractStatus, "err", "Nothing to download. Extract first.");
      return;
    }
    const binStr = atob(recoveredB64);
    const bytes = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) bytes[i] = binStr.charCodeAt(i);
    downloadBytes("recovered.bin", bytes);
  });

  function clearAll() {
    $("password").value = "";
    $("pepper").value = "";
    $("message").value = "";
    $("carrier").value = "";
    $("outCarrier").value = "";
    $("extractCarrier").value = "";
    $("recoveredText").value = "";
    $("recoveredB64").value = "";
    $("pepperRequired").checked = false;
    $("kdfMib").value = 64;
    $("kdfIters").value = 3;
    $("kdfPar").value = 1;
    recoveredB64 = null;
    status(embedStatus, "", "");
    status(extractStatus, "", "");
  }

  $("clearAllBtn").addEventListener("click", () => {
    clearAll();
    status(embedStatus, "ok", "All fields cleared.");
  });

  $("clearExtractBtn").addEventListener("click", () => {
    $("extractCarrier").value = "";
    $("recoveredText").value = "";
    $("recoveredB64").value = "";
    recoveredB64 = null;
    status(extractStatus, "ok", "Extraction fields cleared.");
  });

  // Pre-fill a carrier to make first use easy
  $("carrier").value = generateCarrier(6000);
}

main();