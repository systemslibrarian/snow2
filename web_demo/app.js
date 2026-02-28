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

function flash(btn, msg) {
  const orig = btn.textContent;
  btn.textContent = msg;
  btn.classList.add("flash-ok");
  setTimeout(() => {
    btn.textContent = orig;
    btn.classList.remove("flash-ok");
  }, 1200);
}

function generateCarrier(lines = 6000) {
  const phrases = [
    "The first real snowfall of the season blanketed the mountains overnight",
    "Polar bears roam the frozen tundra in search of seals beneath the ice",
    "Arctic foxes change their fur from brown to white as winter approaches",
    "The northern lights danced across the sky in shimmering curtains of green",
    "Glaciers move imperceptibly, carving valleys over thousands of years",
    "Fresh powder covered every rooftop and fence post in the small village",
    "Researchers at the weather station recorded the lowest temperature this decade",
    "Snowflakes are unique — no two crystals share exactly the same structure",
    "The frozen lake was perfectly still, reflecting the pale winter sun",
    "Huskies pulled the sled effortlessly through the deep, untouched snow",
    "Ice fishermen drilled holes and waited patiently in the bitter cold",
    "A thin layer of frost decorated every window pane in the cabin",
    "The river had frozen solid, forming a natural bridge across the gorge",
    "Children built an enormous snowman in the town square after school",
    "Warm cocoa and wool blankets made the blizzard outside almost welcome",
    "Icicles hung from the eaves like rows of crystal daggers catching the light",
    "The snow-capped peaks were visible for miles against the clear blue sky",
    "A lone wolf howled somewhere far across the frozen wilderness at dusk",
    "Every branch on every tree sagged under the weight of heavy wet snow",
    "The thermometer read minus thirty but the sky had never looked so clear",
    "Penguins huddled together for warmth on the windswept Antarctic shore",
    "Beneath the ice, the lake still held liquid water teeming with life",
    "Avalanche warnings kept the ski patrol busy all through the long weekend",
    "The cabin chimney sent a thin plume of smoke into the silver winter air",
    "Reindeer grazed on lichen they dug from beneath a thin crust of snow",
    "Frost patterns on the glass looked like tiny fern leaves etched in crystal",
    "The snowplow rumbled past at dawn, clearing the road for the morning commute",
    "A pair of snowshoe hares darted across the clearing and vanished into brush",
    "The ice road across the bay would only last another few weeks at most",
    "Wind-driven snow piled into drifts taller than the fence along the property",
    "Scientists drilled ice cores thousands of years old to study ancient climates",
    "The dog curled up by the fire and watched snowflakes swirl past the window",
    "Mountaineers pitched camp at base and waited for the storm to pass",
    "A thick fog rolled in from the coast, turning every surface white with rime",
    "The pond froze overnight, and by morning the children were skating on it",
    "Sleigh bells echoed down the valley as the horse-drawn carriage rounded the bend",
    "The blizzard knocked out power for three days across the northern counties",
    "Maple syrup producers tapped their trees as the last snow began to melt",
    "Snow geese flew south in long wavering lines against the grey November sky",
    "The igloo kept its builders surprisingly warm despite the howling wind outside",
    "Cross-country skiers followed the trail that wound through silent birch forests",
    "The observatory dome was half-buried after the heaviest snowfall on record",
    "A snowy owl perched motionless on a fence post, scanning the white fields",
    "The frozen waterfall hung in mid-cascade, a sculpture of pale blue ice",
    "Hot springs steamed in the cold air, surrounded by banks of untouched snow",
    "The old lighthouse stood alone on the headland, wrapped in freezing sea spray",
    "Caribou migrated hundreds of miles across the tundra before the deep freeze set in",
    "Every footstep crunched loudly in the silence of the snow-covered forest",
    "The meteorologist predicted another six inches by tomorrow afternoon",
    "A single set of fox tracks crossed the meadow and disappeared into the pines",
  ];
  // Shuffle for variety each time
  for (let i = phrases.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [phrases[i], phrases[j]] = [phrases[j], phrases[i]];
  }
  const out = [];
  for (let i = 0; i < lines; i++) {
    out.push(phrases[i % phrases.length]);
  }
  return out.join("\n");
}

function getSecurityInputs() {
  // Prefer decrypt-section fields if they have content, else fall back to main fields
  const password = $("extractPassword").value || $("password").value;
  const pepperRaw = $("extractPepper").value || $("pepper").value;
  const pepper = pepperRaw.length ? pepperRaw : null;

  const pepperRequired = $("pepperRequired").checked;

  // Clamp to browser-safe ranges (matches WASM-side limits)
  const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
  const kdfMib  = clamp(Number($("kdfMib").value  || 64), 8, 128);
  const kdfIters = clamp(Number($("kdfIters").value || 3), 1, 8);
  const kdfPar  = clamp(Number($("kdfPar").value   || 1), 1, 4);

  return { password, pepper, pepperRequired, kdfMib, kdfIters, kdfPar };
}

function getEmbedSecurityInputs() {
  const password = $("password").value;
  const pepperRaw = $("pepper").value;
  const pepper = pepperRaw.length ? pepperRaw : null;
  const pepperRequired = $("pepperRequired").checked;

  const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
  const kdfMib  = clamp(Number($("kdfMib").value  || 64), 8, 128);
  const kdfIters = clamp(Number($("kdfIters").value || 3), 1, 8);
  const kdfPar  = clamp(Number($("kdfPar").value   || 1), 1, 4);

  return { password, pepper, pepperRequired, kdfMib, kdfIters, kdfPar };
}

async function main() {
  const embedStatus = $("embedStatus");
  const extractStatus = $("extractStatus");
  const wasmStatus = $("wasmStatus");

  // Try to load the WASM module — show a clear error if it fails
  let wasmReady = false;
  try {
    status(wasmStatus, "", "Loading encryption engine…");
    await init();
    wasmReady = true;
    status(wasmStatus, "ok", "Ready — encryption engine loaded.");
  } catch (e) {
    status(wasmStatus, "err", "Failed to load encryption engine (WASM). " + String(e?.message || e));
    console.error("WASM init failed:", e);
  }

  function requireWasm(statusEl) {
    if (!wasmReady) {
      status(statusEl, "err", "Encryption engine not loaded. Refresh the page or check console for errors.");
      return false;
    }
    return true;
  }

  // Shared state for recovered binary data — accessible to extract, download, clear
  let recoveredB64 = null;

  // ZW marker toggle state
  let zwVisible = false;
  let zwOriginalText = "";

  $("genCarrier").addEventListener("click", () => {
    $("carrier").value = generateCarrier(6000);
    status(embedStatus, "ok", "Sample cover text generated (6,000 lines). Ready to encrypt.");
  });

  $("embedBtn").addEventListener("click", () => {
    if (!requireWasm(embedStatus)) return;
    try {
      status(embedStatus, "", "Encrypting & hiding…");

      const { password, pepper, pepperRequired, kdfMib, kdfIters, kdfPar } = getEmbedSecurityInputs();
      const message = $("message").value;
      const carrier = $("carrier").value;

      if (!password) throw new Error("Password is required — enter one in Security Settings above.");
      if (!carrier.trim()) throw new Error("Cover text is required — paste text or click 'Generate sample text'.");
      if (!message) throw new Error("Enter a secret message to encrypt.");
      if (pepperRequired && !pepper) throw new Error("Pepper is required (policy enabled) — enter one in Security Settings above.");

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

      // Reset ZW marker toggle
      zwVisible = false;
      zwOriginalText = "";
      $("toggleZw").textContent = "Show hidden markers";

      // Auto-select output so the user can immediately Ctrl+C
      $("outCarrier").focus();
      $("outCarrier").select();

      // Count ZW chars used
      const zwCount = (outCarrier.match(/[\u200B\u200C]/g) || []).length;
      status(embedStatus, "ok", `Encrypted & hidden! (${zwCount} invisible characters inserted). Copy the output and send it anywhere.`);
    } catch (e) {
      status(embedStatus, "err", String(e?.message || e));
    }
  });

  $("downloadCarrier").addEventListener("click", () => {
    const text = $("outCarrier").value;
    if (!text) {
      status(embedStatus, "err", "Nothing to download — encrypt a message first.");
      return;
    }
    downloadText("snow2_carrier_out.txt", text);
  });

  $("copyCarrier").addEventListener("click", async () => {
    const text = $("outCarrier").value;
    if (!text) {
      status(embedStatus, "err", "Nothing to copy — encrypt a message first.");
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      flash($("copyCarrier"), "Copied!");
      status(embedStatus, "ok", "Copied to clipboard.");
    } catch (e) {
      // Fallback: select the text so user can Ctrl+C
      $("outCarrier").focus();
      $("outCarrier").select();
      status(embedStatus, "ok", "Text selected — press Ctrl+C to copy.");
    }
  });

  $("extractBtn").addEventListener("click", () => {
    if (!requireWasm(extractStatus)) return;
    try {
      status(extractStatus, "", "Decrypting…");

      const { password, pepper } = getSecurityInputs();
      const carrier = $("extractCarrier").value;

      if (!password) throw new Error("Password is required — enter the same password used to encrypt.");
      if (!carrier.trim()) throw new Error("Paste the text containing the hidden message above.");

      const res = extract_websafe_zw(carrier, password, pepper);

      $("recoveredText").value = res.as_utf8 || "";
      $("recoveredB64").value = res.as_base64 || "";

      // Store recovered data for later download
      recoveredB64 = res.as_base64;

      status(extractStatus, "ok", `Decrypted successfully! (${res.bytes_len} bytes recovered)`);
    } catch (e) {
      status(extractStatus, "err", String(e?.message || e));
    }
  });

  $("downloadRecovered").addEventListener("click", () => {
    if (!recoveredB64) {
      status(extractStatus, "err", "Nothing to download. Decrypt a message first.");
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
    $("extractPassword").value = "";
    $("extractPepper").value = "";
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
    zwVisible = false;
    zwOriginalText = "";
    $("toggleZw").textContent = "Show hidden markers";
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
    $("extractPassword").value = "";
    $("extractPepper").value = "";
    $("password").value = "";
    $("pepper").value = "";
    recoveredB64 = null;
    status(extractStatus, "ok", "Cleared.");
  });

  // --- Show / hide zero-width markers toggle ---
  $("toggleZw").addEventListener("click", () => {
    const ta = $("outCarrier");
    if (!ta.value) {
      status(embedStatus, "err", "Nothing to inspect — encrypt a message first.");
      return;
    }

    if (!zwVisible) {
      // Show markers
      zwOriginalText = ta.value;
      ta.value = zwOriginalText
        .replace(/\u200B/g, "\u00B7")   // ZWSP → ·
        .replace(/\u200C/g, "\u2022");  // ZWNJ → •
      $("toggleZw").textContent = "Hide markers";
      status(embedStatus, "ok", "Zero-width characters shown as · (0) and • (1). This is for demo only — click Hide to restore.");
    } else {
      // Restore original
      ta.value = zwOriginalText;
      $("toggleZw").textContent = "Show hidden markers";
      status(embedStatus, "ok", "Original text restored.");
    }
    zwVisible = !zwVisible;
  });

  // --- File upload for decrypt ---
  $("uploadFileBtn").addEventListener("click", () => {
    $("fileInput").click();
  });

  $("fileInput").addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      $("extractCarrier").value = reader.result;
      status(extractStatus, "ok", `Loaded "${file.name}" (${reader.result.length.toLocaleString()} chars). Enter password and click Decrypt.`);
    };
    reader.onerror = () => {
      status(extractStatus, "err", "Failed to read file: " + reader.error);
    };
    reader.readAsText(file);
    // Reset so the same file can be re-selected
    e.target.value = "";
  });

  // --- Password show/hide toggles ---
  // Paired fields: toggling one also toggles its sync partner
  const pwPairs = { password: "extractPassword", extractPassword: "password", pepper: "extractPepper", extractPepper: "pepper" };
  document.querySelectorAll(".pw-toggle").forEach(btn => {
    btn.addEventListener("click", () => {
      const input = $(btn.dataset.target);
      if (!input) return;
      const newType = input.type === "password" ? "text" : "password";
      const newLabel = newType === "text" ? "Hide" : "Show";
      input.type = newType;
      btn.textContent = newLabel;
      // Sync paired field's type + toggle label
      const partnerId = pwPairs[btn.dataset.target];
      if (partnerId) {
        const partner = $(partnerId);
        if (partner) partner.type = newType;
        const partnerBtn = document.querySelector(`.pw-toggle[data-target="${partnerId}"]`);
        if (partnerBtn) partnerBtn.textContent = newLabel;
      }
    });
  });

  // --- Sync password/pepper between Security Settings and Decrypt section ---
  function syncFields(sourceId, targetId) {
    $(sourceId).addEventListener("input", () => {
      $(targetId).value = $(sourceId).value;
    });
    $(targetId).addEventListener("input", () => {
      $(sourceId).value = $(targetId).value;
    });
  }
  syncFields("password", "extractPassword");
  syncFields("pepper", "extractPepper");

  // Reset toggle state when output carrier changes
  $("outCarrier").addEventListener("input", () => {
    zwVisible = false;
    zwOriginalText = "";
    $("toggleZw").textContent = "Show hidden markers";
  });

  // Pre-fill a carrier to make first use easy
  $("carrier").value = generateCarrier(6000);
}

main();