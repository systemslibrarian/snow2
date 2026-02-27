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
  const out = [];
  out.push("SNOW2 web demo carrier. Many lines are required in this demo.");
  out.push("Tip: use CLI for file-based carriers and classic-trailing mode.");
  out.push("------------------------------------------------------------");
  for (let i = 1; i <= lines; i++) {
    out.push(`Carrier line ${String(i).padStart(5, "0")}: nothing to see here.`);
  }
  return out.join("\n");
}

function getSecurityInputs() {
  const password = $("password").value;
  const pepperRaw = $("pepper").value;
  const pepper = pepperRaw.length ? pepperRaw : null;

  const pepperRequired = $("pepperRequired").checked;

  const kdfMib = Number($("kdfMib").value || 64);
  const kdfIters = Number($("kdfIters").value || 3);
  const kdfPar = Number($("kdfPar").value || 1);

  return { password, pepper, pepperRequired, kdfMib, kdfIters, kdfPar };
}

async function main() {
  await init();

  const embedStatus = $("embedStatus");
  const extractStatus = $("extractStatus");

  $("genCarrier").addEventListener("click", () => {
    $("carrier").value = generateCarrier(6000);
    status(embedStatus, "ok", "Generated carrier with 6000 lines.");
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

      // Keep bytes in memory for download
      window.__snow2_recovered_b64 = res.as_base64;

      status(extractStatus, "ok", `Extracted ${res.bytes_len} bytes.`);
    } catch (e) {
      status(extractStatus, "err", String(e?.message || e));
    }
  });

  $("downloadRecovered").addEventListener("click", () => {
    const b64 = window.__snow2_recovered_b64;
    if (!b64) return;

    const binStr = atob(b64);
    const bytes = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) bytes[i] = binStr.charCodeAt(i);

    downloadBytes("recovered.bin", bytes);
  });

  // Pre-fill a carrier to make first use easy
  $("carrier").value = generateCarrier(6000);
}

main();