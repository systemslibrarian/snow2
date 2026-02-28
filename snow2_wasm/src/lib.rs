use wasm_bindgen::prelude::*;

use snow2::{config::{EmbedOptions, EmbedSecurityOptions}, crypto::KdfParams, Mode};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Serialize;

#[wasm_bindgen(start)]
pub fn start() {
    // Better panic messages in browser console
    console_error_panic_hook::set_once();
}

#[derive(Serialize)]
struct ExtractResult {
    as_utf8: Option<String>,
    as_base64: String,
    bytes_len: usize,
}

fn build_opts(pepper_required: bool, kdf_mib: u32, kdf_iters: u32, kdf_par: u32) -> EmbedSecurityOptions {
    let mut opts = EmbedSecurityOptions::default();
    opts.pepper_required = pepper_required;

    let m_cost_kib = kdf_mib.saturating_mul(1024);

    opts.kdf = KdfParams {
        m_cost_kib,
        t_cost: kdf_iters,
        p_cost: kdf_par,
        out_len: 32,
    };

    opts
}

/// Embed plaintext string into carrier text using websafe-zw mode (recommended for browsers).
#[wasm_bindgen]
pub fn embed_websafe_zw(
    carrier_text: &str,
    message: &str,
    password: &str,
    pepper: Option<String>,
    pepper_required: bool,
    kdf_mib: u32,
    kdf_iters: u32,
    kdf_par: u32,
) -> Result<String, JsValue> {
    let opts = build_opts(pepper_required, kdf_mib, kdf_iters, kdf_par);

    if opts.pepper_required && pepper.as_deref().map(|s| s.is_empty()).unwrap_or(true) {
        return Err(JsValue::from_str("Pepper is required by policy, but none was provided."));
    }

    let embed_opts = EmbedOptions { security: opts, ..Default::default() };

    let out = snow2::embed_with_options(
        Mode::WebSafeZeroWidth,
        carrier_text,
        message.as_bytes(),
        password.as_bytes(),
        pepper.as_deref().map(|s| s.as_bytes()),
        &embed_opts,
    )
    .map_err(|e| JsValue::from_str(&format!("{e:#}")))?;

    Ok(out)
}

/// Extract payload from carrier text using websafe-zw mode.
/// Returns { as_utf8, as_base64, bytes_len }.
#[wasm_bindgen]
pub fn extract_websafe_zw(
    carrier_text: &str,
    password: &str,
    pepper: Option<String>,
) -> Result<JsValue, JsValue> {
    let bytes = snow2::extract(
        Mode::WebSafeZeroWidth,
        carrier_text,
        password.as_bytes(),
        pepper.as_deref().map(|s| s.as_bytes()),
        None, // no PQC secret key in web demo
    )
    .map_err(|e| JsValue::from_str(&format!("{e:#}")))?;

    let as_base64 = STANDARD.encode(&*bytes);
    let as_utf8 = std::str::from_utf8(&*bytes).ok().map(|s| s.to_string());

    let result = ExtractResult {
        as_utf8,
        as_base64,
        bytes_len: bytes.len(),
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&format!("serde error: {e}")))
}