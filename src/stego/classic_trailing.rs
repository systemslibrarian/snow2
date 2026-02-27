use anyhow::{bail, Result};

/// Classic trailing-whitespace embedding (tribute mode).
///
/// Encoding model (simple + deterministic):
/// - We embed 1 bit per non-empty line by appending a single trailing char:
///   - bit 0 => append a SPACE (' ')
///   - bit 1 => append a TAB ('\t')
///
/// Extraction reads the last trailing whitespace character on each line:
/// - trailing SPACE => 0
/// - trailing TAB   => 1
///
/// IMPORTANT LIMITATIONS:
/// - If the carrier is passed through a whitespace-trimming tool, data is destroyed.
/// - Many editors and platforms remove trailing whitespace.
///
/// This mode is intentionally simple and close in spirit to the original SNOW demo.
/// Later we can add redundancy / ECC, but first we make it correct and predictable.
pub fn embed_bits(carrier_text: &str, bits: &[bool]) -> Result<String> {
    let mut lines: Vec<&str> = carrier_text.split('\n').collect();

    // Count how many lines are usable (we allow empty lines too, but empty lines are fragile;
    // for v0.1 we require non-empty lines to reduce accidental loss).
    let usable = lines.iter().filter(|l| !l.is_empty()).count();

    if bits.len() > usable {
        bail!(
            "Carrier too small for classic-trailing mode: need {} usable lines, have {}.",
            bits.len(),
            usable
        );
    }

    let mut bit_idx = 0usize;

    let mut out_lines: Vec<String> = Vec::with_capacity(lines.len());
    for line in lines.drain(..) {
        if bit_idx < bits.len() && !line.is_empty() {
            // Remove existing trailing spaces/tabs to avoid ambiguity and reduce detection noise.
            let trimmed = line.trim_end_matches([' ', '\t']);
            let marker = if bits[bit_idx] { '\t' } else { ' ' };
            out_lines.push(format!("{trimmed}{marker}"));
            bit_idx += 1;
        } else {
            // Leave line unchanged
            out_lines.push(line.to_string());
        }
    }

    // Preserve original trailing newline behavior:
    // split('\n') drops the delimiter, but keeps a final empty element if input ends with '\n'.
    // Our join will recreate it correctly.
    Ok(out_lines.join("\n"))
}

/// Extract bits from classic-trailing mode.
///
/// Extraction rule:
/// - For each non-empty line, look at trailing whitespace:
///   - If it ends with TAB => bit 1
///   - Else if ends with SPACE => bit 0
///   - Else stop (we assume embedding ended)
///
/// This "stop on first non-marker line" is deliberate:
/// it prevents accidentally reading unrelated trailing whitespace deep in the file.
pub fn extract_bits(carrier_text: &str) -> Result<Vec<bool>> {
    let mut bits = Vec::new();

    for line in carrier_text.split('\n') {
        if line.is_empty() {
            continue;
        }

        // Determine last trailing whitespace char (if any)
        let bytes = line.as_bytes();
        if bytes.is_empty() {
            continue;
        }

        // Walk backwards over trailing spaces/tabs
        let mut idx = bytes.len();
        while idx > 0 && (bytes[idx - 1] == b' ' || bytes[idx - 1] == b'\t') {
            idx -= 1;
        }

        // If no trailing whitespace, stop (end of embedded stream)
        if idx == bytes.len() {
            break;
        }

        // Marker is the LAST trailing whitespace char
        let marker = bytes[bytes.len() - 1];
        match marker {
            b'\t' => bits.push(true),
            b' ' => bits.push(false),
            _ => break,
        }
    }

    Ok(bits)
}