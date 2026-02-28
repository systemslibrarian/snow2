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

/// Embed bits AND fill ALL remaining non-empty lines with random trailing whitespace.
///
/// Defeats detection based on which lines have trailing whitespace.
pub fn embed_bits_with_padding(carrier_text: &str, bits: &[bool]) -> anyhow::Result<String> {
    let lines: Vec<&str> = carrier_text.split('\n').collect();
    let usable = lines.iter().filter(|l| !l.is_empty()).count();

    if bits.len() > usable {
        anyhow::bail!(
            "Carrier too small for classic-trailing mode: need {} usable lines, have {}.",
            bits.len(),
            usable
        );
    }

    // Pre-generate all random bytes for padding lines in a single OS RNG call.
    let padding_lines_count = usable.saturating_sub(bits.len());
    let padding_rand = crate::crypto::random_bytes(padding_lines_count)
        .unwrap_or_else(|_| vec![0u8; padding_lines_count]);
    let mut pad_idx = 0usize;

    let mut bit_idx = 0usize;
    let mut out_lines: Vec<String> = Vec::with_capacity(lines.len());

    for line in &lines {
        if line.is_empty() {
            out_lines.push(String::new());
            continue;
        }

        let trimmed = line.trim_end_matches([' ', '\t']);

        if bit_idx < bits.len() {
            // Embed real data bit
            let marker = if bits[bit_idx] { '\t' } else { ' ' };
            out_lines.push(format!("{trimmed}{marker}"));
            bit_idx += 1;
        } else {
            // Fill remaining lines with random trailing whitespace from pre-generated buffer
            let byte = padding_rand.get(pad_idx).copied().unwrap_or(0);
            pad_idx += 1;
            let marker = if (byte & 1) == 1 { '\t' } else { ' ' };
            out_lines.push(format!("{trimmed}{marker}"));
        }
    }

    Ok(out_lines.join("\n"))
}

/// Extract bits from ALL non-empty lines (does not stop at first
/// unmarked line). Used by v4 pipeline where every line has whitespace.
pub fn extract_all_bits(carrier_text: &str) -> Vec<bool> {
    let mut bits = Vec::new();

    for line in carrier_text.split('\n') {
        if line.is_empty() {
            continue;
        }

        let bytes = line.as_bytes();
        if bytes.is_empty() {
            continue;
        }

        let marker = bytes[bytes.len() - 1];
        match marker {
            b'\t' => bits.push(true),
            b' ' => bits.push(false),
            _ => bits.push(false), // unmodified line, push zero as filler
        }
    }

    bits
}

/// Count the number of usable (non-empty) lines in the carrier.
pub fn usable_lines(carrier_text: &str) -> usize {
    carrier_text.split('\n').filter(|l| !l.is_empty()).count()
}