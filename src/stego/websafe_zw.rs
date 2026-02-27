use anyhow::{bail, Result};

/// Web-safe / copy-paste-friendly embedding using zero-width Unicode.
///
/// Encoding model:
/// - We embed 1 bit per non-empty line by inserting ONE zero-width char at the end of the line.
/// - bit 0 => U+200B ZERO WIDTH SPACE (ZWSP)
/// - bit 1 => U+200C ZERO WIDTH NON-JOINER (ZWNJ)
///
/// Why end-of-line insertion?
/// - Many renderers collapse normal whitespace, but zero-width characters survive more often.
/// - End-of-line avoids interfering with words.
/// - Still, some systems strip these characters; this is "more tolerant" not "bulletproof".
///
/// Extraction reads the last character:
/// - ZWSP => 0
/// - ZWNJ => 1
/// - otherwise stop (assume embedding ended)
const ZW0: char = '\u{200B}'; // ZERO WIDTH SPACE
const ZW1: char = '\u{200C}'; // ZERO WIDTH NON-JOINER

pub fn embed_bits(carrier_text: &str, bits: &[bool]) -> Result<String> {
    let mut lines: Vec<&str> = carrier_text.split('\n').collect();
    let usable = lines.iter().filter(|l| !l.is_empty()).count();

    if bits.len() > usable {
        bail!(
            "Carrier too small for websafe-zw mode: need {} usable lines, have {}.",
            bits.len(),
            usable
        );
    }

    let mut bit_idx = 0usize;
    let mut out_lines: Vec<String> = Vec::with_capacity(lines.len());

    for line in lines.drain(..) {
        if bit_idx < bits.len() && !line.is_empty() {
            // Remove any existing trailing zero-width markers to avoid ambiguity.
            let cleaned = strip_trailing_zw(line);

            let marker = if bits[bit_idx] { ZW1 } else { ZW0 };
            out_lines.push(format!("{cleaned}{marker}"));
            bit_idx += 1;
        } else {
            out_lines.push(line.to_string());
        }
    }

    Ok(out_lines.join("\n"))
}

pub fn extract_bits(carrier_text: &str) -> Result<Vec<bool>> {
    let mut bits = Vec::new();

    for line in carrier_text.split('\n') {
        if line.is_empty() {
            continue;
        }

        let last = line.chars().last();
        let Some(ch) = last else { continue };

        match ch {
            ZW1 => bits.push(true),
            ZW0 => bits.push(false),
            _ => break, // stop at first non-marker line
        }
    }

    Ok(bits)
}

fn strip_trailing_zw(s: &str) -> String {
    let mut chars: Vec<char> = s.chars().collect();
    while matches!(chars.last(), Some(&c) if c == ZW0 || c == ZW1) {
        chars.pop();
    }
    chars.into_iter().collect()
}