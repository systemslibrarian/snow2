use anyhow::{bail, Result};

/// Web-safe / copy-paste-friendly embedding using zero-width Unicode.
///
/// Encoding model (multi-bit):
/// - We embed up to BITS_PER_LINE bits per non-empty line by appending
///   a sequence of zero-width characters at the end of the line.
/// - bit 0 => U+200B ZERO WIDTH SPACE (ZWSP)
/// - bit 1 => U+200C ZERO WIDTH NON-JOINER (ZWNJ)
///
/// With 8 bits per line, a 310-byte payload needs only ~310 lines
/// instead of ~2,480. This makes the carrier size practical for
/// real-world use.
///
/// Why end-of-line insertion?
/// - Many renderers collapse normal whitespace, but zero-width characters survive more often.
/// - End-of-line avoids interfering with words.
/// - Still, some systems strip these characters; this is "more tolerant" not "bulletproof".
///
/// Extraction reads trailing ZW characters from each line:
/// - ZWSP => 0
/// - ZWNJ => 1
/// - Stops at first non-empty line with no trailing ZW chars.
const ZW0: char = '\u{200B}'; // ZERO WIDTH SPACE
const ZW1: char = '\u{200C}'; // ZERO WIDTH NON-JOINER

/// Number of bits encoded per carrier line.
const BITS_PER_LINE: usize = 8;

pub fn embed_bits(carrier_text: &str, bits: &[bool]) -> Result<String> {
    let mut lines: Vec<&str> = carrier_text.split('\n').collect();
    let usable = lines.iter().filter(|l| !l.is_empty()).count();

    // How many lines do we need?
    let lines_needed = (bits.len() + BITS_PER_LINE - 1) / BITS_PER_LINE;

    if lines_needed > usable {
        bail!(
            "Carrier too small for websafe-zw mode: need {} usable lines, have {} \
             ({} bits at {} bits/line).",
            lines_needed,
            usable,
            bits.len(),
            BITS_PER_LINE
        );
    }

    let mut bit_idx = 0usize;
    let mut out_lines: Vec<String> = Vec::with_capacity(lines.len());

    for line in lines.drain(..) {
        if bit_idx < bits.len() && !line.is_empty() {
            // Remove any existing trailing zero-width markers to avoid ambiguity.
            let cleaned = strip_trailing_zw(line);

            // Append up to BITS_PER_LINE ZW chars for this line.
            let mut suffix = String::new();
            for _ in 0..BITS_PER_LINE {
                if bit_idx < bits.len() {
                    suffix.push(if bits[bit_idx] { ZW1 } else { ZW0 });
                    bit_idx += 1;
                }
            }
            out_lines.push(format!("{cleaned}{suffix}"));
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

        // Collect trailing ZW chars from this line.
        let trailing: Vec<bool> = line
            .chars()
            .rev()
            .take_while(|ch| *ch == ZW0 || *ch == ZW1)
            .map(|ch| ch == ZW1)
            .collect();

        if trailing.is_empty() {
            // First non-empty line with no ZW chars → stop.
            break;
        }

        // Reverse because we collected in reverse order.
        bits.extend(trailing.into_iter().rev());
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