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
    let usable = lines.iter().filter(|l| !l.trim_end_matches('\r').is_empty()).count();

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
        // Separate any trailing \r for CRLF preservation.
        let (content, cr) = if line.ends_with('\r') {
            (&line[..line.len() - 1], "\r")
        } else {
            (line, "")
        };

        if bit_idx < bits.len() && !content.is_empty() {
            // Remove any existing trailing zero-width markers to avoid ambiguity.
            let cleaned = strip_trailing_zw(content);

            // Append up to BITS_PER_LINE ZW chars for this line.
            let mut suffix = String::new();
            for _ in 0..BITS_PER_LINE {
                if bit_idx < bits.len() {
                    suffix.push(if bits[bit_idx] { ZW1 } else { ZW0 });
                    bit_idx += 1;
                }
            }
            out_lines.push(format!("{cleaned}{suffix}{cr}"));
        } else {
            out_lines.push(line.to_string());
        }
    }

    Ok(out_lines.join("\n"))
}

pub fn extract_bits(carrier_text: &str) -> Result<Vec<bool>> {
    let mut bits = Vec::new();

    for line in carrier_text.split('\n') {
        // Strip trailing \r so CRLF content is handled correctly.
        let line = line.trim_end_matches('\r');

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

/// Embed bits AND fill ALL remaining non-empty lines with random ZW content.
///
/// This makes it impossible to detect which lines carry real data by
/// checking for the presence/absence of ZW characters — every non-empty
/// line will have ZW content after embedding.
pub fn embed_bits_with_padding(carrier_text: &str, bits: &[bool]) -> anyhow::Result<String> {
    let lines: Vec<&str> = carrier_text.split('\n').collect();
    let usable = lines.iter().filter(|l| !l.trim_end_matches('\r').is_empty()).count();

    let lines_needed = (bits.len() + BITS_PER_LINE - 1) / BITS_PER_LINE;

    if lines_needed > usable {
        anyhow::bail!(
            "Carrier too small for websafe-zw mode: need {} usable lines, have {} \
             ({} bits at {} bits/line).",
            lines_needed,
            usable,
            bits.len(),
            BITS_PER_LINE
        );
    }

    // Pre-generate all random bytes needed for padding lines in one OS RNG call.
    let padding_lines_count = usable.saturating_sub(lines_needed);
    let padding_rand = crate::crypto::random_bytes(padding_lines_count)
        .unwrap_or_else(|_| vec![0u8; padding_lines_count]);
    let mut pad_idx = 0usize;

    let mut bit_idx = 0usize;
    let mut out_lines: Vec<String> = Vec::with_capacity(lines.len());

    for line in &lines {
        // Separate any trailing \r for CRLF preservation.
        let (content, cr) = if line.ends_with('\r') {
            (&line[..line.len() - 1], "\r")
        } else {
            (*line, "")
        };

        if content.is_empty() {
            out_lines.push(line.to_string());
            continue;
        }

        let cleaned = strip_trailing_zw(content);

        if bit_idx < bits.len() {
            // Embed real data bits
            let mut suffix = String::new();
            for _ in 0..BITS_PER_LINE {
                if bit_idx < bits.len() {
                    suffix.push(if bits[bit_idx] { ZW1 } else { ZW0 });
                    bit_idx += 1;
                }
            }
            out_lines.push(format!("{cleaned}{suffix}{cr}"));
        } else {
            // Fill remaining lines with random ZW content from pre-generated buffer
            let byte = padding_rand.get(pad_idx).copied().unwrap_or(0);
            pad_idx += 1;
            let mut suffix = String::new();
            for i in 0..BITS_PER_LINE {
                let bit = ((byte >> (7 - i)) & 1) == 1;
                suffix.push(if bit { ZW1 } else { ZW0 });
            }
            out_lines.push(format!("{cleaned}{suffix}{cr}"));
        }
    }

    Ok(out_lines.join("\n"))
}

/// Extract ALL bits from ALL non-empty lines (does not stop at first
/// unmarked line). Used by v4 pipeline where every line has ZW content.
pub fn extract_all_bits(carrier_text: &str) -> Vec<bool> {
    let mut bits = Vec::new();

    for line in carrier_text.split('\n') {
        // Strip trailing \r so CRLF content is handled correctly.
        let line = line.trim_end_matches('\r');

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
            // No ZW chars — could be an unmodified line in a mixed carrier.
            // Push 8 zero bits as filler so byte alignment is maintained.
            for _ in 0..BITS_PER_LINE {
                bits.push(false);
            }
        } else {
            bits.extend(trailing.into_iter().rev());
        }
    }

    bits
}

/// Count the number of usable (non-empty) lines in the carrier.
pub fn usable_lines(carrier_text: &str) -> usize {
    carrier_text.split('\n').filter(|l| !l.trim_end_matches('\r').is_empty()).count()
}