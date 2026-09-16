//! Steganalysis property tests.
//!
//! These tests exist so the README's steganalysis claims are *executable*
//! rather than prose. Previously the only place these numbers were measured
//! was `web_demo/stress_test.mjs`, which CI never ran, so the figures quoted
//! in the README drifted from anything verifiable.
//!
//! Two kinds of claim are covered, and the distinction is the whole point:
//!
//! 1. **Payload indistinguishability (positive claim).** Once the channel has
//!    been decoded, the recovered bytes look uniformly random. This is what
//!    chi-squared ≈ 255 actually measures.
//!
//! 2. **Channel detectability (negative claim).** The channel itself is
//!    trivially findable, and v4's 100% line coverage makes it *more*
//!    conspicuous than a partially-filled carrier would be. The README says
//!    so; these tests hold it to that and will fail if someone later
//!    reintroduces an undetectability claim by changing the behaviour.

use snow2::{
    config::{EmbedOptions, EmbedSecurityOptions},
    Mode,
};

/// Wire-format markers for `websafe-zw` (documented in README / websafe_zw.rs).
const ZW0: char = '\u{200B}'; // ZERO WIDTH SPACE  → bit 0
const ZW1: char = '\u{200C}'; // ZERO WIDTH NON-JOINER → bit 1

fn carrier(lines: usize) -> String {
    (0..lines)
        .map(|i| format!("Ordinary carrier line number {i} with nothing hidden in it."))
        .collect::<Vec<_>>()
        .join("\n")
}

fn embed_zw(carrier_text: &str, payload: &[u8]) -> String {
    let opts = EmbedOptions::new(EmbedSecurityOptions::default());
    snow2::embed_with_options(
        Mode::WebSafeZeroWidth,
        carrier_text,
        payload,
        b"correct horse battery staple",
        None,
        &opts,
    )
    .expect("embed should succeed")
}

/// Decode the zero-width channel the way an analyst would: take the trailing
/// ZW run on each line, 8 bits per line, MSB first.
fn decode_channel_bytes(stego: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for line in stego.lines() {
        let bits: Vec<bool> = line
            .chars()
            .rev()
            .take_while(|c| *c == ZW0 || *c == ZW1)
            .map(|c| c == ZW1)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        if bits.len() >= 8 {
            let mut byte = 0u8;
            for (i, b) in bits[..8].iter().enumerate() {
                if *b {
                    byte |= 1 << (7 - i);
                }
            }
            out.push(byte);
        }
    }
    out
}

/// Chi-squared statistic of `bytes` against a uniform distribution over 256
/// buckets. For a uniform source the expected value is the degrees of freedom,
/// i.e. 255.
fn chi_squared(bytes: &[u8]) -> f64 {
    assert!(!bytes.is_empty(), "no bytes to test");
    let mut counts = [0usize; 256];
    for b in bytes {
        counts[*b as usize] += 1;
    }
    let expected = bytes.len() as f64 / 256.0;
    counts
        .iter()
        .map(|c| {
            let d = *c as f64 - expected;
            d * d / expected
        })
        .sum()
}

fn lines_with_zw(text: &str) -> usize {
    text.lines()
        .filter(|l| l.chars().any(|c| c == ZW0 || c == ZW1))
        .count()
}

fn non_empty_lines(text: &str) -> usize {
    text.lines()
        .filter(|l| !l.trim_end_matches('\r').is_empty())
        .count()
}

// ── 1. Payload indistinguishability ─────────────────────────────────────────

/// The claim the README quotes as "chi-squared ≈ 255".
///
/// Note what this test has to do *first*: decode the channel. The statistic
/// only says the outer AEAD produces uniform output — which any correct AEAD
/// must — and says nothing about how hard the channel was to find.
#[test]
fn decoded_bitstream_is_uniformly_distributed() {
    let stego = embed_zw(&carrier(8000), b"hello snow2");
    let bytes = decode_channel_bytes(&stego);

    assert!(
        bytes.len() >= 4000,
        "expected a few thousand channel bytes for a stable statistic, got {}",
        bytes.len()
    );

    let chi2 = chi_squared(&bytes);
    // df = 255, so E[chi2] = 255 and sd = sqrt(2*255) ≈ 22.6.
    // 350 is ~4.2 sigma — the same threshold web_demo/stress_test.mjs uses.
    assert!(
        chi2 < 350.0,
        "chi-squared {chi2:.1} over {} bytes suggests the bitstream is not uniform",
        bytes.len()
    );

    let unique = {
        let mut seen = [false; 256];
        for b in &bytes {
            seen[*b as usize] = true;
        }
        seen.iter().filter(|s| **s).count()
    };
    assert_eq!(
        unique,
        256,
        "expected all 256 byte values to appear in {} channel bytes",
        bytes.len()
    );
}

/// No ASCII signature survives into the channel: v4 strips magic bytes, so a
/// scanner cannot key on "SNOW2" the way it could with v1/v3 containers.
#[test]
fn channel_carries_no_magic_bytes() {
    let stego = embed_zw(&carrier(4000), b"hello snow2");
    let bytes = decode_channel_bytes(&stego);
    assert!(
        !bytes.windows(5).any(|w| w == b"SNOW2"),
        "v4 channel must not contain the legacy SNOW2 magic"
    );
}

// ── 2. Channel detectability (the honest negative claim) ────────────────────

/// Baseline: an untouched carrier contains no zero-width characters at all.
/// This is what makes the channel conspicuous — the natural rate is zero, not
/// merely low.
#[test]
fn clean_carrier_contains_no_zero_width_characters() {
    let clean = carrier(500);
    assert_eq!(
        lines_with_zw(&clean),
        0,
        "ordinary text must contain no ZW characters"
    );
}

/// v4 marks *every* non-empty line. The README presents this as removing the
/// message/padding boundary, and simultaneously as the strongest signal that a
/// channel is present. Both halves are asserted here.
#[test]
fn v4_marks_every_non_empty_line() {
    let stego = embed_zw(&carrier(3000), b"x");
    let marked = lines_with_zw(&stego);
    let total = non_empty_lines(&stego);

    assert_eq!(
        marked, total,
        "v4 should mark all {total} non-empty lines, marked {marked}"
    );
    assert!(total > 0, "carrier should have non-empty lines");
}

/// The negative claim, as a test: a three-line scanner that knows nothing
/// about SNOW2 separates carrier from stego perfectly. If this test ever
/// fails, the channel got *harder* to detect and the README's Detectability
/// section should be revisited — it is not a regression, but it is a change in
/// what the project may honestly claim.
#[test]
fn naive_scanner_detects_the_channel() {
    fn looks_like_zw_stego(text: &str) -> bool {
        let n = non_empty_lines(text);
        n > 0 && lines_with_zw(text) * 100 / n > 50
    }

    let clean = carrier(1000);
    let stego = embed_zw(&clean, b"hello snow2");

    assert!(
        !looks_like_zw_stego(&clean),
        "scanner must not flag an untouched carrier"
    );
    assert!(
        looks_like_zw_stego(&stego),
        "scanner is expected to flag a v4 carrier — the channel is not hidden"
    );
}

/// The same property for `classic-trailing`: `cat -A` equivalent. A clean
/// carrier has no trailing whitespace; a v4 classic carrier has it on every
/// non-empty line, which is exactly what "trim trailing whitespace on save"
/// tooling keys on.
#[test]
fn classic_trailing_channel_is_equally_visible() {
    fn lines_with_trailing_ws(text: &str) -> usize {
        text.lines()
            .filter(|l| {
                let l = l.trim_end_matches('\r');
                !l.is_empty() && l.ends_with([' ', '\t'])
            })
            .count()
    }

    let clean = carrier(9000);
    assert_eq!(
        lines_with_trailing_ws(&clean),
        0,
        "generated carrier must start with no trailing whitespace"
    );

    let opts = EmbedOptions::new(EmbedSecurityOptions::default());
    let stego = snow2::embed_with_options(
        Mode::ClassicTrailing,
        &clean,
        b"hello snow2",
        b"correct horse battery staple",
        None,
        &opts,
    )
    .expect("classic embed should succeed");

    let marked = lines_with_trailing_ws(&stego);
    let total = non_empty_lines(&stego);
    assert_eq!(
        marked, total,
        "v4 classic-trailing should mark all {total} non-empty lines, marked {marked}"
    );
}

// ── 3. Length masking ───────────────────────────────────────────────────────

/// Constant-size bucketing: payloads of different lengths that land in the
/// same 64-byte bucket must produce channels of identical length, so the
/// carrier does not leak the payload size directly.
#[test]
fn bucket_padding_masks_small_length_differences() {
    let base = carrier(4000);
    let a = decode_channel_bytes(&embed_zw(&base, b"a")).len();
    let b = decode_channel_bytes(&embed_zw(&base, b"abcdefghij")).len();

    // Both carriers are fully filled, so the observable channel length is
    // carrier-determined, not payload-determined.
    assert_eq!(
        a, b,
        "channel length should not vary with payload size within a bucket"
    );
}
