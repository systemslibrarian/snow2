use snow2::{config::EmbedSecurityOptions, crypto::KdfParams, Mode};

fn big_carrier(lines: usize) -> String {
    (0..lines)
        .map(|i| format!("Carrier line {i}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn pepper_required_blocks_missing_pepper_on_embed() {
    let carrier = big_carrier(6000);
    let payload = b"hello";

    let mut opts = EmbedSecurityOptions::default();
    opts.pepper_required = true;

    let err = snow2::embed_with_options(
        Mode::ClassicTrailing,
        &carrier,
        payload,
        "pw",
        None, // missing pepper
        &opts,
    )
    .unwrap_err();

    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("pepper is required"),
        "unexpected error: {msg}"
    );
}

#[test]
fn pepper_required_blocks_missing_pepper_on_extract() {
    let carrier = big_carrier(6000);
    let payload = b"hello";

    let mut opts = EmbedSecurityOptions::default();
    opts.pepper_required = true;

    let out_carrier = snow2::embed_with_options(
        Mode::ClassicTrailing,
        &carrier,
        payload,
        "pw",
        Some("signal"),
        &opts,
    )
    .expect("embed should succeed");

    let err = snow2::extract(
        Mode::ClassicTrailing,
        &out_carrier,
        "pw",
        None, // missing pepper at extract time
    )
    .unwrap_err();

    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("pepper is required"),
        "unexpected error: {msg}"
    );
}

#[test]
fn kdf_tuning_roundtrip_still_works() {
    let carrier = big_carrier(8000);
    let payload = b"kdf tuning test";

    let mut opts = EmbedSecurityOptions::default();
    opts.pepper_required = true;

    // Example stronger KDF params
    opts.kdf = KdfParams {
        m_cost_kib: 128 * 1024, // 128 MiB
        t_cost: 4,
        p_cost: 1,
        out_len: 32,
    };

    let out_carrier = snow2::embed_with_options(
        Mode::ClassicTrailing,
        &carrier,
        payload,
        "pw",
        Some("signal"),
        &opts,
    )
    .expect("embed should succeed");

    let recovered = snow2::extract(
        Mode::ClassicTrailing,
        &out_carrier,
        "pw",
        Some("signal"),
    )
    .expect("extract should succeed");

    assert_eq!(recovered, payload);
}