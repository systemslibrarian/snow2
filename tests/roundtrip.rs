use snow2::{Mode};

#[test]
fn roundtrip_classic_trailing_message() {
    // Carrier must have at least as many non-empty lines as there are bits to embed.
    // The payload is a full SNOW2 container, so it needs a decent number of lines.
    // We'll give it plenty.
    let carrier = (0..5000)
        .map(|i| format!("This is line {i}"))
        .collect::<Vec<_>>()
        .join("\n");

    let password = "correct horse battery staple";
    let pepper = Some("signal key");
    let payload = b"hello snow2";

    let out_carrier = snow2::embed(
        Mode::ClassicTrailing,
        &carrier,
        payload,
        password,
        pepper,
    ).expect("embed should succeed");

    let recovered = snow2::extract(
        Mode::ClassicTrailing,
        &out_carrier,
        password,
        pepper,
    ).expect("extract should succeed");

    assert_eq!(recovered, payload);
}

#[test]
fn roundtrip_websafe_zw_message() {
    let carrier = (0..5000)
        .map(|i| format!("This is line {i}"))
        .collect::<Vec<_>>()
        .join("\n");

    let password = "pw";
    let pepper = None;
    let payload = b"hello zw";

    let out_carrier = snow2::embed(
        Mode::WebSafeZeroWidth,
        &carrier,
        payload,
        password,
        pepper,
    ).expect("embed should succeed");

    let recovered = snow2::extract(
        Mode::WebSafeZeroWidth,
        &out_carrier,
        password,
        pepper,
    ).expect("extract should succeed");

    assert_eq!(recovered, payload);
}

#[test]
fn wrong_password_fails() {
    let carrier = (0..5000)
        .map(|i| format!("Line {i}"))
        .collect::<Vec<_>>()
        .join("\n");

    let payload = b"top secret";
    let out_carrier = snow2::embed(
        Mode::ClassicTrailing,
        &carrier,
        payload,
        "right-password",
        None,
    ).expect("embed should succeed");

    let err = snow2::extract(
        Mode::ClassicTrailing,
        &out_carrier,
        "wrong-password",
        None,
    ).unwrap_err();

    // Should fail closed (auth fail)
    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("decrypt") || msg.to_lowercase().contains("auth"),
        "unexpected error: {msg}"
    );
}