use snow2::Mode;

#[test]
fn roundtrip_classic_trailing_message() {
    let carrier = (0..5000)
        .map(|i| format!("This is line {i}"))
        .collect::<Vec<_>>()
        .join("\n");

    let password = b"correct horse battery staple";
    let pepper = Some(b"signal key" as &[u8]);
    let payload = b"hello snow2";

    let out_carrier = snow2::embed(
        Mode::ClassicTrailing,
        &carrier,
        payload,
        password,
        pepper,
    )
    .expect("embed should succeed");

    let recovered = snow2::extract(
        Mode::ClassicTrailing,
        &out_carrier,
        password,
        pepper,
        None,
    )
    .expect("extract should succeed");

    assert_eq!(&*recovered, payload);
}

#[test]
fn roundtrip_websafe_zw_message() {
    let carrier = (0..5000)
        .map(|i| format!("This is line {i}"))
        .collect::<Vec<_>>()
        .join("\n");

    let password = b"pw";
    let pepper: Option<&[u8]> = None;
    let payload = b"hello zw";

    let out_carrier = snow2::embed(
        Mode::WebSafeZeroWidth,
        &carrier,
        payload,
        password,
        pepper,
    )
    .expect("embed should succeed");

    let recovered = snow2::extract(
        Mode::WebSafeZeroWidth,
        &out_carrier,
        password,
        pepper,
        None,
    )
    .expect("extract should succeed");

    assert_eq!(&*recovered, payload);
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
        b"right-password",
        None,
    )
    .expect("embed should succeed");

    let err = snow2::extract(
        Mode::ClassicTrailing,
        &out_carrier,
        b"wrong-password",
        None,
        None,
    )
    .unwrap_err();

    // Should fail closed (auth fail)
    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("decrypt") || msg.to_lowercase().contains("auth"),
        "unexpected error: {msg}"
    );
}