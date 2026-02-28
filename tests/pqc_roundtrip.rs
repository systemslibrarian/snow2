#![cfg(feature = "pqc")]
use snow2::pqc::{PqPublicKey, PqSecretKey};
use std::fs;
use std::process::Command;

fn run_command(command: &mut Command) -> (bool, String, String) {
    let output = command.output().expect("Failed to execute command");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (output.status.success(), stdout, stderr)
}

#[test]
fn test_pqc_keygen() {
    let dir = "target/test_pqc_keygen";
    let pk = format!("{dir}/key.pk");
    let sk = format!("{dir}/key.sk");
    fs::create_dir_all(dir).unwrap();

    let mut cmd = Command::new("target/debug/snow2");
    cmd.args(&["pqc-keygen", "--pk-out", &pk, "--sk-out", &sk]);

    let (success, stdout, stderr) = run_command(&mut cmd);
    assert!(
        success,
        "pqc-keygen failed. stdout: {}, stderr: {}",
        stdout, stderr
    );

    let pk_bytes = fs::read(&pk).unwrap();
    let sk_bytes = fs::read(&sk).unwrap();

    assert!(PqPublicKey::from_bytes(&pk_bytes).is_ok());
    assert!(PqSecretKey::from_bytes(&sk_bytes).is_ok());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn test_pqc_roundtrip() {
    let dir = "target/test_pqc_roundtrip";
    let input_file = format!("{dir}/input.txt");
    let carrier_file = format!("{dir}/carrier.txt");
    let stego_file = format!("{dir}/stego.txt");
    let output_file = format!("{dir}/output.txt");
    let pk_file = format!("{dir}/key.pk");
    let sk_file = format!("{dir}/key.sk");

    fs::create_dir_all(dir).unwrap();
    fs::write(&input_file, "PQC test").unwrap();
    let carrier: String = (0..100_000)
        .map(|i| format!("Carrier line number {i}"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&carrier_file, &carrier).unwrap();

    // 1. Key Generation
    let mut keygen_cmd = Command::new("target/debug/snow2");
    keygen_cmd.args(&["pqc-keygen", "--pk-out", &pk_file, "--sk-out", &sk_file]);
    let (success, stdout, stderr) = run_command(&mut keygen_cmd);
    assert!(
        success,
        "pqc-keygen failed. stdout: {}, stderr: {}",
        stdout, stderr
    );

    // 2. Embed
    let mut embed_cmd = Command::new("target/debug/snow2");
    embed_cmd.args(&[
        "embed",
        "--mode",
        "classic-trailing",
        "--carrier",
        &carrier_file,
        "--out",
        &stego_file,
        "--input",
        &input_file,
        "--pqc-pk",
        &pk_file,
    ]);
    let (success, stdout, stderr) = run_command(&mut embed_cmd);
    assert!(
        success,
        "embed --pqc-pk failed. stdout: {}, stderr: {}",
        stdout, stderr
    );

    // 3. Extract
    let mut extract_cmd = Command::new("target/debug/snow2");
    extract_cmd.args(&[
        "extract",
        "--mode",
        "classic-trailing",
        "--carrier",
        &stego_file,
        "--out",
        &output_file,
        "--pqc-sk",
        &sk_file,
    ]);
    let (success, stdout, stderr) = run_command(&mut extract_cmd);
    assert!(
        success,
        "extract --pqc-sk failed. stdout: {}, stderr: {}",
        stdout, stderr
    );

    // 4. Verify
    let original_message = fs::read_to_string(&input_file).unwrap();
    let extracted_message = fs::read_to_string(&output_file).unwrap();
    assert_eq!(original_message, extracted_message);

    let _ = fs::remove_dir_all(dir);
}

// ── Malformed PQC key tests ──────────────────────────────────────────

#[test]
fn test_pqc_public_key_rejects_wrong_size() {
    let short = vec![0u8; 100];
    let err = PqPublicKey::from_bytes(&short).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("Invalid PQC public key length"),
        "expected size rejection, got: {msg}"
    );
}

#[test]
fn test_pqc_secret_key_rejects_wrong_size() {
    let short = vec![0u8; 100];
    let err = PqSecretKey::from_bytes(&short).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("Invalid PQC secret key length"),
        "expected size rejection, got: {msg}"
    );
}

#[test]
fn test_pqc_secret_key_rejects_empty() {
    let err = PqSecretKey::from_bytes(&[]).unwrap_err();
    assert!(format!("{err:#}").contains("Invalid PQC secret key length"));
}

#[test]
fn test_pqc_encrypted_key_rejects_bad_magic() {
    let garbage = b"NOT_SNOW_ENCRYPTED_KEY_FILE_CONTENTS_HERE_1234567890";
    assert!(!PqSecretKey::is_encrypted(garbage));
    let err = PqSecretKey::from_bytes(garbage).unwrap_err();
    assert!(format!("{err:#}").contains("Invalid PQC secret key length"));
}

#[test]
fn test_pqc_encrypted_key_rejects_truncated() {
    let mut data = Vec::new();
    data.extend_from_slice(b"SNOW2EK\0");
    data.push(1); // version
    data.extend_from_slice(&[0u8; 10]); // too short

    assert!(PqSecretKey::is_encrypted(&data));
    let err = PqSecretKey::decrypt(&data, b"password").unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("too short") || msg.to_lowercase().contains("decrypt"),
        "expected truncation rejection, got: {msg}"
    );
}

#[test]
fn test_pqc_encrypted_key_rejects_wrong_password() {
    let (_pk, sk) = snow2::pqc::keypair();
    let encrypted = sk.encrypt(b"correct_password").unwrap();

    let err = PqSecretKey::decrypt(&encrypted, b"wrong_password").unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("decrypt") || msg.to_lowercase().contains("auth"),
        "expected auth failure, got: {msg}"
    );
}

#[test]
fn test_pqc_encrypted_key_roundtrip() {
    let (_pk, sk) = snow2::pqc::keypair();
    let original_bytes = sk.to_bytes();

    let encrypted = sk.encrypt(b"my_password").unwrap();
    assert!(PqSecretKey::is_encrypted(&encrypted));

    let decrypted = PqSecretKey::decrypt(&encrypted, b"my_password").unwrap();
    assert_eq!(original_bytes, decrypted.to_bytes());
}

#[test]
fn test_pqc_to_zeroizing_bytes() {
    let (_pk, sk) = snow2::pqc::keypair();
    let plain = sk.to_bytes();
    let zeroizing = sk.to_zeroizing_bytes();
    assert_eq!(&plain, &*zeroizing, "zeroizing_bytes should match to_bytes");
}
