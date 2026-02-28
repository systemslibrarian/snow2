use snow2::{
    config::{EmbedOptions, EmbedSecurityOptions},
    container::Snow2Container,
    crypto::KdfParams,
    Mode,
};

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

    let sec = EmbedSecurityOptions {
        pepper_required: true,
        ..EmbedSecurityOptions::default()
    };
    let opts = EmbedOptions { security: sec };

    let err = snow2::embed_with_options(
        Mode::ClassicTrailing,
        &carrier,
        payload,
        b"pw",
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

    let sec = EmbedSecurityOptions {
        pepper_required: true,
        ..EmbedSecurityOptions::default()
    };
    let opts = EmbedOptions { security: sec };

    let out_carrier = snow2::embed_with_options(
        Mode::ClassicTrailing,
        &carrier,
        payload,
        b"pw",
        Some(b"signal" as &[u8]),
        &opts,
    )
    .expect("embed should succeed");

    let err = snow2::extract(
        Mode::ClassicTrailing,
        &out_carrier,
        b"pw",
        None, // missing pepper at extract time
        None,
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

    let sec = EmbedSecurityOptions {
        pepper_required: true,
        kdf: KdfParams {
            m_cost_kib: 128 * 1024, // 128 MiB
            t_cost: 4,
            p_cost: 1,
            out_len: 32,
        },
    };
    let opts = EmbedOptions { security: sec };

    let out_carrier = snow2::embed_with_options(
        Mode::ClassicTrailing,
        &carrier,
        payload,
        b"pw",
        Some(b"signal" as &[u8]),
        &opts,
    )
    .expect("embed should succeed");

    let recovered = snow2::extract(
        Mode::ClassicTrailing,
        &out_carrier,
        b"pw",
        Some(b"signal" as &[u8]),
        None,
    )
    .expect("extract should succeed");

    assert_eq!(&*recovered, payload);
}

#[test]
fn kdf_bounds_rejects_extreme_m_cost() {
    // A container with absurdly high m_cost should be rejected during
    // extraction, not after allocating terabytes of RAM.
    let params = KdfParams {
        m_cost_kib: u32::MAX, // ~4 TiB — way above 4 GiB cap
        t_cost: 3,
        p_cost: 1,
        out_len: 32,
    };

    let err = params.validate_extraction_bounds().unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("memory cost too high"),
        "expected memory cost rejection, got: {msg}"
    );
}

#[test]
fn kdf_bounds_rejects_extreme_t_cost() {
    let params = KdfParams {
        m_cost_kib: 64 * 1024,
        t_cost: 1000, // way above 64 cap
        p_cost: 1,
        out_len: 32,
    };

    let err = params.validate_extraction_bounds().unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("time cost too high"),
        "expected time cost rejection, got: {msg}"
    );
}

#[test]
fn kdf_bounds_rejects_wrong_out_len() {
    let params = KdfParams {
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_cost: 1,
        out_len: 64, // only 32 is supported
    };

    let err = params.validate_extraction_bounds().unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("output length"),
        "expected out_len rejection, got: {msg}"
    );
}

#[test]
fn kdf_bounds_accepts_recommended() {
    KdfParams::recommended()
        .validate_extraction_bounds()
        .expect("recommended params should pass bounds check");
}

#[test]
fn kdf_bounds_accepts_hardened() {
    KdfParams::hardened()
        .validate_extraction_bounds()
        .expect("hardened params should pass bounds check");
}

#[test]
fn hardened_profile_roundtrip() {
    let carrier = big_carrier(8000);
    let payload = b"hardened profile test";

    let sec = EmbedSecurityOptions::hardened();
    let opts = EmbedOptions { security: sec };

    let out_carrier = snow2::embed_with_options(
        Mode::ClassicTrailing,
        &carrier,
        payload,
        b"pw",
        Some(b"signal" as &[u8]),
        &opts,
    )
    .expect("embed with hardened profile should succeed");

    let recovered = snow2::extract(
        Mode::ClassicTrailing,
        &out_carrier,
        b"pw",
        Some(b"signal" as &[u8]),
        None,
    )
    .expect("extract should succeed");

    assert_eq!(&*recovered, payload);
}

// ── Embed-side KDF validation ─────────────────────────────────────────

#[test]
fn embed_rejects_weak_kdf_at_seal_time() {
    // Creating a container with KDF params below the extraction-side
    // minimum should fail immediately, not produce a container that
    // can never be extracted.
    let carrier = big_carrier(6000);
    let payload = b"hello";

    let sec = EmbedSecurityOptions {
        kdf: KdfParams {
            m_cost_kib: 1024, // 1 MiB — way below 8 MiB minimum
            t_cost: 3,
            p_cost: 1,
            out_len: 32,
        },
        ..EmbedSecurityOptions::default()
    };
    let opts = EmbedOptions { security: sec };

    let err =
        snow2::embed_with_options(Mode::ClassicTrailing, &carrier, payload, b"pw", None, &opts)
            .unwrap_err();

    let msg = format!("{err:#}");
    assert!(
        msg.contains("memory cost too low"),
        "expected embed-side KDF rejection, got: {msg}"
    );
}

#[test]
fn embed_rejects_absurd_kdf_at_seal_time() {
    let carrier = big_carrier(6000);
    let payload = b"hello";

    let sec = EmbedSecurityOptions {
        kdf: KdfParams {
            m_cost_kib: u32::MAX,
            t_cost: 3,
            p_cost: 1,
            out_len: 32,
        },
        ..EmbedSecurityOptions::default()
    };
    let opts = EmbedOptions { security: sec };

    let err =
        snow2::embed_with_options(Mode::ClassicTrailing, &carrier, payload, b"pw", None, &opts)
            .unwrap_err();

    let msg = format!("{err:#}");
    assert!(
        msg.contains("memory cost too high"),
        "expected embed-side KDF rejection, got: {msg}"
    );
}

// ── Malformed container parsing ───────────────────────────────────────

#[test]
fn from_bytes_rejects_truncated_input() {
    assert!(Snow2Container::from_bytes(b"").is_err());
    assert!(Snow2Container::from_bytes(b"SNOW").is_err());
    assert!(Snow2Container::from_bytes(b"SNOW2\x01").is_err());
}

#[test]
fn from_bytes_rejects_bad_magic() {
    let err = Snow2Container::from_bytes(b"FAKE2\x01\x00\x00\x00\x00").unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("not a snow2 container"),
        "expected magic rejection, got: {msg}"
    );
}

#[test]
fn from_bytes_rejects_oversized_header() {
    // header_len = 1 MiB (way above 64 KiB cap)
    let mut input = Vec::new();
    input.extend_from_slice(b"SNOW2");
    input.push(1); // version
    input.extend_from_slice(&(1_048_576u32).to_le_bytes()); // 1 MiB
    input.extend_from_slice(&[0u8; 100]); // filler

    let err = Snow2Container::from_bytes(&input).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("Header too large"),
        "expected header size rejection, got: {msg}"
    );
}

// ── KDF boundary-value tests ─────────────────────────────────────────

#[test]
fn kdf_bounds_accepts_max_m_cost() {
    // Exactly at the 512 MiB cap — should pass
    let params = KdfParams {
        m_cost_kib: 512 * 1024,
        t_cost: 3,
        p_cost: 1,
        out_len: 32,
    };
    params
        .validate_extraction_bounds()
        .expect("exactly-at-max m_cost should pass");
}

#[test]
fn kdf_bounds_rejects_just_above_max_m_cost() {
    // 1 KiB above 512 MiB cap — should be rejected
    let params = KdfParams {
        m_cost_kib: 512 * 1024 + 1,
        t_cost: 3,
        p_cost: 1,
        out_len: 32,
    };
    let err = params.validate_extraction_bounds().unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("memory cost too high"),
        "expected just-above-max rejection, got: {msg}"
    );
}

#[test]
fn kdf_bounds_accepts_min_m_cost() {
    // Exactly at the 8 MiB floor — should pass
    let params = KdfParams {
        m_cost_kib: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
        out_len: 32,
    };
    params
        .validate_extraction_bounds()
        .expect("exactly-at-min m_cost should pass");
}

#[test]
fn kdf_bounds_rejects_just_below_min_m_cost() {
    // 1 KiB below 8 MiB floor — should be rejected
    let params = KdfParams {
        m_cost_kib: 8 * 1024 - 1,
        t_cost: 1,
        p_cost: 1,
        out_len: 32,
    };
    let err = params.validate_extraction_bounds().unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("memory cost too low"),
        "expected just-below-min rejection, got: {msg}"
    );
}

#[test]
fn kdf_bounds_accepts_max_t_cost() {
    let params = KdfParams {
        m_cost_kib: 64 * 1024,
        t_cost: 64,
        p_cost: 1,
        out_len: 32,
    };
    params
        .validate_extraction_bounds()
        .expect("exactly-at-max t_cost should pass");
}

#[test]
fn kdf_bounds_rejects_just_above_max_t_cost() {
    let params = KdfParams {
        m_cost_kib: 64 * 1024,
        t_cost: 65,
        p_cost: 1,
        out_len: 32,
    };
    let err = params.validate_extraction_bounds().unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("time cost too high"),
        "expected t_cost rejection, got: {msg}"
    );
}

#[test]
fn kdf_bounds_accepts_max_p_cost() {
    let params = KdfParams {
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_cost: 16,
        out_len: 32,
    };
    params
        .validate_extraction_bounds()
        .expect("exactly-at-max p_cost should pass");
}

#[test]
fn kdf_bounds_rejects_just_above_max_p_cost() {
    let params = KdfParams {
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_cost: 17,
        out_len: 32,
    };
    let err = params.validate_extraction_bounds().unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("parallelism too high"),
        "expected p_cost rejection, got: {msg}"
    );
}

// ── secure_fs tests ──────────────────────────────────────────────────

#[test]
fn write_secure_creates_file_atomically() {
    let dir = "target/test_write_secure_atomic";
    std::fs::create_dir_all(dir).unwrap();
    let path = format!("{}/test_output.txt", dir);

    snow2::secure_fs::write_secure(&path, b"atomic write test", false).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "atomic write test");

    // Verify no leftover temp files
    let temps: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
        .collect();
    assert!(
        temps.is_empty(),
        "temp file was not cleaned up: {:?}",
        temps
    );

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn write_secure_sensitive_sets_permissions() {
    let dir = "target/test_write_secure_perms";
    std::fs::create_dir_all(dir).unwrap();
    let path = format!("{}/test_sensitive.txt", dir);

    snow2::secure_fs::write_secure(&path, b"sensitive data", true).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "sensitive data");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(
            perms.mode() & 0o777,
            0o600,
            "sensitive file should be mode 0o600"
        );
    }

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn write_secure_temp_names_are_unique() {
    // Write the same path twice — both should succeed (no collision on temp name)
    let dir = "target/test_write_secure_unique";
    std::fs::create_dir_all(dir).unwrap();
    let path = format!("{}/test_unique.txt", dir);

    snow2::secure_fs::write_secure(&path, b"first", false).unwrap();
    snow2::secure_fs::write_secure(&path, b"second", false).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "second");

    let _ = std::fs::remove_dir_all(dir);
}
