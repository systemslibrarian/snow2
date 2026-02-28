use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use snow2::{
    config::EmbedOptions,
    crypto::KdfParams,
    Mode,
};
use zeroize::Zeroize;

use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "snow2",
    version,
    about = "SNOW2 — A modern Rust tribute to Matthew Kwan's SNOW.",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Embed a message or file into a carrier text file
    Embed {
        /// Embedding mode: classic-trailing | websafe-zw
        #[arg(long)]
        mode: String,

        /// Path to carrier file
        #[arg(long)]
        carrier: String,

        /// Output carrier file
        #[arg(long)]
        out: String,

        /// Message to embed (mutually exclusive with --input)
        #[arg(long)]
        message: Option<String>,

        /// Input file to embed (mutually exclusive with --message)
        #[arg(long)]
        input: Option<String>,

        /// Password
        #[arg(long)]
        password: Option<String>,

        /// Optional pepper / signal key
        #[arg(long)]
        pepper: Option<String>,

        /// Require pepper during decrypt (policy is authenticated in the container header)
        #[arg(long, default_value_t = false)]
        pepper_required: bool,

        /// Argon2id memory cost in MiB (default: 64)
        #[arg(long, default_value_t = 64)]
        kdf_mib: u32,

        /// Argon2id iterations/time cost (default: 3)
        #[arg(long, default_value_t = 3)]
        kdf_iters: u32,

        /// Argon2id parallelism (default: 1)
        #[arg(long, default_value_t = 1)]
        kdf_par: u32,

        /// (PQC) Enable post-quantum hybrid encryption.
        #[cfg(feature = "pqc")]
        #[arg(long)]
        pqc_pk: Option<String>,

        /// (PQC) Path to secret key for signing (default: auto-discover from PK path).
        #[cfg(feature = "pqc")]
        #[arg(long)]
        pqc_sk: Option<String>,

        /// (PQC) Password for encrypted secret key file.
        #[cfg(feature = "pqc")]
        #[arg(long)]
        pqc_sk_password: Option<String>,
    },

    /// Extract a message/file from a carrier text file
    Extract {
        /// Embedding mode used: classic-trailing | websafe-zw
        #[arg(long)]
        mode: String,

        /// Path to carrier file
        #[arg(long)]
        carrier: String,

        /// Output file for extracted payload
        #[arg(long)]
        out: String,

        /// Password
        #[arg(long)]
        password: Option<String>,

        /// Optional pepper / signal key
        #[arg(long)]
        pepper: Option<String>,

        /// (PQC) Path to PQC private key file for decryption.
        #[cfg(feature = "pqc")]
        #[arg(long)]
        pqc_sk: Option<String>,

        /// (PQC) Password for encrypted secret key file.
        #[cfg(feature = "pqc")]
        #[arg(long)]
        pqc_sk_password: Option<String>,
    },

    /// Generate a new PQC keypair (if feature is enabled).
    #[cfg(feature = "pqc")]
    PqcKeygen {
        /// Path for the new public key file.
        #[arg(long)]
        pk_out: String,
        /// Path for the new secret key file.
        #[arg(long)]
        sk_out: String,
        /// Password to encrypt the secret key. If omitted, the key is stored unencrypted.
        #[arg(long)]
        sk_password: Option<String>,
    },

    /// Best-effort file shredding (overwrite + remove; see docs for SSD/CoW limits)
    Shred {
        /// Path to the file to securely delete
        #[arg(long)]
        path: String,

        /// Number of overwrite passes (1–5, default: 3). A final random pass is always added.
        #[arg(long, default_value_t = 3)]
        passes: usize,
    },

    /// Scan a carrier for whitespace/normalization risk (informational)
    Scan {
        /// Path to carrier file
        #[arg(long)]
        carrier: String,
    },

    /// Print tribute message
    Tribute,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Embed {
            mode,
            carrier,
            out,
            message,
            input,
            password,
            pepper,
            pepper_required,
            kdf_mib,
            kdf_iters,
            kdf_par,
            #[cfg(feature = "pqc")]
            pqc_pk,
            #[cfg(feature = "pqc")]
            pqc_sk,
            #[cfg(feature = "pqc")]
            pqc_sk_password,
        } => {
            #[cfg(feature = "pqc")]
            let pqc_enabled = pqc_pk.is_some();
            #[cfg(not(feature = "pqc"))]
            let pqc_enabled = false;
            let mut password = get_password(password, !pqc_enabled)?;
            let pepper = get_pepper(pepper)?;
            let res = cmd_embed(
                &mode,
                &carrier,
                &out,
                message.as_deref(),
                input.as_deref(),
                &password,
                pepper.as_deref().map(|p| p.as_bytes()),
                pepper_required,
                kdf_mib,
                kdf_iters,
                kdf_par,
                #[cfg(feature = "pqc")]
                pqc_pk.as_deref(),
                #[cfg(feature = "pqc")]
                pqc_sk.as_deref(),
                #[cfg(feature = "pqc")]
                pqc_sk_password.as_deref(),
            );
            password.zeroize();
            if let Some(mut p) = pepper {
                p.zeroize();
            }
            res
        }

        Commands::Extract {
            mode,
            carrier,
            out,
            password,
            pepper,
            #[cfg(feature = "pqc")]
            pqc_sk,
            #[cfg(feature = "pqc")]
            pqc_sk_password,
        } => {
            #[cfg(feature = "pqc")]
            let pqc_sk_is_none = pqc_sk.is_none();
            #[cfg(not(feature = "pqc"))]
            let pqc_sk_is_none = true;
            let mut password = get_password(password, pqc_sk_is_none)?;
            let pepper = get_pepper(pepper)?;
            let res = cmd_extract(
                &mode,
                &carrier,
                &out,
                &password,
                pepper.as_deref().map(|p| p.as_bytes()),
                #[cfg(feature = "pqc")]
                pqc_sk.as_deref(),
                #[cfg(feature = "pqc")]
                pqc_sk_password.as_deref(),
            );
            password.zeroize();
            if let Some(mut p) = pepper {
                p.zeroize();
            }
            res
        }

        #[cfg(feature = "pqc")]
        Commands::PqcKeygen { pk_out, sk_out, sk_password } => cmd_pqc_keygen(&pk_out, &sk_out, sk_password.as_deref()),

        Commands::Shred { path, passes } => cmd_shred(&path, passes),

        Commands::Scan { carrier } => cmd_scan(&carrier),

        Commands::Tribute => {
            println!("SNOW2 ❄️");
            println!("Inspired by Matthew Kwan's original SNOW steganography tool.");
            println!("A modern Rust reimagining with contemporary cryptography.");
            println!();
            println!("Dedicated to my Dad — a Navy veteran who knew Morse code.");
            Ok(())
        }
    }
}

fn get_password(password: Option<String>, required: bool) -> Result<Zeroizing<String>> {
    match password {
        Some(p) => Ok(Zeroizing::new(p)),
        None => {
            if required {
                let p = rpassword::prompt_password("Password: ")?;
                Ok(Zeroizing::new(p))
            } else {
                Ok(Zeroizing::new(String::new()))
            }
        }
    }
}

fn get_pepper(pepper: Option<String>) -> Result<Option<Zeroizing<String>>> {
    match pepper {
        Some(p) => Ok(Some(Zeroizing::new(p))),
        None => {
            if atty::is(atty::Stream::Stdin) {
                Ok(None)
            } else {
                // If stdin is not a tty, try to read pepper from it
                let mut buf = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
                let buf = buf.trim_end();
                if buf.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(Zeroizing::new(buf.to_string())))
                }
            }
        }
    }
}

fn cmd_embed(
    mode_s: &str,
    carrier_path: &str,
    out_path: &str,
    message: Option<&str>,
    input_path: Option<&str>,
    password: &Zeroizing<String>,
    pepper: Option<&[u8]>,
    pepper_required: bool,
    kdf_mib: u32,
    kdf_iters: u32,
    kdf_par: u32,
    #[cfg(feature = "pqc")] pqc_pk_path: Option<&str>,
    #[cfg(feature = "pqc")] pqc_sk_path: Option<&str>,
    #[cfg(feature = "pqc")] pqc_sk_password: Option<&str>,
) -> Result<()> {
    if message.is_some() && input_path.is_some() {
        bail!("Use either --message or --input, not both.");
    }
    if message.is_none() && input_path.is_none() {
        bail!("Provide one of --message or --input.");
    }

    let mode = Mode::parse(mode_s)?;

    let carrier_text = std::fs::read_to_string(carrier_path)
        .with_context(|| format!("read carrier file: {carrier_path}"))?;

    let payload: Vec<u8> = if let Some(msg) = message {
        msg.as_bytes().to_vec()
    } else {
        let p = input_path.expect("checked above");
        std::fs::read(p).with_context(|| format!("read input file: {p}"))?
    };

    // Build security options from CLI flags
    let mut opts = EmbedOptions::default();
    opts.security.pepper_required = pepper_required;

    // Convert MiB -> KiB for Argon2 Params
    let m_cost_kib = kdf_mib.saturating_mul(1024);

    opts.security.kdf = KdfParams {
        m_cost_kib,
        t_cost: kdf_iters,
        p_cost: kdf_par,
        out_len: 32,
    };

    #[cfg(feature = "pqc")]
    {
        if let Some(pk_path) = pqc_pk_path {
            opts.security.pqc_enabled = true;
            let pk_bytes = std::fs::read(pk_path)
                .with_context(|| format!("Failed to read PQC public key from {}", pk_path))?;
            let pk = snow2::pqc::PqPublicKey::from_bytes(&pk_bytes)?;
            opts.pqc_keys.pk = Some(pk);

            // Load secret key: explicit path, or auto-discover from PK path
            let sk_file_path = if let Some(explicit) = pqc_sk_path {
                std::path::PathBuf::from(explicit)
            } else {
                std::path::Path::new(pk_path).with_extension("sk")
            };

            if sk_file_path.exists() {
                let sk_bytes = std::fs::read(&sk_file_path)
                    .with_context(|| format!("Failed to read PQC secret key from {:?}", sk_file_path))?;

                // Auto-detect encrypted keys and decrypt if needed
                let sk_pw = pqc_sk_password.map(|p| p.as_bytes());
                let sk = snow2::pqc::PqSecretKey::load(&sk_bytes, sk_pw)
                    .with_context(|| format!("Failed to load PQC secret key from {:?}", sk_file_path))?;
                opts.pqc_keys.sk = Some(sk);
            }
        }
    }

    // Enforce policy locally too (container open will enforce later as well)
    if opts.security.pepper_required && pepper.is_none() {
        bail!("--pepper-required was set, but no --pepper was provided.");
    }

    let out_text = snow2::embed_with_options(
        mode,
        &carrier_text,
        &payload,
        password.as_bytes(),
        pepper,
        &opts,
    )
    .context("embed failed")?;

    snow2::secure_fs::write_secure(out_path, out_text.as_bytes(), false)
        .with_context(|| format!("write output carrier: {out_path}"))?;

    println!("OK: embedded {} bytes using mode {}", payload.len(), mode.as_str());
    #[cfg(feature = "pqc")]
    if opts.security.pqc_enabled {
        println!("Encryption: PQC Hybrid (Kyber1024 + XChaCha20-Poly1305)");
    } else {
        println!(
            "KDF: Argon2id m={} MiB t={} p={} (pepper_required={})",
            kdf_mib, kdf_iters, kdf_par, pepper_required
        );
    }
    #[cfg(not(feature = "pqc"))]
    println!(
        "KDF: Argon2id m={} MiB t={} p={} (pepper_required={})",
        kdf_mib, kdf_iters, kdf_par, pepper_required
    );
    println!("Wrote: {out_path}");
    Ok(())
}

fn cmd_extract(
    mode_s: &str,
    carrier_path: &str,
    out_path: &str,
    password: &Zeroizing<String>,
    pepper: Option<&[u8]>,
    #[cfg(feature = "pqc")] pqc_sk_path: Option<&str>,
    #[cfg(feature = "pqc")] pqc_sk_password: Option<&str>,
) -> Result<()> {
    let mode = Mode::parse(mode_s)?;

    let carrier_text = std::fs::read_to_string(carrier_path)
        .with_context(|| format!("read carrier file: {carrier_path}"))?;

    #[cfg(feature = "pqc")]
    let pqc_sk = if let Some(path) = pqc_sk_path {
        let sk_bytes = std::fs::read(path)
            .with_context(|| format!("Failed to read PQC secret key from {}", path))?;

        // Auto-detect encrypted keys and decrypt to raw bytes
        if snow2::pqc::PqSecretKey::is_encrypted(&sk_bytes) {
            let sk_pw = pqc_sk_password
                .map(|p| p.as_bytes())
                .ok_or_else(|| anyhow::anyhow!(
                    "PQC secret key is encrypted; provide --pqc-sk-password to decrypt it."
                ))?;
            let sk = snow2::pqc::PqSecretKey::decrypt(&sk_bytes, sk_pw)?;
            Some(sk.to_zeroizing_bytes())
        } else {
            Some(zeroize::Zeroizing::new(sk_bytes))
        }
    } else {
        None
    };

    #[cfg(not(feature = "pqc"))]
    let pqc_sk: Option<zeroize::Zeroizing<Vec<u8>>> = None;

    let payload = snow2::extract(
        mode,
        &carrier_text,
        password.as_bytes(),
        pepper,
        pqc_sk.as_deref().map(|v| v.as_slice()),
    )
    .context("extract failed")?;

    snow2::secure_fs::write_secure(out_path, &payload[..], true)
        .with_context(|| format!("write extracted payload: {out_path}"))?;

    println!("OK: extracted {} bytes using mode {}", payload.len(), mode.as_str());
    println!("Wrote: {out_path}");
    Ok(())
}

#[cfg(feature = "pqc")]
fn cmd_pqc_keygen(pk_path: &str, sk_path: &str, sk_password: Option<&str>) -> Result<()> {
    let (pk, sk) = snow2::pqc::keypair();

    let pk_bytes = pk.to_bytes();

    // Write public key (not sensitive — permissions are normal)
    snow2::secure_fs::write_secure(pk_path, &pk_bytes, false)
        .with_context(|| format!("write public key to {}", pk_path))?;

    // Handle secret key encryption
    let mut sk_bytes = if let Some(password) = sk_password {
        let encrypted = sk.encrypt(password.as_bytes())
            .context("encrypt secret key")?;
        println!("Secret key encrypted with provided password.");
        encrypted
    } else {
        eprintln!(
            "WARNING: Secret key written WITHOUT encryption. \
             Use --sk-password to protect it."
        );
        sk.to_bytes()
    };

    // Write secret key with hardened permissions (0o600 on Unix)
    snow2::secure_fs::write_secure(sk_path, &sk_bytes, true)
        .with_context(|| format!("write secret key to {}", sk_path))?;

    // Zeroize the secret key bytes now that they've been written to disk.
    use zeroize::Zeroize;
    sk_bytes.zeroize();

    println!("Wrote PQC keypair:");
    println!("  Public key: {} ({} bytes)", pk_path, pk_bytes.len());
    println!("  Secret key: {} ({} bytes, encrypted={})", sk_path, sk_bytes.len(), sk_password.is_some());
    Ok(())
}

fn cmd_shred(path: &str, passes: usize) -> Result<()> {
    if !std::path::Path::new(path).exists() {
        bail!("File not found: {}", path);
    }

    let metadata = std::fs::metadata(path)
        .with_context(|| format!("stat file: {}", path))?;
    let size = metadata.len();

    snow2::secure_fs::secure_delete(path, passes)
        .with_context(|| format!("secure delete: {}", path))?;

    println!(
        "OK: shredded (best-effort) {} ({} bytes, {} pattern passes + 1 random pass)",
        path, size, passes
    );
    Ok(())
}

fn cmd_scan(carrier_path: &str) -> Result<()> {
    let carrier_bytes = std::fs::read(carrier_path)
        .with_context(|| format!("read carrier file: {carrier_path}"))?;
    let carrier_text = String::from_utf8_lossy(&carrier_bytes);

    let total_lines = carrier_text.lines().count();
    let non_empty_lines = carrier_text.lines().filter(|l| !l.is_empty()).count();
    let bytes = carrier_bytes.len();

    // Count zero-width characters
    let zw_chars: usize = carrier_text.chars().filter(|c| matches!(*c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}')).count();

    let trailing_ws_lines = carrier_text
        .lines()
        .filter(|l| !l.is_empty() && (l.ends_with(' ') || l.ends_with('\t')))
        .count();

    // Capacity estimates: each non-empty line carries 1 bit in both modes.
    // We subtract 8 bytes (64 bits) for the bitstream framing header
    // (4 bytes length + 4 bytes CRC-32).
    let raw_bits = non_empty_lines;
    let framing_overhead_bits: usize = 64; // length (32) + CRC-32 (32)
    let usable_bits = raw_bits.saturating_sub(framing_overhead_bits);
    let usable_bytes = usable_bits / 8;

    // Detect line endings
    let crlf_count = carrier_bytes.windows(2).filter(|w| w == b"\r\n").count();
    let lf_only_count = carrier_bytes.iter().filter(|&&b| b == b'\n').count().saturating_sub(crlf_count);
    let line_ending = if crlf_count > 0 && lf_only_count == 0 {
        "CRLF (Windows)"
    } else if crlf_count == 0 {
        "LF (Unix)"
    } else {
        "Mixed CRLF/LF"
    };

    // Detect tabs in content (not trailing whitespace — those are stego)
    let lines_with_tabs = carrier_text
        .lines()
        .filter(|l| l.contains('\t'))
        .count();

    println!("Scan results for: {carrier_path}");
    println!("  Length:        {} bytes", bytes);
    println!("  Lines:         {} (non-empty: {})", total_lines, non_empty_lines);
    println!("  Line endings:  {}", line_ending);
    println!("  Trailing WS:   {} lines", trailing_ws_lines);
    println!("  Zero-width:    {} characters", zw_chars);
    println!("  Lines w/ tabs: {}", lines_with_tabs);
    println!();
    println!("  Stego capacity (1 bit/line, minus framing):");
    println!("    Available:   {} bits = {} bytes", usable_bits, usable_bytes);

    if usable_bytes < 64 {
        println!("    WARNING: Very low capacity. Carrier may be too small for most payloads.");
    }

    // Diagnostics / warnings
    let mut warnings = Vec::new();

    if crlf_count > 0 {
        warnings.push(
            "CRLF line endings detected. Some editors/platforms may convert these to LF, \
             destroying embedded data. Consider normalizing to LF before embedding."
                .to_string(),
        );
    }

    if lines_with_tabs > 0 {
        warnings.push(format!(
            "{} lines contain tab characters. Some editors auto-expand tabs to spaces, \
             which would corrupt classic-trailing stego data.",
            lines_with_tabs
        ));
    }

    if trailing_ws_lines > 0 {
        warnings.push(format!(
            "{} lines already have trailing whitespace. This carrier may already contain \
             classic-trailing encoded data, or editors may strip trailing whitespace on save.",
            trailing_ws_lines
        ));
    }

    if zw_chars > 0 {
        warnings.push(format!(
            "{} zero-width characters found. This carrier may already contain \
             websafe-zw encoded data.",
            zw_chars
        ));
    }

    if !warnings.is_empty() {
        println!();
        for (i, w) in warnings.iter().enumerate() {
            println!("  WARNING {}: {}", i + 1, w);
        }
    }

    Ok(())
}
