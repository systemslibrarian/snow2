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
        } => {
            let pqc_enabled = pqc_pk.is_some();
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
        } => {
            let mut password = get_password(password, pqc_sk.is_none())?;
            let pepper = get_pepper(pepper)?;
            let res = cmd_extract(
                &mode,
                &carrier,
                &out,
                &password,
                pepper.as_deref().map(|p| p.as_bytes()),
                #[cfg(feature = "pqc")]
                pqc_sk.as_deref(),
            );
            password.zeroize();
            if let Some(mut p) = pepper {
                p.zeroize();
            }
            res
        }

        #[cfg(feature = "pqc")]
        Commands::PqcKeygen { pk_out, sk_out } => cmd_pqc_keygen(&pk_out, &sk_out),

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

            // For roundtrip testing, we need the secret key too.
            // In a real scenario, the embedder only has the public key.
            // We'll assume the secret key is in the same directory with a .sk extension.
            let sk_path = std::path::Path::new(pk_path).with_extension("sk");
            if sk_path.exists() {
                let sk_bytes = std::fs::read(&sk_path)
                    .with_context(|| format!("Failed to read PQC secret key from {:?}", sk_path))?;
                let sk = snow2::pqc::PqSecretKey::from_bytes(&sk_bytes)?;
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

    std::fs::write(out_path, out_text.as_bytes())
        .with_context(|| format!("write output carrier: {out_path}"))?;

    println!("OK: embedded {} bytes using mode {}", payload.len(), mode.as_str());
    if opts.security.pqc_enabled {
        println!("Encryption: PQC Hybrid (Kyber1024 + XChaCha20-Poly1305)");
    } else {
        println!(
            "KDF: Argon2id m={} MiB t={} p={} (pepper_required={})",
            kdf_mib, kdf_iters, kdf_par, pepper_required
        );
    }
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
) -> Result<()> {
    let mode = Mode::parse(mode_s)?;

    let carrier_text = std::fs::read_to_string(carrier_path)
        .with_context(|| format!("read carrier file: {carrier_path}"))?;

    #[cfg(feature = "pqc")]
    let pqc_sk = if let Some(path) = pqc_sk_path {
        Some(
            std::fs::read(path)
                .with_context(|| format!("Failed to read PQC secret key from {}", path))?,
        )
    } else {
        None
    };

    let payload = snow2::extract(
        mode,
        &carrier_text,
        password.as_bytes(),
        pepper,
        #[cfg(feature = "pqc")]
        pqc_sk.as_deref(),
    )
    .context("extract failed")?;

    std::fs::write(out_path, &payload[..])
        .with_context(|| format!("write extracted payload: {out_path}"))?;

    println!("OK: extracted {} bytes using mode {}", payload.len(), mode.as_str());
    println!("Wrote: {out_path}");
    Ok(())
}

#[cfg(feature = "pqc")]
fn cmd_pqc_keygen(pk_path: &str, sk_path: &str) -> Result<()> {
    let (pk, sk) = snow2::pqc::keypair();

    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();

    std::fs::write(pk_path, &pk_bytes)
        .with_context(|| format!("write public key to {}", pk_path))?;
    std::fs::write(sk_path, &sk_bytes)
        .with_context(|| format!("write secret key to {}", sk_path))?;
    println!("Wrote PQC keypair:");
    println!("  Public key: {} ({} bytes)", pk_path, pk_bytes.len());
    println!("  Secret key: {} ({} bytes)", sk_path, sk_bytes.len());
    Ok(())
}

fn cmd_scan(carrier_path: &str) -> Result<()> {
    let carrier_text = std::fs::read_to_string(carrier_path)
        .with_context(|| format!("read carrier file: {carrier_path}"))?;

    let total_lines = carrier_text.lines().count();
    let non_empty_lines = carrier_text.lines().filter(|l| !l.is_empty()).count();
    let bytes = carrier_text.len();

    // Count zero-width characters
    let zw_chars: usize = carrier_text.chars().filter(|c| matches!(*c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}')).count();

    let trailing_ws_lines = carrier_text
        .lines()
        .filter(|l| !l.is_empty() && (l.ends_with(' ') || l.ends_with('\t')))
        .count();

    println!("Scan results for: {carrier_path}");
    println!("  Length: {} bytes", bytes);
    println!("  Lines: {}", total_lines);
    println!("  Non-empty lines: {}", non_empty_lines);
    println!("  Lines with trailing whitespace: {}", trailing_ws_lines);
    println!("  Zero-width characters found: {}", zw_chars);

    if trailing_ws_lines > 0 {
        println!();
        println!("NOTE: Trailing whitespace detected. This carrier may already contain classic-trailing encoded data.");
    }
    if zw_chars > 0 {
        println!();
        println!("NOTE: Zero-width characters detected. This carrier may already contain websafe-zw encoded data.");
    }

    Ok(())
}
