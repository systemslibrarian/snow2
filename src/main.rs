use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use snow2::{config::EmbedSecurityOptions, crypto::KdfParams, Mode};

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
        password: String,

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
        password: String,

        /// Optional pepper / signal key
        #[arg(long)]
        pepper: Option<String>,
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
        } => cmd_embed(
            &mode,
            &carrier,
            &out,
            message.as_deref(),
            input.as_deref(),
            &password,
            pepper.as_deref(),
            pepper_required,
            kdf_mib,
            kdf_iters,
            kdf_par,
        ),

        Commands::Extract {
            mode,
            carrier,
            out,
            password,
            pepper,
        } => cmd_extract(&mode, &carrier, &out, &password, pepper.as_deref()),

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

fn cmd_embed(
    mode_s: &str,
    carrier_path: &str,
    out_path: &str,
    message: Option<&str>,
    input_path: Option<&str>,
    password: &str,
    pepper: Option<&str>,
    pepper_required: bool,
    kdf_mib: u32,
    kdf_iters: u32,
    kdf_par: u32,
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
    let mut opts = EmbedSecurityOptions::default();
    opts.pepper_required = pepper_required;

    // Convert MiB -> KiB for Argon2 Params
    let m_cost_kib = kdf_mib.saturating_mul(1024);

    opts.kdf = KdfParams {
        m_cost_kib,
        t_cost: kdf_iters,
        p_cost: kdf_par,
        out_len: 32,
    };

    // Enforce policy locally too (container open will enforce later as well)
    if opts.pepper_required && pepper.is_none() {
        bail!("--pepper-required was set, but no --pepper was provided.");
    }

    let out_text = snow2::embed_with_options(mode, &carrier_text, &payload, password, pepper, &opts)
        .context("embed failed")?;

    std::fs::write(out_path, out_text.as_bytes())
        .with_context(|| format!("write output carrier: {out_path}"))?;

    println!("OK: embedded {} bytes using mode {}", payload.len(), mode.as_str());
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
    password: &str,
    pepper: Option<&str>,
) -> Result<()> {
    let mode = Mode::parse(mode_s)?;

    let carrier_text = std::fs::read_to_string(carrier_path)
        .with_context(|| format!("read carrier file: {carrier_path}"))?;

    let payload = snow2::extract(mode, &carrier_text, password, pepper).context("extract failed")?;

    std::fs::write(out_path, &payload).with_context(|| format!("write extracted payload: {out_path}"))?;

    println!("OK: extracted {} bytes using mode {}", payload.len(), mode.as_str());
    println!("Wrote: {out_path}");
    Ok(())
}

fn cmd_scan(carrier_path: &str) -> Result<()> {
    let carrier_text = std::fs::read_to_string(carrier_path)
        .with_context(|| format!("read carrier file: {carrier_path}"))?;

    let total_lines = carrier_text.split('\n').count();
    let non_empty_lines = carrier_text.split('\n').filter(|l| !l.is_empty()).count();
    let bytes = carrier_text.as_bytes().len();

    let trailing_ws_lines = carrier_text
        .split('\n')
        .filter(|l| !l.is_empty() && (l.ends_with(' ') || l.ends_with('\t')))
        .count();

    println!("Carrier: {carrier_path}");
    println!("Bytes: {}", bytes);
    println!("Lines: {}", total_lines);
    println!("Non-empty lines: {}", non_empty_lines);
    println!("Lines with trailing space/tab: {}", trailing_ws_lines);

    println!();
    println!("Reminder:");
    println!("  - classic-trailing is most fragile (trimming breaks it).");
    println!("  - websafe-zw may survive more workflows, but some systems strip zero-width chars.");
    println!("  - Larger encrypted payloads need more carrier capacity.");
    Ok(())
}