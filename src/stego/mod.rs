use anyhow::{anyhow, bail, Context, Result};

pub mod classic_trailing;
pub mod websafe_zw;

// ── Raw bit ↔ byte conversion (no CRC framing) ──────────────────────────
//
// Used by the v4 hardened pipeline where outer AEAD already provides
// integrity checking, making the CRC-32 frame redundant.

/// Convert bytes to bits (MSB-first per byte) — raw, no framing.
pub fn raw_bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for &b in bytes {
        for i in (0..8).rev() {
            bits.push(((b >> i) & 1) == 1);
        }
    }
    bits
}

/// Convert bits to bytes (MSB-first per byte) — raw, no framing.
/// Trailing bits that don't fill a full byte are discarded.
pub fn raw_bits_to_bytes(bits: &[bool]) -> Vec<u8> {
    let byte_count = bits.len() / 8;
    let mut bytes = Vec::with_capacity(byte_count);
    for i in 0..byte_count {
        let mut b = 0u8;
        for j in 0..8 {
            b = (b << 1) | (bits[i * 8 + j] as u8);
        }
        bytes.push(b);
    }
    bytes
}

// ── CRC-framed bit ↔ byte conversion ────────────────────────────────────

/// Convert bytes to a bit vector (MSB-first per byte).
///
/// The bitstream is framed with a length prefix and a CRC-32 integrity checksum:
///
/// ```text
/// [len_u32_le (4 bytes)][crc32_le (4 bytes)][data...]
/// ```
///
/// The CRC-32 catches corruption in the steganographic layer (e.g. whitespace
/// stripping, copy-paste mangling) before the container parser or AEAD sees it.
pub fn bytes_to_bits(bytes: &[u8]) -> Result<Vec<bool>> {
    let len: u32 = bytes
        .len()
        .try_into()
        .map_err(|_| anyhow!("Payload too large for bitstream framing (max {} bytes).", u32::MAX))?;

    // CRC-32 over the raw data payload
    let crc = crc32fast::hash(bytes);

    let mut framed = Vec::with_capacity(4 + 4 + bytes.len());
    framed.extend_from_slice(&len.to_le_bytes());
    framed.extend_from_slice(&crc.to_le_bytes());
    framed.extend_from_slice(bytes);

    let mut bits = Vec::with_capacity(framed.len() * 8);
    for b in framed {
        for i in (0..8).rev() {
            bits.push(((b >> i) & 1) == 1);
        }
    }
    Ok(bits)
}

/// Helper: read `count` bytes from `bits` starting at bit position `bit_offset`.
/// Returns a `Vec<u8>` of `count` bytes.
fn read_bytes_from_bits(bits: &[bool], bit_offset: usize, count: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(count);
    for byte_i in 0..count {
        let mut b = 0u8;
        for bit_j in 0..8 {
            let bit = bits[bit_offset + byte_i * 8 + bit_j];
            b = (b << 1) | (bit as u8);
        }
        out.push(b);
    }
    out
}

/// Convert bits back to bytes, using the length + CRC-32 header.
///
/// Verifies the CRC-32 checksum before returning the data. Returns ONLY
/// the data bytes (not including the 8-byte header).
pub fn bits_to_bytes(bits: &[bool]) -> Result<Vec<u8>> {
    // Need at least 64 bits for [len (32 bits)] + [crc (32 bits)]
    if bits.len() < 64 {
        bail!("Not enough bits to contain length + checksum prefix.");
    }

    // Read length (first 4 bytes / 32 bits)
    let len_bytes_raw = read_bytes_from_bits(bits, 0, 4);
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&len_bytes_raw);
    let data_len = u32::from_le_bytes(len_bytes) as usize;

    // Read CRC (next 4 bytes / 32 bits)
    let crc_bytes_raw = read_bytes_from_bits(bits, 32, 4);
    let mut crc_bytes = [0u8; 4];
    crc_bytes.copy_from_slice(&crc_bytes_raw);
    let expected_crc = u32::from_le_bytes(crc_bytes);

    // Validate total required length
    let header_bytes = 8usize; // len + crc
    let total_bytes = header_bytes
        .checked_add(data_len)
        .context("length overflow")?;
    let total_bits = total_bytes
        .checked_mul(8)
        .context("bit length overflow")?;

    if bits.len() < total_bits {
        bail!(
            "Not enough bits for declared payload length (need {}, got {}).",
            total_bits,
            bits.len()
        );
    }

    // Extract data bytes (starting after the 8-byte header = bit 64)
    let data = read_bytes_from_bits(bits, 64, data_len);

    // Verify CRC-32
    let actual_crc = crc32fast::hash(&data);
    if actual_crc != expected_crc {
        bail!(
            "Bitstream integrity check failed (CRC-32 mismatch: expected {:08X}, got {:08X}). \
             The carrier may have been corrupted (whitespace stripped, copy-paste mangled, etc.).",
            expected_crc,
            actual_crc
        );
    }

    Ok(data)
}