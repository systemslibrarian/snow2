use anyhow::{bail, Context, Result};

pub mod classic_trailing;
pub mod websafe_zw;

/// Convert bytes to a bit vector (MSB-first per byte).
///
/// IMPORTANT: We add a 4-byte little-endian length prefix so extraction
/// knows exactly how many bytes to reconstruct.
///
/// Encoded stream:
/// [len_u32_le][data...]
pub fn bytes_to_bits(mut bytes: Vec<u8>) -> Vec<bool> {
    let len: u32 = bytes
        .len()
        .try_into()
        .unwrap_or(u32::MAX); // extremely unlikely; we keep simple here

    let mut framed = Vec::with_capacity(4 + bytes.len());
    framed.extend_from_slice(&len.to_le_bytes());
    framed.append(&mut bytes);

    let mut bits = Vec::with_capacity(framed.len() * 8);
    for b in framed {
        for i in (0..8).rev() {
            bits.push(((b >> i) & 1) == 1);
        }
    }
    bits
}

/// Convert bits back to bytes, using the 4-byte length prefix.
/// Returns ONLY the data bytes (not including length prefix).
pub fn bits_to_bytes(bits: &[bool]) -> Result<Vec<u8>> {
    if bits.len() < 32 {
        bail!("Not enough bits to contain length prefix.");
    }

    // Read first 32 bits as u32 LE length (byte order LE, but bits are MSB-first within each byte)
    let mut len_bytes = [0u8; 4];
    for byte_idx in 0..4 {
        let mut b = 0u8;
        for bit_idx in 0..8 {
            let bit = bits[byte_idx * 8 + bit_idx];
            b = (b << 1) | (bit as u8);
        }
        len_bytes[byte_idx] = b;
    }
    let data_len = u32::from_le_bytes(len_bytes) as usize;

    let total_bytes = 4usize
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

    let mut out = Vec::with_capacity(data_len);

    // Parse bytes starting at bit 32
    let start = 32;
    for byte_i in 0..data_len {
        let mut b = 0u8;
        for bit_j in 0..8 {
            let bit = bits[start + byte_i * 8 + bit_j];
            b = (b << 1) | (bit as u8);
        }
        out.push(b);
    }

    Ok(out)
}