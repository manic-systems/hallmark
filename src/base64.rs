//! RFC 4648 base64 with the standard alphabet, as used for Nix signing keys
//! and signatures.

use thiserror::Error;

const ALPHABET: &[u8; 64] =
  b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[expect(clippy::cast_possible_truncation, reason = "i ranges over 0..64")]
const DECODE: [u8; 256] = {
  let mut table = [0xFF_u8; 256];
  let mut i = 0;
  while i < 64 {
    table[ALPHABET[i] as usize] = i as u8;
    i += 1;
  }
  table
};

/// Why a base64 string could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecodeError {
  /// A byte that is not in the base64 alphabet, including misplaced `=`.
  #[error("invalid base64 character {0:?}")]
  InvalidChar(u8),
  /// The length cannot come from any encoding, padded or unpadded.
  #[error("invalid base64 length {0}")]
  InvalidLength(usize),
  /// The final character encodes bits past the end of the decoded bytes, so
  /// the input would not round-trip.
  #[error("base64 input has non-zero padding bits")]
  NonZeroPadding,
}

/// Encode `bytes` as padded base64.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
  let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
  for chunk in bytes.chunks(3) {
    let n = chunk
      .iter()
      .enumerate()
      .fold(0_u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
    for i in 0..4 {
      if i <= chunk.len() {
        out.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 0x3F) as usize]));
      } else {
        out.push('=');
      }
    }
  }
  out
}

/// Decode base64, with or without trailing `=` padding.
///
/// Nix and tools like `atticd` are inconsistent about trailing `=` padding on
/// public keys, so decoding must accept both.
///
/// # Errors
///
/// Returns [`DecodeError::InvalidChar`] for a byte outside the alphabet,
/// [`DecodeError::InvalidLength`] for a length no encoding produces, or
/// [`DecodeError::NonZeroPadding`] when the final character carries bits
/// that would not round-trip.
#[expect(
  clippy::cast_possible_truncation,
  reason = "acc is masked to fewer than 8 + 6 bits, so the shifted byte fits"
)]
pub fn decode(input: &str) -> Result<Vec<u8>, DecodeError> {
  let bytes = input.as_bytes();
  let data = bytes
    .strip_suffix(b"==")
    .or_else(|| bytes.strip_suffix(b"="))
    .unwrap_or(bytes);

  let padded = data.len() != bytes.len();
  if (padded && !bytes.len().is_multiple_of(4)) || data.len() % 4 == 1 {
    return Err(DecodeError::InvalidLength(bytes.len()));
  }

  let mut out = Vec::with_capacity(data.len() * 3 / 4);
  let mut acc = 0_u32;
  let mut bits = 0;
  for &c in data {
    let value = DECODE[usize::from(c)];
    if value == 0xFF {
      return Err(DecodeError::InvalidChar(c));
    }
    acc = acc << 6 | u32::from(value);
    bits += 6;
    if bits >= 8 {
      bits -= 8;
      out.push((acc >> bits) as u8);
      acc &= (1 << bits) - 1;
    }
  }

  if acc != 0 {
    return Err(DecodeError::NonZeroPadding);
  }
  Ok(out)
}
