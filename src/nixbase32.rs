//! Nix's base32 (which is not RFC 4648). The alphabet omits `e o u t` and
//! digits are emitted most-significant-first, so a 20-byte store-path digest
//! encodes to 32 characters and a 32-byte hash to 52.

use thiserror::Error;

const ALPHABET: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";

// `i` ranges over 0..32, so the `as u8` is exact.
#[allow(clippy::cast_possible_truncation)]
const DECODE: [u8; 256] = {
  let mut table = [0xFF_u8; 256];
  let mut i = 0;
  while i < 32 {
    table[ALPHABET[i] as usize] = i as u8;
    i += 1;
  }
  table
};

/// Why a nixbase32 string could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecodeError {
  /// A byte that is not in the Nix alphabet (which omits `e`, `o`, `u`, `t`).
  #[error("invalid nixbase32 character {0:?}")]
  InvalidChar(u8),
  /// The most-significant character encodes bits that fall outside the
  /// decoded byte length, so the input would not round-trip.
  #[error("nixbase32 input has non-zero padding bits")]
  NonZeroPadding,
}

/// The number of nixbase32 characters that encode `len` bytes.
#[must_use]
pub const fn encode_len(len: usize) -> usize {
  if len == 0 { 0 } else { (len * 8 - 1) / 5 + 1 }
}

/// The number of bytes that `len` nixbase32 characters decode to.
#[must_use]
pub const fn decode_len(len: usize) -> usize {
  len * 5 / 8
}

/// Encode `bytes` as a nixbase32 string, most-significant digit first.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
  let len = encode_len(bytes.len());
  let mut out = String::with_capacity(len);
  for n in (0..len).rev() {
    let b = n * 5;
    let i = b / 8;
    let j = b % 8;
    let c = (u32::from(bytes[i]) >> j)
      | bytes.get(i + 1).map_or(0, |&b| u32::from(b) << (8 - j));
    out.push(char::from(ALPHABET[(c & 0x1F) as usize]));
  }
  out
}

/// Decode a nixbase32 string into its bytes.
///
/// # Errors
///
/// Returns [`DecodeError::InvalidChar`] for a byte outside the Nix alphabet
/// (which omits `e`, `o`, `u`, and `t`), or
/// [`DecodeError::NonZeroPadding`] when the final character carries bits
/// that would not round-trip.
// The narrowing casts keep only the low bits of each 5-bit digit; the
// overflow is captured separately as `carry`.
#[allow(clippy::cast_possible_truncation)]
pub fn decode(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
  let output_len = decode_len(input.len());
  let mut output = vec![0_u8; output_len];
  for (n, &c) in input.iter().rev().enumerate() {
    let digit = DECODE[c as usize];
    if digit == 0xFF {
      return Err(DecodeError::InvalidChar(c));
    }
    let digit = u16::from(digit);
    let b = n * 5;
    let i = b / 8;
    let j = (b % 8) as u16;
    output[i] |= (digit << j) as u8;
    let carry = (digit >> (8 - j)) as u8;
    if i + 1 < output_len {
      output[i + 1] |= carry;
    } else if carry != 0 {
      return Err(DecodeError::NonZeroPadding);
    }
  }
  Ok(output)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn empty() {
    assert_eq!(encode(&[]), "");
    assert_eq!(decode(b"").unwrap(), Vec::<u8>::new());
  }

  #[test]
  fn sha256_empty_vector() {
    let digest: [u8; 32] = [
      0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 0x9A, 0xFB, 0xF4, 0xC8,
      0x99, 0x6F, 0xB9, 0x24, 0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C,
      0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55,
    ];
    let encoded = encode(&digest);
    assert_eq!(
      encoded,
      "0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73"
    );
    assert_eq!(encoded.len(), 52);
    assert_eq!(decode(encoded.as_bytes()).unwrap(), digest);
  }

  #[test]
  fn roundtrip_digest() {
    let digest: [u8; 20] =
      *b"\x8a\x12\x32\x15\x22\xfd\x91\xef\xbd\x60\xeb\xb2\x48\x1a\xf8\x85\x80\xf6\x16\x00";
    let encoded = encode(&digest);
    assert_eq!(encoded, "00bgd045z0d4icpbc2yyz4gx48ak44la");
    assert_eq!(decode(encoded.as_bytes()).unwrap(), digest);
  }

  #[test]
  fn rejects_invalid_char() {
    assert!(matches!(
      decode(b"00bgd045z0d4icpbc2yyz4gx48aku4la"),
      Err(DecodeError::InvalidChar(b'u'))
    ));
  }
}
