//! Content hashes in every encoding Nix accepts: `<algo>:<hex>`,
//! `<algo>:<nixbase32>`, `<algo>:<base64>`, and SRI `<algo>-<base64>`.

use std::{
  fmt,
  str::FromStr,
};

use flub::Error;

use crate::{
  base64,
  nixbase32,
};

/// A hash algorithm Nix supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
  /// SHA-1.
  Sha1,
  /// SHA-256, the algorithm of every NAR hash.
  Sha256,
  /// SHA-512.
  Sha512,
}

impl Algorithm {
  /// The digest length in bytes.
  #[must_use]
  pub const fn digest_len(self) -> usize {
    match self {
      Self::Sha1 => 20,
      Self::Sha256 => 32,
      Self::Sha512 => 64,
    }
  }

  /// The lowercase name Nix uses as a hash prefix.
  #[must_use]
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Sha1 => "sha1",
      Self::Sha256 => "sha256",
      Self::Sha512 => "sha512",
    }
  }
}

impl FromStr for Algorithm {
  type Err = ParseHashError;

  fn from_str(name: &str) -> Result<Self, Self::Err> {
    match name {
      "sha1" => Ok(Self::Sha1),
      "sha256" => Ok(Self::Sha256),
      "sha512" => Ok(Self::Sha512),
      _ => Err(ParseHashError::UnknownAlgorithm(name.to_owned())),
    }
  }
}

impl fmt::Display for Algorithm {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(self.as_str())
  }
}

/// Why a hash string could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseHashError {
  /// Neither a `:` nor an SRI `-` separates the algorithm from the digest.
  #[error("hash {0:?} has no algorithm prefix")]
  MissingAlgorithm(String),
  /// The algorithm prefix is not one Nix supports.
  #[error("unknown hash algorithm {0:?}")]
  UnknownAlgorithm(String),
  /// The digest has a hex length but is not valid hex.
  #[error("invalid hex digest")]
  Hex,
  /// The digest has a nixbase32 length but is not valid nixbase32.
  #[error("invalid nixbase32 digest")]
  Nixbase32(#[source] nixbase32::DecodeError),
  /// The digest is not valid base64.
  #[error("invalid base64 digest")]
  Base64(#[source] base64::DecodeError),
  /// The decoded digest has the wrong length for its algorithm.
  #[error("{algorithm} digest has {got} bytes, want {}", .algorithm.digest_len())]
  Length {
    /// The algorithm named by the prefix.
    algorithm: Algorithm,
    /// The decoded byte length.
    got:       usize,
  },
}

/// A digest tagged with its algorithm. Renders as `<algo>:<nixbase32>`, the
/// form Nix signs over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Hash {
  /// A SHA-1 digest.
  Sha1([u8; 20]),
  /// A SHA-256 digest.
  Sha256([u8; 32]),
  /// A SHA-512 digest.
  Sha512([u8; 64]),
}

impl Hash {
  /// Tag `digest` with `algorithm`.
  ///
  /// # Errors
  ///
  /// Returns [`ParseHashError::Length`] if `digest` is not exactly
  /// [`Algorithm::digest_len`] bytes.
  pub fn new(algorithm: Algorithm, digest: &[u8]) -> Result<Self, ParseHashError> {
    let wrong_length = |_| {
      ParseHashError::Length {
        algorithm,
        got: digest.len(),
      }
    };
    Ok(match algorithm {
      Algorithm::Sha1 => Self::Sha1(digest.try_into().map_err(wrong_length)?),
      Algorithm::Sha256 => Self::Sha256(digest.try_into().map_err(wrong_length)?),
      Algorithm::Sha512 => Self::Sha512(digest.try_into().map_err(wrong_length)?),
    })
  }

  /// The algorithm that produced this digest.
  #[must_use]
  pub const fn algorithm(&self) -> Algorithm {
    match *self {
      Self::Sha1(_) => Algorithm::Sha1,
      Self::Sha256(_) => Algorithm::Sha256,
      Self::Sha512(_) => Algorithm::Sha512,
    }
  }

  /// The raw digest bytes.
  #[must_use]
  pub const fn digest(&self) -> &[u8] {
    match *self {
      Self::Sha1(ref digest) => digest,
      Self::Sha256(ref digest) => digest,
      Self::Sha512(ref digest) => digest,
    }
  }
}

impl FromStr for Hash {
  type Err = ParseHashError;

  fn from_str(input: &str) -> Result<Self, Self::Err> {
    if let Some((name, digest)) = input.split_once(':') {
      let algorithm = name.parse::<Algorithm>()?;
      let len = algorithm.digest_len();
      let bytes = if digest.len() == len * 2 {
        hex_decode(digest).ok_or(ParseHashError::Hex)?
      } else if digest.len() == nixbase32::encode_len(len) {
        nixbase32::decode(digest.as_bytes()).map_err(ParseHashError::Nixbase32)?
      } else {
        base64::decode(digest).map_err(ParseHashError::Base64)?
      };
      return Self::new(algorithm, &bytes);
    }

    let (name, digest) = input
      .split_once('-')
      .ok_or_else(|| ParseHashError::MissingAlgorithm(input.to_owned()))?;
    let bytes = base64::decode(digest).map_err(ParseHashError::Base64)?;
    Self::new(name.parse()?, &bytes)
  }
}

impl fmt::Display for Hash {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "{}:{}",
      self.algorithm(),
      nixbase32::encode(self.digest())
    )
  }
}

impl fmt::LowerHex for Hash {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    self
      .digest()
      .iter()
      .try_for_each(|byte| write!(f, "{byte:02x}"))
  }
}

const fn nibble(digit: u8) -> Option<u8> {
  match digit {
    b'0'..=b'9' => Some(digit - b'0'),
    b'a'..=b'f' => Some(digit - b'a' + 10),
    b'A'..=b'F' => Some(digit - b'A' + 10),
    _ => None,
  }
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
  let (pairs, rest) = hex.as_bytes().as_chunks::<2>();
  if !rest.is_empty() {
    return None;
  }
  pairs
    .iter()
    .map(|&[high, low]| Some((nibble(high)? << 4_u8) | nibble(low)?))
    .collect()
}
