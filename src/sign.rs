//! Ed25519 signing and verification of narinfo fingerprints, in Nix's
//! `name:base64` key format.

use std::{
  fmt,
  str::FromStr,
};

use thiserror::Error;

use crate::{
  base64,
  base64::DecodeError,
  fingerprint::fingerprint,
  narinfo::{
    NarInfo,
    Signature,
  },
};

/// Why a `<name>:<base64>` key string could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum KeyError {
  /// No `:` separates the key name from its base64 payload.
  #[error("key {input:?} is missing a ':' separator")]
  MissingSeparator {
    /// The offending key string.
    input: String,
  },
  /// The portion before the `:` is empty.
  #[error("key {input:?} has an empty name")]
  EmptyName {
    /// The offending key string.
    input: String,
  },
  /// The payload is not valid base64.
  #[error("key {input:?} is not valid base64: {source}")]
  InvalidBase64 {
    /// The offending key string.
    input:  String,
    /// The underlying base64 decode error.
    source: DecodeError,
  },
  /// The decoded payload has the wrong number of bytes for the key type.
  #[error("key has invalid size {got}, want {want}")]
  InvalidSize {
    /// The decoded byte length.
    got:  usize,
    /// The expected byte length (64 for secret keys, 32 for public keys).
    want: usize,
  },
  /// The bytes are the right length but not a valid Ed25519 key.
  #[error("key {input:?} is not a valid Ed25519 key")]
  InvalidKey {
    /// The offending key string.
    input:  String,
    /// Why the Ed25519 library rejected the key.
    source: ed25519_compact::Error,
  },
}

fn parse_named<const N: usize>(input: &str) -> Result<(&str, [u8; N]), KeyError> {
  let (name, b64) = input.trim().split_once(':').ok_or_else(|| {
    KeyError::MissingSeparator {
      input: input.to_owned(),
    }
  })?;
  if name.is_empty() {
    return Err(KeyError::EmptyName {
      input: input.to_owned(),
    });
  }

  let raw = base64::decode(b64).map_err(|source| {
    KeyError::InvalidBase64 {
      input: input.to_owned(),
      source,
    }
  })?;
  let bytes = raw.try_into().map_err(|wrong: Vec<u8>| {
    KeyError::InvalidSize {
      got:  wrong.len(),
      want: N,
    }
  })?;
  Ok((name, bytes))
}

/// A binary cache signing key, as written by
/// `nix-store --generate-binary-cache-key`: `<name>:<base64 of 64 bytes>`.
pub struct SecretKey {
  name: String,
  key:  ed25519_compact::SecretKey,
}

impl FromStr for SecretKey {
  type Err = KeyError;

  /// Parse a signing key from Nix's `<name>:<base64 of 64 bytes>` form.
  ///
  /// # Errors
  ///
  /// Returns [`KeyError`] if the name is missing or empty, the payload is
  /// not valid base64, decodes to the wrong length, or is not a valid
  /// Ed25519 signing key.
  fn from_str(input: &str) -> Result<Self, Self::Err> {
    let (name, bytes) = parse_named::<64>(input)?;
    let key = ed25519_compact::SecretKey::new(bytes);
    key
      .validate_public_key(&key.public_key())
      .map_err(|source| {
        KeyError::InvalidKey {
          input: input.to_owned(),
          source,
        }
      })?;
    Ok(Self {
      name: name.to_owned(),
      key,
    })
  }
}

impl SecretKey {
  /// The key name, used as the signature prefix.
  #[must_use]
  pub fn name(&self) -> &str {
    &self.name
  }

  /// This key's signature over `fingerprint`.
  #[expect(
    clippy::missing_panics_doc,
    clippy::expect_used,
    reason = "parse rejects an empty name and splits at the first ':', so the name is valid"
  )]
  #[must_use]
  pub fn sign(&self, fingerprint: &str) -> Signature {
    let signature = self.key.sign(fingerprint, None);
    Signature::new(self.name.as_str(), *signature).expect("key names are validated on parse")
  }

  /// The matching public key, for `trusted-public-keys`.
  #[must_use]
  pub fn public_key(&self) -> PublicKey {
    PublicKey {
      name: self.name.clone(),
      key:  self.key.public_key(),
    }
  }
}

/// A binary cache public key: `<name>:<base64 of 32 bytes>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
  name: String,
  key:  ed25519_compact::PublicKey,
}

impl FromStr for PublicKey {
  type Err = KeyError;

  /// Parse a public key from Nix's `<name>:<base64 of 32 bytes>` form.
  ///
  /// # Errors
  ///
  /// Returns [`KeyError`] if the name is missing or empty, the payload is
  /// not valid base64, decodes to the wrong length, or is not a valid
  /// Ed25519 verifying key.
  fn from_str(input: &str) -> Result<Self, Self::Err> {
    let (name, bytes) = parse_named::<32>(input)?;
    let key = ed25519_compact::PublicKey::new(bytes);
    key.validate().map_err(|source| {
      KeyError::InvalidKey {
        input: input.to_owned(),
        source,
      }
    })?;
    Ok(Self {
      name: name.to_owned(),
      key,
    })
  }
}

impl PublicKey {
  /// The key name a signature must carry to be checked against this key.
  #[must_use]
  pub fn name(&self) -> &str {
    &self.name
  }

  /// Whether one of `sigs` (each `<name>:<base64>`) verifies `fingerprint`
  /// under this key.
  #[must_use]
  pub fn verify(&self, fingerprint: &str, sigs: &[Signature]) -> bool {
    sigs
      .iter()
      .filter(|sig| sig.key_name() == self.name)
      .any(|sig| {
        let signature = ed25519_compact::Signature::new(*sig.bytes());
        self.key.verify(fingerprint, &signature).is_ok()
      })
  }
}

/// Renders as the `<name>:<base64>` form used in `trusted-public-keys`.
impl fmt::Display for PublicKey {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}:{}", self.name, base64::encode(self.key.as_ref()))
  }
}

#[expect(
  clippy::multiple_inherent_impl,
  reason = "signing lives behind the `sign` feature, apart from parsing"
)]
impl NarInfo {
  /// Sign this narinfo's fingerprint and append the signature.
  pub fn sign(&mut self, key: &SecretKey) {
    let fp = fingerprint(self);
    self.sig.push(key.sign(&fp));
  }

  /// Whether any signature verifies under one of `keys`.
  #[must_use]
  pub fn verify(&self, keys: &[PublicKey]) -> bool {
    let fp = fingerprint(self);
    keys.iter().any(|key| key.verify(&fp, &self.sig))
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn keypair(seed: [u8; 32], name: &str) -> SecretKey {
    let keypair = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(seed));
    format!("{name}:{}", base64::encode(keypair.sk.as_ref()))
      .parse()
      .unwrap()
  }

  fn sample() -> NarInfo {
    "StorePath: /nix/store/00bgd045z0d4icpbc2yyz4gx48ak44la-test\nURL: nar/x.nar\nNarHash: \
     sha256:0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73\nNarSize: 12\nReferences: \
     00bgd045z0d4icpbc2yyz4gx48ak44la-test\n"
      .parse()
      .unwrap()
  }

  #[test]
  fn sign_verify_roundtrip() {
    let sk = keypair([7; 32], "cache");
    let mut ni = sample();
    ni.sign(&sk);
    assert!(ni.verify(&[sk.public_key()]));
  }

  #[test]
  fn rejects_wrong_key() {
    let sk = keypair([7; 32], "cache");
    let other = keypair([9; 32], "cache");
    let mut ni = sample();
    ni.sign(&sk);
    assert!(!ni.verify(&[other.public_key()]));
  }

  #[test]
  fn rejects_tampered_content() {
    let sk = keypair([7; 32], "cache");
    let mut ni = sample();
    ni.sign(&sk);
    ni.nar_size = 999;
    assert!(!ni.verify(&[sk.public_key()]));
  }

  #[test]
  fn public_key_tolerates_missing_padding() {
    let sk = keypair([3; 32], "cache");
    let padded = sk.public_key().to_string();
    let unpadded = padded.trim_end_matches('=').to_owned();
    assert!(unpadded.ends_with(|last: char| last != '='));
    let from_padded = padded.parse::<PublicKey>().unwrap();
    let from_unpadded = unpadded.parse::<PublicKey>().unwrap();
    assert_eq!(from_padded, from_unpadded);
  }

  #[test]
  fn key_error_paths() {
    assert!(matches!(
      "no-separator".parse::<PublicKey>(),
      Err(KeyError::MissingSeparator { .. })
    ));
    assert!(matches!(
      ":dGVzdA==".parse::<PublicKey>(),
      Err(KeyError::EmptyName { .. })
    ));
    assert!(matches!(
      "test:!!!".parse::<PublicKey>(),
      Err(KeyError::InvalidBase64 { .. })
    ));
    assert!(matches!(
      "test:dGVzdA==".parse::<PublicKey>(),
      Err(KeyError::InvalidSize { want: 32, .. })
    ));
  }
}
