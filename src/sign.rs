//! Ed25519 signing and verification of narinfo fingerprints, in Nix's
//! `name:base64` key format.

use base64::{
  DecodeError,
  Engine,
  alphabet,
  engine::{
    DecodePaddingMode,
    GeneralPurpose,
    GeneralPurposeConfig,
    general_purpose::STANDARD,
  },
};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use thiserror::Error;

use crate::{fingerprint::fingerprint, narinfo::NarInfo};

const STORE_DIR: &str = "/nix/store";

/// Nix and tools like `atticd` are inconsistent about trailing `=` padding on
/// public keys, so decoding must accept both.
const STANDARD_LENIENT: GeneralPurpose = GeneralPurpose::new(
  &alphabet::STANDARD,
  GeneralPurposeConfig::new()
    .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

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
    input: String,
  },
}

fn split_name(input: &str) -> Result<(&str, &str), KeyError> {
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
  Ok((name, b64))
}

/// A binary cache signing key, as written by
/// `nix-store --generate-binary-cache-key`: `<name>:<base64 of 64 bytes>`.
pub struct SecretKey {
  name: String,
  key:  ed25519_dalek::SigningKey,
}

impl SecretKey {
  /// Parse a signing key from Nix's `<name>:<base64 of 64 bytes>` form.
  ///
  /// # Errors
  ///
  /// Returns [`KeyError`] if the name is missing or empty, the payload is
  /// not valid base64, decodes to the wrong length, or is not a valid
  /// Ed25519 signing key.
  pub fn parse(input: &str) -> Result<Self, KeyError> {
    let (name, b64) = split_name(input)?;
    let raw = STANDARD_LENIENT.decode(b64).map_err(|source| {
      KeyError::InvalidBase64 {
        input: input.to_owned(),
        source,
      }
    })?;
    let bytes: [u8; 64] = raw.try_into().map_err(|raw: Vec<u8>| {
      KeyError::InvalidSize {
        got:  raw.len(),
        want: 64,
      }
    })?;
    let key =
      ed25519_dalek::SigningKey::from_keypair_bytes(&bytes).map_err(|_| {
        KeyError::InvalidKey {
          input: input.to_owned(),
        }
      })?;
    Ok(Self {
      name: name.to_owned(),
      key,
    })
  }

  /// The key name, used as the signature prefix.
  #[must_use]
  pub fn name(&self) -> &str {
    &self.name
  }

  /// The `<name>:<base64>` signature over `fingerprint`.
  #[must_use]
  pub fn sign(&self, fingerprint: &str) -> String {
    let sig = self.key.sign(fingerprint.as_bytes());
    format!("{}:{}", self.name, STANDARD.encode(sig.to_bytes()))
  }

  /// The matching public key, for `trusted-public-keys`.
  #[must_use]
  pub fn public_key(&self) -> PublicKey {
    PublicKey {
      name: self.name.clone(),
      key:  self.key.verifying_key(),
    }
  }
}

/// A binary cache public key: `<name>:<base64 of 32 bytes>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
  name: String,
  key:  VerifyingKey,
}

impl PublicKey {
  /// Parse a public key from Nix's `<name>:<base64 of 32 bytes>` form.
  ///
  /// # Errors
  ///
  /// Returns [`KeyError`] if the name is missing or empty, the payload is
  /// not valid base64, decodes to the wrong length, or is not a valid
  /// Ed25519 verifying key.
  pub fn parse(input: &str) -> Result<Self, KeyError> {
    let (name, b64) = split_name(input)?;
    let raw = STANDARD_LENIENT.decode(b64).map_err(|source| {
      KeyError::InvalidBase64 {
        input: input.to_owned(),
        source,
      }
    })?;
    let bytes: [u8; 32] = raw.try_into().map_err(|raw: Vec<u8>| {
      KeyError::InvalidSize {
        got:  raw.len(),
        want: 32,
      }
    })?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| {
      KeyError::InvalidKey {
        input: input.to_owned(),
      }
    })?;
    Ok(Self {
      name: name.to_owned(),
      key,
    })
  }

  /// The key name a signature must carry to be checked against this key.
  #[must_use]
  pub fn name(&self) -> &str {
    &self.name
  }

  /// Whether one of `sigs` (each `<name>:<base64>`) verifies `fingerprint`
  /// under this key.
  #[must_use]
  pub fn verify(&self, fingerprint: &str, sigs: &[String]) -> bool {
    for sig in sigs {
      let Some((name, b64)) = sig.split_once(':') else {
        continue;
      };
      if name != self.name {
        continue;
      }
      let Ok(raw) = STANDARD_LENIENT.decode(b64) else {
        continue;
      };
      let Ok(bytes) = <[u8; 64]>::try_from(raw.as_slice()) else {
        continue;
      };
      let signature = Signature::from_bytes(&bytes);
      if self.key.verify(fingerprint.as_bytes(), &signature).is_ok() {
        return true;
      }
    }
    false
  }

  /// Render as the `<name>:<base64>` form used in `trusted-public-keys`.
  #[must_use]
  pub fn to_nix_string(&self) -> String {
    format!("{}:{}", self.name, STANDARD.encode(self.key.to_bytes()))
  }
}

impl NarInfo {
  /// Sign this narinfo's fingerprint and append the signature, using
  /// `/nix/store` as the store directory.
  pub fn sign(&mut self, key: &SecretKey) {
    let fp = fingerprint(STORE_DIR, self);
    self.sig.push(key.sign(&fp));
  }

  /// Whether any signature verifies under one of `keys`; store paths are
  /// assumed to be under `/nix/store`.
  #[must_use]
  pub fn verify(&self, keys: &[PublicKey]) -> bool {
    let fp = fingerprint(STORE_DIR, self);
    keys.iter().any(|k| k.verify(&fp, &self.sig))
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn keypair(seed: [u8; 32], name: &str) -> SecretKey {
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let keypair = signing.to_keypair_bytes();
    SecretKey::parse(&format!("{name}:{}", STANDARD.encode(keypair))).unwrap()
  }

  fn sample() -> NarInfo {
    NarInfo {
      store_path: "/nix/store/abc-test".to_owned(),
      nar_hash: "sha256:abc".to_owned(),
      nar_size: 12,
      references: vec!["abc-test".to_owned()],
      ..Default::default()
    }
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
    let padded = sk.public_key().to_nix_string();
    let unpadded = padded.trim_end_matches('=').to_owned();
    assert!(unpadded.ends_with(|c: char| c != '='));
    let a = PublicKey::parse(&padded).unwrap();
    let b = PublicKey::parse(&unpadded).unwrap();
    assert_eq!(a, b);
  }

  #[test]
  fn key_error_paths() {
    assert!(matches!(
      PublicKey::parse("no-separator"),
      Err(KeyError::MissingSeparator { .. })
    ));
    assert!(matches!(
      PublicKey::parse(":dGVzdA=="),
      Err(KeyError::EmptyName { .. })
    ));
    assert!(matches!(
      PublicKey::parse("test:!!!"),
      Err(KeyError::InvalidBase64 { .. })
    ));
    assert!(matches!(
      PublicKey::parse("test:dGVzdA=="),
      Err(KeyError::InvalidSize { want: 32, .. })
    ));
  }
}
