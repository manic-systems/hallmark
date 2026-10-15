//! Store paths (`/nix/store/<32-char nixbase32>-<name>`) and the
//! content-addressed path construction Nix uses for fixed-output derivations,
//! `builtins.toFile` and `nix-store --add`.

use sha2::{Digest, Sha256};
use thiserror::Error;

pub use crate::nixbase32;

/// The canonical Nix store directory, without a trailing slash.
pub const STORE_DIR: &str = "/nix/store";
/// [`STORE_DIR`] with the trailing slash that precedes a path component.
pub const STORE_DIR_WITH_SLASH: &str = "/nix/store/";
/// The length in bytes of the digest a store-path hash encodes.
pub const DIGEST_SIZE: usize = 20;
/// The length in nixbase32 characters of an encoded [`DIGEST_SIZE`] digest.
pub const ENCODED_DIGEST_SIZE: usize = nixbase32::encode_len(DIGEST_SIZE);

/// Why a string is not a valid store path or store-path component.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseStorePathError {
  /// The byte at [`ENCODED_DIGEST_SIZE`] is not the `-` that must separate the
  /// hash from the name.
  #[error("missing dash between hash and name")]
  MissingDash,
  /// The hash prefix is not valid nixbase32.
  #[error("invalid hash encoding: {0}")]
  DigestEncoding(#[from] nixbase32::DecodeError),
  /// The component is too short to hold a hash and name, or the name is empty
  /// or longer than the 211-byte limit.
  #[error("invalid length")]
  Length,
  /// The name contains a byte outside the allowed store-path alphabet.
  #[error("invalid name")]
  Name,
  /// The path does not begin with [`STORE_DIR_WITH_SLASH`].
  #[error("missing /nix/store prefix")]
  MissingStoreDir,
}

/// Why a content-addressed store path could not be constructed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BuildError {
  /// The requested name is not a valid store-path name.
  #[error("invalid store path name {name:?}: {source}")]
  Name {
    /// The rejected name.
    name:   String,
    /// The validation error it produced.
    source: ParseStorePathError,
  },
  /// A reference string could not be interpreted as a store path.
  #[error("invalid reference {0:?}")]
  Reference(String),
  /// A [`Method::Flat`] path was given references, which flat hashing cannot
  /// express.
  #[error("flat content-addressed paths cannot have references")]
  FlatWithReferences,
}

const fn is_name_char(c: u8) -> bool {
  matches!(c,
    b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'+' | b'-' | b'_' | b'?' | b'=' | b'.')
}

/// Validate a store-path name (the part after the `-`).
///
/// # Errors
///
/// Returns [`ParseStorePathError::Length`] for an empty or over-211-byte name,
/// or [`ParseStorePathError::Name`] for a disallowed character.
pub fn validate_name(name: &str) -> Result<(), ParseStorePathError> {
  if name.is_empty() || name.len() > 211 {
    return Err(ParseStorePathError::Length);
  }
  if name.bytes().all(is_name_char) {
    Ok(())
  } else {
    Err(ParseStorePathError::Name)
  }
}

/// A validated absolute `/nix/store/<hash>-<name>` path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StorePath {
  path: String,
}

/// A borrowed, validated store path or its `<hash>-<name>` component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StorePathRef<'a> {
  path: &'a str,
}

fn validate_component(component: &str) -> Result<(), ParseStorePathError> {
  let bytes = component.as_bytes();
  if bytes.len() < ENCODED_DIGEST_SIZE + 2 {
    return Err(ParseStorePathError::Length);
  }
  if bytes[ENCODED_DIGEST_SIZE] != b'-' {
    return Err(ParseStorePathError::MissingDash);
  }
  nixbase32::decode(&bytes[..ENCODED_DIGEST_SIZE])?;
  validate_name(&component[ENCODED_DIGEST_SIZE + 1..])
}

impl<'a> StorePathRef<'a> {
  /// Validate the `<hash>-<name>` component that follows `/nix/store/`.
  ///
  /// # Errors
  ///
  /// Returns [`ParseStorePathError`] if the hash is malformed, the `-`
  /// separator is missing, or the name is invalid.
  pub fn from_bytes(component: &'a str) -> Result<Self, ParseStorePathError> {
    validate_component(component)?;
    Ok(Self { path: component })
  }

  /// Validate a full `/nix/store/<hash>-<name>` path.
  ///
  /// # Errors
  ///
  /// Returns [`ParseStorePathError::MissingStoreDir`] if the
  /// `/nix/store/` prefix is absent; otherwise returns the component errors
  /// from [`StorePathRef::from_bytes`].
  pub fn from_absolute_path(
    path: &'a str,
  ) -> Result<Self, ParseStorePathError> {
    let component = path
      .strip_prefix(STORE_DIR_WITH_SLASH)
      .ok_or(ParseStorePathError::MissingStoreDir)?;
    validate_component(component)?;
    Ok(Self { path })
  }

  /// The nixbase32 hash prefix, without the name or store directory.
  #[must_use]
  pub fn hash(&self) -> &'a str {
    let start = self.path.len() - self.component().len();
    &self.path[start..start + ENCODED_DIGEST_SIZE]
  }

  /// The name that follows the `-`.
  #[must_use]
  pub fn name(&self) -> &'a str {
    let component = self.component();
    &component[ENCODED_DIGEST_SIZE + 1..]
  }

  /// The 20-byte digest the hash encodes.
  // The hash was decoded during validation, so decoding it again is
  // infallible; the `expect` records that invariant rather than a runtime
  // failure mode.
  #[allow(clippy::missing_panics_doc)]
  #[must_use]
  pub fn digest(&self) -> [u8; DIGEST_SIZE] {
    let mut out = [0_u8; DIGEST_SIZE];
    let decoded = nixbase32::decode(self.hash().as_bytes())
      .expect("validated on construction");
    out.copy_from_slice(&decoded);
    out
  }

  /// The validated string this handle wraps: a full store path from
  /// [`StorePathRef::from_absolute_path`], or a `<hash>-<name>` component
  /// from [`StorePathRef::from_bytes`].
  #[must_use]
  pub fn as_str(&self) -> &'a str {
    self.path
  }

  fn component(&self) -> &'a str {
    self
      .path
      .strip_prefix(STORE_DIR_WITH_SLASH)
      .unwrap_or(self.path)
  }

  /// Copy into an owning [`StorePath`].
  #[must_use]
  pub fn to_owned(&self) -> StorePath {
    StorePath {
      path: self.path.to_owned(),
    }
  }
}

impl StorePath {
  /// Validate a full `/nix/store/<hash>-<name>` path.
  ///
  /// # Errors
  ///
  /// See [`StorePathRef::from_absolute_path`].
  pub fn parse(path: &str) -> Result<Self, ParseStorePathError> {
    StorePathRef::from_absolute_path(path).map(|p| p.to_owned())
  }

  /// Validate that `path` is a well-formed `/nix/store/<hash>-<name>` path.
  ///
  /// # Errors
  ///
  /// See [`StorePathRef::from_absolute_path`].
  pub fn validate(path: &str) -> Result<(), ParseStorePathError> {
    StorePathRef::from_absolute_path(path).map(|_| ())
  }

  fn from_digest_and_name(
    digest: &[u8; DIGEST_SIZE],
    name: &str,
  ) -> Result<Self, ParseStorePathError> {
    validate_name(name)?;
    Ok(Self {
      path: format!(
        "{STORE_DIR_WITH_SLASH}{}-{name}",
        nixbase32::encode(digest)
      ),
    })
  }

  /// A borrowing view of this path.
  #[must_use]
  pub fn as_ref(&self) -> StorePathRef<'_> {
    StorePathRef { path: &self.path }
  }

  /// The nixbase32 hash prefix, without the name or store directory.
  #[must_use]
  pub fn hash(&self) -> &str {
    self.as_ref().hash()
  }

  /// The name that follows the `-`.
  #[must_use]
  pub fn name(&self) -> &str {
    self.as_ref().name()
  }

  /// The 20-byte digest the hash encodes.
  #[must_use]
  pub fn digest(&self) -> [u8; DIGEST_SIZE] {
    self.as_ref().digest()
  }

  /// The full `/nix/store/<hash>-<name>` string.
  #[must_use]
  pub fn as_str(&self) -> &str {
    &self.path
  }
}

impl std::fmt::Display for StorePath {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(&self.path)
  }
}

/// How a content-addressed dump is addressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
  /// `text:sha256`, as used by `builtins.toFile` and `nix-store --add`.
  Text,
  /// `fixed:sha256`, a flat fixed-output derivation.
  Flat,
  /// `fixed:r:sha256`, a recursive (NAR) fixed-output derivation.
  Recursive,
}

impl Method {
  /// Render the `<type>:sha256:<nixbase32>` content address for `digest`.
  ///
  /// # Returns
  ///
  /// The Nix content-address string for this hashing method and `digest`.
  #[must_use]
  pub fn content_address(self, digest: &[u8; 32]) -> String {
    let hash = nixbase32::encode(digest);
    match self {
      Self::Text => format!("text:sha256:{hash}"),
      Self::Flat => format!("fixed:sha256:{hash}"),
      Self::Recursive => format!("fixed:r:sha256:{hash}"),
    }
  }
}

fn hex_lower(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut out = String::with_capacity(bytes.len() * 2);
  for &b in bytes {
    out.push(char::from(HEX[(b >> 4) as usize]));
    out.push(char::from(HEX[(b & 0x0F) as usize]));
  }
  out
}

fn compress_hash<const N: usize>(input: &[u8]) -> [u8; N] {
  let mut out = [0_u8; N];
  for (i, &b) in input.iter().enumerate() {
    out[i % N] ^= b;
  }
  out
}

fn format_references(
  ty: &str,
  references: &[&str],
  has_self_ref: bool,
) -> String {
  let mut out = ty.to_owned();
  for reference in references {
    out.push(':');
    out.push_str(reference);
  }
  if has_self_ref {
    out.push_str(":self");
  }
  out
}

fn from_fingerprint_parts(
  ty: &str,
  inner_digest: &[u8; 32],
  name: &str,
) -> Result<StorePath, BuildError> {
  let fingerprint =
    format!("{ty}:sha256:{}:{STORE_DIR}:{name}", hex_lower(inner_digest));
  let compressed = compress_hash::<DIGEST_SIZE>(
    Sha256::digest(fingerprint.as_bytes()).as_slice(),
  );
  StorePath::from_digest_and_name(&compressed, name).map_err(|source| {
    BuildError::Name {
      name: name.to_owned(),
      source,
    }
  })
}

/// Build a content-addressed store path.
///
/// `digest` is the sha256 of the dump for [`Method::Flat`] /
/// [`Method::Recursive`], or of the file contents for [`Method::Text`].
/// `references` are absolute store paths.
///
/// # Errors
///
/// Returns [`BuildError::FlatWithReferences`] if `method` is [`Method::Flat`]
/// and `references` is non-empty, or [`BuildError::Name`] if `name` is not
/// a valid store-path name.
pub fn build_ca_path(
  method: Method,
  digest: &[u8; 32],
  name: &str,
  references: &[&str],
  has_self_ref: bool,
) -> Result<StorePath, BuildError> {
  match method {
    Method::Text => {
      let ty = format_references("text", references, false);
      from_fingerprint_parts(&ty, digest, name)
    },
    Method::Recursive => {
      let ty = format_references("source", references, has_self_ref);
      from_fingerprint_parts(&ty, digest, name)
    },
    Method::Flat => {
      if !references.is_empty() {
        return Err(BuildError::FlatWithReferences);
      }
      let inner = Sha256::digest(
        format!("fixed:out:sha256:{}:", hex_lower(digest)).as_bytes(),
      );
      let inner: [u8; 32] = inner.into();
      from_fingerprint_parts("output:out", &inner, name)
    },
  }
}

/// Build a `text:sha256` store path from file contents.
///
/// # Errors
///
/// See [`build_ca_path`].
pub fn build_text_path(
  name: &str,
  content: &[u8],
  references: &[&str],
) -> Result<StorePath, BuildError> {
  let digest: [u8; 32] = Sha256::digest(content).into();
  build_ca_path(Method::Text, &digest, name, references, false)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parse_valid() {
    let p = StorePath::parse(
      "/nix/store/00bgd045z0d4icpbc2yyz4gx48ak44la-net-tools-1.\
       60_p20170221182432",
    )
    .unwrap();
    assert_eq!(p.hash(), "00bgd045z0d4icpbc2yyz4gx48ak44la");
    assert_eq!(p.name(), "net-tools-1.60_p20170221182432");
    assert_eq!(
      p.digest(),
      *b"\x8a\x12\x32\x15\x22\xfd\x91\xef\xbd\x60\xeb\xb2\x48\x1a\xf8\x85\x80\xf6\x16\x00"
    );
  }

  #[test]
  fn parse_invalid_edges() {
    assert_eq!(
      StorePath::parse("foobar-123"),
      Err(ParseStorePathError::MissingStoreDir)
    );
    assert_eq!(
      StorePath::parse("/nix/store/00bgd045z0d4icpbc2yy-"),
      Err(ParseStorePathError::Length)
    );
    assert!(
      StorePath::parse("/nix/store/00bgd045z0d4icpbc2yyz4gx48aku4la-net-tools")
        .is_err()
    );
    assert_eq!(
      StorePathRef::from_bytes("00bgd045z0d4icpbc2yyz4gx48ak44lanet-tools"),
      Err(ParseStorePathError::MissingDash)
    );
    assert!(
      StorePath::parse("/nix/store/00bgd045z0d4icpbc2yyz4gx48ak44la-net/tools")
        .is_err()
    );
  }

  #[test]
  fn text_path_zero_references() {
    let p = build_text_path("foo", b"bar", &[]).unwrap();
    assert_eq!(
      p.as_str(),
      "/nix/store/vxjiwkjkn7x4079qvh1jkl5pn05j2aw0-foo"
    );
  }

  #[test]
  fn text_path_with_references() {
    let inner = build_text_path("foo", b"bar", &[]).unwrap();
    let outer =
      build_text_path("baz", inner.as_str().as_bytes(), &[inner.as_str()])
        .unwrap();
    assert_eq!(
      outer.as_str(),
      "/nix/store/5xd714cbfnkz02h2vbsj4fm03x3f15nf-baz"
    );
  }

  #[test]
  fn ca_source_path_with_reference() {
    let digest: [u8; 32] = nixbase32::decode(
      b"1xqkzcb3909fp07qngljr4wcdnrh1gdam1m2n29i6hhrxlmkgkv1",
    )
    .unwrap()
    .try_into()
    .unwrap();
    let p = build_ca_path(
      Method::Recursive,
      &digest,
      "baz",
      &["/nix/store/dxwkwjzdaq7ka55pkk252gh32bgpmql4-foo"],
      false,
    )
    .unwrap();
    assert_eq!(
      p.as_str(),
      "/nix/store/s89y431zzhmdn3k8r96rvakryddkpv2v-baz"
    );
  }

  #[test]
  fn flat_with_references_rejected() {
    let refs = ["/nix/store/00000000000000000000000000000000-x"];
    assert_eq!(
      build_ca_path(Method::Flat, &[0; 32], "x", &refs, false),
      Err(BuildError::FlatWithReferences)
    );
  }
}
