//! Store paths (`/nix/store/<32-char nixbase32>-<name>`) and the
//! content-addressed path construction Nix uses for fixed-output derivations,
//! `builtins.toFile` and `nix-store --add`.

use std::{
  fmt,
  str::FromStr,
};

use flub::Error;
use hmac_sha256::Hash as Sha256;

use crate::{
  hash::{
    Algorithm,
    Hash,
    ParseHashError,
  },
  nixbase32,
};

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
  /// The path is not directly inside the expected store directory.
  #[error("path is not in the store directory")]
  MissingStoreDir,
}

/// Why a string cannot be used as a store directory.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("store directory {path:?} is not a canonical absolute path")]
pub struct StoreDirError {
  /// The rejected directory.
  pub path: String,
}

/// Why a content-addressed store path could not be constructed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid store path name {name:?}")]
pub struct BuildError {
  /// The rejected name.
  pub name:   String,
  /// The validation error it produced.
  #[source]
  pub source: ParseStorePathError,
}

const fn is_name_char(byte: u8) -> bool {
  matches!(byte,
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
  path:   String,
  digest: [u8; DIGEST_SIZE],
}

/// A borrowed, validated store path or its `<hash>-<name>` component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StorePathRef<'path> {
  path:   &'path str,
  digest: [u8; DIGEST_SIZE],
}

fn validate_component(component: &str) -> Result<[u8; DIGEST_SIZE], ParseStorePathError> {
  let bytes = component.as_bytes();
  if bytes.len() < ENCODED_DIGEST_SIZE + 2 {
    return Err(ParseStorePathError::Length);
  }
  if bytes[ENCODED_DIGEST_SIZE] != b'-' {
    return Err(ParseStorePathError::MissingDash);
  }
  let decoded = nixbase32::decode(&bytes[..ENCODED_DIGEST_SIZE])?;
  let Ok(digest) = <[u8; DIGEST_SIZE]>::try_from(decoded) else {
    return Err(ParseStorePathError::Length);
  };
  let (_, name) = component.split_at(ENCODED_DIGEST_SIZE + 1);
  validate_name(name)?;
  Ok(digest)
}

impl<'path> StorePathRef<'path> {
  /// Validate the `<hash>-<name>` component that follows `/nix/store/`.
  ///
  /// # Errors
  ///
  /// Returns [`ParseStorePathError`] if the hash is malformed, the `-`
  /// separator is missing, or the name is invalid.
  pub fn from_component(component: &'path str) -> Result<Self, ParseStorePathError> {
    let digest = validate_component(component)?;
    Ok(Self {
      path: component,
      digest,
    })
  }

  /// Validate a full `/nix/store/<hash>-<name>` path.
  ///
  /// # Errors
  ///
  /// Returns [`ParseStorePathError::MissingStoreDir`] if the
  /// `/nix/store/` prefix is absent, or the component errors from
  /// [`StorePathRef::from_component`].
  pub fn from_absolute_path(path: &'path str) -> Result<Self, ParseStorePathError> {
    let component = path
      .strip_prefix(STORE_DIR_WITH_SLASH)
      .ok_or(ParseStorePathError::MissingStoreDir)?;
    let digest = validate_component(component)?;
    Ok(Self { path, digest })
  }

  /// The nixbase32 hash prefix, without the name or store directory.
  #[expect(
    clippy::same_name_method,
    reason = "`hash` names the store-path hash part, as in Nix"
  )]
  #[must_use]
  pub fn hash(&self) -> &'path str {
    let (hash, _) = self.base_name().split_at(ENCODED_DIGEST_SIZE);
    hash
  }

  /// The name that follows the `-`.
  #[must_use]
  pub fn name(&self) -> &'path str {
    let (_, name) = self.base_name().split_at(ENCODED_DIGEST_SIZE + 1);
    name
  }

  /// The 20-byte digest the hash encodes.
  #[must_use]
  pub const fn digest(&self) -> [u8; DIGEST_SIZE] {
    self.digest
  }

  /// The validated string this handle wraps, which is a full store path from
  /// [`StorePathRef::from_absolute_path`] or a `<hash>-<name>` component
  /// from [`StorePathRef::from_component`].
  #[must_use]
  pub const fn as_str(&self) -> &'path str {
    self.path
  }

  /// The `<hash>-<name>` part, without the store directory.
  #[must_use]
  pub fn base_name(&self) -> &'path str {
    self
      .path
      .rsplit_once('/')
      .map_or(self.path, |(_, component)| component)
  }
}

impl From<StorePathRef<'_>> for StorePath {
  fn from(path_ref: StorePathRef<'_>) -> Self {
    Self {
      path:   path_ref.path.to_owned(),
      digest: path_ref.digest,
    }
  }
}

impl FromStr for StorePath {
  type Err = ParseStorePathError;

  fn from_str(path: &str) -> Result<Self, Self::Err> {
    StorePathRef::from_absolute_path(path).map(Self::from)
  }
}

impl StorePath {
  /// A borrowing view of this path.
  #[must_use]
  pub fn as_path_ref(&self) -> StorePathRef<'_> {
    StorePathRef {
      path:   &self.path,
      digest: self.digest,
    }
  }

  /// The nixbase32 hash prefix, without the name or store directory.
  #[expect(
    clippy::same_name_method,
    reason = "`hash` names the store-path hash part, as in Nix"
  )]
  #[must_use]
  pub fn hash(&self) -> &str {
    self.as_path_ref().hash()
  }

  /// The name that follows the `-`.
  #[must_use]
  pub fn name(&self) -> &str {
    self.as_path_ref().name()
  }

  /// The 20-byte digest the hash encodes.
  #[must_use]
  pub const fn digest(&self) -> [u8; DIGEST_SIZE] {
    self.digest
  }

  /// The full `/nix/store/<hash>-<name>` string.
  #[must_use]
  pub fn as_str(&self) -> &str {
    &self.path
  }

  /// The `<hash>-<name>` part, without the store directory.
  #[must_use]
  pub fn base_name(&self) -> &str {
    self.as_path_ref().base_name()
  }
}

impl AsRef<str> for StorePath {
  fn as_ref(&self) -> &str {
    &self.path
  }
}

impl fmt::Display for StorePath {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(&self.path)
  }
}

/// The directory store paths live in, [`STORE_DIR`] unless the store was
/// configured with another location.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StoreDir {
  path: String,
}

impl StoreDir {
  /// Use `path` as the store directory.
  ///
  /// Nix compares store paths textually, so the directory must be spelled
  /// canonically for paths under it to match.
  ///
  /// # Errors
  ///
  /// Returns [`StoreDirError`] unless `path` is absolute, has no trailing
  /// slash, and has no empty, `.` or `..` components.
  pub fn new<P>(path: P) -> Result<Self, StoreDirError>
  where
    P: Into<String>,
  {
    let owned_path = path.into();
    let canonical = owned_path.strip_prefix('/').is_some_and(|rest| {
      rest
        .split('/')
        .all(|component| !matches!(component, "" | "." | ".."))
    });
    if canonical {
      Ok(Self { path: owned_path })
    } else {
      Err(StoreDirError { path: owned_path })
    }
  }

  /// The directory, without a trailing slash.
  #[must_use]
  pub fn as_str(&self) -> &str {
    &self.path
  }

  /// Validate `path` as a `<hash>-<name>` entry directly inside this
  /// directory.
  ///
  /// # Errors
  ///
  /// Returns [`ParseStorePathError::MissingStoreDir`] if `path` is not
  /// directly inside this directory, or the component errors from
  /// [`StorePathRef::from_component`].
  pub fn parse(&self, path: &str) -> Result<StorePath, ParseStorePathError> {
    let component = path
      .strip_prefix(self.path.as_str())
      .and_then(|rest| rest.strip_prefix('/'))
      .ok_or(ParseStorePathError::MissingStoreDir)?;
    let digest = validate_component(component)?;
    Ok(StorePath {
      path: path.to_owned(),
      digest,
    })
  }

  /// The store path for the `<hash>-<name>` entry `base_name` inside this
  /// directory.
  ///
  /// # Errors
  ///
  /// Returns the component errors from [`StorePathRef::from_component`].
  pub fn join(&self, base_name: &str) -> Result<StorePath, ParseStorePathError> {
    let digest = validate_component(base_name)?;
    Ok(StorePath {
      path: format!("{}/{base_name}", self.path),
      digest,
    })
  }

  /// Nix's `makeStorePath` in this directory, with references already
  /// appended to `ty`.
  ///
  /// # Errors
  ///
  /// Returns [`BuildError`] if `name` is not a valid store-path name.
  pub fn make_store_path(
    &self,
    ty: &str,
    inner_digest: &[u8; 32],
    name: &str,
  ) -> Result<StorePath, BuildError> {
    validate_name(name).map_err(|source| {
      BuildError {
        name: name.to_owned(),
        source,
      }
    })?;
    let fingerprint = format!(
      "{ty}:sha256:{:x}:{}:{name}",
      Hash::Sha256(*inner_digest),
      self.path
    );
    let digest = compress_hash::<DIGEST_SIZE>(&Sha256::hash(fingerprint.as_bytes()));
    Ok(StorePath {
      path: format!("{}/{}-{name}", self.path, nixbase32::encode(&digest)),
      digest,
    })
  }
}

impl FromStr for StoreDir {
  type Err = StoreDirError;

  fn from_str(path: &str) -> Result<Self, Self::Err> {
    Self::new(path)
  }
}

impl Default for StoreDir {
  fn default() -> Self {
    Self {
      path: STORE_DIR.to_owned(),
    }
  }
}

impl fmt::Display for StoreDir {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(&self.path)
  }
}

/// Why a content address could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseContentAddressError {
  /// The prefix is not `text:`, `fixed:` or `fixed:r:`.
  #[error("unknown content-address method in {0:?}")]
  UnknownMethod(String),
  /// A `text:` address used a hash other than SHA-256.
  #[error("text content addresses must use sha256, not {0}")]
  TextNotSha256(Algorithm),
  /// The hash after the method prefix is invalid.
  #[error("invalid content-address hash")]
  Hash(#[source] ParseHashError),
}

/// A narinfo `CA` value: how a content-addressed path was hashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentAddress {
  /// `text:sha256:…`, as used by `builtins.toFile` and `nix-store --add`.
  Text([u8; 32]),
  /// `fixed:<algo>:…`, a flat fixed-output derivation.
  Flat(Hash),
  /// `fixed:r:<algo>:…`, a recursive (NAR) fixed-output derivation.
  Recursive(Hash),
}

impl FromStr for ContentAddress {
  type Err = ParseContentAddressError;

  fn from_str(input: &str) -> Result<Self, Self::Err> {
    let parse_hash = |hash: &str| hash.parse::<Hash>().map_err(ParseContentAddressError::Hash);
    if let Some(hash) = input.strip_prefix("text:") {
      return match parse_hash(hash)? {
        Hash::Sha256(digest) => Ok(Self::Text(digest)),
        other @ (Hash::Sha1(_) | Hash::Sha512(_)) => {
          Err(ParseContentAddressError::TextNotSha256(other.algorithm()))
        },
      };
    }
    if let Some(hash) = input.strip_prefix("fixed:r:") {
      return Ok(Self::Recursive(parse_hash(hash)?));
    }
    if let Some(hash) = input.strip_prefix("fixed:") {
      return Ok(Self::Flat(parse_hash(hash)?));
    }
    Err(ParseContentAddressError::UnknownMethod(input.to_owned()))
  }
}

impl ContentAddress {
  /// Nix's `makeFixedOutputPath` for a path without references.
  ///
  /// # Errors
  ///
  /// Returns [`BuildError`] if `name` is not a valid store-path name.
  pub fn store_path(&self, name: &str) -> Result<StorePath, BuildError> {
    self.store_path_in(&StoreDir::default(), name)
  }

  /// [`ContentAddress::store_path`] in the store directory `dir`.
  ///
  /// # Errors
  ///
  /// Returns [`BuildError`] if `name` is not a valid store-path name.
  pub fn store_path_in(&self, dir: &StoreDir, name: &str) -> Result<StorePath, BuildError> {
    let (prefix, hash) = match *self {
      Self::Text(sha256) => return dir.make_store_path("text", &sha256, name),
      Self::Recursive(Hash::Sha256(sha256)) => {
        return dir.make_store_path("source", &sha256, name);
      },
      Self::Flat(hash) => ("", hash),
      Self::Recursive(hash) => ("r:", hash),
    };
    let inner =
      Sha256::hash(format!("fixed:out:{prefix}{}:{hash:x}:", hash.algorithm()).as_bytes());
    dir.make_store_path("output:out", &inner, name)
  }
}

impl fmt::Display for ContentAddress {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match *self {
      Self::Text(digest) => write!(f, "text:{}", Hash::Sha256(digest)),
      Self::Flat(hash) => write!(f, "fixed:{hash}"),
      Self::Recursive(hash) => write!(f, "fixed:r:{hash}"),
    }
  }
}

/// The inputs that determine a content-addressed store path.
///
/// Each variant carries only what its hashing scheme can express, so flat
/// paths have no references and only recursive paths can refer to themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentAddressed<'refs> {
  /// File contents hashed with SHA-256, as `builtins.toFile` does.
  Text {
    /// SHA-256 of the file contents.
    sha256:     [u8; 32],
    /// The store paths the file refers to.
    references: &'refs [StorePath],
  },
  /// A flat fixed-output derivation.
  Flat {
    /// SHA-256 of the output file.
    sha256: [u8; 32],
  },
  /// A recursive (NAR) fixed-output derivation.
  Recursive {
    /// SHA-256 of the output's NAR serialization.
    sha256:     [u8; 32],
    /// The store paths the output refers to.
    references: &'refs [StorePath],
    /// Whether the output refers to its own path.
    self_ref:   bool,
  },
}

impl ContentAddressed<'_> {
  /// The narinfo `CA` value these inputs produce.
  #[must_use]
  pub const fn content_address(&self) -> ContentAddress {
    match *self {
      Self::Text { sha256, .. } => ContentAddress::Text(sha256),
      Self::Flat { sha256 } => ContentAddress::Flat(Hash::Sha256(sha256)),
      Self::Recursive { sha256, .. } => ContentAddress::Recursive(Hash::Sha256(sha256)),
    }
  }

  /// The `/nix/store` path these inputs produce under `name`.
  ///
  /// # Errors
  ///
  /// Returns [`BuildError`] if `name` is not a valid store-path name.
  pub fn store_path(&self, name: &str) -> Result<StorePath, BuildError> {
    self.store_path_in(&StoreDir::default(), name)
  }

  /// [`ContentAddressed::store_path`] in the store directory `dir`.
  ///
  /// # Errors
  ///
  /// Returns [`BuildError`] if `name` is not a valid store-path name.
  pub fn store_path_in(&self, dir: &StoreDir, name: &str) -> Result<StorePath, BuildError> {
    match *self {
      Self::Text { sha256, references } => {
        dir.make_store_path(&format_references("text", references, false), &sha256, name)
      },
      Self::Flat { sha256 } => ContentAddress::Flat(Hash::Sha256(sha256)).store_path_in(dir, name),
      Self::Recursive {
        sha256,
        references,
        self_ref,
      } => {
        dir.make_store_path(
          &format_references("source", references, self_ref),
          &sha256,
          name,
        )
      },
    }
  }
}

/// Nix's `compressHash`, folding `input` into `N` bytes by XOR.
#[must_use]
pub fn compress_hash<const N: usize>(input: &[u8]) -> [u8; N] {
  let mut out = [0_u8; N];
  for (index, &byte) in input.iter().enumerate() {
    out[index % N] ^= byte;
  }
  out
}

fn format_references(ty: &str, references: &[StorePath], has_self_ref: bool) -> String {
  let mut out = ty.to_owned();
  for reference in references {
    out.push(':');
    out.push_str(reference.as_str());
  }
  if has_self_ref {
    out.push_str(":self");
  }
  out
}

/// [`StoreDir::make_store_path`] in [`STORE_DIR`].
///
/// # Errors
///
/// Returns [`BuildError`] if `name` is not a valid store-path name.
pub fn make_store_path(
  ty: &str,
  inner_digest: &[u8; 32],
  name: &str,
) -> Result<StorePath, BuildError> {
  StoreDir::default().make_store_path(ty, inner_digest, name)
}

/// Build a `text:sha256` store path from file contents.
///
/// # Errors
///
/// Returns [`BuildError`] if `name` is not a valid store-path name.
pub fn build_text_path(
  name: &str,
  content: &[u8],
  references: &[StorePath],
) -> Result<StorePath, BuildError> {
  ContentAddressed::Text {
    sha256: Sha256::hash(content),
    references,
  }
  .store_path(name)
}

#[cfg(test)]
mod tests {
  use std::slice;

  use super::*;

  #[test]
  fn parse_valid() {
    let store_path = "/nix/store/00bgd045z0d4icpbc2yyz4gx48ak44la-net-tools-1.60_p20170221182432"
      .parse::<StorePath>()
      .unwrap();
    assert_eq!(store_path.hash(), "00bgd045z0d4icpbc2yyz4gx48ak44la");
    assert_eq!(store_path.name(), "net-tools-1.60_p20170221182432");
    assert_eq!(
      store_path.digest(),
      *b"\x8a\x12\x32\x15\x22\xfd\x91\xef\xbd\x60\xeb\xb2\x48\x1a\xf8\x85\x80\xf6\x16\x00"
    );
  }

  #[test]
  fn parse_invalid_edges() {
    assert_eq!(
      "foobar-123".parse::<StorePath>(),
      Err(ParseStorePathError::MissingStoreDir)
    );
    assert_eq!(
      "/nix/store/00bgd045z0d4icpbc2yy-".parse::<StorePath>(),
      Err(ParseStorePathError::Length)
    );
    "/nix/store/00bgd045z0d4icpbc2yyz4gx48aku4la-net-tools"
      .parse::<StorePath>()
      .unwrap_err();
    assert_eq!(
      StorePathRef::from_component("00bgd045z0d4icpbc2yyz4gx48ak44lanet-tools"),
      Err(ParseStorePathError::MissingDash)
    );
    "/nix/store/00bgd045z0d4icpbc2yyz4gx48ak44la-net/tools"
      .parse::<StorePath>()
      .unwrap_err();
  }

  #[test]
  fn parse_in_custom_store_dir() {
    let dir = StoreDir::new("/var/lib/nix/store").unwrap();
    let store_path = dir
      .parse("/var/lib/nix/store/00bgd045z0d4icpbc2yyz4gx48ak44la-net-tools")
      .unwrap();
    assert_eq!(store_path.hash(), "00bgd045z0d4icpbc2yyz4gx48ak44la");
    assert_eq!(store_path.name(), "net-tools");
    assert_eq!(
      store_path.as_str(),
      "/var/lib/nix/store/00bgd045z0d4icpbc2yyz4gx48ak44la-net-tools"
    );
  }

  #[test]
  fn parse_outside_store_dir_rejected() {
    let dir = StoreDir::new("/var/lib/nix/store").unwrap();
    for path in [
      "/nix/store/00bgd045z0d4icpbc2yyz4gx48ak44la-net-tools",
      "/var/lib/nix/storex/00bgd045z0d4icpbc2yyz4gx48ak44la-net-tools",
      "/var/lib/nix/store/sub/00bgd045z0d4icpbc2yyz4gx48ak44la-net-tools",
    ] {
      assert!(dir.parse(path).is_err(), "{path}");
    }
    assert_eq!(
      StoreDir::default().parse("/var/lib/nix/store/x"),
      Err(ParseStorePathError::MissingStoreDir)
    );
  }

  #[test]
  fn default_store_dir_matches_parse() {
    let path = "/nix/store/00bgd045z0d4icpbc2yyz4gx48ak44la-net-tools";
    assert_eq!(StoreDir::default().as_str(), STORE_DIR);
    assert_eq!(StoreDir::default().parse(path), path.parse::<StorePath>());
  }

  #[test]
  fn non_canonical_store_dir_rejected() {
    for dir in [
      "",
      "/",
      "nix/store",
      "/nix/store/",
      "/nix//store",
      "/nix/./store",
      "/nix/../store",
    ] {
      assert!(StoreDir::new(dir).is_err(), "{dir:?}");
    }
  }

  #[test]
  fn text_path_zero_references() {
    let store_path = build_text_path("foo", b"bar", &[]).unwrap();
    assert_eq!(
      store_path.as_str(),
      "/nix/store/vxjiwkjkn7x4079qvh1jkl5pn05j2aw0-foo"
    );
  }

  #[test]
  fn text_path_with_references() {
    let inner = build_text_path("foo", b"bar", &[]).unwrap();
    let outer = build_text_path("baz", inner.as_str().as_bytes(), slice::from_ref(&inner)).unwrap();
    assert_eq!(
      outer.as_str(),
      "/nix/store/5xd714cbfnkz02h2vbsj4fm03x3f15nf-baz"
    );
  }

  #[test]
  fn ca_source_path_with_reference() {
    let digest: [u8; 32] =
      nixbase32::decode(b"1xqkzcb3909fp07qngljr4wcdnrh1gdam1m2n29i6hhrxlmkgkv1")
        .unwrap()
        .try_into()
        .unwrap();
    let references = ["/nix/store/dxwkwjzdaq7ka55pkk252gh32bgpmql4-foo"
      .parse::<StorePath>()
      .unwrap()];
    let store_path = ContentAddressed::Recursive {
      sha256:     digest,
      references: &references,
      self_ref:   false,
    }
    .store_path("baz")
    .unwrap();
    assert_eq!(
      store_path.as_str(),
      "/nix/store/s89y431zzhmdn3k8r96rvakryddkpv2v-baz"
    );
  }
}
