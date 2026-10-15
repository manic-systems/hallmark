//! Parsing and rendering of the `.narinfo` metadata format served by Nix
//! binary caches.

use std::{
  fmt,
  io::{
    self,
    BufRead as _,
    BufReader,
    Read,
  },
  num::ParseIntError,
  str::FromStr,
};

use flub::Error;

use crate::{
  base64,
  hash::{
    Hash,
    ParseHashError,
  },
  store_path::{
    ContentAddress,
    ParseContentAddressError,
    ParseStorePathError,
    StoreDir,
    StoreDirError,
    StorePath,
  },
};

/// A narinfo field, named by its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Field {
  /// The `StorePath` key.
  StorePath,
  /// The `URL` key.
  Url,
  /// The `Compression` key.
  Compression,
  /// The `FileHash` key.
  FileHash,
  /// The `FileSize` key.
  FileSize,
  /// The `NarHash` key.
  NarHash,
  /// The `NarSize` key.
  NarSize,
  /// The `References` key.
  References,
  /// The `Deriver` key.
  Deriver,
  /// The `Sig` key.
  Sig,
  /// The `CA` key.
  Ca,
}

impl Field {
  const ALL: [Self; 11] = [
    Self::StorePath,
    Self::Url,
    Self::Compression,
    Self::FileHash,
    Self::FileSize,
    Self::NarHash,
    Self::NarSize,
    Self::References,
    Self::Deriver,
    Self::Sig,
    Self::Ca,
  ];

  /// The key as it appears in a narinfo document.
  #[must_use]
  pub const fn key(self) -> &'static str {
    match self {
      Self::StorePath => "StorePath",
      Self::Url => "URL",
      Self::Compression => "Compression",
      Self::FileHash => "FileHash",
      Self::FileSize => "FileSize",
      Self::NarHash => "NarHash",
      Self::NarSize => "NarSize",
      Self::References => "References",
      Self::Deriver => "Deriver",
      Self::Sig => "Sig",
      Self::Ca => "CA",
    }
  }

  fn from_key(key: &str) -> Option<Self> {
    Self::ALL.into_iter().find(|field| field.key() == key)
  }
}

impl fmt::Display for Field {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(self.key())
  }
}

/// Why a narinfo field value was rejected.
#[derive(Debug, Error)]
pub enum FieldError {
  /// A size was not a valid integer.
  #[error("invalid integer")]
  Int(#[source] ParseIntError),
  /// A store path or reference was malformed.
  #[error("invalid store path")]
  StorePath(#[source] ParseStorePathError),
  /// The directory of `StorePath` is not a canonical store directory.
  #[error("invalid store directory")]
  StoreDir(#[source] StoreDirError),
  /// A hash was malformed.
  #[error("invalid hash")]
  Hash(#[source] ParseHashError),
  /// A signature was malformed.
  #[error("invalid signature")]
  Signature(#[source] ParseSignatureError),
  /// A content address was malformed.
  #[error("invalid content address")]
  ContentAddress(#[source] ParseContentAddressError),
}

/// Why a narinfo document could not be parsed.
#[derive(Debug, Error)]
pub enum NarInfoError {
  /// The underlying reader failed.
  #[error("read narinfo")]
  Io(#[source] io::Error),
  /// A non-empty line did not contain the `": "` key/value separator.
  #[error("malformed line: {0:?}")]
  MalformedLine(String),
  /// A field every narinfo must carry was absent.
  #[error("missing {0}")]
  MissingField(Field),
  /// A field's value was rejected.
  #[error("invalid {field}")]
  Field {
    /// The field whose value was rejected.
    field:  Field,
    /// Why it was rejected.
    #[source]
    source: FieldError,
  },
}

impl NarInfoError {
  fn field(field: Field) -> impl FnOnce(FieldError) -> Self {
    move |source| Self::Field { field, source }
  }
}

/// The compression applied to a NAR as served.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub enum Compression {
  /// No compression.
  None,
  /// `xz`.
  Xz,
  /// `bzip2`, which Nix assumes when a narinfo omits `Compression`.
  #[default]
  Bzip2,
  /// `zstd`.
  Zstd,
  /// `br`, Brotli.
  Brotli,
  /// `gzip`.
  Gzip,
  /// `lz4`.
  Lz4,
  /// `lzip`.
  Lzip,
  /// Any other method, kept verbatim.
  Other(String),
}

impl From<&str> for Compression {
  fn from(name: &str) -> Self {
    match name {
      "none" => Self::None,
      "xz" => Self::Xz,
      "bzip2" => Self::Bzip2,
      "zstd" => Self::Zstd,
      "br" => Self::Brotli,
      "gzip" => Self::Gzip,
      "lz4" => Self::Lz4,
      "lzip" => Self::Lzip,
      other => Self::Other(other.to_owned()),
    }
  }
}

impl fmt::Display for Compression {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match *self {
      Self::None => "none",
      Self::Xz => "xz",
      Self::Bzip2 => "bzip2",
      Self::Zstd => "zstd",
      Self::Brotli => "br",
      Self::Gzip => "gzip",
      Self::Lz4 => "lz4",
      Self::Lzip => "lzip",
      Self::Other(ref name) => name,
    })
  }
}

/// Why a `<key-name>:<base64>` signature could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseSignatureError {
  /// No `:` separates the key name from the signature.
  #[error("signature is missing a ':' separator")]
  MissingSeparator,
  /// The key name is empty or contains a `:`.
  #[error("invalid signature key name {0:?}")]
  KeyName(String),
  /// The signature is not valid base64.
  #[error("signature is not valid base64")]
  Base64(#[source] base64::DecodeError),
  /// The signature does not decode to 64 bytes.
  #[error("signature has {0} bytes, want 64")]
  Length(usize),
}

/// An Ed25519 signature over a narinfo fingerprint, tagged with the name of
/// the key that made it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Signature {
  key_name: String,
  bytes:    [u8; 64],
}

impl Signature {
  /// Tag `bytes` with `key_name`.
  ///
  /// # Errors
  ///
  /// Returns [`ParseSignatureError::KeyName`] if `name` is empty or
  /// contains a `:`.
  pub fn new<N>(name: N, bytes: [u8; 64]) -> Result<Self, ParseSignatureError>
  where
    N: Into<String>,
  {
    let key_name = name.into();
    if key_name.is_empty() || key_name.contains(':') {
      return Err(ParseSignatureError::KeyName(key_name));
    }
    Ok(Self { key_name, bytes })
  }

  /// The name of the key that made this signature.
  #[must_use]
  pub fn key_name(&self) -> &str {
    &self.key_name
  }

  /// The raw signature.
  #[must_use]
  pub const fn bytes(&self) -> &[u8; 64] {
    &self.bytes
  }
}

impl FromStr for Signature {
  type Err = ParseSignatureError;

  fn from_str(input: &str) -> Result<Self, Self::Err> {
    let (key_name, encoded) = input
      .split_once(':')
      .ok_or(ParseSignatureError::MissingSeparator)?;
    let raw = base64::decode(encoded).map_err(ParseSignatureError::Base64)?;
    let bytes = <[u8; 64]>::try_from(raw.as_slice())
      .map_err(|_error| ParseSignatureError::Length(raw.len()))?;
    Self::new(key_name, bytes)
  }
}

impl fmt::Display for Signature {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}:{}", self.key_name, base64::encode(&self.bytes))
  }
}

/// A parsed `.narinfo` document.
///
/// The [`std::fmt::Display`] impl reproduces the canonical field order Nix
/// emits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NarInfo {
  /// The store path this entry describes.
  pub store_path:  StorePath,
  /// The NAR's location relative to the cache root (`nar/<hash>.nar.<ext>`).
  pub url:         String,
  /// The compression applied to the NAR as served.
  pub compression: Compression,
  /// Hash of the compressed NAR as served, if the cache advertises it.
  pub file_hash:   Option<Hash>,
  /// Byte size of the compressed NAR as served, if advertised.
  pub file_size:   Option<u64>,
  /// Hash of the uncompressed NAR, part of the signed fingerprint.
  pub nar_hash:    Hash,
  /// Byte size of the uncompressed NAR, part of the signed fingerprint.
  pub nar_size:    u64,
  /// Runtime references, in the same store directory as `store_path`.
  pub references:  Vec<StorePath>,
  /// The deriver (`.drv`) that produced this path, if recorded.
  pub deriver:     Option<StorePath>,
  /// Signatures over the fingerprint.
  pub sig:         Vec<Signature>,
  /// The content address for content-addressed paths, if any.
  pub ca:          Option<ContentAddress>,
}

impl NarInfo {
  /// Parse a narinfo from any reader.
  ///
  /// References and the deriver are resolved against the directory of
  /// `StorePath`. Unknown keys are ignored.
  ///
  /// # Errors
  ///
  /// Returns [`NarInfoError`] on I/O errors, a malformed line, a missing
  /// required field, or a field value that does not parse.
  pub fn parse<R>(reader: R) -> Result<Self, NarInfoError>
  where
    R: Read,
  {
    let mut store_path_value = None;
    let mut url = None;
    let mut compression = None;
    let mut file_hash = None;
    let mut file_size = None;
    let mut nar_hash = None;
    let mut nar_size = None;
    let mut references_text = String::new();
    let mut deriver_name = None;
    let mut sig = Vec::new();
    let mut ca = None;

    for result in BufReader::new(reader).lines() {
      let line = result.map_err(NarInfoError::Io)?;
      if line.is_empty() {
        continue;
      }

      let (key, value) = line
        .split_once(": ")
        .ok_or_else(|| NarInfoError::MalformedLine(line.clone()))?;
      let Some(field) = Field::from_key(key) else {
        continue;
      };
      let invalid = NarInfoError::field(field);

      match field {
        Field::StorePath => store_path_value = Some(value.to_owned()),
        Field::Url => url = Some(value.to_owned()),
        Field::Compression => compression = Some(Compression::from(value)),
        Field::FileHash => {
          file_hash = Some(value.parse().map_err(FieldError::Hash).map_err(invalid)?);
        },
        Field::FileSize => {
          file_size = Some(value.parse().map_err(FieldError::Int).map_err(invalid)?);
        },
        Field::NarHash => {
          nar_hash = Some(value.parse().map_err(FieldError::Hash).map_err(invalid)?);
        },
        Field::NarSize => {
          nar_size = Some(value.parse().map_err(FieldError::Int).map_err(invalid)?);
        },
        Field::References => value.clone_into(&mut references_text),
        Field::Deriver if !value.is_empty() && value != "unknown-deriver" => {
          deriver_name = Some(value.to_owned());
        },
        Field::Deriver => {},
        Field::Sig => {
          sig.push(
            value
              .parse()
              .map_err(FieldError::Signature)
              .map_err(invalid)?,
          );
        },
        Field::Ca => {
          ca = Some(
            value
              .parse()
              .map_err(FieldError::ContentAddress)
              .map_err(invalid)?,
          );
        },
      }
    }

    let store_path_text = store_path_value.ok_or(NarInfoError::MissingField(Field::StorePath))?;
    let (dir, _) = store_path_text.rsplit_once('/').unwrap_or_default();
    let store_dir = StoreDir::new(dir)
      .map_err(FieldError::StoreDir)
      .map_err(NarInfoError::field(Field::StorePath))?;
    let store_path = store_dir
      .parse(&store_path_text)
      .map_err(FieldError::StorePath)
      .map_err(NarInfoError::field(Field::StorePath))?;

    let references = references_text
      .split_whitespace()
      .map(|base_name| store_dir.join(base_name))
      .collect::<Result<_, _>>()
      .map_err(FieldError::StorePath)
      .map_err(NarInfoError::field(Field::References))?;
    let deriver = deriver_name
      .map(|base_name| store_dir.join(&base_name))
      .transpose()
      .map_err(FieldError::StorePath)
      .map_err(NarInfoError::field(Field::Deriver))?;

    Ok(Self {
      store_path,
      url: url.ok_or(NarInfoError::MissingField(Field::Url))?,
      compression: compression.unwrap_or_default(),
      file_hash,
      file_size,
      nar_hash: nar_hash.ok_or(NarInfoError::MissingField(Field::NarHash))?,
      nar_size: nar_size.ok_or(NarInfoError::MissingField(Field::NarSize))?,
      references,
      deriver,
      sig,
      ca,
    })
  }
}

impl FromStr for NarInfo {
  type Err = NarInfoError;

  fn from_str(text: &str) -> Result<Self, Self::Err> {
    Self::parse(text.as_bytes())
  }
}

impl fmt::Display for NarInfo {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    writeln!(f, "StorePath: {}", self.store_path)?;
    writeln!(f, "URL: {}", self.url)?;
    writeln!(f, "Compression: {}", self.compression)?;
    if let Some(file_hash) = self.file_hash.as_ref() {
      writeln!(f, "FileHash: {file_hash}")?;
    }
    if let Some(file_size) = self.file_size {
      writeln!(f, "FileSize: {file_size}")?;
    }
    writeln!(f, "NarHash: {}", self.nar_hash)?;
    writeln!(f, "NarSize: {}", self.nar_size)?;
    let references: Vec<_> = self.references.iter().map(StorePath::base_name).collect();
    writeln!(f, "References: {}", references.join(" "))?;
    if let Some(deriver) = self.deriver.as_ref() {
      writeln!(f, "Deriver: {}", deriver.base_name())?;
    }
    for sig in &self.sig {
      writeln!(f, "Sig: {sig}")?;
    }
    if let Some(ca) = self.ca.as_ref() {
      writeln!(f, "CA: {ca}")?;
    }
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const SAMPLE: &str =
    "StorePath: /nix/store/00bgd045z0d4icpbc2yyz4gx48ak44la-net-tools-1.60\nURL: \
     nar/abc.nar.xz\nCompression: xz\nFileHash: \
     sha256:0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73\nFileSize: 42\nNarHash: \
     sha256:0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73\nNarSize: 123\nReferences: \
     00bgd045z0d4icpbc2yyz4gx48ak44la-net-tools-1.60 \
     7rjj0i6b2cvz01iw7hd1xk5f0r48rd8w-glibc-2.39\nDeriver: \
     xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-net-tools-1.60.drv\nSig: \
     cache.example.org:\
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\nCA: \
     fixed:r:sha256:0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73\n";

  #[test]
  fn roundtrip() {
    let ni = SAMPLE.parse::<NarInfo>().unwrap();
    assert_eq!(ni.references.len(), 2);
    assert_eq!(ni.file_size, Some(42));
    assert_eq!(ni.nar_size, 123);
    assert_eq!(ni.compression, Compression::Xz);
    assert_eq!(ni.to_string(), SAMPLE);
  }

  #[test]
  fn missing_store_path_errors() {
    assert!(matches!(
      "URL: nar/abc.nar.xz\nNarSize: 1\n".parse::<NarInfo>(),
      Err(NarInfoError::MissingField(Field::StorePath))
    ));
  }

  #[test]
  fn malformed_line_errors() {
    assert!(matches!(
      "StorePath: /nix/store/abc\nno-colon-here\n".parse::<NarInfo>(),
      Err(NarInfoError::MalformedLine(_))
    ));
  }
}
