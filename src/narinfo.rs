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
};

use thiserror::Error;

/// Why a narinfo document could not be parsed.
#[derive(Debug, Error)]
pub enum NarInfoError {
  /// The underlying reader failed.
  #[error("read narinfo: {0}")]
  Io(#[from] io::Error),
  /// A non-empty line did not contain the `": "` key/value separator.
  #[error("malformed line: {0:?}")]
  MalformedLine(String),
  /// No `StorePath` field was present, so the document is unusable.
  #[error("missing StorePath")]
  MissingStorePath,
  /// A numeric field (`FileSize` or `NarSize`) was not a valid integer.
  #[error("{field}: {source}")]
  ParseInt {
    /// The field whose value failed to parse.
    field:  &'static str,
    /// The underlying integer-parse error.
    source: ParseIntError,
  },
}

/// A parsed `.narinfo` document.
///
/// Optional fields are `None`/empty when absent. [`NarInfo::render`] (and the
/// [`std::fmt::Display`] impl) reproduce the canonical field order Nix emits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NarInfo {
  /// The absolute store path this entry describes.
  pub store_path:  String,
  /// The NAR's location relative to the cache root (`nar/<hash>.nar.<ext>`).
  pub url:         String,
  /// The compression algorithm applied to the NAR (`xz`, `zstd`, `none`, …).
  pub compression: String,
  /// Hash of the compressed NAR as served, if the cache advertises it.
  pub file_hash:   Option<String>,
  /// Byte size of the compressed NAR as served, if advertised.
  pub file_size:   Option<u64>,
  /// Hash of the uncompressed NAR; part of the signed fingerprint.
  pub nar_hash:    String,
  /// Byte size of the uncompressed NAR; part of the signed fingerprint.
  pub nar_size:    u64,
  /// Runtime references, as store-path components or absolute paths.
  pub references:  Vec<String>,
  /// The deriver (`.drv`) that produced this path, if recorded.
  pub deriver:     Option<String>,
  /// Signatures over the fingerprint, each `<key-name>:<base64>`.
  pub sig:         Vec<String>,
  /// The content address for content-addressed paths, if any.
  pub ca:          Option<String>,
}

impl NarInfo {
  /// Parse a narinfo from any reader.
  ///
  /// # Errors
  ///
  /// Returns [`NarInfoError`] if a line is malformed, an integer field cannot
  /// be parsed, an I/O error occurs, or `StorePath` is missing.
  pub fn parse<R>(reader: R) -> Result<Self, NarInfoError>
  where
    R: Read,
  {
    let mut narinfo = Self::default();
    for result in BufReader::new(reader).lines() {
      let line = result?;
      if line.is_empty() {
        continue;
      }
      let (key, value) = line
        .split_once(": ")
        .ok_or_else(|| NarInfoError::MalformedLine(line.clone()))?;
      match key {
        "StorePath" => value.clone_into(&mut narinfo.store_path),
        "URL" => value.clone_into(&mut narinfo.url),
        "Compression" => value.clone_into(&mut narinfo.compression),
        "FileHash" => narinfo.file_hash = Some(value.to_owned()),
        "FileSize" => {
          narinfo.file_size = Some(value.parse().map_err(|source| {
            NarInfoError::ParseInt {
              field: "FileSize",
              source,
            }
          })?);
        },
        "NarHash" => value.clone_into(&mut narinfo.nar_hash),
        "NarSize" => {
          narinfo.nar_size = value.parse().map_err(|source| {
            NarInfoError::ParseInt {
              field: "NarSize",
              source,
            }
          })?;
        },
        "References" if !value.is_empty() => {
          narinfo.references = value.split_whitespace().map(str::to_owned).collect();
        },
        "Deriver" if !value.is_empty() => {
          narinfo.deriver = Some(value.to_owned());
        },
        "Sig" => narinfo.sig.push(value.to_owned()),
        "CA" => narinfo.ca = Some(value.to_owned()),
        _ => {},
      }
    }
    if narinfo.store_path.is_empty() {
      return Err(NarInfoError::MissingStorePath);
    }
    Ok(narinfo)
  }

  /// Parse a narinfo from a string slice.
  ///
  /// # Errors
  ///
  /// See [`NarInfo::parse`].
  pub fn parse_str(text: &str) -> Result<Self, NarInfoError> {
    Self::parse(text.as_bytes())
  }

  /// Render back to the canonical narinfo text, newline-terminated.
  #[must_use]
  pub fn render(&self) -> String {
    self.to_string()
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
    writeln!(f, "References: {}", self.references.join(" "))?;
    if let Some(deriver) = self.deriver.as_ref() {
      writeln!(f, "Deriver: {deriver}")?;
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
     nar/abc.nar.xz\nCompression: xz\nFileHash: sha256:abc\nFileSize: 42\nNarHash: \
     sha256:def\nNarSize: 123\nReferences: 00bgd045z0d4icpbc2yyz4gx48ak44la-net-tools-1.60 \
     foo-dep\nDeriver: xxx.drv\nSig: cache.example.org:AAAA\nCA: fixed:r:sha256:0000\n";

  #[test]
  fn roundtrip() {
    let ni = NarInfo::parse_str(SAMPLE).unwrap();
    assert_eq!(ni.references.len(), 2);
    assert_eq!(ni.file_size, Some(42));
    assert_eq!(ni.nar_size, 123);
    assert_eq!(ni.render(), SAMPLE);
  }

  #[test]
  fn missing_store_path_errors() {
    assert!(matches!(
      NarInfo::parse_str("URL: nar/abc.nar.xz\nNarSize: 1\n"),
      Err(NarInfoError::MissingStorePath)
    ));
  }

  #[test]
  fn malformed_line_errors() {
    assert!(matches!(
      NarInfo::parse_str("StorePath: /nix/store/abc\nno-colon-here\n"),
      Err(NarInfoError::MalformedLine(_))
    ));
  }
}
