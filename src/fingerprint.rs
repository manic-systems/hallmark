//! The string Nix signs for a store path.

use crate::{narinfo::NarInfo, nixbase32};

fn nibble(b: u8) -> Option<u8> {
  match b {
    b'0'..=b'9' => Some(b - b'0'),
    b'a'..=b'f' => Some(b - b'a' + 10),
    b'A'..=b'F' => Some(b - b'A' + 10),
    _ => None,
  }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
  if !s.len().is_multiple_of(2) {
    return None;
  }
  let bytes = s.as_bytes();
  let mut out = Vec::with_capacity(s.len() / 2);
  for i in (0..bytes.len()).step_by(2) {
    out.push((nibble(bytes[i])? << 4) | nibble(bytes[i + 1])?);
  }
  Some(out)
}

/// Normalize a `sha256:<64 hex>` nar-hash to `sha256:<52 nixbase32>`.
///
/// `atticd` serves `NarHash` as hex but signs over the base32 form, so the
/// fingerprint must be recomputed against base32 to verify those signatures.
/// Inputs already in base32, or not recognizably hex, are returned unchanged.
///
/// # Returns
///
/// The base32 form when `s` is a valid `sha256:` hex digest; otherwise `s`
/// unchanged.
#[must_use]
pub fn normalize_nar_hash(s: &str) -> String {
  let Some((algo, digest)) = s.split_once(':') else {
    return s.to_owned();
  };
  if algo == "sha256"
    && digest.len() == 64
    && digest.bytes().all(|b| b.is_ascii_hexdigit())
    && let Some(bytes) = hex_decode(digest)
  {
    return format!("{algo}:{}", nixbase32::encode(&bytes));
  }
  s.to_owned()
}

/// Decode a `sha256:<digest>` nar-hash into its 32 raw bytes.
///
/// Accepts both the 64-character hex and 52-character nixbase32 encodings Nix
/// and binary caches use interchangeably.
///
/// # Returns
///
/// `Some` containing the 32 raw bytes for a valid `sha256:` digest; `None`
/// for a non-`sha256` algorithm, a missing `:` separator, or a digest with
/// the wrong length or encoding.
#[must_use]
pub fn parse_nar_hash(s: &str) -> Option<[u8; 32]> {
  let (algo, digest) = s.split_once(':')?;
  if algo != "sha256" {
    return None;
  }
  let bytes = match digest.len() {
    64 => hex_decode(digest)?,
    52 => nixbase32::decode(digest.as_bytes()).ok()?,
    _ => return None,
  };
  bytes.try_into().ok()
}

fn absolutize(store_dir: &str, reference: &str) -> String {
  if reference.starts_with('/') {
    reference.to_owned()
  } else {
    format!("{store_dir}/{reference}")
  }
}

/// The Nix fingerprint:
/// `1;<store_path>;<nar_hash>;<nar_size>;<comma-separated sorted abs refs>`.
#[must_use]
pub fn fingerprint(store_dir: &str, narinfo: &NarInfo) -> String {
  let mut refs: Vec<String> = narinfo
    .references
    .iter()
    .map(|r| absolutize(store_dir, r))
    .collect();
  refs.sort();
  format!(
    "1;{};{};{};{}",
    narinfo.store_path,
    normalize_nar_hash(&narinfo.nar_hash),
    narinfo.nar_size,
    refs.join(",")
  )
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn known_vector() {
    let ni = NarInfo {
      store_path: "/nix/store/abc-test".to_owned(),
      nar_hash: "sha256:xyz".to_owned(),
      nar_size: 100,
      references: vec!["foo".to_owned(), "bar".to_owned()],
      ..Default::default()
    };
    assert_eq!(
      fingerprint("/nix/store", &ni),
      "1;/nix/store/abc-test;sha256:xyz;100;/nix/store/bar,/nix/store/foo"
    );
  }

  #[test]
  fn normalizes_attic_hex_hash() {
    let hex =
      "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let b32 = "sha256:0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73";
    assert_eq!(normalize_nar_hash(hex), b32);
    assert_eq!(normalize_nar_hash(b32), b32);
    assert_eq!(normalize_nar_hash("md5:abc"), "md5:abc");
  }
}
