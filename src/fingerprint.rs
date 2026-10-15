//! The string Nix signs for a store path.

use crate::{
  narinfo::NarInfo,
  store_path::StorePath,
};

/// The Nix fingerprint:
/// `1;<store_path>;<nar_hash>;<nar_size>;<comma-separated sorted refs>`.
///
/// The NAR hash always renders as nixbase32, so narinfos whose `NarHash` was
/// served as hex (as `atticd` does) still verify.
#[must_use]
pub fn fingerprint(narinfo: &NarInfo) -> String {
  let mut references: Vec<_> = narinfo.references.iter().map(StorePath::as_str).collect();
  references.sort_unstable();
  format!(
    "1;{};{};{};{}",
    narinfo.store_path,
    narinfo.nar_hash,
    narinfo.nar_size,
    references.join(",")
  )
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn known_vector() {
    let ni = "StorePath: /nix/store/00bgd045z0d4icpbc2yyz4gx48ak44la-test\nURL: \
              nar/x.nar\nNarHash: \
              sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nNarSize: \
              100\nReferences: 7rjj0i6b2cvz01iw7hd1xk5f0r48rd8w-foo \
              00bgd045z0d4icpbc2yyz4gx48ak44la-bar\n"
      .parse::<NarInfo>()
      .unwrap();
    assert_eq!(
      fingerprint(&ni),
      "1;/nix/store/00bgd045z0d4icpbc2yyz4gx48ak44la-test;sha256:\
       0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73;100;/nix/store/\
       00bgd045z0d4icpbc2yyz4gx48ak44la-bar,/nix/store/7rjj0i6b2cvz01iw7hd1xk5f0r48rd8w-foo"
    );
  }
}
