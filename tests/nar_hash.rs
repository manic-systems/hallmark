use hallmark::fingerprint::{normalize_nar_hash, parse_nar_hash};

const HEX: &str =
  "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const B32: &str = "sha256:0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73";
const EMPTY_SHA256: [u8; 32] = [
  0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 0x9A, 0xFB, 0xF4, 0xC8, 0x99,
  0x6F, 0xB9, 0x24, 0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C, 0xA4, 0x95,
  0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55,
];

#[test]
fn normalize_hex_to_base32() {
  assert_eq!(normalize_nar_hash(HEX), B32);
  assert_eq!(normalize_nar_hash(B32), B32);
}

fn upper_digest(h: &str) -> String {
  let (algo, digest) = h.split_once(':').unwrap();
  format!("{algo}:{}", digest.to_uppercase())
}

#[test]
fn normalize_accepts_uppercase_hex() {
  assert_eq!(normalize_nar_hash(&upper_digest(HEX)), B32);
}

#[test]
fn normalize_passes_through_sri_and_other_algos() {
  let sri = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
  assert_eq!(normalize_nar_hash(sri), sri);
  assert_eq!(normalize_nar_hash("md5:abc"), "md5:abc");
  assert_eq!(normalize_nar_hash("not-a-hash"), "not-a-hash");
}

#[test]
fn parse_hex_and_base32_agree() {
  assert_eq!(parse_nar_hash(HEX), Some(EMPTY_SHA256));
  assert_eq!(parse_nar_hash(B32), Some(EMPTY_SHA256));
  assert_eq!(parse_nar_hash(&upper_digest(HEX)), Some(EMPTY_SHA256));
}

#[test]
fn parse_rejects_bad_inputs() {
  assert_eq!(parse_nar_hash("sha256:short"), None);
  assert_eq!(
    parse_nar_hash("sha1:e3b0c44298fc1c149afbf4c8996fb924"),
    None
  );
  assert_eq!(parse_nar_hash("no-separator"), None);
  assert_eq!(
    parse_nar_hash(
      "sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
    ),
    None
  );
}
