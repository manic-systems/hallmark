use hallmark::hash::Hash;

const HEX: &str = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const B32: &str = "sha256:0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73";
const SRI: &str = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
const EMPTY_SHA256: [u8; 32] = [
  0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24,
  0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C, 0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55,
];

#[test]
fn every_encoding_parses_to_the_same_hash() {
  let upper_hex = HEX.replace(
    "e3b0c44298fc1c149afbf4c8996fb924",
    "E3B0C44298FC1C149AFBF4C8996FB924",
  );
  for input in [HEX, B32, SRI, upper_hex.as_str()] {
    assert_eq!(
      input.parse::<Hash>(),
      Ok(Hash::Sha256(EMPTY_SHA256)),
      "{input}"
    );
  }
}

#[test]
fn renders_as_nixbase32() {
  assert_eq!(HEX.parse::<Hash>().unwrap().to_string(), B32);
}

#[test]
fn rejects_bad_inputs() {
  for input in [
    "sha256:short",
    "sha1:e3b0c44298fc1c149afbf4c8996fb924",
    "md5:abc",
    "not-a-hash",
    "sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
  ] {
    assert!(input.parse::<Hash>().is_err(), "{input}");
  }
}
