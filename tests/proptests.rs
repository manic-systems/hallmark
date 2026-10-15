use hallmark::{narinfo::NarInfo, nixbase32};
use proptest::{collection::vec, option::of, prelude::*};

proptest! {
  #[test]
  fn nixbase32_roundtrips(bytes in vec(any::<u8>(), 0..64)) {
    let encoded = nixbase32::encode(&bytes);
    prop_assert_eq!(encoded.len(), nixbase32::encode_len(bytes.len()));
    let decoded = nixbase32::decode(encoded.as_bytes()).unwrap();
    prop_assert_eq!(decoded, bytes);
  }

  #[test]
  fn nixbase32_rejects_out_of_alphabet(
    mut encoded in "[0-9abcdfghijklmnpqrsvwxyz]{0,40}"
  ) {
    encoded.push('e');
    prop_assert!(nixbase32::decode(encoded.as_bytes()).is_err());
  }
}

prop_compose! {
  fn arb_narinfo()(
    store_path in "/nix/store/[0-9a-df-np-sv-z]{32}-[a-z0-9.+-]{1,24}",
    url in "[a-zA-Z0-9._+/=-]{1,24}",
    compression in prop_oneof!["xz", "zstd", "none", "bzip2"],
    file_hash in of("sha256:[0-9a-df-np-sv-z]{52}"),
    file_size in of(any::<u64>()),
    nar_hash in "sha256:[0-9a-df-np-sv-z]{52}",
    nar_size in any::<u64>(),
    references in vec("[a-z0-9.+-]{1,24}", 0..5),
    deriver in of("[a-z0-9.+-]{1,24}\\.drv"),
    sig in vec("[a-z0-9.-]{1,12}:[A-Za-z0-9+/]{8,40}", 0..4),
    ca in of("fixed:r:sha256:[0-9a-df-np-sv-z]{52}"),
  ) -> NarInfo {
    NarInfo {
      store_path,
      url,
      compression,
      file_hash,
      file_size,
      nar_hash,
      nar_size,
      references,
      deriver,
      sig,
      ca,
    }
  }
}

proptest! {
  #[test]
  fn narinfo_parse_render_roundtrips(info in arb_narinfo()) {
    let rendered = info.render();
    let parsed = NarInfo::parse_str(&rendered).unwrap();
    prop_assert_eq!(&parsed, &info);
    prop_assert_eq!(parsed.render(), rendered);
  }
}
