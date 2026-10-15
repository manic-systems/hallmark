use hallmark::{
  hash::Hash,
  narinfo::{
    Compression,
    NarInfo,
    Signature,
  },
  nixbase32,
  store_path::{
    ContentAddress,
    StoreDir,
    StorePath,
  },
};
use proptest::{
  array::uniform,
  collection::vec,
  option::of,
  prelude::*,
};

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

const BASE_NAME: &str = "[0-9a-df-np-sv-z]{32}-[a-z0-9.+-]{1,24}";
const DRV_BASE_NAME: &str = "[0-9a-df-np-sv-z]{32}-[a-z0-9.+-]{1,24}\\.drv";

fn arb_store_path(pattern: &'static str) -> impl Strategy<Value = StorePath> {
  pattern.prop_filter_map("valid store path", |base_name| {
    StoreDir::default().join(&base_name).ok()
  })
}

fn arb_signature() -> impl Strategy<Value = Signature> {
  ("[a-z0-9.-]{1,12}", uniform::<_, 64>(any::<u8>()))
    .prop_filter_map("valid signature", |(key_name, bytes)| {
      Signature::new(key_name, bytes).ok()
    })
}

prop_compose! {
  fn arb_narinfo()(
    store_path in arb_store_path(BASE_NAME),
    url in "[a-zA-Z0-9._+/=-]{1,24}",
    compression in prop_oneof!["xz", "zstd", "none", "bzip2", "lz77"],
    file_hash in of(any::<[u8; 32]>()),
    file_size in of(any::<u64>()),
    nar_hash in any::<[u8; 32]>(),
    nar_size in any::<u64>(),
    references in vec(arb_store_path(BASE_NAME), 0..5),
    deriver in of(arb_store_path(DRV_BASE_NAME)),
    sig in vec(arb_signature(), 0..4),
    ca in of(any::<[u8; 32]>()),
  ) -> NarInfo {
    NarInfo {
      store_path,
      url,
      compression: Compression::from(compression.as_str()),
      file_hash: file_hash.map(Hash::Sha256),
      file_size,
      nar_hash: Hash::Sha256(nar_hash),
      nar_size,
      references,
      deriver,
      sig,
      ca: ca.map(|digest| ContentAddress::Recursive(Hash::Sha256(digest))),
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
