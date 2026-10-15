use hallmark::{
  narinfo::{
    Compression,
    NarInfo,
  },
  nixbase32,
  store_path::{
    BuildError,
    ContentAddress,
    ContentAddressed,
    ParseStorePathError,
    StorePath,
    build_text_path,
  },
};

const FULL: &str =
  "StorePath: /nix/store/00bgd045z0d4icpbc2yyz4gx48ak44la-net-tools-1.60\nURL: \
   nar/1q8w.nar.xz\nCompression: xz\nFileHash: \
   sha256:0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73\nFileSize: 4096\nNarHash: \
   sha256:0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73\nNarSize: 20480\nReferences: \
   00bgd045z0d4icpbc2yyz4gx48ak44la-net-tools-1.60 \
   7rjj0i6b2cvz01iw7hd1xk5f0r48rd8w-glibc-2.39\nDeriver: \
   xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-net-tools-1.60.drv\nSig: \
   cache.nixos.org-1:\
   AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\nSig: \
   cache.example.org-1:\
   AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\nCA: \
   fixed:r:sha256:0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73\n";

#[test]
fn full_narinfo_roundtrips_canonically() {
  let ni = NarInfo::parse_str(FULL).unwrap();
  assert_eq!(ni.references.len(), 2);
  assert_eq!(ni.sig.len(), 2);
  assert_eq!(ni.file_size, Some(4096));
  assert_eq!(ni.nar_size, 20480);
  assert!(matches!(ni.ca, Some(ContentAddress::Recursive(_))));
  assert_eq!(
    ni.deriver.as_ref().unwrap().base_name(),
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-net-tools-1.60.drv"
  );
  assert_eq!(ni.render(), FULL);
}

#[test]
fn minimal_narinfo_omitting_optional_fields() {
  let text = "StorePath: /nix/store/00bgd045z0d4icpbc2yyz4gx48ak44la-x\nURL: \
              nar/x.nar\nCompression: none\nNarHash: \
              sha256:0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73\nNarSize: 7\n";
  let ni = NarInfo::parse_str(text).unwrap();
  assert!(ni.file_hash.is_none());
  assert!(ni.file_size.is_none());
  assert!(ni.deriver.is_none());
  assert!(ni.ca.is_none());
  assert!(ni.references.is_empty());
  assert!(ni.sig.is_empty());
}

#[test]
fn narinfo_tolerates_unknown_keys_and_blank_lines() {
  let text = "StorePath: /nix/store/00bgd045z0d4icpbc2yyz4gx48ak44la-x\n\nURL: \
              nar/x.nar\nSomethingNew: ignore me\nCompression: zstd\nNarHash: \
              sha256:0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73\nNarSize: 1\n";
  let ni = NarInfo::parse_str(text).unwrap();
  assert_eq!(ni.compression, Compression::Zstd);
  assert_eq!(ni.url, "nar/x.nar");
}

#[test]
fn compression_variants_parse() {
  for compression in ["xz", "zstd", "bzip2", "none", "br"] {
    let text = format!(
      "StorePath: /nix/store/00bgd045z0d4icpbc2yyz4gx48ak44la-x\nURL: u\nCompression: \
       {compression}\nNarHash: \
       sha256:0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73\nNarSize: 1\n"
    );
    let parsed = NarInfo::parse_str(&text).unwrap().compression;
    assert_eq!(parsed.to_string(), compression);
    assert!(!matches!(parsed, Compression::Other(_)));
  }
}

#[test]
fn text_path_known_vector() {
  let path = build_text_path("foo", b"bar", &[]).unwrap();
  assert_eq!(
    path.as_str(),
    "/nix/store/vxjiwkjkn7x4079qvh1jkl5pn05j2aw0-foo"
  );
}

fn foo() -> Result<StorePath, ParseStorePathError> {
  StorePath::parse("/nix/store/dxwkwjzdaq7ka55pkk252gh32bgpmql4-foo")
}

fn recursive(
  sha256: [u8; 32],
  references: &[StorePath],
  self_ref: bool,
) -> Result<StorePath, BuildError> {
  ContentAddressed::Recursive {
    sha256,
    references,
    self_ref,
  }
  .store_path("n")
}

#[test]
fn recursive_path_with_reference_known_vector() {
  let sha256: [u8; 32] = nixbase32::decode(b"1xqkzcb3909fp07qngljr4wcdnrh1gdam1m2n29i6hhrxlmkgkv1")
    .unwrap()
    .try_into()
    .unwrap();
  let path = ContentAddressed::Recursive {
    sha256,
    references: &[foo().unwrap()],
    self_ref: false,
  }
  .store_path("baz")
  .unwrap();
  assert_eq!(
    path.as_str(),
    "/nix/store/s89y431zzhmdn3k8r96rvakryddkpv2v-baz"
  );
}

#[test]
fn flat_path_is_valid() {
  let path = ContentAddressed::Flat { sha256: [0x11; 32] }
    .store_path("f")
    .unwrap();
  StorePath::parse(path.as_str()).unwrap();
}

#[test]
fn self_reference_changes_recursive_path() {
  assert_ne!(
    recursive([0x22; 32], &[], false).unwrap(),
    recursive([0x22; 32], &[], true).unwrap()
  );
}

#[test]
fn extra_references_change_recursive_path() {
  let baz = StorePath::parse("/nix/store/s89y431zzhmdn3k8r96rvakryddkpv2v-baz").unwrap();
  assert_ne!(
    recursive([0x33; 32], &[foo().unwrap()], false).unwrap(),
    recursive([0x33; 32], &[foo().unwrap(), baz], false).unwrap()
  );
}

#[test]
fn ca_path_construction_is_deterministic() {
  let text = ContentAddressed::Text {
    sha256:     [0x44; 32],
    references: &[],
  };
  assert_eq!(text.store_path("n").unwrap(), text.store_path("n").unwrap());
}
