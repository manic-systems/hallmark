use hallmark::{
  narinfo::NarInfo,
  nixbase32,
  store_path::{Method, StorePath, build_ca_path, build_text_path},
};

const FULL: &str =
  "StorePath: \
   /nix/store/00bgd045z0d4icpbc2yyz4gx48ak44la-net-tools-1.60\nURL: \
   nar/1q8w.nar.xz\nCompression: xz\nFileHash: sha256:1q8wabc\nFileSize: \
   4096\nNarHash: \
   sha256:0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73\nNarSize: \
   20480\nReferences: 00bgd045z0d4icpbc2yyz4gx48ak44la-net-tools-1.60 \
   7rjj0i6b2cvz01iw7hd1xk5f0r48rd8w-glibc-2.39\nDeriver: \
   xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-net-tools-1.60.drv\nSig: \
   cache.nixos.org-1:aaaa\nSig: cache.example.org-1:bbbb\nCA: \
   fixed:r:sha256:0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73\n";

#[test]
fn full_narinfo_roundtrips_canonically() {
  let ni = NarInfo::parse_str(FULL).unwrap();
  assert_eq!(ni.references.len(), 2);
  assert_eq!(ni.sig.len(), 2);
  assert_eq!(ni.file_size, Some(4096));
  assert_eq!(ni.nar_size, 20480);
  assert!(ni.ca.as_deref().unwrap().starts_with("fixed:r:sha256:"));
  assert_eq!(
    ni.deriver.as_deref().unwrap(),
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-net-tools-1.60.drv"
  );
  assert_eq!(ni.render(), FULL);
}

#[test]
fn minimal_narinfo_omitting_optional_fields() {
  let text = "StorePath: /nix/store/00bgd045z0d4icpbc2yyz4gx48ak44la-x\nURL: \
              nar/x.nar\nCompression: none\nNarHash: sha256:zzz\nNarSize: 7\n";
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
  let text = "StorePath: \
              /nix/store/00bgd045z0d4icpbc2yyz4gx48ak44la-x\n\nURL: \
              nar/x.nar\nSomethingNew: ignore me\nCompression: zstd\nNarHash: \
              sha256:zzz\nNarSize: 1\n";
  let ni = NarInfo::parse_str(text).unwrap();
  assert_eq!(ni.compression, "zstd");
  assert_eq!(ni.url, "nar/x.nar");
}

#[test]
fn compression_variants_parse() {
  for compression in ["xz", "zstd", "bzip2", "none", "br"] {
    let text = format!(
      "StorePath: /nix/store/00bgd045z0d4icpbc2yyz4gx48ak44la-x\nURL: \
       u\nCompression: {compression}\nNarHash: sha256:z\nNarSize: 1\n"
    );
    assert_eq!(NarInfo::parse_str(&text).unwrap().compression, compression);
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

#[test]
fn recursive_path_with_reference_known_vector() {
  let digest: [u8; 32] =
    nixbase32::decode(b"1xqkzcb3909fp07qngljr4wcdnrh1gdam1m2n29i6hhrxlmkgkv1")
      .unwrap()
      .try_into()
      .unwrap();
  let path = build_ca_path(
    Method::Recursive,
    &digest,
    "baz",
    &["/nix/store/dxwkwjzdaq7ka55pkk252gh32bgpmql4-foo"],
    false,
  )
  .unwrap();
  assert_eq!(
    path.as_str(),
    "/nix/store/s89y431zzhmdn3k8r96rvakryddkpv2v-baz"
  );
}

#[test]
fn flat_path_is_valid_and_rejects_references() {
  let digest = [0x11_u8; 32];
  let path = build_ca_path(Method::Flat, &digest, "f", &[], false).unwrap();
  StorePath::parse(path.as_str()).unwrap();
  let refs = ["/nix/store/00000000000000000000000000000000-x"];
  build_ca_path(Method::Flat, &digest, "f", &refs, false).unwrap_err();
}

#[test]
fn self_reference_changes_recursive_path() {
  let digest = [0x22_u8; 32];
  let without =
    build_ca_path(Method::Recursive, &digest, "n", &[], false).unwrap();
  let with = build_ca_path(Method::Recursive, &digest, "n", &[], true).unwrap();
  assert_ne!(without.as_str(), with.as_str());
}

#[test]
fn extra_references_change_recursive_path() {
  let digest = [0x33_u8; 32];
  let one = build_ca_path(
    Method::Recursive,
    &digest,
    "n",
    &["/nix/store/dxwkwjzdaq7ka55pkk252gh32bgpmql4-foo"],
    false,
  )
  .unwrap();
  let two = build_ca_path(
    Method::Recursive,
    &digest,
    "n",
    &[
      "/nix/store/dxwkwjzdaq7ka55pkk252gh32bgpmql4-foo",
      "/nix/store/s89y431zzhmdn3k8r96rvakryddkpv2v-baz",
    ],
    false,
  )
  .unwrap();
  assert_ne!(one.as_str(), two.as_str());
}

#[test]
fn ca_path_construction_is_deterministic() {
  let digest = [0x44_u8; 32];
  let first = build_ca_path(Method::Text, &digest, "n", &[], false).unwrap();
  let second = build_ca_path(Method::Text, &digest, "n", &[], false).unwrap();
  assert_eq!(first, second);
}
