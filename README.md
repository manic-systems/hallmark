# hallmark

Pure-Rust Nix binary-cache and store primitives such as, but not limited to
store paths, `.narinfo`, fingerprints, Ed25519 signing, and NAR archives.

## Motivation

Hallmark aims to be a dependency-light and safe library crate for interacting
with Nix binary caches without `libnix` or `nix-compat`. It is a foundation
crate meant to be the one correct implementation of the framing and hashing
rules other tools build on, with each concern behind its own feature flag.

## Feature flags

<!--markdownlint-disable MD013-->

| Feature       | Default | Pulls in                                 | Provides                                                               |
| ------------- | ------- | ---------------------------------------- | ---------------------------------------------------------------------- |
| `store_path`  | yes     | `sha2`                                   | `/nix/store/<hash>-<name>` parsing, nixbase32, content-addressed paths |
| `narinfo`     | yes     | -                                        | `.narinfo` parse and render                                            |
| `fingerprint` | yes     | `narinfo`                                | the exact string Nix signs, plus nar-hash normalization and parsing    |
| `sign`        | yes     | `base64`, `ed25519-dalek`, `fingerprint` | Ed25519 signing and verification in Nix's `name:base64` format         |
| `nar`         | no      | -                                        | NAR reader, writer, in-memory tree, and filesystem dump                |

<!--markdownlint-enable MD013-->

> [!NOTE]
> The `nar` feature is off by default; enable it with:
>
> ```toml
> hallmark = { version = "1.0", features = ["nar"] }
> ```

## Examples

Parse, verify and render a narinfo:

```rust,no_run
use hallmark::{NarInfo, PublicKey};

let text = std::fs::read_to_string("example.narinfo")?;
let info = NarInfo::parse_str(&text)?;

let key = PublicKey::parse("cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=")?;
if info.verify(&[key]) {
  println!("signature ok");
}
print!("{info}");
# Ok::<(), Box<dyn std::error::Error>>(())
```

Sign a narinfo with a secret key:

```rust
use hallmark::{NarInfo, SecretKey};

let key = SecretKey::parse("cache-1:<base64 of 64-byte secret>");
# let _ = key;
```

Build a content-addressed store path (`builtins.toFile "foo" "bar"`):

```rust
use hallmark::store_path::build_text_path;

let path = build_text_path("foo", b"bar", &[])?;
assert_eq!(path.as_str(), "/nix/store/vxjiwkjkn7x4079qvh1jkl5pn05j2aw0-foo");
# Ok::<(), hallmark::store_path::BuildError>(())
```

Serialize a file and read a NAR back into a tree (requires `nar`):

```rust,ignore
use hallmark::nar::{self, Entry};

let mut bytes = Vec::new();
nar::write_nar(&mut bytes, &Entry::File {
  executable: false,
  contents: b"hello".to_vec(),
})?;

let tree = nar::read_nar(&mut bytes.as_slice())?;
assert!(matches!(tree, Entry::File { .. }));
# Ok::<(), std::io::Error>(())
```
