#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![expect(
  clippy::doc_include_without_cfg,
  reason = "missing_docs needs the crate doc in non-rustdoc builds too"
)]
#![doc = include_str!("../README.md")]

#[cfg(any(feature = "store_path", feature = "fingerprint"))]
pub mod nixbase32;

#[cfg(feature = "store_path")] pub mod store_path;

#[cfg(feature = "narinfo")] pub mod narinfo;

#[cfg(feature = "fingerprint")] pub mod fingerprint;

#[cfg(feature = "sign")] pub mod base64;

#[cfg(feature = "sign")] pub mod sign;

#[cfg(feature = "nar")] pub mod nar;
