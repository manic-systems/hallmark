#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

#[cfg(any(feature = "store_path", feature = "fingerprint"))]
pub mod nixbase32;

#[cfg(feature = "store_path")] pub mod store_path;

#[cfg(feature = "narinfo")] pub mod narinfo;

#[cfg(feature = "fingerprint")] pub mod fingerprint;

#[cfg(feature = "sign")] pub mod sign;

#[cfg(feature = "nar")] pub mod nar;

#[cfg(feature = "narinfo")]
pub use narinfo::{NarInfo, NarInfoError};
#[cfg(feature = "sign")]
pub use sign::{KeyError, PublicKey, SecretKey};
#[cfg(feature = "store_path")]
pub use store_path::{Method, StorePath, StorePathRef};
