#![no_main]

use hallmark::store_path::StorePath;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
  if let Ok(text) = std::str::from_utf8(data) {
    let _ = StorePath::parse(text);
  }
});
