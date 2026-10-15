#![no_main]

use hallmark::narinfo::NarInfo;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
  if let Ok(info) = NarInfo::parse(data) {
    let _ = info.render();
  }
});
