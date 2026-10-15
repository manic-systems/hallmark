#![no_main]

use libfuzzer_sys::fuzz_target;
use hallmark::NarInfo;

fuzz_target!(|data: &[u8]| {
  if let Ok(info) = NarInfo::parse(data) {
    let _ = info.render();
  }
});
