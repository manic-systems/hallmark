{
  mkShell,
  cargo,
  rustc,
  rustfmt,
  clippy,
  wild,
  rust-analyzer,
  cargo-nextest,
}: let
  inherit (rustc) llvmPackages;
in
  mkShell {
    strictDeps = true;
    nativeBuildInputs = [
      cargo
      rustc

      wild
      llvmPackages.clang

      (rustfmt.override {asNightly = true;})
      clippy
      rust-analyzer

      cargo-nextest
    ];
  }
