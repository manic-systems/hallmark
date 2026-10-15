{
  lib,
  rustPlatform,
}:
rustPlatform.buildRustPackage (finalAttrs: {
  pname = "hallmark";
  version = "1.0.0";
  src = let
    fs = lib.fileset;
    s = ../.;
  in
    fs.toSource {
      root = s;
      fileset = fs.unions [
        (s + /src)
        (s + /tests)

        (s + /Cargo.toml)
        (s + /Cargo.lock)
        (s + /README.md)
      ];
    };

  cargoLock.lockFile = "${finalAttrs.src}/Cargo.lock";
})
