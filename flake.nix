{
  description = "Pure-Rust Nix binary-cache and store primitives";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs?ref=nixos-unstable";

  outputs = {
    self,
    nixpkgs,
  }: let
    systems = ["x86_64-linux" "aarch64-linux"];
    forEachSystem = nixpkgs.lib.genAttrs systems;
    pkgsForEach = system: nixpkgs.legacyPackages.${system};

    hallmarkFor = system: let
      pkgs = pkgsForEach system;
    in
      pkgs.rustPlatform.buildRustPackage {
        pname = "hallmark";
        version = "0.1.0";
        src = self;
        cargoLock.lockFile = ./Cargo.lock;
      };
  in {
    packages = forEachSystem (system: {
      hallmark = hallmarkFor system;
      default = self.packages.${system}.hallmark;
    });

    devShells = forEachSystem (system: let
      pkgs = pkgsForEach system;
    in {
      default = pkgs.mkShell {
        strictDeps = true;
        nativeBuildInputs = [pkgs.cargo pkgs.rustc pkgs.gcc];
        packages = [pkgs.rustfmt pkgs.clippy pkgs.rust-analyzer pkgs.taplo];
      };
    });

    checks = forEachSystem (system: let
      pkgs = pkgsForEach system;
    in {
      package = self.packages.${system}.hallmark;
      test =
        (hallmarkFor system).overrideAttrs (_: {
          pname = "hallmark-tests";
          doCheck = true;
        });
    });

    formatter = forEachSystem (system: (pkgsForEach system).alejandra);
  };
}
