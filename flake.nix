{
  description = "Anti Website Fingerprinting Library";

  inputs = {
    nixpkgs.url = "https://channels.nixos.org/nixpkgs-unstable/nixexprs.tar.xz";
    flake-utils.url = "github:numtide/flake-utils";

    treefmt = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    treefmt,
    naersk,
    rust-overlay,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        overlays = [(import rust-overlay)];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        src = builtins.path {
          path = ./.;
          name = "harper";
        };

        toolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = ["rust-analyzer" "rust-src"];
        };
        naersk' = naersk.lib.${system}.override {
          cargo = toolchain;
          rustc = toolchain;
        };

        treefmtConfig = treefmt.lib.evalModule pkgs {
          projectRootFile = "flake.nix";
          programs.rustfmt.enable = true;
          programs.alejandra.enable = true;
        };

        buildInputs = with pkgs; [openssl pkg-config];
        extraShellInputs = with pkgs; [
          cargo-audit
          cargo-edit
          cargo-machete
          cargo-nextest
          cargo-outdated
          cargo-tarpaulin
        ];
      in {
        formatter = treefmtConfig.config.build.wrapper;

        # Default package for `nix build`
        packages.default = naersk'.buildPackage {
          inherit buildInputs src;
          doDoc = true;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = buildInputs ++ extraShellInputs;
          nativeBuildInputs = [
            toolchain
          ];
          RUST_SRC_PATH = "${toolchain}/lib/rustlib/src/rust/library";
        };

        checks = {
          # This will just fail in CI/CD, but locally will actually
          # do the formatting.
          formatting = treefmtConfig.config.build.check self;

          # In CI/CD this will already be fulfilled as we build the package
          # with `nix build` beforehand
          package = self.packages.${system}.default;

          # Lint and test
          clippy = naersk'.buildPackage {
            inherit buildInputs src;
            mode = "clippy";
          };

          test = naersk'.buildPackage {
            inherit buildInputs src;
            mode = "test";
          };
        };
      }
    );
}
