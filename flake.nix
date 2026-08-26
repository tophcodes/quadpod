{
  description = "quadpod - SPARQL-authoritative Solid pod";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, flake-utils, nixpkgs, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            cargo
            rustc
            # clippy and rustfmt belong here, or `cargo clippy` inside the shell
            # picks up whatever driver the host has. A driver built by a
            # different rustc than the one that compiled the dependencies fails
            # the whole tree with E0514.
            clippy
            rustfmt
            clang
            libclang
            pkg-config
            openssl
          ];
          shellHook = ''
            export LIBCLANG_PATH="${pkgs.libclang.lib}/lib"
          '';
        };
      }
    );
}
