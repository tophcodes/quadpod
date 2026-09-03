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
            # The advisory check CI runs. Here rather than installed in the
            # workflow so the version is pinned by flake.lock like every other
            # tool, and so `cargo audit` locally is the same command CI runs.
            cargo-audit
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
