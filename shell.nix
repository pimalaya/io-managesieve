{
  nixpkgs ? <nixpkgs>,
  system ? builtins.currentSystem,
  pkgs ? import nixpkgs { inherit system; },
  pimalaya ? import (fetchTarball "https://github.com/pimalaya/nix/archive/master.tar.gz"),
  fenix ? import (fetchTarball "https://github.com/nix-community/fenix/archive/monthly.tar.gz") { },
}:

let
  inherit (pkgs)
    cargo-deny
    cargo-tarpaulin
    openssl
    pkg-config
    ;

  shell = pimalaya.mkShell {
    inherit
      nixpkgs
      system
      pkgs
      fenix
      ;
  };

in
shell.overrideAttrs (prev: {
  LD_LIBRARY_PATH = "${prev.LD_LIBRARY_PATH or ""}:" + (pkgs.lib.makeLibraryPath [
    openssl
  ]);

  nativeBuildInputs = (prev.nativeBuildInputs or [ ]) ++ [
    pkg-config
  ];

  buildInputs = (prev.buildInputs or [ ]) ++ [
    cargo-deny
    cargo-tarpaulin
    openssl
  ];
})
