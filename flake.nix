{
  description = "Nixtornet";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    NixVirt = {
      url = "https://flakehub.com/f/AshleyYakeley/NixVirt/*.tar.gz";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    systems.url = "github:nix-systems/x86_64-linux"; # currently only support x86_64-linux because of NixVirt
    flake-utils = {
      url = "github:numtide/flake-utils";
      inputs.systems.follows = "systems";
    };

    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, treefmt-nix, NixVirt, ... }:
    let
      modules = import ./modules { inherit NixVirt; };
    in
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = import nixpkgs {
            inherit system;
          };
          lib = pkgs.lib;
          treefmt = treefmt-nix.lib.evalModule pkgs {
            projectRootFile = "flake.nix";
            programs = {
              nixpkgs-fmt.enable = true;
            };
          };
        in
        {
          formatter = treefmt.config.build.wrapper;
          checks = lib.recurseIntoAttrs (
            import tests/default.nix {
              inherit pkgs lib NixVirt;
              module = self.nixosModules.default;
            }
          );

          packages = {
            checks = self.checks.${system};
          };
        }) // {
      nixosModules.default = modules.default;
    };
}
