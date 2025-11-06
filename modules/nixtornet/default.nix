{ NixVirt }: { config, lib, pkgs, ... }: {
  _module.args.nixvirt-lib = NixVirt.lib;
  imports = [
    NixVirt.nixosModules.default
    ./config
    ./options.nix
  ];
}
