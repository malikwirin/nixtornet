{ NixVirt }:

{
  default = import ./nixtornet/default.nix { inherit NixVirt; };
}
