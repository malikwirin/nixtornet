{ pkgs }:

{
  grep = "${pkgs.gnugrep}/bin/grep";
  ip = "${pkgs.iproute2}/bin/ip";
  iptables = "${pkgs.iptables}/bin/iptables";
  nft = "${pkgs.nftables}/bin/nft";
  ss = "${pkgs.iproute2}/bin/ss";
  systemctl = "${pkgs.systemd}/bin/systemctl";
  udhcpc = "${pkgs.busybox}/bin/udhcpc";
  virsh = "${pkgs.libvirt}/bin/virsh";
  inherit (pkgs.lib) concatMapStringsSep;
}
