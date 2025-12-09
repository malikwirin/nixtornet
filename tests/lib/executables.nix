{ pkgs }:

{
  dig = "${pkgs.dig}/bin/dig";
  dnsmasq = "${pkgs.dnsmasq}/bin/dnsmasq";
  grep = "${pkgs.gnugrep}/bin/grep";
  ip = "${pkgs.iproute2}/bin/ip";
  iptables = "${pkgs.iptables}/bin/iptables";
  journalctl = "${pkgs.systemd}/bin/journalctl";
  killall = "${pkgs.killall}/bin/killall";
  nft = "${pkgs.nftables}/bin/nft";
  ping = "${pkgs.iputils}/bin/ping";
  pkill = "${pkgs.procps}/bin/pkill";
  socat = "${pkgs.socat}/bin/socat";
  ss = "${pkgs.iproute2}/bin/ss";
  systemctl = "${pkgs.systemd}/bin/systemctl";
  tcpdump = "${pkgs.tcpdump}/bin/tcpdump";
  timeout = "${pkgs.coreutils}/bin/timeout";
  udhcpc = "${pkgs.busybox}/bin/udhcpc";
  virsh = "${pkgs.libvirt}/bin/virsh";
  inherit (pkgs.lib) concatMapStringsSep;
}
