{ pkgs
, lib
, module
, useNftables ? true
}:

let
  common = import ./common.nix { inherit pkgs; };
  executables = import ./lib/executables.nix { inherit pkgs; };
  helpers = import ./lib/default.nix { inherit pkgs; };
  shell-scripts = import ./lib/shell-scripts.nix { inherit pkgs; };
  inherit (executables) ip ping udhcpc;
  gatewayIp = "192.168.100.1";
in
pkgs.testers.runNixOSTest {
  name = "nixtornet-dns-connectivity-${if useNftables then "nftables" else "iptables"}";

  nodes.host =
    { config
    , pkgs
    , ...
    }:
    {
      imports = [
        module
      ];

      networking = {
        nftables.enable = useNftables;
        firewall.enable = true;
      };

      services = {
        nixtornet = common.configs.host.services.nixtornet;
        tor.enable = lib.mkForce false;
      };

      # TODO: mock-tor dnsmasq must also listen on bridge IP (192.168.100.1:9053)
      # Currently only listens on 127.0.0.1:9053, but NAT redirect sends
      # packets to the bridge IP. See DNSPort config in modules/nixtornet/config/default.nix
      systemd.services.mock-tor = {
        description = "Mock DNS server on Tor DNSPort";
        wantedBy = [ "multi-user.target" ];
        before = [ "nixtornets.service" ];
        after = [ "network.target" ];

        serviceConfig = {
          Type = "forking";
          ExecStart = shell-scripts.start-mock-tor gatewayIp;
          ExecStop = shell-scripts.stop-mock-tor;
          RemainAfterExit = true;
        };
      };

      systemd.services.tor = {
        description = "Tor Service Alias";
        requires = [ "mock-tor.service" ];
        after = [ "mock-tor.service" ];
        wantedBy = [ "multi-user.target" ];
        serviceConfig.Type = "oneshot";
        serviceConfig.RemainAfterExit = true;
        script = "echo 'Tor DNS mock active'";
      };

      virtualisation = {
        memorySize = 4096;
        cores = 2;
      };
    };

  testScript =
    let
      bridgeName = "virbr-tornet";
      namespace = "dns-test";
      vethHost = "veth-host";
      vethGuest = "veth-guest";
    in
    ''
      import time

      host.start()

      ${helpers.waitForServices [
        "multi-user.target"
        "libvirtd.service"
        "mock-tor.service"
        "nixtornets.service"
      ]}
      print("✓ All services started")

      ${helpers.checkNetwork {
        name = "tornet";
        active = true;
      }}
      print("✓ Tornet network active")

      # Phase 1: Validate Tor DNS mock infrastructure
      ${helpers.validateTorDnsMock {
      }}

      # Phase 2: Validate DNS NAT redirection rules
      ${helpers.validateDnsNatRules {
        inherit useNftables bridgeName;
        table = "ip nixtornet-tor";
      }}

      # Setup guest namespace with DHCP
      print("\n" + "=" * 60)
      print("Guest Namespace Setup")
      print("=" * 60)

      ${helpers.createNetworkNamespace { name = namespace; }}
      ${helpers.createVethPair {
        inherit vethHost vethGuest;
        bridge = bridgeName;
      }}
      ${helpers.moveIfaceToNamespace {
        iface = vethHost;
        inherit namespace;
      }}
      ${helpers.bringUpInterfaces {
        inherit namespace;
        hostIface = vethGuest;
        guestIface = vethHost;
      }}
      print("✓ Namespace and veth pair configured")

      # Obtain DHCP lease
      print("\nObtaining DHCP lease...")
      host.succeed("${ip} netns exec ${namespace} timeout 10 ${udhcpc} -i ${vethHost} -n -q -T 5 -t 6 -A 3")
      print("✓ DHCP lease obtained")

      ${helpers.hasIPv4InNamespace {
        inherit namespace;
        iface = vethHost;
      }}

      # Verify gateway reachability
      print("\nVerifying gateway reachability...")
      host.succeed("${ip} netns exec ${namespace} ${ping} -c 1 -W 2 ${gatewayIp}")
      print("✓ Gateway reachable")

      # Phase 3: DNS flow test with packet capture
      ${helpers.testDnsFlowWithCapture {
        inherit namespace bridgeName useNftables;
      }}

      # Phase 4: Check Tor DNS server logs
      ${helpers.checkTorDnsLogs {
      }}

      # Cleanup
      print("\n" + "=" * 60)
      print("Cleanup")
      print("=" * 60)
      host.succeed("${ip} netns del ${namespace} || true")
      print("✓ Namespace removed")
    '';
}
