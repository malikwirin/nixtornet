{ pkgs
, lib
, module
, useNftables ? true
}:

let
  helpers = import ./lib/default.nix { inherit pkgs; };
in
pkgs.testers.runNixOSTest {
  name = "nixtornet-dhcp-connectivity-${if useNftables then "nftables" else "iptables"}";

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

      services.nixtornet = {
        enable = true;
        tor.enable = true;
        tor.networks = [ "tornet" ];

        networks.tornet = {
          name = "tornet";
          uuid = "12345678-abcd-1234-abcd-123456789abc";

          ip = {
            address = "192.168.100.1";
            netmask = "255.255.255.0";
            dhcp = {
              range = {
                start = "192.168.100.10";
                end = "192.168.100.100";
              };
            };
          };
        };
      };

      services.tor.enable = lib.mkForce false;

      systemd.services.mock-tor = {
        description = "Mock Tor for DHCP test";
        wantedBy = [ "multi-user.target" ];
        before = [ "nixtornets.service" ];
        after = [ "network.target" ];

        serviceConfig = {
          Type = "forking";
          ExecStart = pkgs.writeShellScript "start-mock-tor" ''
            ${pkgs.socat}/bin/socat \
              TCP-LISTEN:9040,bind=127.0.0.1,fork,reuseaddr \
              SYSTEM:'echo "Mock Tor TransPort"' &

            ${pkgs.socat}/bin/socat \
              UDP-LISTEN:9053,bind=0.0.0.0,fork,reuseaddr \
              SYSTEM:'echo "Mock Tor DNSPort"' &

            echo $! > /run/mock-tor.pid
          '';
          ExecStop = pkgs.writeShellScript "stop-mock-tor" ''
            if [ -f /run/mock-tor.pid ]; then
              kill $(cat /run/mock-tor.pid) 2>/dev/null || true
              rm /run/mock-tor.pid
            fi
            pkill -f "socat.*9040" || true
            pkill -f "socat.*9053" || true
          '';
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
        script = "echo 'Tor alias active'";
      };

      virtualisation = {
        memorySize = 4096;
        cores = 2;
      };
    };

  testScript =
    let
      bridgeName = "virbr-tornet";
      namespace = "dhcp-test";
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

      # === INFRASTRUCTURE SETUP ===
      print("\n" + "=" * 60)
      print("DHCP CONNECTIVITY TEST")
      print("=" * 60)
      print("")
      print("Setup: Creating network namespace simulating VM...")
      print("")

      # Verify bridge exists
      ${helpers.checkNetwork {
        name = "tornet";
        active = true;
      }}
      print("✓ Tornet network active")

      host.succeed("ip link show ${bridgeName}")
      print("✓ Bridge ${bridgeName} exists")

      # Verify dnsmasq running
      host.succeed("ps aux | grep -i dnsmasq | grep -v grep")
      print("✓ dnsmasq DHCP server running")

      # === CREATE NAMESPACE WITH VETH ===
      print("\nCreating network namespace to simulate VM...")

      ${helpers.createNetworkNamespace { name = namespace; }}
      print("✓ Namespace 'dhcp-test' created")

      ${helpers.createVethPair {
        vethHost = "veth-host";
        vethGuest = "veth-guest";
        bridge = bridgeName;
      }}
      print("✓ veth pair created and connected to bridge")

      ${helpers.moveIfaceToNamespace {
        iface = "veth-host";
        inherit namespace;
      }}
      print("✓ veth-host moved to namespace")

      ${helpers.bringUpInterfaces {
        inherit namespace;
        hostIface = "veth-guest";
        guestIface = "veth-host";
      }}
      print("✓ Interfaces brought up")

      # === ANALYZE BASELINE COUNTERS ===
      print("\n" + "-" * 60)
      print("BASELINE: Packet counters BEFORE DHCP attempt")
      print("-" * 60)
      ${helpers.analyzeFirewallCounters {
        table = "ip nixtornet-tor";
        chain = "LIBVIRT_FWO";
        inherit useNftables bridgeName;
      }}

      ${helpers.attemptDhcpAndAnalyzeCounters {
        iface = "veth-host";
        inherit useNftables bridgeName namespace;
        table = "ip nixtornet-tor";
        chain = "LIBVIRT_FWO";
      }}

      # === CHECK RESULTS ===
      print("\n" + "-" * 60)
      print("IPv4 Address Check")
      print("-" * 60)

      ${helpers.hasIPv4InNamespace {
        inherit namespace;
        iface = "veth-host";
      }}

      ${helpers.analyzeFirewallState {
        inherit useNftables bridgeName;
        table = "ip nixtornet-tor";
        chain = "LIBVIRT_FWO";
      }}

      # === DHCP LOGS ===
      print("\n" + "-" * 60)
      print("DHCP Client Logs")
      print("-" * 60)
      dhcp_logs_result = host.execute("cat /tmp/dhcp-result.txt")
      if dhcp_logs_result[0] == 0:
        print(f"\n{dhcp_logs_result[1]}")
      else:
        print("(No DHCP logs found)")

      # === SUMMARY ===
      print("\n" + "=" * 60)
      print("SUMMARY: DHCP Connectivity Test")
      print("=" * 60)
      print("")
      print("This test reproduces the DHCP bug in Nixtornet:")
      print("")
      print("Expected behavior (after fix):")
      print("  ✓ udhcpc should obtain IP from range 192.168.100.10-100")
      print("  ✓ veth-host should show 'inet 192.168.100.X/24'")
      print("  ✓ Packet counters increase in ACCEPT rules, not REJECT")
      print("")
      print("Current behavior (with bug):")
      print("  ✗ udhcpc times out waiting for DHCP reply")
      print("  ✗ veth-host has only IPv6 link-local (fe80::...)")
      print("  ✗ Packet counters increase in REJECT rules")
      print("  ✗ nftables rejects UDP 67/68 packets")
      print("")
      print("Root cause:")
      print("  The firewall's FORWARD chain rejects all traffic except:")
      print("    - TCP to port 9040 (Tor TransPort)")
      print("    - UDP to port 53 (Tor DNSPort)")
      print("    - Established/related connections")
      print("")
      print("  DHCP-DISCOVER packets (UDP 67/68 broadcast from VM)")
      print("  don't match any of these conditions")
      print("  → Gets rejected by the final 'reject' rule")
      print("")
      print("  Fix: Add explicit DHCP exception rule before reject")
      print("")
      print("=" * 60)

      # Cleanup
      host.succeed("ip netns del dhcp-test || true")
    '';
}
