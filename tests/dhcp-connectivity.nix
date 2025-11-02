{ pkgs
, lib
, module
}:

let
  helpers = import ./lib/default.nix { inherit pkgs; };
in
pkgs.testers.runNixOSTest {
  name = "nixtornet-dhcp-connectivity";

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
        nftables.enable = true;
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

  testScript = let bridgeName = "virbr-tornet"; nft = "${pkgs.nftables}/bin/nft"; in ''
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

    ${helpers.createNetworkNamespace { name = "dhcp-test"; }}
    print("✓ Namespace 'dhcp-test' created")

    ${helpers.createVethPair {
      vethHost = "veth-host";
      vethGuest = "veth-guest";
      bridge = bridgeName;
    }}
    print("✓ veth pair created and connected to bridge")

    ${helpers.moveIfaceToNamespace {
      iface = "veth-host";
      namespace = "dhcp-test";
    }}
    print("✓ veth-host moved to namespace")

    ${helpers.bringUpInterfaces {
      namespace = "dhcp-test";
      hostIface = "veth-guest";
      guestIface = "veth-host";
    }}
    print("✓ Interfaces brought up")

    # === ANALYZE BASELINE COUNTERS ===
    print("\n" + "-" * 60)
    print("BASELINE: Packet counters BEFORE DHCP attempt")
    print("-" * 60)
    ${helpers.analyzeNftablesCounters {
      table = "ip nixtornet-tor";
      chain = "LIBVIRT_FWO";
      rulePattern = "${bridgeName}";
    }}

    # === ATTEMPT DHCP ===
    print("\n" + "-" * 60)
    print("TEST: Attempting to get IPv4 via DHCP...")
    print("-" * 60)

    # Start DHCP client in namespace (will likely timeout/fail due to bug)
    host.succeed("ip netns exec dhcp-test timeout 10 udhcpc -i veth-host -n -q -T 5 -t 3 2>&1 | tee /tmp/dhcp-result.txt || true")
    print("DHCP client attempt finished")

    time.sleep(1)

    # === ANALYZE COUNTERS AFTER DHCP ===
    print("\n" + "-" * 60)
    print("AFTER DHCP: Packet counters AFTER DHCP attempt")
    print("-" * 60)
    ${helpers.analyzeNftablesCounters {
      table = "ip nixtornet-tor";
      chain = "LIBVIRT_FWO";
      rulePattern = "${bridgeName}";
    }}

    # === CHECK RESULTS ===
    print("\n" + "-" * 60)
    print("IPv4 Address Check")
    print("-" * 60)

    ${helpers.hasIPv4InNamespace {
      namespace = "dhcp-test";
      iface = "veth-host";
    }}

    # === FIREWALL ANALYSIS ===
    print("\n" + "-" * 60)
    print("FIREWALL ANALYSIS: nftables rules inspection")
    print("-" * 60)

    # Dump the nixtornet-tor table for inspection
    nixtornet_tor_table = host.succeed("${nft} list table ip nixtornet-tor")
    print(f"\nComplete nixtornet-tor table:\n{nixtornet_tor_table}")

    # Check for existing DHCP exception rules
    dhcp_check_result = host.execute("${nft} list table ip nixtornet-tor | grep -E 'dport 67|dport 68|dhcp'")
    if dhcp_check_result[0] == 0:
      print("\n✓ DHCP exception rules found in nftables")
      print(f"  {dhcp_check_result[1]}")
    else:
      print("\n✗ NO DHCP exception rules found in nftables")
      print("  This explains why DHCP fails!")

    # Inspect the specific LIBVIRT_FWO chain
    fwo_chain = host.succeed("${nft} list chain ip nixtornet-tor LIBVIRT_FWO")
    print(f"\nnixtornet-tor forward chain (where packets get rejected):\n{fwo_chain}")

    # Check Nixtornet's own Tor proxy rules
    nixtornet_tor = host.succeed("${nft} list table ip nixtornet-tor")
    print(f"\nNixtornet Tor proxy table:\n{nixtornet_tor}")

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
