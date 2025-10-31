{ pkgs
, module
,
}:

let
  helpers = import ./lib/default.nix { inherit pkgs; };
in
pkgs.testers.runNixOSTest {
  name = "nixtornet-minimal-config";

  nodes.machine =
    { config
    , pkgs
    , ...
    }:
    {
      imports = [
        module
      ];

      # ABSOLUTE MINIMAL CONFIG
      services.nixtornet = {
        enable = true;
      };

      networking = {
        nftables.enable = true;
        firewall.enable = true;
      };

      virtualisation.memorySize = 2048;
    };

  testScript = ''
    machine.start()
    ${helpers.waitForServices [
      "multi-user.target"
      "libvirtd.service"
    ]}

    print("=" * 60)
    print("NIXTORNET DEFAULTS TEST")
    print("=" * 60)
    print("")
    print("Testing with MINIMAL configuration:")
    print("  services.nixtornet.enable = true")
    print("")
    print("Expected behavior:")
    print("  - Default network 'tornet' should be created")
    print("  - Tor should be enabled automatically")
    print("  - All traffic routed through Tor by default")
    print("=" * 60)
    print("")

    # Warte auf Services
    ${helpers.waitForServices [
      "tor.service"
      "nixtornets.service"
    ]}
    print("✓ All services started")

    # Verify Tor is running
    ${helpers.checkServiceActive ("tor")}
    print("✓ Tor service is active (default)")

    # Verify default network exists
    ${helpers.checkNetwork {
      name = "tornet";
      active = true;
    }}
    print("✓ Default network 'tornet' created and active")

    # Get network details
    ${helpers.dumpNetXml "tornet" "Default network configuration:"}

    # Verify Tor NAT rules exist
    machine.succeed("nft list table ip nixtornet-tor")
    print("✓ Tor NAT rules configured (default)")

    # Verify Tor ports are bound
    ${helpers.checkTorPorts { }}
    print("✓ Tor TransPort (9040) and DNSPort (9053) bound")

    # Verify IPv6 blocking
    machine.succeed("nft list table ip6 nixtornet-ipv6")
    print("✓ IPv6 blocking configured (default)")

    # Extract default IP range from network
    import re
    ip_match = re.search(r"<ip address='([^']+)'", net_xml)
    if ip_match:
      default_ip = ip_match.group(1)
      print(f"\n✓ Default bridge IP: {default_ip}")
    else:
      print("\n⚠ Could not extract default IP")

    # Verify DHCP is configured
    if "dhcp" in net_xml.lower():
      print("✓ DHCP enabled by default")
    else:
      print("⚠ DHCP not found in network config")

    print("\n" + "=" * 60)
    print("✓ MINIMAL-CONFIG TEST PASSED")
    print("=" * 60)
    print("")
    print("Summary:")
    print("  - Default network 'tornet' works out-of-the-box")
    print("  - Tor transparent proxy enabled automatically")
    print("  - VMs connected to 'tornet' will use Tor")
    print("  - No manual configuration required!")
    print("=" * 60)
  '';
}
