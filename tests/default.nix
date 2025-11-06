{ pkgs
, lib
, NixVirt
, module
}:
let
  helpers = import ./lib/default.nix { inherit pkgs; };
  makeTest =
    { useNftables }:
    pkgs.testers.runNixOSTest {
      name = "nixtornet-${if useNftables then "nftables" else "iptables"}";

      nodes.machine =
        { config, pkgs, ... }:
        {
          imports = [ module ];

          networking = {
            firewall.enable = true;
            nftables.enable = useNftables;
          };

          services.nixtornet = {
            enable = true;
            tor = {
              enable = true;
              networks = [ "test-net" ];
            };
            networks.test-net = {
              name = "test-net";
              uuid = "12345678-1234-1234-1234-123456789abc";
              ip = {
                address = "192.168.100.1";
                netmask = "255.255.255.0";
                dhcp = {
                  range = {
                    start = "192.168.100.2";
                    end = "192.168.100.254";
                  };
                };
              };
            };
          };

          virtualisation.memorySize = 2048;
          virtualisation.cores = 2;
        };

      testScript = ''
        machine.start()

        ${helpers.waitForServices [
          "multi-user.target"
          "tor.service"
          "libvirtd.service"
        ]}

        # check net existance
        ${helpers.checkNetwork { name = "test-net"; }}

        ${helpers.checkServiceActive "tor.service"}

        ${helpers.checkTorPorts { }}

        ${
          if useNftables then
            ''
              # nftables specific tests
              # check existence of nftables Tor-Proxy-Table
              machine.succeed("nft list table ip nixtornet-tor")

              # check redirect configuration
              machine.succeed("nft list table ip nixtornet-tor | grep 'redirect to :9040'")
              machine.succeed("nft list table ip nixtornet-tor | grep 'redirect to :9053'")

              # check IPv6-Blocking-Table
              machine.succeed("nft list table ip6 nixtornet-ipv6")
              machine.succeed("nft list table ip6 nixtornet-ipv6 | grep 'virbr-test-net'")

              print("✓ All tests passed (nftables backend)!")
            ''
          else
            ''
              # iptables specific Tests
              # Test NAT-Rules
              machine.succeed("iptables -t nat -L PREROUTING | grep 9040")

              machine.succeed("${pkgs.iptables}/bin/iptables-save -t nat | grep virbr-test")
              machine.succeed("${pkgs.iptables}/bin/iptables-save -t nat | grep 'virbr-test.*tcp.*--to-ports 9040'")
              machine.succeed("${pkgs.iptables}/bin/iptables-save -t nat | grep 'virbr-test.*udp.*dport 53.*--to-ports 9053'")

              print("✓ All tests passed (iptables backend)!")
            ''
        }
      '';
    };

  tests = {
    iptables = makeTest { useNftables = false; };
    nftables = makeTest { useNftables = true; };
    tor-routing-e2e = import ./tor-routing-e2e.nix { inherit lib module pkgs; };
    minimal-config = import ./minimal-config.nix { inherit module pkgs; };
    dhcp-connectivity-iptables = import ./dhcp-connectivity.nix { inherit lib module pkgs; useNftables = false; };
    dhcp-connectivity-nftables = import ./dhcp-connectivity.nix { inherit lib module pkgs; useNftables = true; };
  };
in
tests
  // {
  all =
    pkgs.runCommand "nixtornet-all-tests"
      {
        nativeBuildInputs = [ pkgs.coreutils ];
      }
      ''
        echo "Running all nixtornet tests..."

        test -e ${tests.iptables}
        test -e ${tests.nftables}
        test -e ${tests.tor-routing-e2e}
        test -e ${tests.minimal-config}
        test -e ${tests.dhcp-connectivity-iptables}
        test -e ${tests.dhcp-connectivity-nftables}

        echo "✓ All nixtornet tests passed"
        mkdir -p $out

        ln -s ${tests.iptables} $out/iptables
        ln -s ${tests.nftables} $out/nftables
        ln -s ${tests.tor-routing-e2e} $out/tor-routing-e2e
        ln -s ${tests.minimal-config} $out/minimal-config
        ln -s ${tests.dhcp-connectivity-iptables} $out/dhcp-connectivity-iptables
        ln -s ${tests.dhcp-connectivity-nftables} $out/dhcp-connectivity-nftables
      '';
}
