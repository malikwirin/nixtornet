{ config
, lib
, nixvirt-lib
, pkgs
, ...
}:

with lib;
let
  cfg = config.services.nixtornet;
  torCfg = config.services.tor;

  # Import helpers
  helpers = import ./lib.nix { inherit lib; };

  # Backend detection
  useNftables = config.networking.nftables.enable;

  # Select backend
  backend = if useNftables then helpers.backends.nftables else helpers.backends.iptables;

  # Filtered network lists
  torNetworks = filter (net: elem net.name cfg.tor.networks) (attrValues cfg.networks);
  isolatedNetworks = filter (net: net.isolation.enable) (attrValues cfg.networks);

  # Get actual Tor ports from configuration
  torTransPort = helpers.extractPort torCfg.settings.TransPort;
  torDnsPort = helpers.extractPort torCfg.settings.DNSPort;
  ss = "${pkgs.iproute2}/bin/ss";
in
{
  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.tor.enable -> config.networking.firewall.enable;
        message = ''
          Tor-libvirt-network requires the firewall to be enabled for transparent proxying.
          Please set: networking.firewall.enable = true;
        '';
      }
      {
        assertion =
          cfg.tor.enable && (length cfg.tor.networks > 0) -> (torCfg.settings.AutomapHostsOnResolve or false);
        message = ''
          Transparent DNS proxying for Tor requires AutomapHostsOnResolve to be enabled.
          This is automatically configured but may have been overridden.
        '';
      }
      {
        assertion = cfg.tor.enable -> (torTransPort != null);
        message = ''
          Could not extract Tor TransPort from services.tor.settings.TransPort.

          Current value: ${toString torCfg.settings.TransPort}

          Please ensure services.tor.settings.TransPort is properly configured.
          Expected formats:
            - Integer: 9040
            - Attrset: { addr = "127.0.0.1"; port = 9040; }
            - List: [{ addr = "127.0.0.1"; port = 9040; }]
        '';
      }
      {
        assertion = cfg.tor.enable -> (torDnsPort != null);
        message = ''
          Could not extract Tor DNSPort from services.tor.settings.DNSPort.

          Current value: ${toString torCfg.settings.DNSPort}

          Please ensure services.tor.settings.DNSPort is properly configured.
          Expected formats:
            - Integer: 9053
            - Attrset: { addr = "0.0.0.0"; port = 9053; }
            - List: [{ addr = "0.0.0.0"; port = 9053; }]
        '';
      }
    ];

    # Enable IP forwarding
    boot.kernel.sysctl = {
      "net.ipv4.ip_forward" = 1;
    }
    // optionalAttrs cfg.tor.enable (
      # deactivate ipv6 on tor networks
      listToAttrs (
        flatten (
          map
            (networkCfg: [
              (nameValuePair "net.ipv6.conf.${networkCfg.bridge.name}.disable_ipv6" (
                if elem networkCfg.name cfg.tor.networks then 1 else 0
              ))
              (nameValuePair "net.ipv6.conf.${networkCfg.bridge.name}.autoconf" 0)
            ])
            (attrValues cfg.networks)
        )
      )
    );

    # Configure Tor if enabled
    services.tor = mkIf cfg.tor.enable {
      enable = mkDefault true;
      client.enable = mkDefault true;
      settings = {
        # Tor's default virtual address network range for .onion addresses.
        # This range is used internally by Tor and does not conflict with real IPs.
        # See: https://spec.torproject.org/address-spec.html
        VirtualAddrNetworkIPv4 = mkDefault "10.192.0.0/10"; # FIXME: add source to this specific range

        # Automatically map .onion addresses to virtual IPs when resolving.
        # Required for transparent DNS proxying to correctly handle onion services.
        # See: https://2019.www.torproject.org/docs/tor-manual.html.en#AutomapHostsOnResolve
        AutomapHostsOnResolve = mkDefault true;

        TransPort = mkDefault {
          addr = "127.0.0.1";
          port = 9040;
        };

        # DNSPort für transparent DNS
        DNSPort = mkDefault {
          addr = "0.0.0.0";
          port = 9053;
        };
      };
    };

    virtualisation.libvirt = {
      enable = true;

      # Configure libvirt networks using NixVirt
      connections.${cfg.libvirt.connection} = {
        networks = mapAttrsToList
          (name: networkCfg: {
            # Use NixVirt's writeXML function with the proper structure
            definition = nixvirt-lib.network.writeXML (helpers.mkNetworkDefinition networkCfg);
            active = networkCfg.active;
          })
          cfg.networks;
      };
    };

    # Configure firewall rules for Tor and isolation
    networking = {
      nftables = mkIf useNftables {
        tables = {
          # Tor transparent proxy table
          nixtornet-tor = mkIf (cfg.tor.enable && length torNetworks > 0) (
            backend.mkTorProxyTable cfg torTransPort torDnsPort torNetworks
          );

          # Network isolation table
          nixtornet-isolation = mkIf (length isolatedNetworks > 0) (
            backend.mkIsolationTable isolatedNetworks
          );

          # IPv6 blocking table
          nixtornet-ipv6 = mkIf (cfg.tor.enable && length torNetworks > 0) (
            backend.mkIPv6BlockTable torNetworks
          );
        };
      };

      firewall = mkIf (!useNftables) {
        # Custom iptables rules
        extraCommands = ''
          # Tor transparent proxy rules
          ${concatStringsSep "\n" (
            mapAttrsToList (
              name: networkCfg: backend.mkTorProxyRules cfg torTransPort torDnsPort networkCfg
            ) cfg.networks
          )}
              
          # Network isolation rules
          ${concatStringsSep "\n" (
            mapAttrsToList (name: networkCfg: backend.mkIsolationRules networkCfg) cfg.networks
          )}

          # IPv6 für Tor-Netzwerke blockieren
          ${concatStringsSep "\n" (
            map (
              networkCfg:
              optionalString (elem networkCfg.name cfg.tor.networks) (backend.mkIPv6BlockRules pkgs networkCfg)
            ) (attrValues cfg.networks)
          )}
        '';

        extraStopCommands = ''
          # Cleanup Tor rules
          ${concatStringsSep "\n" (
            mapAttrsToList (
              name: networkCfg: backend.mkTorCleanupRules torTransPort torDnsPort networkCfg
            ) cfg.networks
          )}

          # Cleanup isolation rules
          ${concatStringsSep "\n" (
            mapAttrsToList (name: networkCfg: backend.mkIsolationCleanupRules networkCfg) cfg.networks
          )}

          # Cleanup IPv6 rules
          ${concatStringsSep "\n" (
            map (
              networkCfg:
              optionalString (elem networkCfg.name cfg.tor.networks) (backend.mkIPv6BlockCleanupRules networkCfg)
            ) (attrValues cfg.networks)
          )}
        '';
      };
    };

    systemd.services = {
      # Create systemd service for network management
      nixtornets = mkIf cfg.tor.enable {
        description = "Tor-integrated libvirt network manager";

        after = [
          "tor.service"
          "libvirtd.service"
          "firewall.service"
        ];

        requires = [
          "tor.service"
          "libvirtd.service"
        ];

        wantedBy = [ "multi-user.target" ];
        restartIfChanged = true;

        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;

          ExecStart =
            let
              transPort = (toString torTransPort);
            in
            pkgs.writeShellScript "start-tor-networks" ''
              set -e

              echo "Verifying Tor-libvirt network integration..."

              sleep 2

              # verify TransPort
              if ! ${ss} -tln | ${pkgs.gnugrep}/bin/grep -q ":${transPort}"; then
                echo "ERROR: Tor TransPort (${transPort}) not bound"
                ${ss} -tln | ${pkgs.gnugrep}/bin/grep tor || echo "No Tor ports found"
                exit 1
              fi
              echo "✓ Tor TransPort (${transPort}) is bound"

              # verify DNSPort
              if ! ${ss} -uln | ${pkgs.gnugrep}/bin/grep -q ":${toString torDnsPort}"; then
                echo "ERROR: Tor DNSPort (${toString torDnsPort}) not bound"
                exit 1
              fi
              echo "✓ Tor DNSPort (${toString torDnsPort}) is bound"

              # verify NAT-Rules (backend-agnostic via iptables-save/nft)
              ${
                if useNftables then
                  ''
                    # Verify nftables rules
                    if ! ${pkgs.nftables}/bin/nft list table ip nixtornet-tor >/dev/null 2>&1; then
                      echo "ERROR: nftables Tor proxy table not found"
                      exit 1
                    fi
                    echo "✓ nftables Tor proxy rules verified"
                  ''
                else
                  ''
                    # Verify iptables rules
                    ${concatStringsSep "\n" (
                      map (
                        networkCfg:
                        optionalString (elem networkCfg.name cfg.tor.networks) ''
                          if ! ${config.networking.firewall.package}/bin/iptables -t nat -C PREROUTING -i ${networkCfg.bridge.name} -p tcp --syn -j REDIRECT --to-ports ${transPort} 2>/dev/null; then
                            echo "ERROR: NAT rule for ${networkCfg.bridge.name} not found"
                            exit 1
                          fi
                          echo "✓ NAT rules for ${networkCfg.bridge.name} verified"
                        ''
                      ) (attrValues cfg.networks)
                    )}
                  ''
              }

              echo "✓ Tor-libvirt integration verified successfully"
            '';

          ExecStop = pkgs.writeShellScript "stop-tor-networks" ''
            echo "Stopping Tor-libvirt network integration..."
          '';
        };
      };

      # Add monitoring and logging
      nixtornet-monitor = mkIf cfg.tor.enable {
        description = "Monitor Tor-libvirt network traffic";
        after = [ "nixtornets.service" ];
        wants = [ "nixtornets.service" ];
        wantedBy = [ "multi-user.target" ];

        serviceConfig = {
          Type = "simple";
          Restart = "always";
          RestartSec = "60";

          ExecStart = pkgs.writeShellScript "monitor-tor-networks" ''
            set -e

            while true; do
              # Check Tor connection count
              TOR_CONNECTIONS=$(${ss} -tn 2>/dev/null | ${pkgs.gnugrep}/bin/grep -c ":${toString torTransPort}" || true)
              
              if [ "$TOR_CONNECTIONS" -gt 50 ]; then
                echo "WARNING: High number of Tor connections: $TOR_CONNECTIONS"
              fi
              
              # Log to journal
              echo "Tor connections: $TOR_CONNECTIONS" | ${config.systemd.package}/bin/systemd-cat -t nixtornet-monitor
              
              sleep 60
            done
          '';
        };
      };
    };
  };
}
