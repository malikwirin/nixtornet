{ lib
, ...
}:

with lib;

let
  default-net = {
    tornet = {
      name = "tornet";
      uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"; # TODO: # Generate UUID from network name

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

      forward = {
        mode = "nat";
      };
      active = true;
    };
  };
in
{
  options.services.nixtornet = {
    enable = mkEnableOption "Tor-integrated libvirt network management";

    networks = mkOption {
      default = default-net;
      type = types.attrsOf (
        types.submodule (
          { name, config, ... }:
          {
            options = {
              name = mkOption {
                type = types.str;
                default = name;
                description = "Network name";
                example = "tor-dev";
              };

              uuid = mkOption {
                type = types.str;
                description = ''
                  Network UUID (generate with: uuidgen)

                  Example: 12345678-1234-1234-1234-123456789abc
                '';
                example = "a1b2c3d4-1234-5678-90ab-cdef12345678";
              };

              forward = mkOption {
                type = types.submodule {
                  options = {
                    mode = mkOption {
                      type = types.enum [
                        "nat"
                        "none"
                        "route"
                        "bridge"
                      ];
                      default = default-net.tornet.forward.mode;
                      description = "Forward mode";
                    };
                  };
                };
                default = default-net.tornet.forward;
                description = "Network forwarding configuration";
              };

              bridge = mkOption {
                type = types.submodule {
                  options = {
                    name = mkOption {
                      type = types.str;
                      default = "virbr-${config.name}";
                      defaultText = literalExpression ''"virbr-''${config.name}"'';
                      description = "Bridge interface name (auto-generated from network name by default)";
                      example = "virbr-tor";
                    };
                    stp = mkOption {
                      type = types.bool;
                      default = true;
                      description = "Enable Spanning Tree Protocol";
                    };
                    delay = mkOption {
                      type = types.int;
                      default = 0;
                      description = "Bridge delay in seconds";
                    };
                  };
                };
                default = { };
                description = "Bridge configuration";
              };

              ip = mkOption {
                description = "IP address configuration";
                default = default-net.tornet.ip;
                type = types.submodule {
                  options = {
                    address = mkOption {
                      type = types.str;
                      default = default-net.tornet.ip.address;
                      description = "Gateway IP address";
                      example = "192.168.100.1";
                    };
                    netmask = mkOption {
                      type = types.str;
                      default = default-net.tornet.ip.netmask;
                      description = "Network netmask (defaults to /24 network)";
                    };
                    dhcp = mkOption {
                      default = default-net.tornet.ip.dhcp;
                      type = types.nullOr (
                        types.submodule {
                          options = {
                            range = mkOption {
                              type = types.submodule {
                                options = {
                                  start = mkOption {
                                    type = types.str;
                                    description = "DHCP range start address";
                                    example = "192.168.100.2";
                                  };
                                  end = mkOption {
                                    type = types.str;
                                    description = "DHCP range end address";
                                    example = "192.168.100.254";
                                  };
                                };
                              };
                              description = "DHCP address range";
                            };
                          };
                        }
                      );
                      description = ''
                        DHCP configuration (optional).
                        If null, no DHCP server will be configured for this network.
                      '';
                      example = {
                        range = {
                          start = "192.168.100.2";
                          end = "192.168.100.254";
                        };
                      };
                    };
                  };
                };
              };

              isolation = mkOption {
                type = types.submodule {
                  options = {
                    enable = mkOption {
                      type = types.bool;
                      default = false;
                      description = "Enable network isolation";
                    };

                    cidrBits = mkOption {
                      type = types.int;
                      default = 24;
                      description = "CIDR bits for isolation rules";
                    };

                    blockHTTP = mkOption {
                      type = types.bool;
                      default = true;
                      description = "Block HTTP/HTTPS traffic";
                    };

                    blockDNS = mkOption {
                      type = types.bool;
                      default = true;
                      description = "Block DNS traffic";
                    };

                    allowedPorts = mkOption {
                      type = types.listOf types.int;
                      default = [ ];
                      description = "List of allowed TCP ports to gateway";
                    };
                  };
                };
                default = { };
              };

              active = mkOption {
                type = types.bool;
                default = true;
                description = "Whether to activate the network";
              };
            };
          }
        )
      );
      description = "Libvirt networks configuration";
    };

    tor = mkOption {
      default = { };
      type = types.submodule {
        options = {
          enable = mkOption {
            type = types.bool;
            default = true;
            description = ''
              Enable Tor integration for selected networks.

              This will configure the necessary Tor settings for transparent proxying.
              Configure Tor itself using {option}`services.tor.settings`.
            '';
          };

          networks = mkOption {
            type = types.listOf types.str;
            default = [ default-net.tornet.name ];
            description = "List of networks that should use Tor (by name)";
            example = [
              "tor-dev"
              "tor-prod"
            ];
          };
        };
      };
    };

    libvirt = mkOption {
      type = types.submodule {
        options = {
          connection = mkOption {
            type = types.str;
            default = "qemu:///system";
            description = "Libvirt connection URI";
          };
        };
      };
      default = { };
    };

    _internalDebugTrace = mkOption {
      type = types.bool;
      default = false;
      description = "Internal option to enable verbose nftables tracing for tests.";
    };
  };
}
