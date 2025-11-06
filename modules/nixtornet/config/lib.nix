{ lib }:

with lib;
{
  extractPort =
    setting:
    if setting == null then
      null
    else if isInt setting then
      setting
    else if isAttrs setting then
      setting.port or null
    else if isList setting && length setting > 0 then
      extractPort (head setting)
    else
      null;

  # Helper function to create a network definition from our config
  mkNetworkDefinition = networkCfg: {
    inherit (networkCfg) name uuid forward;
    bridge = {
      inherit (networkCfg.bridge) name stp delay;
    };
    ip = {
      inherit (networkCfg.ip) address netmask;
    }
    // optionalAttrs (networkCfg.ip.dhcp != null) {
      dhcp = {
        range = {
          inherit (networkCfg.ip.dhcp.range) start end;
        };
      };
    };
  };

  backends = {
    iptables = {
      # Generate iptables rules for network isolation
      mkIsolationRules =
        networkCfg:
        let
          ipAddress = networkCfg.ip.address;
          bridgeName = networkCfg.bridge.name;
          cidrBits = toString networkCfg.isolation.cidrBits;
        in
        optionalString networkCfg.isolation.enable ''
          # Block direct internet access for ${networkCfg.name}
          ${optionalString networkCfg.isolation.blockHTTP ''
            iptables -I FORWARD -i ${bridgeName} -p tcp --dport 80 -j DROP
            iptables -I FORWARD -i ${bridgeName} -p tcp --dport 443 -j DROP
          ''}

          ${optionalString networkCfg.isolation.blockDNS ''
            iptables -I FORWARD -i ${bridgeName} -p udp --dport 53 -j DROP
          ''}

          # Allow specified services
          ${concatStringsSep "\n" (
            map (
              port:
              "iptables -I FORWARD -i ${bridgeName} -d ${ipAddress} -p tcp --dport ${toString port} -j ACCEPT"
            ) networkCfg.isolation.allowedPorts
          )}

          # Allow internal network communication
          iptables -I FORWARD -i ${bridgeName} -d ${ipAddress}/${cidrBits} -j ACCEPT
        '';

      # Generate cleanup rules for isolation
      mkIsolationCleanupRules =
        networkCfg:
        let
          ipAddress = networkCfg.ip.address;
          bridgeName = networkCfg.bridge.name;
          cidrBits = toString networkCfg.isolation.cidrBits;
        in
        optionalString networkCfg.isolation.enable ''
          ${optionalString networkCfg.isolation.blockHTTP ''
            iptables -D FORWARD -i ${bridgeName} -p tcp --dport 80 -j DROP 2>/dev/null || true
            iptables -D FORWARD -i ${bridgeName} -p tcp --dport 443 -j DROP 2>/dev/null || true
          ''}

          ${optionalString networkCfg.isolation.blockDNS ''
            iptables -D FORWARD -i ${bridgeName} -p udp --dport 53 -j DROP 2>/dev/null || true
          ''}

          ${concatStringsSep "\n" (
            map (
              port:
              "iptables -D FORWARD -i ${bridgeName} -d ${ipAddress} -p tcp --dport ${toString port} -j ACCEPT 2>/dev/null || true"
            ) networkCfg.isolation.allowedPorts
          )}

          iptables -D FORWARD -i ${bridgeName} -d ${ipAddress}/${cidrBits} -j ACCEPT 2>/dev/null || true
        '';

      # Generate iptables rules for Tor transparent proxy
      mkTorProxyRules =
        cfg: torTransPort: torDnsPort: networkCfg:
        let
          gatewayAddress = networkCfg.ip.address;
          bridgeName = networkCfg.bridge.name;
        in
        optionalString (elem networkCfg.name cfg.tor.networks) ''
          # Transparent proxy for TCP traffic
          iptables -t nat -A PREROUTING -i ${bridgeName} -p tcp --syn -j REDIRECT --to-ports ${toString torTransPort}

          # DNS redirection to Tor
          iptables -t nat -A PREROUTING -i ${bridgeName} -p udp --dport 53 -j REDIRECT --to-ports ${toString torDnsPort}

          # Allow forwarding for established connections
          iptables -A FORWARD -i ${bridgeName} -m state --state ESTABLISHED,RELATED -j ACCEPT

          # Allow internal network traffic
          iptables -A FORWARD -i ${bridgeName} -d ${gatewayAddress}/24 -j ACCEPT

          # Allow DHCP (necessary for guest VMs to obtain IP addresses)
          iptables -A FORWARD -i ${bridgeName} -p udp --dport 67:68 -d ${gatewayAddress} -j ACCEPT
          
          # Block everything else from this network
          iptables -A FORWARD -i ${bridgeName} -j REJECT --reject-with icmp-host-prohibited
        '';

      # Generate cleanup rules for Tor
      mkTorCleanupRules =
        torTransPort: torDnsPort: networkCfg:
        let
          bridgeName = networkCfg.bridge.name;
          gwAddr = networkCfg.ip.address;
        in
        ''
          iptables -t nat -D PREROUTING -i ${bridgeName} -p tcp --syn -j REDIRECT --to-ports ${toString torTransPort} 2>/dev/null || true
          iptables -t nat -D PREROUTING -i ${bridgeName} -p udp --dport 53 -j REDIRECT --to-ports ${toString torDnsPort} 2>/dev/null || true
          iptables -D FORWARD -i ${bridgeName} -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
          iptables -D FORWARD -i ${bridgeName} -d ${gwAddr}/24 -j ACCEPT 2>/dev/null || true
          iptables -D FORWARD -i ${bridgeName} -j REJECT --reject-with icmp-host-prohibited 2>/dev/null || true
        '';

      mkIPv6BlockRules = pkgs: networkCfg: ''
        if ${pkgs.iproute2}/bin/ip link show ${networkCfg.bridge.name} >/dev/null 2>&1; then
          ip6tables -I FORWARD -i ${networkCfg.bridge.name} -j DROP 2>/dev/null || true
          ip6tables -I OUTPUT -o ${networkCfg.bridge.name} -j DROP 2>/dev/null || true
        fi
      '';

      mkIPv6BlockCleanupRules = networkCfg: ''
        ip6tables -D FORWARD -i ${networkCfg.bridge.name} -j DROP 2>/dev/null || true
        ip6tables -D OUTPUT -o ${networkCfg.bridge.name} -j DROP 2>/dev/null || true
      '';
    };

    nftables = {
      mkTorProxyTable = cfg: torTransPort: torDnsPort: torNetworks: {
        family = "ip";
        content = ''
          ${optionalString cfg._internalDebugTrace ''
            chain NIROTORNET_TRACE {
              type filter hook forward priority -500;
              meta nftrace set 1;
            }
          ''}

          chain prerouting {
            type nat hook prerouting priority dstnat;
            
            ${concatMapStringsSep "\n" (net: ''
              # Tor transparent proxy for ${net.name}
              iifname "${net.bridge.name}" tcp flags syn counter redirect to :${toString torTransPort}
              iifname "${net.bridge.name}" udp dport 53 counter redirect to :${toString torDnsPort}
            '') torNetworks}
          }

          chain NIXTORNET_FWO {
            type filter hook forward priority filter -1;
            
            ${concatMapStringsSep "\n" (net: ''
              # Allow established connections for ${net.name}
              iifname "${net.bridge.name}" ct state established,related counter accept
              # Allow internal network traffic
              iifname "${net.bridge.name}" ip daddr ${net.ip.address}/24 counter accept # TODO: Make CIDR configurable
              # Allow DHCP (necessary for guest VMs to obtain IP addresses)
              iifname "${net.bridge.name}" udp dport {67, 68} ip daddr ${net.ip.address} counter accept
            '') torNetworks}
          }
        '';
      };

      mkIsolationTable = isolatedNetworks: {
        family = "ip";
        content = ''
          chain NIXTORNET_ISOLATION {
            type filter hook forward priority filter + 10;
            
            ${concatMapStringsSep "\n" (
              net:
              optionalString net.isolation.enable ''
                # Isolation rules for ${net.name}
                ${optionalString net.isolation.blockHTTP ''
                  iifname "${net.bridge.name}" tcp dport { 80, 443 } counter drop
                ''}
                ${optionalString net.isolation.blockDNS ''
                  iifname "${net.bridge.name}" udp dport 53 counter drop
                ''}
                ${concatMapStringsSep "\n" (port: ''
                  iifname "${net.bridge.name}" ip daddr ${net.ip.address} tcp dport ${toString port} counter accept
                '') net.isolation.allowedPorts}
                iifname "${net.bridge.name}" ip daddr ${net.ip.address}/${toString net.isolation.cidrBits} counter accept
              ''
            ) isolatedNetworks}
          }
        '';
      };

      mkIPv6BlockTable = torNetworks: {
        family = "ip6";
        content = ''
          chain NIXTORNET_FWO_IPv6 {
            type filter hook forward priority filter;
            ${concatMapStringsSep "\n" (net: ''
              iifname "${net.bridge.name}" counter drop
            '') torNetworks}
          }

          chain NIXTORNET_OUT_IPv6 {
            type filter hook output priority filter;
            ${concatMapStringsSep "\n" (net: ''
              oifname "${net.bridge.name}" counter drop
            '') torNetworks}
          }
        '';
      };
    };
  };
}
