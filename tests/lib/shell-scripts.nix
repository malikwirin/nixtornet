{ pkgs }:

let
  executables = import ./executables.nix { inherit pkgs; };
  inherit (executables) dig dnsmasq grep ip iptables pkill socat;
in
{
  /**
    Shell script to inspect iptables rules for a specific network interface.

    This script queries both the NAT table (PREROUTING) and Filter table (FORWARD)
    to provide a complete picture of firewall rules for the given bridge.

    Type: inspectIptablesRules :: String -> Derivation

    Arguments:
    - bridgeName: Bridge interface name (e.g. "virbr-tornet")

    Returns:
    A shell script that outputs formatted iptables rules.
    Can be called from tests as: machine.succeed("${inspectIptablesRules}")
  */
  inspectIptablesRules =
    bridgeName:
    pkgs.writeShellScript "inspect-iptables-rules" ''
      set -euo pipefail

      BRIDGE_NAME="${bridgeName}"

      echo "=== NAT Table (PREROUTING) ==="
      ${iptables} -t nat -L PREROUTING -v -n 2>/dev/null | ${grep} "$BRIDGE_NAME" || echo "  (no rules found)"

      echo ""
      echo "=== Filter Table (FORWARD) ==="
      ${iptables} -L FORWARD -v -n 2>/dev/null | ${grep} "$BRIDGE_NAME" || echo "  (no rules found)"

      echo ""
      echo "=== All Rules (complete output) ==="
      ${iptables} -t nat -L -v -n 2>/dev/null | ${grep} -A 10 "Chain PREROUTING"
      ${iptables} -L -v -n 2>/dev/null | ${grep} -A 15 "Chain FORWARD"
    '';

  /**
    Execute DNS query in network namespace.

    This is a shell script that performs a DNS query using dig from within
    a network namespace.

    Type: queryDnsInNamespace :: Derivation (Shell Script)

    Usage:
    queryDnsInNamespace <namespace> <server> <domain>

    Arguments (positional):
    $1 - namespace: Network namespace name
    $2 - server: DNS server IP address
    $3 - domain: Domain to query

    Returns:
    DNS answer on stdout if successful.

    Example:
    ${queryDnsInNamespace} dns-test 192.168.100.1 google.com
  */
  queryDnsInNamespace = pkgs.writeShellScript "query-dns-in-namespace" ''
    NAMESPACE="$1"
    SERVER="$2"
    DOMAIN="$3"
  
    ${ip} netns exec "$NAMESPACE" \
    ${dig} @"$SERVER" "$DOMAIN" +short +time=3 +tries=1
  '';

  /**
    Start mock Tor service with TransPort and DNSPort.

    This script starts two services to mock Tor's transparent proxy functionality:
    1. socat on TCP port 9040 (TransPort) - accepts and discards connections
    2. dnsmasq on UDP port 9053 (DNSPort) - responds to all DNS queries with 1.1.1.1

    Used in tests to simulate Tor without running the actual Tor daemon.

    Type: start-mock-tor :: Derivation

    Returns:
    A shell script that can be used as systemd ExecStart.

    Example:
    systemd.services.mock-tor.serviceConfig.ExecStart = shell-scripts.start-mock-tor;
  */
  start-mock-tor = pkgs.writeShellScript "start-mock-tor" ''
    ${socat} TCP-LISTEN:9040,bind=127.0.0.1,fork,reuseaddr /dev/null &
    
    # Mock DNSPort (actual DNS responder for test)
    exec ${dnsmasq} \
      --port=9053 \
      --bind-interfaces \
      --interface=lo \
      --address=/#/1.1.1.1 \
      --cache-size=0 \
      --no-hosts \
      --no-resolv \
      --log-queries
  '';

  /**
    Stop mock Tor service processes.

    Terminates both the socat (TransPort mock) and dnsmasq (DNSPort mock) processes
    started by start-mock-tor. Uses pkill to find and stop the processes gracefully.

    Type: stop-mock-tor :: Derivation

    Returns:
    A shell script that can be used as systemd ExecStop.
    Continues on error (|| true) to ensure cleanup always succeeds.

    Example:
    systemd.services.mock-tor.serviceConfig.ExecStop = shell-scripts.stop-mock-tor;
  */
  stop-mock-tor = pkgs.writeShellScript "stop-mock-tor" ''
    ${pkill} -f "socat.*9040" || true
    ${pkill} dnsmasq || true
  '';
}
