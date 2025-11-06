{ pkgs }:

let
  executables = import ./executables.nix { inherit pkgs; };
  inherit (executables) grep iptables;
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
}
