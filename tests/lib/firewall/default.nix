{ executables, pkgs, shell-scripts }:

let
  specifications = import ./specifications.nix { inherit executables pkgs shell-scripts; };
  inherit (executables) grep nft;
in
rec {
  /**
    Analyze firewall packet counters for a specific bridge after DHCP attempt.

    This function inspects the packet counters in firewall rules to see if packets
    matching the bridge interface have been processed. It works differently for each backend:
    - nftables: Filters the chain output for rules matching the bridge name and containing counters
    - iptables: Uses inspectIptablesRules helper to show complete rule information

    Useful for debugging whether firewall rules are being hit and processing packets.

    Type: analyzeFirewallCounters :: {
    useNftables :: Bool,
    table :: String (nftables only),
    chain :: String (nftables only),
    bridgeName :: String
    } -> String

    Arguments:
    - useNftables: If true, uses nftables backend; if false, uses iptables
    - table: nftables table name (e.g. "ip nixtornet-tor") - required for nftables
    - chain: nftables chain name (e.g. "NIXTORNET_FWO") - required for nftables
    - bridgeName: Bridge interface name (e.g. "virbr-tornet") - used by both backends

    Returns:
    Python code that:
    - For nftables: Lists the chain and greps for rules matching the bridge with counter data
    - For iptables: Shows complete NAT and FORWARD chain inspection output
    - Prints formatted counter data or "Counter pattern not found" if no matches

    Example (nftables):
    analyzeFirewallCounters {
      useNftables = true;
      table = "ip nixtornet-tor";
      chain = "NIXTORNET_FWO";
      bridgeName = "virbr-tornet";
    }

    Example (iptables):
    analyzeFirewallCounters {
      useNftables = false;
      bridgeName = "virbr-tornet";
    }

    Notes:
    - The counter data shows which rules have been matched and how many packets/bytes processed
    - Helpful for determining if firewall rules are being evaluated correctly
    - Part of the DHCP testing workflow to verify packet flow through firewall
  */
  analyzeFirewallCounters =
    { useNftables
    , table
    , chain
    , bridgeName
    }:
    if useNftables then
      ''
        counters = machine.execute("${nft} list chain ${table} ${chain} 2>/dev/null | ${grep} '${bridgeName}' | ${grep} 'counter' || true")

        if counters[0] == 0 and counters[1].strip():
          print(f"Counter data:\n{counters[1]}")
        else:
          print("Counter pattern not found")
      ''
    else
      ''
        firewall_output = machine.succeed("${shell-scripts.inspectIptablesRules bridgeName}")
        print(f"Counter data (iptables):\n{firewall_output}")
      '';

  /**
    Comprehensive firewall state analysis with DHCP diagnostics.

    This is a high-level composition function that combines three backend-agnostic
    helper functions to provide complete firewall visibility:
    1. Dumps the complete firewall configuration (via dumpFirewallRules)
    2. Checks for DHCP exception rules (via checkDhcpRules)
    3. Inspects the specific forwarding chain (via inspectChain)

    Works with both nftables and iptables backends.

    Type: analyzeFirewallState :: {
    useNftables :: Bool,
    table :: String (nftables only),
    chain :: String (nftables only),
    bridgeName :: String (iptables only)
    } -> String

    Arguments:
    - useNftables: Whether to use nftables (true) or iptables (false)
    - table: nftables table name (required for nftables)
    - chain: nftables chain name (required for nftables)
    - bridgeName: Bridge name for iptables inspection (required for iptables)

    Returns:
    Python code that prints a formatted "FIREWALL ANALYSIS" section containing:
    - Complete firewall configuration dump
    - DHCP rule diagnostics (✓ found or ✗ missing)
    - Forwarding chain inspection with rule counters

    Example (nftables):
    analyzeFirewallState {
      useNftables = true;
      table = "ip nixtornet-tor";
      chain = "NIXTORNET_FWO";
    }

    Example (iptables):
    analyzeFirewallState {
      useNftables = false;
      bridgeName = "virbr-tornet";
    }

    Notes:
    - This is a composition function; actual logic resides in dumpFirewallRules, checkDhcpRules, and inspectChain
    - Useful for full firewall inspection in test output
    - Prints clear section headers to organize output
  */
  analyzeFirewallState =
    { useNftables
    , table
    , chain
    , bridgeName
    }:
    let
      ruleset = if useNftables then table else bridgeName;
      target = if useNftables then chain else bridgeName;
      backendName = if useNftables then "nftables" else "iptables";
    in
    ''
      # === FIREWALL ANALYSIS ===
      print("\n" + "-" * 60)
      print("FIREWALL ANALYSIS: ${backendName} rules inspection")
      print("-" * 60)

      # Dump the complete firewall configuration
      ${dumpFirewallRules {
        inherit useNftables ruleset;
      }}

      # Check for DHCP exception rules
      ${checkDhcpRules {
        inherit useNftables table;
      }}

      # Inspect the specific forwarding chain
      ${inspectChain {
        inherit useNftables table target;
      }}
    '';

  /**
    Check for DHCP exception rules (UDP 67/68) in firewall (backend-agnostic).

    Automatically detects backend (nftables or iptables) and searches with
    the appropriate patterns and commands for each backend.

    Type: checkDhcpRules :: {
      useNftables :: Bool,
      table :: String (nftables only),
    } -> String

    Arguments:
      - useNftables: Whether to use nftables (true) or iptables (false)
      - table: nftables table name (e.g. "ip nixtornet-tor") - required for nftables

    Returns:
      Python code that searches for DHCP rules and prints diagnostics:
      - ✓ Rules found: Shows matching rules
      - ✗ Rules missing: Explains why DHCP fails

    Example (nftables):
      checkDhcpRules {
        useNftables = true;
        table = "ip nixtornet-tor";
      }

    Example (iptables):
      checkDhcpRules {
        useNftables = false;
      }
  */
  checkDhcpRules =
    { useNftables
    , table ? null
    }:
    let
      # Backend-specific configuration
      inherit (specifications.dhcpCheck { inherit useNftables table; }) command patterns successMsg failureMsg;
    in
    ''
      dhcp_check_result = machine.execute("${command} 2>/dev/null | ${grep} -E '${patterns}' || true")
      if dhcp_check_result[0] == 0 and dhcp_check_result[1].strip():
        print("\n✓ ${successMsg}")
        print(f"  {dhcp_check_result[1]}")
      else:
        print("\n✗ ${failureMsg}")
        print("  This explains why DHCP fails!")
    '';

  /**
    Dump complete firewall configuration for debugging and inspection.

    This function displays the full firewall ruleset for either nftables or iptables,
    with an optional custom heading. It's useful for understanding the effective
    firewall state during tests.

    Type: dumpFirewallRules :: {
    useNftables :: Bool,
    ruleset :: String,
    heading :: String (optional)
    } -> String

    Arguments:
    - useNftables: If true, dumps nftables table; if false, dumps iptables rules
    - ruleset: For nftables: table name (e.g. "ip nixtornet-tor")
              For iptables: bridge name (e.g. "virbr-tornet")
    - heading: Custom heading for output. If not provided, backend-specific defaults are used
              (defaults: "Complete nftables ruleset" or "Complete iptables ruleset")

    Returns:
    Python code that executes the backend-specific command and prints the ruleset
    with the appropriate heading.

    Example (nftables with default heading):
    dumpFirewallRules { useNftables = true; ruleset = "ip nixtornet-tor"; }
    => Prints "Complete nftables ruleset:" followed by nft output

    Example (iptables with custom heading):
    dumpFirewallRules {
      useNftables = false;
      ruleset = "virbr-tornet";
      heading = "Bridge firewall inspection";
    }
    => Prints "Bridge firewall inspection:" followed by iptables output

    Notes:
    - Delegates backend configuration to firewallSpecifications.dumpRuleset
    - The custom heading parameter overrides the backend-specific default
    - Useful for debugging firewall state in test output
  */
  dumpFirewallRules =
    { useNftables
    , ruleset
    , heading ? null
    }:
    let
      inherit (specifications.dumpRuleset { inherit useNftables ruleset; }) command defaultHeading;
      finalHeading = if heading != null then heading else defaultHeading;
    in
    ''
      output = machine.succeed("${command}")
      print(f"\n${finalHeading}:\n{output}")
    '';

  /**
    Inspect firewall chain (backend-agnostic).

    Automatically selects the appropriate command based on the backend
    and executes it to inspect the chain/forwarding rules.

    Type: inspectChain :: {
      useNftables :: Bool,
      table :: String (used by nftables),
      target :: String (chain name for nftables, bridge name for iptables),
      heading :: String (optional)
    } -> String

    Arguments:
      - useNftables: Whether to use nftables (true) or iptables (false)
      - table: nftables table name (e.g. "ip nixtornet-tor") - required for nftables
      - target: nftables chain name (e.g. "NIXTORNET_FWO") or iptables bridge (e.g. "virbr-tornet")
      - heading: Custom heading for output (optional, backend-specific default)

    Returns:
      Python code that:
      - Executes the backend-specific command
      - Prints output with heading

    Example (nftables):
      inspectChain {
        useNftables = true;
        table = "ip nixtornet-tor";
        target = "NIXTORNET_FWO";
        heading = "nftables forwarding chain";
      }

    Example (iptables):
      inspectChain {
        useNftables = false;
        table = "";
        target = "virbr-tornet";
      }
  */
  inspectChain =
    { useNftables
    , table
    , target
    , heading ? null
    }:
    let
      inherit (specifications.inspectChain { inherit useNftables table target; }) command defaultHeading;
      finalHeading = if heading != null then heading else defaultHeading;
    in
    ''
      chain_output = machine.succeed("${command}")
      print(f"\n${finalHeading}:\n{chain_output}")
    '';
}
