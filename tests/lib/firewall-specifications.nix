{ pkgs }:

let
  executables = import ./executables.nix { inherit pkgs; };
  shell-scripts = import ./shell-scripts.nix { inherit pkgs; };
  inherit (executables) grep iptables nft;
  inherit (shell-scripts) inspectIptablesRules;
in
{
  /**
    Generate backend-specific configuration for DHCP rule inspection.
    
    This function encapsulates the differences between nftables and iptables
    backends when checking for DHCP exception rules (UDP ports 67/68).
    
    Type: dhcpCheck :: {
      useNftables :: Bool,
      table :: String (optional, nftables only)
    } -> {
      command :: String,
      patterns :: String,
      successMsg :: String,
      failureMsg :: String
    }
    
    Arguments:
      - useNftables: If true, generates nftables configuration; if false, iptables
      - table: nftables table name (e.g. "ip nixtornet-tor"), required for nftables backend
    
    Returns:
      A configuration object containing:
      - command: Shell command to execute for listing rules
      - patterns: Regex pattern to search for DHCP-related rules
      - successMsg: Message to print when DHCP rules are found
      - failureMsg: Message to print when DHCP rules are NOT found
    
    Example (nftables):
      dhcpCheck { useNftables = true; table = "ip nixtornet-tor"; }
      => { command = "nft list table ip nixtornet-tor"; patterns = "dport 67|dport 68|dhcp"; ... }
    
    Example (iptables):
      dhcpCheck { useNftables = false; }
      => { command = "iptables -L FORWARD -v -n"; patterns = "dpt:domain|dpt:bootpc|dpt:bootps"; ... }
    
    Notes:
      - nftables uses port number patterns: dport 67, dport 68
      - iptables uses service name patterns: bootpc (UDP 68), bootps (UDP 67), domain (UDP 53)
      - The patterns are designed to catch both explicit rules and implicit DNS/DHCP handling
  */
  dhcpCheck = { useNftables, table ? null }:
    if useNftables then
      {
        command = "${nft} list table ${table}";
        patterns = "dport 67|dport 68|dhcp";
        successMsg = "DHCP exception rules found in nftables";
        failureMsg = "NO DHCP exception rules found in nftables";
      }
    else
      {
        command = "${iptables} -L FORWARD -v -n";
        patterns = "dpt:domain|dpt:bootpc|dpt:bootps";
        successMsg = "DHCP exception rules found in iptables";
        failureMsg = "NO DHCP exception rules found in iptables";
      };

  /**
    Generate backend-specific configuration for dumping complete firewall rulesets.

    Abstracts the differences between nftables and iptables when dumping
    the complete, unfiltered firewall configuration.

    Type: dumpRuleset :: {
    useNftables :: Bool,
    ruleset :: String
    } -> {
    command :: String,
    defaultHeading :: String
    }

    Arguments:
    - useNftables: If true, generates nftables configuration; if false, iptables
    - ruleset: For nftables: table name (e.g. "ip nixtornet-tor")
              For iptables: bridge name (e.g. "virbr-tornet")

    Returns:
    A configuration object containing:
    - command: Shell command to dump the complete ruleset
    - defaultHeading: Default heading (can be overridden by caller)

    Example (nftables):
    dumpRuleset { useNftables = true; ruleset = "ip nixtornet-tor"; }
    => { command = "nft list table ip nixtornet-tor"; 
         defaultHeading = "Complete nftables ruleset"; }

    Example (iptables):
    dumpRuleset { useNftables = false; ruleset = "virbr-tornet"; }
    => { command = "${shell-scripts.inspectIptablesRules "virbr-tornet"}"; 
         defaultHeading = "Complete iptables ruleset"; }

    Notes:
    - nftables: Directly executes "nft list table" for the specified table
    - iptables: Uses shell-scripts.inspectIptablesRules to show NAT and FORWARD chains
    - The caller (dumpFirewallRules) is responsible for setting finalHeading (custom heading overrides default)
    - The command is a pre-computed string that can be directly passed to machine.succeed()
  */
  dumpRuleset = { useNftables, ruleset }:
    if useNftables then
      {
        command = "${nft} list table ${ruleset}";
        defaultHeading = "Complete nftables ruleset";
      }
    else
      {
        command = "${inspectIptablesRules ruleset}";
        defaultHeading = "Complete iptables ruleset";
      };

  /**
    Generate backend-specific configuration for inspecting firewall chains.
    
    This function abstracts the differences between nftables and iptables
    when querying packet-processing chains (where forwarding rules are evaluated).
    
    Type: inspectChain :: {
      useNftables :: Bool,
      table :: String,
      target :: String
    } -> {
      command :: String,
      defaultHeading :: String
    }
    
    Arguments:
      - useNftables: If true, generates nftables configuration; if false, iptables
      - table: nftables table name (e.g. "ip nixtornet-tor"), used for nftables only
      - target: For nftables: chain name (e.g. "LIBVIRT_FWO")
               For iptables: bridge name (e.g. "virbr-tornet") to filter output
    
    Returns:
      A configuration object containing:
      - command: Shell command to list and inspect the chain/forwarding rules
      - defaultHeading: Human-readable heading for console output
    
    Example (nftables):
      inspectChain { useNftables = true; table = "ip nixtornet-tor"; target = "LIBVIRT_FWO"; }
      => { command = "nft list chain ip nixtornet-tor LIBVIRT_FWO"; 
           defaultHeading = "Forward chain (where packets get processed)"; }
    
    Example (iptables):
      inspectChain { useNftables = false; table = ""; target = "virbr-tornet"; }
      => { command = "iptables -L FORWARD -v -n ... | grep virbr-tornet"; 
           defaultHeading = "Forward chain (where packets get processed)"; }
    
    Notes:
      - nftables: Directly queries the specified chain in the table
      - iptables: Lists FORWARD chain and filters for the bridge interface
      - Both backends inspect the same logical concept: where packets are actually forwarded
      - The command output includes rule counters (packet/byte counts) which are useful for debugging
  */
  inspectChain = { useNftables, table, target }:
    if useNftables then
      {
        command = "${nft} list chain ${table} ${target}";
        defaultHeading = "Forward chain (where packets get processed)";
      }
    else
      {
        command = "${iptables} -L FORWARD -v -n 2>/dev/null | ${grep} -E 'Chain FORWARD|^.*${target}' || true";
        defaultHeading = "FORWARD chain (where packets get processed)";
      };
}
