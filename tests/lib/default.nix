{ pkgs }:

let
  executables = import ./executables.nix { inherit pkgs; };
  firewallSpecifications = import ./firewall-specifications.nix { inherit pkgs; };
  shell-scripts = import ./shell-scripts.nix { inherit pkgs; };
  inherit (executables) concatMapStringsSep ip nft virsh systemctl ss grep udhcpc;
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
    Attempt DHCP in a network namespace and analyze firewall counters before/after.
    
    This is a complete workflow function that:
    1. Attempts DHCP via udhcpc in the specified namespace
    2. Logs the result for later inspection
    3. Waits for firewall counters to stabilize
    4. Analyzes the firewall state AFTER the DHCP attempt
    
    Works with both nftables and iptables backends.
    
    Type: attemptDhcpAndAnalyzeCounters :: {
      namespace :: String,
      iface :: String,
      useNftables :: Bool,
      bridgeName :: String,
      table :: String (optional, nftables only),
      chain :: String (optional, nftables only),
      timeout :: Int (optional, default: 10),
      logFile :: String (optional, default: "/tmp/dhcp-result.txt")
    } -> String
    
    Arguments:
      - namespace: Network namespace where DHCP should be attempted (e.g. "dhcp-test")
      - iface: Interface to run DHCP on (e.g. "veth-host")
      - useNftables: Whether to use nftables (true) or iptables (false)
      - bridgeName: Bridge name for counter filtering (e.g. "virbr-tornet")
      - table: nftables table name (e.g. "ip nixtornet-tor")
      - chain: nftables chain name (e.g. "NIXTORNET_FWO")
      - timeout: DHCP client timeout in seconds (default: 10)
      - logFile: Path to store DHCP client output (default: "/tmp/dhcp-result.txt")
    
    Returns:
      Python code that:
      - Prints section headers
      - Executes udhcpc with timeout (allows failure via || true)
      - Waits 1 second for firewall counters to update
      - Calls analyzeFirewallCounters to show packet state after attempt
      - Stores logs in logFile for later inspection
    
    Example:
      attemptDhcpAndAnalyzeCounters {
        namespace = "dhcp-test";
        iface = "veth-host";
        useNftables = true;
        bridgeName = "virbr-tornet";
        table = "ip nixtornet-tor";
        chain = "NIXTORNET_FWO";
      }
  */
  attemptDhcpAndAnalyzeCounters =
    { namespace
    , iface
    , useNftables
    , bridgeName
    , table ? null
    , chain ? null
    , timeout ? 10
    , logFile ? "/tmp/dhcp-result.txt"
    }:
    ''
      # === ATTEMPT DHCP ===
      print("\n" + "-" * 60)
      print("TEST: Attempting DHCP in namespace '${namespace}' on interface '${iface}'")
      print("-" * 60)
      
      # Attempt DHCP with timeout (may fail if UDP 67/68 is blocked by firewall)
      machine.execute("${ip} netns exec ${namespace} timeout ${toString timeout} ${udhcpc} -i ${iface} -n -q -T 5 -t 6 -A 3 2>&1 | tee ${logFile} || true")
      print("DHCP client attempt finished")
      
      # Brief pause to allow firewall counters to update
      time.sleep(1)
      
      # === ANALYZE COUNTERS AFTER DHCP ===
      print("\n" + "-" * 60)
      print("AFTER DHCP: Packet counters AFTER DHCP attempt")
      print("-" * 60)
      ${analyzeFirewallCounters {
        inherit useNftables bridgeName table chain;
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
      inherit (firewallSpecifications.dhcpCheck { inherit useNftables table; }) command patterns successMsg failureMsg;
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
    Create an isolated network namespace for VM simulation.

    Type: createNetworkNamespace :: { name :: String } -> String

    Arguments:
      - name: Namespace name (e.g. "testns")

    Example:
      createNetworkNamespace { name = "testns"; }
      => machine.succeed("ip netns add testns")
  */
  createNetworkNamespace =
    { name }:
    ''
      machine.succeed("${ip} netns add ${name}")
    '';

  /**
    Create a virtual ethernet pair (veth) and attach one end to a bridge.

    Type: createVethPair :: { vethHost :: String, vethGuest :: String, bridge :: String } -> String

    Arguments:
      - vethHost: Name of interface on host side (e.g. "veth0")
      - vethGuest: Name of interface on guest side (e.g. "veth1")
      - bridge: Bridge to attach guest interface to (e.g. "virbr-tornet")

    Returns:
      Creates veth pair and connects vethGuest to the bridge.

    Example:
      createVethPair { vethHost = "veth0"; vethGuest = "veth1"; bridge = "virbr-tornet"; }
      => Creates veth0 <-> veth1 and attaches veth1 to virbr-tornet
  */
  createVethPair =
    { vethHost
    , vethGuest
    , bridge
    ,
    }:
    ''
      machine.succeed("${ip} link add ${vethHost} type veth peer name ${vethGuest}")
      machine.succeed("${ip} link set ${vethGuest} master ${bridge}")
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
      inherit (firewallSpecifications.dumpRuleset { inherit useNftables ruleset; }) command defaultHeading;
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
      inherit (firewallSpecifications.inspectChain { inherit useNftables table target; }) command defaultHeading;
      finalHeading = if heading != null then heading else defaultHeading;
    in
    ''
      chain_output = machine.succeed("${command}")
      print(f"\n${finalHeading}:\n{chain_output}")
    '';

  /**
    Check if a network interface has an IPv4 address in a given namespace.
    
    Validates that the interface has a valid IPv4 address within the expected range.
    If validation fails, the test stops with an error.

    Type: hasIPv4InNamespace :: {
    namespace :: String,
    iface :: String,
    expectedRange :: String (optional, default: "192.168.100")
    } -> String

    Arguments:
      - namespace: Network namespace name (e.g. "dhcp-test")
      - iface: Interface name (e.g. "veth-host")
      - expectedRange: IP range prefix to validate against (default: "192.168.100")
                       e.g. "192.168.100" matches 192.168.100.0/24
                       e.g. "10.0" matches 10.0.0.0/8

    Returns:
      Test script that:
      - ✓ Prints success and continues if IPv4 found in expected range
      - ✗ Fails the entire test if no IPv4 found
      - ✗ Fails the entire test if IPv4 is outside expected range

    Example:
    hasIPv4InNamespace { 
      namespace = "dhcp-test"; 
      iface = "veth-host";
    }
    => Uses default range "192.168.100"

    hasIPv4InNamespace { 
      namespace = "dhcp-test"; 
      iface = "veth-host"; 
      expectedRange = "10.0.0";
    }
    => Validates IP is in 10.0.0.0/24 range
  */
  hasIPv4InNamespace =
    { namespace
    , iface
    , expectedRange ? "192.168.100"
    }:
    ''
      # Check if interface has IPv4
      ipv4_result = machine.execute(
        "${ip} netns exec ${namespace} ip addr show ${iface} | ${grep} 'inet ' | ${grep} -v 'inet6'"
      )

      if ipv4_result[0] == 0:
        print("✓ SUCCESS: Interface ${iface} has IPv4 address")
        print(f"  {ipv4_result[1]}")
        # Verify IP is in expected range
        machine.succeed("${ip} netns exec ${namespace} ip addr show ${iface} | ${grep} 'inet ${expectedRange}'")
      else:
        print("✗ FAILURE: Interface ${iface} has NO IPv4 address")
        print("  (Only IPv6 link-local, DHCP failed)")
        machine.succeed("false")
    '';

  /**
    Move a network interface to a namespace.

    Type: moveIfaceToNamespace :: { iface :: String, namespace :: String } -> String

    Arguments:
      - iface: Interface name (e.g. "veth0")
      - namespace: Target namespace name (e.g. "testns")

    Example:
      moveIfaceToNamespace { iface = "veth0"; namespace = "testns"; }
      => machine.succeed("ip link set veth0 netns testns")
  */
  moveIfaceToNamespace =
    { iface, namespace }:
    ''
      machine.succeed("${ip} link set ${iface} netns ${namespace}")
    '';

  /**
    Bring up network interfaces (both on host and in namespace).

    Type: bringUpInterfaces :: { namespace :: String, hostIface :: String, guestIface :: String } -> String

    Arguments:
      - namespace: Namespace name (null for host namespace)
      - hostIface: Interface to bring up on host (e.g. "veth1")
      - guestIface: Interface to bring up in namespace (e.g. "veth0")

    Example:
      bringUpInterfaces { namespace = "testns"; hostIface = "veth1"; guestIface = "veth0"; }
      => Brings up veth1 on host and veth0 in testns
  */
  bringUpInterfaces =
    { namespace
    , hostIface
    , guestIface
    ,
    }:
    ''
      machine.succeed("${ip} link set ${hostIface} up")
      machine.succeed("${ip} netns exec ${namespace} ${ip} link set ${guestIface} up")
      machine.succeed("${ip} netns exec ${namespace} ${ip} link set lo up")
    '';

  /**
    Configure DNS resolver for a network namespace.

    Type: configureNamespaceDns :: {
      namespace :: String,
      dnsServers :: String list
    } -> String

    Arguments:
      - namespace: Namespace name (e.g. "testns")
      - dnsServers: List of DNS servers (e.g. ["192.168.100.1"])

    Example:
      configureNamespaceDns {
        namespace = "testns";
        dnsServers = ["192.168.100.1"];
      }
      => Creates /etc/netns/testns/resolv.conf with nameserver entry
  */
  configureNamespaceDns =
    { namespace, dnsServers }:
    ''
      machine.succeed("mkdir -p /etc/netns/${namespace}")
      machine.succeed(
        "echo '${
          concatMapStringsSep "\n" (dns: "nameserver ${dns}") dnsServers
        }' > /etc/netns/${namespace}/resolv.conf"
      )
    '';

  /**
    Configure IP address and default route in a network namespace.

    Type: configureNamespaceNetwork :: {
      namespace :: String,
      iface :: String,
      ipAddr :: String,
      gateway :: String
    } -> String

    Arguments:
      - namespace: Namespace name (e.g. "testns")
      - iface: Interface name (e.g. "veth0")
      - ipAddr: IP address with CIDR (e.g. "192.168.100.50/24")
      - gateway: Gateway IP (e.g. "192.168.100.1")

    Example:
      configureNamespaceNetwork {
        namespace = "testns";
        iface = "veth0";
        ipAddr = "192.168.100.50/24";
        gateway = "192.168.100.1";
      }
      => Configures IP and default route in namespace
  */
  configureNamespaceNetwork =
    { namespace
    , iface
    , ipAddr
    , gateway
    ,
    }:
    ''
      machine.succeed("${ip} netns exec ${namespace} ${ip} addr add ${ipAddr} dev ${iface}")
      machine.succeed("${ip} netns exec ${namespace} ${ip} route add default via ${gateway}")
    '';

  /**
    Setup a complete isolated network namespace with veth connection to a bridge.

    This is a high-level convenience function that combines all namespace setup steps.

    Type: setupNamespaceForBridge :: {
      namespace :: String,
      bridge :: String,
      vethHost :: String,
      vethGuest :: String,
      namespaceIp :: String,
      gatewayIp :: String
    } -> String

    Arguments:
      - namespace: Namespace name (e.g. "testns")
      - bridge: Bridge to connect to (e.g. "virbr-tornet")
      - vethHost: Host-side veth interface (e.g. "veth0")
      - vethGuest: Guest-side veth interface (e.g. "veth1")
      - namespaceIp: IP address for namespace with CIDR (e.g. "192.168.100.50/24")
      - gatewayIp: Gateway IP address (e.g. "192.168.100.1")
      - dns: if dns should also be configured (default true)

    Returns:
      Complete setup in a single call.

    Example:
      setupNamespaceForBridge {
        namespace = "testns";
        bridge = "virbr-tornet";
        vethHost = "veth0";
        vethGuest = "veth1";
        namespaceIp = "192.168.100.50/24";
        gatewayIp = "192.168.100.1";
      }
      => Creates namespace, veth pair, configures networking, brings up all interfaces
  */
  setupNamespaceForBridge =
    { namespace
    , bridge
    , vethHost
    , vethGuest
    , namespaceIp
    , gatewayIp
    , dns ? true
    ,
    }:
    ''
      ${createNetworkNamespace { name = namespace; }}
      ${createVethPair { inherit vethHost vethGuest bridge; }}
      ${moveIfaceToNamespace {
        iface = vethHost;
        inherit namespace;
      }}
      ${bringUpInterfaces {
        inherit namespace;
        hostIface = vethGuest;
        guestIface = vethHost;
      }}
      ${configureNamespaceNetwork {
        inherit namespace;
        iface = vethHost;
        ipAddr = namespaceIp;
        gateway = gatewayIp;
      }}
      ${
        if dns then
          configureNamespaceDns {
            inherit namespace;
            dnsServers = [ gatewayIp ];
          }
        else
          ""
      }
    '';

  /**
    Check if a libvirt network exists, and optionally if it is active.

    Type: checkNetwork :: { name :: String, active :: Bool } -> String

    Arguments:
      - name: Name of the libvirt network to check.
      - active: If true, also check if the network is active (default: false).

    Example:
      checkNetwork { name = "tornet"; }
      => machine.succeed("virsh net-list --all | grep 'tornet'")

      checkNetwork { name = "tornet"; active = true; }
      => machine.succeed("virsh net-list | grep 'tornet' | grep 'active'")
  */
  checkNetwork =
    { name
    , active ? false
    }:
    let
      allFlag = if active then "" else "--all";
      activeCheck = if active then " | ${grep} 'active'" else "";
    in
    ''machine.succeed("${virsh} net-list ${allFlag} | ${grep} '${name}'${activeCheck}")'';

  /**
    Check if a systemd service is active.

    Type: checkServiceActive :: String -> String

    Example:
      checkServiceActive "tor.service"
      => machine.succeed("systemctl is-active tor.service")
  */
  checkServiceActive = service: ''
    machine.succeed("${systemctl} is-active ${service}")
  '';

  /**
    Check if any process is listening on a given TCP or UDP port.
    Optionally filter by process name.

    Type: checkPortBound :: { port :: Int, protocol :: String, process :: String/null } -> String

    Arguments:
      - port: Port number to check.
      - protocol: "tcp" or "udp" (default: "tcp").
      - process: Optional process name to filter for (e.g. "tor").
      - quiet: Use -q flag for quiet mode (default: false).

    Example:
      checkPortBound { port = 9040; protocol = "tcp"; }
      => machine.succeed("ss -tlnp | grep ':9040'")

      checkPortBound { port = 9040; protocol = "tcp"; process = "tor"; }
      => machine.succeed("ss -tlnp | grep ':9040' | grep tor")
  */
  checkPortBound =
    { port
    , protocol ? "tcp"
    , process ? null
    , quiet ? false
    ,
    }:
    let
      flag = if protocol == "tcp" then "tlnp" else "ulnp";
      quietFlag = if quiet then "-q" else "";
      processCheck = if process != null then " | ${grep} ${quietFlag} ${process}" else "";
    in
    ''
      machine.succeed("${ss} -${flag} | ${grep} ':${toString port}'${processCheck}")
    '';

  /**
    Check if socat is listening on both Tor TransPort (TCP) and DNSPort (UDP).

    This is a convenience function specifically for testing mock Tor setups
    where socat is used to bind the required ports instead of a real Tor daemon.
    Uses quiet mode by default for clean test output.

    Type: checkSocatPorts :: { transPort :: Int, dnsPort :: Int } -> String

    Arguments:
      - transPort: TCP port for transparent proxy (default: 9040)
      - dnsPort: UDP port for DNS queries (default: 9053)

    Returns:
      A NixOS test script that verifies socat is bound to both ports.
      Equivalent to:
        ss -tlnp | grep ':9040' | grep -q socat
        ss -ulnp | grep ':9053' | grep -q socat

    Example:
      checkSocatPorts { }
      => Checks default ports 9040 (TCP) and 9053 (UDP)

      checkSocatPorts { transPort = 9050; dnsPort = 5353; }
      => Checks custom socat ports

    Note:
      This function assumes socat is running and bound to the specified ports.
      It uses quiet mode (-q flag) to suppress output and only check exit codes,
      making it ideal for infrastructure verification in E2E tests.
  */
  checkSocatPorts =
    { transPort ? 9040
    , dnsPort ? 9053
    ,
    }:
    checkTorPorts {
      inherit transPort dnsPort;
      process = "socat";
      quiet = true;
    };

  /**
    Check both Tor TransPort (TCP) and DNSPort (UDP) bindings.

    Type: checkTorPorts :: { transPort :: Int, dnsPort :: Int } -> String

    This is a convenience function that verifies both Tor ports
    required for transparent proxying are properly bound.

    Arguments:
      - transPort: TCP port for transparent proxy (default: 9040)
      - dnsPort: UDP port for DNS queries (default: 9053)
      - quiet: Use quiet mode (default: false)
      - process: Process name to filter for (default: "tor")

    Example:
      checkTorPorts { }
      => Checks default ports 9040 (TCP) and 9053 (UDP)

      checkTorPorts { transPort = 9050; dnsPort = 5353; }
      => Checks custom ports
  */
  checkTorPorts =
    { transPort ? 9040
    , dnsPort ? 9053
    , quiet ? false
    , process ? "tor"
    ,
    }:
    ''
      ${checkPortBound {
        port = transPort;
        protocol = "tcp";
        inherit process quiet;
      }}
      ${checkPortBound {
        port = dnsPort;
        protocol = "udp";
        inherit process quiet;
      }}
    '';

  /**
    Dump the XML configuration of a libvirt network and print it with a heading.

    Type: dumpNetXml :: String -> String -> String

    Arguments:
      - network: Name of the libvirt network to dump.
      - heading: A string heading to print above the XML output.

    Example:
      dumpNetXml "tornet" "Default network configuration:"
      => net_xml: str = machine.run("virsh net-dumpxml tornet")
         print("\nDefault network configuration:\n", net_xml)

    Note:
      This helper is useful for debugging and inspecting the effective libvirt network configuration
      directly in the test output.
  */
  dumpNetXml = network: heading: ''
    net_xml: str = machine.succeed("${virsh} net-dumpxml ${network}")
    print("\n${heading}:\n", net_xml)
  '';

  /**
    Wait for a single systemd service to reach active state.

    Type: waitForService :: String -> String

    Example:
      waitForService "tor.service"
      => machine.wait_for_unit("tor.service")
  */
  waitForService = service: ''
    machine.wait_for_unit("${service}")
  '';

  /**
    Wait for multiple systemd services to reach active state.

    Type: waitForServices :: [String] -> String

    Services are waited for sequentially in the order provided.

    Example:
      waitForServices [ "tor.service" "libvirtd.service" ]
      => machine.wait_for_unit("tor.service")
         machine.wait_for_unit("libvirtd.service")
  */
  waitForServices = services: ''
    ${builtins.concatStringsSep "\n" (map waitForService services)}
  '';
}
