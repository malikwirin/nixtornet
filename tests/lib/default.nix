{ pkgs }:

let
  executables = import ./executables.nix { inherit pkgs; };
  shell-scripts = import ./shell-scripts.nix { inherit pkgs; };
  firewall = import ./firewall { inherit executables pkgs shell-scripts; };
  inherit (executables) dig concatMapStringsSep ip iptables nft virsh systemctl pkill ss grep tcpdump udhcpc;
  inherit (firewall) analyzeFirewallCounters;
in
firewall // rec {
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
    Capture and analyze DNS packets on specified interfaces.

    Starts tcpdump on bridge and loopback interfaces to track DNS packets,
    performs an action, then stops captures and returns packet data.

    Type: captureDnsPackets :: {
    bridgeName :: String,
    dnsPort :: Int,
    action :: String
    } -> String

    Arguments:
    - bridgeName: Bridge interface to monitor
    - dnsPort: DNS port on localhost to monitor (default: 9053)
    - action: Python code to execute while capturing

    Returns:
    Python code that captures packets, runs action, and returns
    (bridge_packets, tor_packets) tuples.

    Example:
    captureDnsPackets {
      bridgeName = "virbr-tornet";
      dnsPort = 9053;
      action = "dns_result = machine.execute(...)";
    }
  */
  captureDnsPackets =
    { bridgeName
    , dnsPort ? 9053
    , action
    }:
    ''
      print("Start tcpdump in background with explicit detach")
      machine.succeed(
        "(${tcpdump} -i ${bridgeName} -n udp port 53 -w /tmp/dns-bridge.pcap </dev/null >/dev/null 2>&1 &) && sleep 0.1"
      )
      machine.succeed(
        "(${tcpdump} -i lo -n udp port ${toString dnsPort} -w /tmp/dns-tor.pcap </dev/null >/dev/null 2>&1 &) && sleep 0.1"
      )
      time.sleep(1)

      # Execute the action (DNS query)
      ${action}

      time.sleep(2)

      # Stop captures
      machine.execute("${pkill} tcpdump || true")
      time.sleep(1)

      # Read captures
      bridge_packets = machine.execute(
        "${tcpdump} -r /tmp/dns-bridge.pcap -n 2>/dev/null || echo 'No packets captured'"
      )
      tor_packets = machine.execute(
        "${tcpdump} -r /tmp/dns-tor.pcap -n 2>/dev/null || echo 'No packets captured'"
      )
    '';

  /**
    Check Tor DNS mock server logs for received queries.
  
    Type: checkTorDnsLogs :: {
    logFile :: String,
    expectedQuery :: String
    } -> String
  
    Arguments:
    - logFile: Path to DNS server log
    - expectedQuery: Query that should appear in logs
  
    Example:
    checkTorDnsLogs {
      logFile = "/var/log/mock-tor-dns.log";
      expectedQuery = "google.com";
    }
  */
  checkTorDnsLogs =
    { logFile ? "/var/log/mock-tor-dns.log"
    , expectedQuery ? "google.com"
    }:
    ''
      print("\n" + "=" * 60)
      print("Tor DNS Server Logs")
      print("=" * 60)
    
      log_result = machine.execute("cat ${logFile} 2>/dev/null || echo 'No log file'")
    
      if log_result[0] == 0 and log_result[1].strip():
        print("DNS Server Log:")
        print(log_result[1])
      
        if "${expectedQuery}" in log_result[1]:
          print("\n✓ Query for '${expectedQuery}' found in logs")
        else:
          print("\n✗ Query for '${expectedQuery}' NOT found in logs")
          print("  DNS server did not receive the query")
      else:
        print("✗ No log output available")
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
      - gatewayIp: Gateway IP address (default "192.168.100.1")
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
    , gatewayIp ? "192.168.100.1"
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
    Test DNS flow from guest namespace through Tor with diagnostic output.

    Performs end-to-end DNS query test with packet capture to diagnose
    exactly where DNS traffic fails in the Tor transparent proxy chain.

    Type: testDnsFlowWithCapture :: {
    namespace :: String,
    bridgeName :: String,
    gatewayIp :: String,
    dnsPort :: Int,
    mockAnswer :: String,
    query :: String,
    timeout :: Int
    } -> String

    Arguments:
    - namespace: Network namespace simulating guest VM
    - bridgeName: Bridge interface to capture packets on
    - gatewayIp: Gateway IP (DNS server from guest perspective, default: 192.168.100.1)
    - dnsPort: Tor DNS port on localhost (default: 9053)
    - mockAnswer: Expected DNS answer for validation (default: "1.1.1.1")
    - query: Domain name to query (default: "google.com")
    - timeout: DNS query timeout in seconds (default: "10")

    Returns:
    Python test code that:
    - Captures DNS packets on bridge and localhost
    - Performs DNS query with timeout protection
    - Diagnoses failure location (namespace, firewall, or Tor DNS)

    Example:
    testDnsFlowWithCapture {
      namespace = "dns-test";
      bridgeName = "virbr-tornet";
    }
  */
  testDnsFlowWithCapture =
    { namespace
    , bridgeName
    , gatewayIp ? "192.168.100.1"
    , dnsPort ? 9053
    , mockAnswer ? "1.1.1.1"
    , query ? "google.com"
    , timeout ? "10"
    }:
    ''
      print("\n" + "=" * 60)
      print("DNS Flow Test with Packet Capture")
      print("=" * 60)

      print("Starting packet captures...")
      ${captureDnsPackets {
        inherit bridgeName dnsPort;
        action = ''
          print("Querying ${query} via ${gatewayIp}...")
          print("Starting DNS query with timeout...")
          dns_result = machine.execute(
            "${executables.timeout} ${timeout} ${shell-scripts.queryDnsInNamespace} ${namespace} ${gatewayIp} ${query} || true"
          )
          # Handle timeout exit code (124)
          if dns_result[0] == 124:
            dns_result = (124, "DNS query timed out")
        '';
      }}

      # Display captured packets
      print("\n--- Packet Analysis ---")
      print("\nPackets on bridge (${bridgeName}):")
      print(bridge_packets[1] if bridge_packets[1].strip() else "  No packets")
    
      print("\nPackets on localhost:${toString dnsPort} (Tor DNS):")
      print(tor_packets[1] if tor_packets[1].strip() else "  No packets")

      # Evaluate DNS query result
      print("\n--- DNS Query Result ---")
      if dns_result[0] == 0 and "${mockAnswer}" in dns_result[1]:
        print("✓ DNS QUERY SUCCESS")
        print("  Query: ${query}")
        print(f"  Answer: {dns_result[1].strip()}")
      else:
        print("✗ DNS QUERY FAILED")
        print(f"  Exit code: {dns_result[0]}")
        print(f"  Output: {dns_result[1]}")

        # Diagnose failure point
        has_bridge_packets = (
          bridge_packets[0] == 0 
          and bridge_packets[1].strip() 
          and "No packets" not in bridge_packets[1]
        )
        has_tor_packets = (
          tor_packets[0] == 0 
          and tor_packets[1].strip() 
          and "No packets" not in tor_packets[1]
        )

        if has_bridge_packets and not has_tor_packets:
          print("\n⚠️ DIAGNOSIS: NAT redirect not working")
          print("  - Packets reach bridge ✔️")
          print("  - Packets do NOT reach Tor DNS ❌")
          print("  - Likely cause: Firewall blocks DNS before NAT redirect")
          machine.succeed("false")
        elif not has_bridge_packets:
          print("\n⚠️ DIAGNOSIS: Packets not leaving namespace")
          print("  - Check namespace routing and interface status")
          machine.succeed("false")
        elif has_tor_packets:
          print("\n⚠️ DIAGNOSIS: Tor DNS receives query but response fails")
          print("  - Check Tor DNS mock configuration")
          machine.succeed("false")
        else:
          print("\n⚠️ DIAGNOSIS: Unknown failure")
          print("  - No packets captured anywhere")
          machine.succeed("false")
    '';

  /**
    Verify NAT redirection rules for DNS traffic exist.
  
    Checks that firewall rules are configured to redirect UDP port 53
    from bridge to Tor DNS port.
  
    Type: validateDnsNatRules :: {
    useNftables :: Bool,
    table :: String,
    bridgeName :: String,
    dnsPort :: Int
    } -> String
  
    Arguments:
    - useNftables: Backend selection
    - table: nftables table name (e.g. "ip nixtornet-tor")
    - bridgeName: Bridge interface (e.g. "virbr-tornet")
    - dnsPort: Target DNS port for redirect (default: 9053)
  
    Example:
    validateDnsNatRules {
      useNftables = true;
      table = "ip nixtornet-tor";
      bridgeName = "virbr-tornet";
      dnsPort = 9053;
    }
  */
  validateDnsNatRules =
    { useNftables
    , table
    , bridgeName
    , dnsPort ? 9053
    }:
    let
      nftablesCheck = ''
        nat_result = machine.execute(
          "${nft} list table ${table} | ${grep} 'udp dport 53.*redirect to :${toString dnsPort}'"
        )
      '';
      iptablesCheck = ''
        nat_result = machine.execute(
          "${iptables} -t nat -L PREROUTING -n -v | ${grep} '${bridgeName}' | ${grep} 'udp dpt:53'"
        )
      '';
    in
    ''
      print("\n" + "=" * 60)
      print("Validate DNS NAT Redirection Rules")
      print("=" * 60)
    
      ${if useNftables then nftablesCheck else iptablesCheck}
    
      if nat_result[0] == 0 and nat_result[1].strip():
        print("✓ DNS NAT redirect rule exists")
        print(f"  {nat_result[1]}")
      else:
        print("✗ DNS NAT redirect rule NOT found")
        print("  DNS packets from guests will not reach Tor DNS")
        machine.succeed("false")
    '';

  /**
    Verify that the Tor DNS mock server is running and accessible.
  
    This validates the test infrastructure before attempting DNS queries from guests.
  
    Type: validateTorDnsMock :: {
    dnsPort :: Int,
    mockAnswer :: String
    } -> String
  
    Arguments:
    - dnsPort: Port where mock Tor DNS is listening (default: 9053)
    - mockAnswer: Expected IP answer from mock (default: "1.1.1.1")
  
    Returns:
    Test script that:
    - Checks if port 9053 is bound
    - Performs direct DNS query to localhost:9053
    - Validates mock responds with expected answer
  
    Example:
    validateTorDnsMock { dnsPort = 9053; mockAnswer = "1.1.1.1"; }
  */
  validateTorDnsMock =
    { dnsPort ? 9053
    , mockAnswer ? "1.1.1.1"
    }:
    ''
      print("\n" + "=" * 60)
      print("Validate Tor DNS Mock Infrastructure")
      print("=" * 60)
    
      # Check DNS port is bound
      ${checkPortBound {
        port = dnsPort;
        protocol = "udp";
        process = "dnsmasq";
      }}
      print("✓ Mock Tor DNS bound to port ${toString dnsPort}")
    
      # Direct query to mock
      direct_result = machine.succeed(
        "${dig} @127.0.0.1 -p ${toString dnsPort} test.com +short"
      )
    
      if "${mockAnswer}" in direct_result:
        print("✓ Mock Tor DNS responds correctly")
        print(f"  Answer: {direct_result.strip()}")
      else:
        print("✗ Mock Tor DNS response unexpected")
        print("  Expected: ${mockAnswer}")
        print(f"  Got: {direct_result}")
        machine.succeed("false")
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
