{ pkgs }:

let
  executables = import ./executables.nix { inherit pkgs; };
  shell-scripts = import ./shell-scripts.nix { inherit pkgs; };
  firewall = import ./firewall { inherit executables pkgs shell-scripts; };
  network-namespace = import ./network-namespace.nix { inherit executables firewall pkgs; };
  inherit (executables) dig iptables journalctl nft virsh systemctl pkill ss grep tcpdump;
in
firewall // network-namespace // rec {
  /**
    Capture and analyze DNS packets on specified interfaces.

    Starts tcpdump on bridge and loopback interfaces to track DNS packets before 
    DNAT (port 53 on bridge) and after DNAT (port ${dnsPort} on localhost), performs 
    an action, then stops captures and returns packet data.

    Type: captureDnsPackets :: {
    bridgeName :: String,
    dnsPort :: Int,
    action :: String
    } -> String

    Arguments:
    - bridgeName: Bridge interface to monitor
    - dnsPort: Tor DNS port to monitor (default: 9053)
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
      # Capture incoming DNS queries (port 53) on bridge
      machine.succeed(
        "(${tcpdump} -i ${bridgeName} -n udp port 53 -w /tmp/dns-bridge.pcap </dev/null >/dev/null 2>&1 &) && sleep 0.1"
      )
      # Capture redirected DNS traffic (port ${toString dnsPort}) on loopback
      # After DNAT, packets are redirected to localhost where Tor DNSPort listens
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
    '';

  /**
    Check Tor DNS mock server logs for received queries.
  
    Type: checkTorDnsLogs :: {
    serviceName :: String,
    expectedQuery :: String
    } -> String
  
    Arguments:
    - serviceName: name of the Tor DNS mock service
    - expectedQuery: Query that should appear in logs
  
    Example:
    checkTorDnsLogs {
      serviceName = "mock-tor.service";
      expectedQuery = "google.com";
    }
  */
  checkTorDnsLogs =
    { serviceName ? "mock-tor.service"
    , expectedQuery ? "google.com"
    }:
    ''
      print("\n" + "=" * 60)
      print("Tor DNS Server Logs")
      print("=" * 60)
    
      log_result = machine.execute("${journalctl} -u ${serviceName} --no-pager | ${grep} '${expectedQuery}' || echo 'No queries found'")

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
    Evaluate DNS query result and diagnose failures.
    
    Expects the following variables to be in scope:
    - dns_result: Tuple of (exit_code, output) from DNS query
    - has_bridge_packets: Boolean indicating if packets reached the bridge
    - has_tor_packets: Boolean indicating if packets reached Tor DNS
    
    Type: evaluateDnsQueryResult :: {
      mockAnswer :: String,
      query :: String
      dnsPort :: Int
    } -> String
    
    Arguments:
    - mockAnswer: Expected DNS answer for validation
    - query: Domain name that was queried
    - dnsPort: Tor DNS port (default: 9053)
    
    Returns:
    Python code that evaluates the DNS query result and diagnoses failures.
  */
  evaluateDnsQueryResult = { mockAnswer, query, dnsPort ? 9053 }:
    ''
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

        # Diagnose the failure
        if has_bridge_packets and not has_tor_packets:
          print("\n⚠️ DIAGNOSIS: DNAT redirect not working")
          print("  - Packets reach bridge (port 53) ✔️")
          print("  - Packets do NOT reach localhost Tor DNS (port ${toString dnsPort}) ❌")
          print("  - Likely causes:")
          print("    * DNAT rule missing or incorrect")
          print("    * Firewall blocks redirected traffic to localhost")
          print("    * Tor DNS not listening on 127.0.0.1:${toString dnsPort}")
          machine.succeed("false")
        elif not has_bridge_packets:
          print("\n⚠️ DIAGNOSIS: Packets not leaving namespace")
          print("  - No DNS queries (port 53) detected on bridge")
          print("  - Check namespace routing and interface status")
          machine.succeed("false")
        elif has_tor_packets:
          print("\n⚠️ DIAGNOSIS: Tor DNS receives query but response fails")
          print("  - Packets reach localhost:${toString dnsPort} ✔️")
          print("  - But DNS query failed (no response or wrong answer)")
          print("  - Check Tor DNS mock configuration and response handling")
          machine.succeed("false")
        else:
          print("\n⚠️ DIAGNOSIS: Unknown failure")
          print("  - No packets captured on bridge or localhost")
          machine.succeed("false")
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
    useNftables :: Bool
    } -> String

    Arguments:
    - namespace: Network namespace simulating guest VM
    - bridgeName: Bridge interface to capture packets on
    - gatewayIp: Gateway IP (DNS server from guest perspective, default: 192.168.100.1)
    - dnsPort: Tor DNS port on localhost (default: 9053)
    - mockAnswer: Expected DNS answer for validation (default: "1.1.1.1")
    - query: Domain name to query (default: "google.com")
    - timeout: DNS query timeout in seconds (default: "10")
    - useNftables: Whether to use nftables or iptables as firewall backend

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
    , useNftables
    }:
    ''
      print("\n" + "=" * 60)
      print("DNS Flow Test with Packet Capture")
      print("=" * 60)

      # Debug: Show firewall rules and listening ports
      ${firewall.dumpFirewallRules {
        inherit useNftables;
        ruleset = if useNftables then "ip nixtornet-tor" else bridgeName;
        heading = "Firewall and Network State";
      }}

      print("\n[Listening on UDP ports]")
      print(machine.succeed("${ss} -ulnp"))

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

      # Read captures
      bridge_packets = machine.execute(
        "${tcpdump} -r /tmp/dns-bridge.pcap -n 2>/dev/null || echo 'No packets captured'"
      )
      tor_packets = machine.execute(
        "${tcpdump} -r /tmp/dns-tor.pcap -n 2>/dev/null || echo 'No packets captured'"
      )

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

      # Display captured packets
      print("\n--- Packet Analysis ---")
      print("\nPackets on bridge (${bridgeName}):")
      print(bridge_packets[1] if bridge_packets[1].strip() else "  No packets")
  
      print("\nPackets on localhost:${toString dnsPort} (Tor DNS after redirect):")
      print(tor_packets[1] if tor_packets[1].strip() else "  No packets")

      ${evaluateDnsQueryResult { inherit mockAnswer query; }}
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
