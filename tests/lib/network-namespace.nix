{ executables, firewall, pkgs }:
let
  inherit (executables) concatMapStringsSep grep ip udhcpc;
  inherit (firewall) analyzeFirewallCounters;
in
rec {
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
      - dnsServers: List of DNS servers (default: [ "192.168.100.1" ])

    Example:
      configureNamespaceDns {
        namespace = "testns";
        dnsServers = ["192.168.100.1"];
      }
      => Creates /etc/netns/testns/resolv.conf with nameserver entry
  */
  configureNamespaceDns =
    { namespace, dnsServers ? [ "192.168.100.1" ] }:
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
      - gateway: Gateway IP (default: "192.168.100.1")

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
    , gateway ? "192.168.100.1"
    ,
    }:
    ''
      machine.succeed("${ip} netns exec ${namespace} ${ip} addr add ${ipAddr} dev ${iface}")
      machine.succeed("${ip} netns exec ${namespace} ${ip} route add default via ${gateway}")
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
}
