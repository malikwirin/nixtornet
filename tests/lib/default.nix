{ pkgs }:

let
  grep = "${pkgs.gnugrep}/bin/grep";
  ip = "${pkgs.iproute2}/bin/ip";
  ss = "${pkgs.iproute2}/bin/ss";
  systemctl = "${pkgs.systemd}/bin/systemctl";
  virsh = "${pkgs.libvirt}/bin/virsh";
  inherit (pkgs.lib) concatMapStringsSep;
in
rec {

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
    ,
    }:
    if active then
      ''machine.succeed("${virsh} net-list | ${grep} '${name}' | ${grep} 'active'")''
    else
      ''machine.succeed("${virsh} net-list --all | ${grep} '${name}'")'';

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
