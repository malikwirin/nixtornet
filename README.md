# NixTorNet

A NixOS module for transparent Tor integration with libvirt virtual machines, providing secure and anonymous development environments.

## Features

- ✅ **Transparent Tor Routing** - All VM traffic automatically routed through Tor
- ✅ **Dual Firewall Backend Support** - Works with both iptables and nftables automatically
- ✅ **Automatic DNS Redirection** - DNS queries handled via Tor DNSPort
- ✅ **Network Isolation** - Optional complete network isolation without internet access
- ✅ **IPv6 Blocking** - Targeted IPv6 disabling for Tor-enabled networks to prevent leaks
- ✅ **Monitoring & Logging** - Built-in connection monitoring and systemd journal integration
- ✅ **NixVirt Integration** - Declarative network definitions using NixVirt
- ✅ **Multi-Network Support** - Configure multiple networks with different security profiles
- ✅ **Zero VM Configuration** - VMs work transparently without internal Tor setup
- ✅ **Upstream Tor Integration** - Uses NixOS Tor module directly, no redundant configuration

## Table of Contents

- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)
- [Security Considerations](#security-considerations)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)
- [Performance Tuning](#performance-tuning)

## Quick Start

> **Note:** This module works with both iptables (default) and nftables firewall backends. 
> The backend is automatically detected - no special configuration needed!

### 1. Add to your NixOS configuration

```nix
{ config, pkgs, nixtornet, ... }:

{
  imports = [
    nixtornet.nixosModules.default
  ];

  # The module automatically configures Tor with sensible defaults
  # You can customize Tor settings via services.tor.settings
  services.tor.settings = {
    # Optional: customize Tor configuration
    # The module sets required values for transparent proxying
  };

  networking.firewall.enable = true;  # Required for transparent proxying

  services.nixtornet = {
    enable = true;

    tor = {
      enable = true;
      networks = [ "tor-dev" ];
    };

    networks = {
      tor-dev = {
        name = "tor-dev";
        uuid = "12345678-1234-1234-1234-123456789abc";
        bridge.name = "virbr-tor";
        ip = {
          address = "192.168.100.1";
          netmask = "255.255.255.0";
          dhcp = {
            range = {
              start = "192.168.100.2";
              end = "192.168.100.254";
            };
          };
        };
      };
    };
  };
}
```

### 2. Build and activate

```bash
sudo nixos-rebuild switch
```

### 3. Create a VM using the network

```bash
virt-install \
  --name dev-vm \
  --ram 4096 \
  --vcpus 2 \
  --disk size=20 \
  --network network=tor-dev \
  --cdrom /path/to/nixos.iso
```

All traffic from this VM will now automatically route through Tor!

## Architecture

### Network Flow

```
┌─────────────────────────────────────────────────────┐
│                  Internet                           │
│                     ▲                               │
└─────────────────────┼───────────────────────────────┘
                      │
              ┌───────▼────────┐
              │  Tor Network   │
              │   (3 Relays)   │
              └───────┬────────┘
                      │
┌─────────────────────▼───────────────────────────────┐
│              Host System (NixOS)                    │
│                                                     │
│  ┌──────────────┐    ┌─────────────┐               │
│  │ Tor Daemon   │◄──►│  iptables   │               │
│  │ TransPort    │    │  NAT Rules  │               │
│  │ :9040        │    │             │               │
│  └──────┬───────┘    └─────────────┘               │
│         │                                           │
│  ┌──────▼───────────────────────────┐               │
│  │    libvirt Bridge (virbr-tor)    │               │
│  │      Gateway: 192.168.100.1      │               │
│  └──────┬───────────────────────────┘               │
└─────────┼─────────────────────────────────────────┘
          │
┌─────────▼─────────────────────────────────────────┐
│          Development VM                           │
│                                                   │
│  • No Tor configuration needed                    │
│  • All TCP traffic → Tor transparently           │
│  • All DNS queries → Tor DNSPort                 │
│  • IPv6 blocked to prevent leaks                 │
│                                                   │
│  Normal development workflow:                     │
│  $ git clone https://github.com/user/repo.git   │
│  $ curl https://api.github.com                   │
│  $ npm install                                    │
└───────────────────────────────────────────────────┘
```

### How it works

1. **iptables NAT Rules**: Intercept VM traffic and redirect to Tor
   - TCP SYN packets → TransPort (9040)
   - UDP port 53 (DNS) → DNSPort (9053)

2. **Tor Transparent Proxy**: Routes traffic through Tor network
   - Each network gets dedicated TransPort binding
   - DNS resolution via Tor to prevent leaks

3. **IPv6 Protection**: Kernel-level IPv6 disabling
   - Per-interface sysctl configuration
   - Additional ip6tables blocking rules

4. **Network Isolation**: Optional complete air-gapping
   - Block HTTP/HTTPS direct access
   - Allow only specified ports to gateway
   - Internal network communication permitted

## Installation
### Flake Setup

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    nixtornet = {
      url = "git+https://codeberg.org/malik/nixtornet.git";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, nixtornet }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        nixtornet.nixosModules.default
        {
          networking.firewall.enable = true;  # Required!
          services.nixtornet.enable = true;
          # ... rest of configuration
        }
      ];
    };
  };
}
```
## Configuration

### Configuration Options

#### `services.nixtornet.enable`
- **Type**: `boolean`
- **Default**: `false`
- **Description**: Enable the Tor-libvirt network system

#### `services.nixtornet.networks`
- **Type**: `attrsOf (submodule)`
- **Default**: `{}`
- **Description**: Libvirt network definitions

##### Network Options

**`name`** (required)
- **Type**: `string`
- **Description**: Network name for libvirt

**`uuid`** (required)
- **Type**: `string`
- **Description**: Network UUID (generate with `uuidgen`)

**`bridge`**
- **Type**: `submodule`
- **Description**: Bridge interface configuration

```nix
bridge = {
  name = "virbr-tor";    # Bridge interface name (auto-generated from network name by default)
  stp = true;            # Spanning Tree Protocol
  delay = 0;             # Bridge delay in seconds
};
```

**`ip`**
- **Type**: `submodule`
- **Description**: IP address configuration

```nix
ip = {
  address = "192.168.100.1";
  netmask = "255.255.255.0";
  dhcp = {
    range = {
      start = "192.168.100.2";
      end = "192.168.100.254";
    };
  };
};
```

**`forward`**
- **Type**: `submodule`
- **Default**: `{ mode = "nat"; }`
- **Description**: Network forwarding mode

```nix
forward = {
  mode = "nat";  # Options: "nat", "none", "route", "bridge"
};
```

**`isolation`**
- **Type**: `submodule`
- **Default**: `{ enable = false; }`
- **Description**: Network isolation settings

```nix
isolation = {
  enable = true;
  blockHTTP = true;         # Block HTTP/HTTPS
  blockDNS = true;          # Block DNS
  allowedPorts = [ 22 ];    # Allowed ports to gateway
  cidrBits = 24;            # CIDR for isolation rules
};
```

**`active`**
- **Type**: `boolean`
- **Default**: `true`
- **Description**: Whether to automatically start the network

#### `services.nixtornet.tor`
- **Type**: `submodule`
- **Description**: Tor integration configuration

##### Tor Options

**`enable`**
- **Type**: `boolean`
- **Default**: `true`
- **Description**: Enable Tor integration for selected networks

**`networks`**
- **Type**: `listOf string`
- **Default**: `[]`
- **Description**: List of network names that should route through Tor
- **Example**: `[ "tor-dev" "tor-prod" ]`

**Important**: This module configures Tor via `services.tor.settings` automatically. For additional Tor configuration, use `services.tor.settings` directly:

```nix
# The module sets these automatically for transparent proxying:
services.tor.settings = {
  VirtualAddrNetworkIPv4 = "10.192.0.0/10";  # Auto-configured
  AutomapHostsOnResolve = true;              # Auto-configured
  TransPort = [ ... ];                       # Auto-configured per network
  DNSPort = [ ... ];                         # Auto-configured
};

# You can add your own settings:
services.tor.settings = {
  # These will be merged with the auto-configuration
  MaxCircuitDirtiness = 600;
  NumEntryGuards = 8;
  ExcludeNodes = "{cn},{ru}";
  StrictNodes = true;
};
```

#### `services.nixtornet.libvirt`
- **Type**: `submodule`
- **Description**: Libvirt connection settings

**`connection`**
- **Type**: `string`
- **Default**: `"qemu:///system"`
- **Description**: Libvirt connection URI

### Firewall Requirement

**This module requires the NixOS firewall to be enabled** for transparent proxying to work:

```nix
networking.firewall.enable = true;  # Required!
```

The module will show an assertion error at build time if the firewall is disabled.

## Usage Examples

### Example 1: Simple Tor Development Environment

Perfect for anonymous development work:

```nix
{
  networking.firewall.enable = true;  # Required

  services.nixtornet = {
    enable = true;

    tor = {
      enable = true;
      networks = [ "tor-dev" ];
    };

    networks = {
      tor-dev = {
        name = "tor-dev";
        uuid = "a1b2c3d4-1234-5678-90ab-cdef12345678";
        ip = {
          address = "192.168.100.1";
          netmask = "255.255.255.0";
          dhcp = {
            range = {
              start = "192.168.100.10";
              end = "192.168.100.250";
            };
          };
        };
      };
    };
  };
}
```

**Test the VM:**

```bash
# Inside the VM
curl https://check.torproject.org/api/ip
# {"IsTor":true,"IP":"xxx.xxx.xxx.xxx"}

curl https://api.ipify.org
# Shows Tor exit node IP
```

### Example 2: Multiple Networks with Different Security Profiles

```nix
{
  networking.firewall.enable = true;

  services.nixtornet = {
    enable = true;

    tor = {
      enable = true;
      # Only these networks use Tor
      networks = [ "tor-research" "tor-sensitive" ];
    };

    networks = {
      # Tor-enabled research network
      tor-research = {
        name = "tor-research";
        uuid = "11111111-1111-1111-1111-111111111111";
        ip = {
          address = "192.168.100.1";
          netmask = "255.255.255.0";
          dhcp.range = {
            start = "192.168.100.2";
            end = "192.168.100.254";
          };
        };
      };

      # Tor-enabled for sensitive work
      tor-sensitive = {
        name = "tor-sensitive";
        uuid = "22222222-2222-2222-2222-222222222222";
        ip = {
          address = "192.168.101.1";
          netmask = "255.255.255.0";
          dhcp.range = {
            start = "192.168.101.2";
            end = "192.168.101.254";
          };
        };
      };

      # Completely isolated network (no Tor, no internet)
      isolated = {
        name = "isolated";
        uuid = "33333333-3333-3333-3333-333333333333";
        forward.mode = "none";
        ip = {
          address = "192.168.200.1";
          netmask = "255.255.255.0";
          dhcp.range = {
            start = "192.168.200.2";
            end = "192.168.200.254";
          };
        };
        isolation = {
          enable = true;
          blockHTTP = true;
          blockDNS = true;
          allowedPorts = [ 22 ];  # Only SSH to gateway
        };
      };

      # Regular development network (no Tor)
      normal-dev = {
        name = "normal-dev";
        uuid = "44444444-4444-4444-4444-444444444444";
        ip = {
          address = "192.168.150.1";
          netmask = "255.255.255.0";
          dhcp.range = {
            start = "192.168.150.2";
            end = "192.168.150.254";
          };
        };
      };
    };
  };

  # Customize Tor configuration
  services.tor.settings = {
    # Performance tuning
    MaxCircuitDirtiness = 600;
    NewCircuitPeriod = 30;
    NumEntryGuards = 8;
    
    # Geographic preferences
    ExitNodes = "{us},{de},{nl},{ch}";
    ExcludeNodes = "{cn},{ru},{ir},{kp}";
    StrictNodes = true;
  };
}
```

### Example 4: Development Workflow Integration

Complete example for a development workstation:

```nix
{ config, pkgs, nixtornet, ... }:

{
  imports = [
    nixtornet.nixosModules.default
  ];

  networking.firewall.enable = true;

  services.nixtornet = {
    enable = true;

    tor = {
      enable = true;
      networks = [ "tor-komodo-dev" ];
    };

    networks = {
      tor-komodo-dev = {
        name = "tor-komodo-dev";
        uuid = "komodo12-3456-7890-abcd-ef1234567890";
        ip = {
          address = "192.168.120.1";
          netmask = "255.255.255.0";
          dhcp.range = {
            start = "192.168.120.10";
            end = "192.168.120.100";
          };
        };
      };
    };
  };

  # Optimize Tor for git operations
  services.tor.settings = {
    MaxCircuitDirtiness = 1800;
    NumEntryGuards = 8;
  };

  # Convenience aliases
  environment.shellAliases = {
    vm-start = "virsh start komodo-dev-vm";
    vm-stop = "virsh shutdown komodo-dev-vm";
    vm-console = "virsh console komodo-dev-vm";
    tor-status = "systemctl status tor";
    tor-circuits = "echo 'GETINFO circuit-status' | nc 127.0.0.1 9051";
  };
}
```

**Create the VM:**

```bash
# Generate UUIDs
uuidgen  # For VM
uuidgen  # For network (already in config above)

# Create VM
virt-install \
  --name komodo-dev-vm \
  --ram 8192 \
  --vcpus 4 \
  --disk size=50,format=qcow2 \
  --network network=tor-komodo-dev \
  --cdrom /path/to/nixos-minimal.iso \
  --graphics vnc,listen=127.0.0.1 \
  --noautoconsole

# Connect with virt-manager
virt-manager
```

**Inside the VM, test Tor connection:**

```bash
# Verify Tor
curl https://check.torproject.org/api/ip

# Check your apparent location
curl https://ipapi.co/json
```

## Security Considerations

### What This System Protects Against

✅ **IP Address Exposure**: All connections routed through Tor
✅ **DNS Leaks**: DNS queries handled via Tor DNSPort
✅ **IPv6 Leaks**: IPv6 disabled for Tor networks
✅ **Traffic Analysis**: Encrypted through Tor network
✅ **Geographic Location**: Hidden by Tor exit nodes
✅ **ISP Surveillance**: Traffic content hidden from ISP

### Limitations

❌ **Tor Network Attacks**: Exit nodes can see unencrypted traffic (use HTTPS!)
❌ **Timing Attacks**: Large data transfers may be correlatable
❌ **VM Escape**: If VM is compromised, host may be accessible
❌ **Side-Channel Attacks**: Hardware-level attacks still possible
❌ **Application-Level Leaks**: Applications may leak identifying information

### Best Practices

1. **Always Use HTTPS**
   ```bash
   # Good
   git clone https://github.com/user/repo.git
   
   # Bad (unencrypted over Tor)
   git clone http://github.com/user/repo.git
   ```

2. **Verify Tor Connection**
   ```bash
   # In VM before starting work
   curl https://check.torproject.org/api/ip | jq '.IsTor'
   # Should return: true
   ```

3. **Use Separate VMs for Different Projects**
   ```bash
   # Avoid correlation across projects
   virsh start project-a-vm  # For project A
   virsh start project-b-vm  # For project B
   ```

4. **Monitor for Leaks**
   ```bash
   # On host
   journalctl -u nixtornet-monitor -f
   
   # Watch for warnings
   ```

5. **Keep Software Updated**
   ```bash
   # Regular updates
   sudo nixos-rebuild switch --upgrade
   ```

## Monitoring

### Check System Status

```bash
# Service status
systemctl status tor
systemctl status libvirtd
systemctl status nixtornets
systemctl status nixtornet-monitor

# View logs
journalctl -u tor -f
journalctl -u nixtornets -f
journalctl -u nixtornet-monitor -f
```

### Verify Network Configuration

```bash
# List networks
virsh net-list --all

# Show network details
virsh net-dumpxml tor-dev

# Check if network is active
virsh net-info tor-dev
```

### Monitor Tor Connections

```bash
# Active Tor connections
ss -tn | grep :9040

# Tor circuit status (requires ControlPort to be configured)
# In your config: services.tor.settings.ControlPort = 9051;
echo 'GETINFO circuit-status' | nc 127.0.0.1 9051

# Connection count
ss -tn | grep :9040 | wc -l
```

### Verify iptables Rules

```bash
# NAT rules
sudo iptables -t nat -L PREROUTING -v -n | grep virbr

# Forward rules
sudo iptables -L FORWARD -v -n | grep virbr

# IPv6 blocking
sudo ip6tables -L FORWARD -v -n | grep virbr
```

## Troubleshooting

### VM Cannot Connect to Internet

**Symptoms:**
```bash
# In VM
curl google.com
# curl: (7) Failed to connect
```

**Solution:**
```bash
# 1. Check firewall is enabled
systemctl status firewall

# 2. Check Tor is running
sudo systemctl status tor

# 3. Verify service is running
sudo systemctl status nixtornets

# 4. Check iptables rules
sudo iptables -t nat -L -v -n | grep virbr

# 5. Restart services
sudo systemctl restart nixtornets
sudo systemctl restart tor

# 6. Verify network is active
virsh net-info tor-dev
```

### DNS Not Working

**Symptoms:**
```bash
# In VM
nslookup github.com
# ;; connection timed out
```

**Solution:**
```bash
# 1. Check VM's DNS configuration
cat /etc/resolv.conf
# Should contain: nameserver 192.168.100.1

# 2. Test Tor DNS
dig @192.168.100.1 github.com

# 3. Verify Tor DNS port
sudo netstat -tlnp | grep 9053

# 4. Check iptables DNS redirect
sudo iptables -t nat -L -v -n | grep 9053
```

### Slow Connection Speed

**Causes & Solutions:**

1. **Tor Network Congestion**
   ```nix
   # Add to configuration
   services.tor.settings = {
     NumEntryGuards = 8;
     MaxCircuitDirtiness = 1800;
   };
   ```

2. **Too Many Circuits**
   ```bash
   # Check circuit count (requires ControlPort)
   echo 'GETINFO circuit-status' | nc 127.0.0.1 9051 | wc -l
   
   # If > 50, restart Tor
   sudo systemctl restart tor
   ```

3. **VM Resource Constraints**
   ```bash
   # Increase VM resources
   virsh setmaxmem dev-vm 8388608 --config
   virsh setmem dev-vm 8388608
   ```

### IPv6 Leaking

**Check for leaks:**
```bash
# In VM
curl -6 https://api64.ipify.org
# Should fail or timeout

# On host, verify IPv6 is disabled
cat /proc/sys/net/ipv6/conf/virbr-tor/disable_ipv6
# Should return: 1
```

**Fix:**
```bash
# Manually disable if needed
sudo sysctl -w net.ipv6.conf.virbr-tor.disable_ipv6=1
```

### Firewall Not Enabled Error

**Symptoms:**
```bash
sudo nixos-rebuild switch
# error: assertion failed at /etc/nixos/modules/nixtornet/default.nix:397:9
# Tor-libvirt-network requires the firewall to be enabled for transparent proxying.
```

**Solution:**
```nix
{
  # Add to your configuration
  networking.firewall.enable = true;
}
```

## Testing

### Verify Tor Functionality

```bash
#!/usr/bin/env bash
# test-tor-network.sh

echo "Testing Tor-libvirt network..."

# 1. Check services
systemctl is-active tor >/dev/null && echo "✓ Tor is running" || echo "✗ Tor is not running"
systemctl is-active libvirtd >/dev/null && echo "✓ libvirtd is running" || echo "✗ libvirtd is not running"

# 2. Check firewall
systemctl is-active firewall >/dev/null && echo "✓ Firewall is enabled" || echo "✗ Firewall is not enabled"

# 3. Check network
virsh net-list --all | grep -q "tor-dev.*active" && echo "✓ tor-dev network is active" || echo "✗ tor-dev network is not active"

# 4. Check iptables
sudo iptables -t nat -L PREROUTING | grep -q "virbr-tor" && echo "✓ iptables rules present" || echo "✗ iptables rules missing"

# 5. Test Tor connection
curl -s https://check.torproject.org/api/ip | jq -r '.IsTor' | grep -q "true" && echo "✓ Tor connection works" || echo "✗ Tor connection failed"

echo "Test complete!"
```

### Test in VM

```bash
#!/usr/bin/env bash
# In VM: test-anonymity.sh

echo "Testing anonymity..."

# Check Tor
TOR_STATUS=$(curl -s https://check.torproject.org/api/ip | jq -r '.IsTor')
if [ "$TOR_STATUS" = "true" ]; then
    echo "✓ Connected via Tor"
    IP=$(curl -s https://check.torproject.org/api/ip | jq -r '.IP')
    echo "  Exit IP: $IP"
else
    echo "✗ NOT connected via Tor!"
    exit 1
fi

# Check IPv6 is blocked
if curl -6 --max-time 5 https://api64.ipify.org 2>&1 | grep -q "Could not resolve\|Connection refused\|Network is unreachable"; then
    echo "✓ IPv6 is properly blocked"
else
    echo "✗ IPv6 leak detected!"
    exit 1
fi

# Check DNS
DNS_RESULT=$(dig +short github.com)
if [ -n "$DNS_RESULT" ]; then
    echo "✓ DNS resolution works"
else
    echo "✗ DNS resolution failed"
    exit 1
fi

echo "All tests passed!"
```

## Related Documentation

- [NixVirt Documentation](https://github.com/AshleyYakeley/NixVirt) - Declarative libvirt configuration
- [Tor Project](https://www.torproject.org/) - Anonymity network
- [NixOS Tor Module](https://search.nixos.org/options?query=services.tor) - Upstream Tor configuration
- [libvirt Documentation](https://libvirt.org/) - Virtualization API

## Acknowledgments

- Built on [NixVirt](https://github.com/AshleyYakeley/NixVirt) by Ashley Yakeley
- Uses NixOS Tor module for reliable Tor configuration
- Inspired by Whonix and Tails for secure computing
- Tor Project for anonymity infrastructure
