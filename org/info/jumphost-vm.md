# SSH Jumphost VM for Tor-Isolated Networks

## The Problem

You can't SSH directly to VMs on the `tornet` network because all their traffic goes through Tor. Adding a second network interface to those VMs is dangerous - it creates leak risks.

## The Solution

Use a dedicated **jumphost VM** that sits between your host and Tor-VMs:

```
Host → Management-VM → Tor-VM
       (clearnet)      (over tornet)
```

## Network Setup

Two separate networks:

**`tornet`** (Tor-routed):
- 192.168.100.0/24
- All traffic through Tor
- Tor-VMs connect here only

**`management`** (regular NAT):
- 192.168.200.0/24  
- No Tor routing
- For host access to jumphost

## Config

### Networks

```nix
services.nixtornet = {
  enable = true;
  
  # Already exists as default
  networks.tornet = { ... };
  
  # Add management network
  networks.management = {
    name = "management";
    uuid = "12345678-abcd-1234-abcd-222222222222";
    ip = {
      address = "192.168.200.1";
      netmask = "255.255.255.0";
      dhcp.range = {
        start = "192.168.200.10";
        end = "192.168.200.100";
      };
    };
  };
  
  # Tor only for tornet!
  tor.networks = [ "tornet" ];
};
```

### Jumphost VM

Gets **both** interfaces:

```nix
# jumphost-vm.nix
{
  networking = {
    interfaces = {
      eth0.useDHCP = true;  # management network
      eth1.useDHCP = true;  # tornet
    };
    
    # Default route through management (NOT Tor)
    defaultGateway = "192.168.200.1";
    nameservers = [ "192.168.200.1" ];
  };
  
  services.openssh.enable = true;
  
  # Optional: useful tools
  environment.systemPackages = with pkgs; [ vim tmux ];
}
```

### Tor-VM

Gets **only** tornet:

```nix
# tor-vm.nix
{
  networking = {
    interfaces.eth0.useDHCP = true;  # tornet only!
    defaultGateway = "192.168.100.1";
    nameservers = [ "192.168.100.1" ];
    enableIPv6 = false;
  };
  
  # Emergency access
  boot.kernelParams = [ "console=ttyS0" ];
  
  services.openssh.enable = true;
  
  # Extra paranoid: block all non-Tor traffic
  networking.firewall.extraCommands = ''
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -d 192.168.100.0/24 -j ACCEPT
    iptables -A OUTPUT -j DROP
  '';
}
```

## Usage

**SSH chain:**
```bash
# Host → Jumphost
ssh user@192.168.200.10

# Jumphost → Tor-VM
ssh user@192.168.100.50
```

**Direct with ProxyJump:**
```bash
ssh -J user@192.168.200.10 user@192.168.100.50
```

**File transfer:**
```bash
scp -J user@192.168.200.10 file.txt user@192.168.100.50:/tmp/
```

**Emergency access (no network):**
```bash
virsh console tor-vm
```

## Why This is Secure

✅ Tor-VM has **zero** direct host access  
✅ No second interface on Tor-VM = no leaks  
✅ All Tor-VM internet traffic goes through Tor  
✅ Management traffic completely separated  
✅ Firewall prevents accidental clearnet usage  

## Quick Verify

**On Tor-VM:**
```bash
# Should show Tor exit IP
curl https://check.torproject.org/api/ip

# Should only show eth0 + lo
ip link show

# Should only have route to 192.168.100.0/24
ip route show
```

## Architecture

```
┌─ Host ─────────────────────────┐
│                                │
│  virbr-mgmt      virbr-tornet │
│  192.168.200.1   192.168.100.1│
└────┬─────────────────┬─────────┘
     │                 │
┌────┴───────┐    ┌────┴────────┐
│ Jumphost   │    │ Tor-VM      │
│            │    │             │
│ eth0 eth1  │    │ eth0        │
│  ↓    ↓    │    │  ↓          │
│ mgmt tornet│◄───┤ tornet only │
└────────────┘SSH └─────────────┘
                        ↓
                    All traffic
                    through Tor
```

That's it. Simple, secure, no leaks.
