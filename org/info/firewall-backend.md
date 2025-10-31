# Firewall Backend Compatibility

This module supports **both iptables and nftables** firewall backends with automatic detection and configuration.

## Supported Backends

### iptables (Traditional)
- **Status**: Fully supported
- **Default on**: Most NixOS systems (when `networking.nftables.enable` is not set)
- **Implementation**: Uses `networking.firewall.extraCommands` for rule injection
- **Advantages**: 
  - Mature and battle-tested
  - Extensive tooling ecosystem
  - Wide third-party compatibility

### nftables (Modern)
- **Status**: Fully supported (automatic)
- **Enable with**: `networking.nftables.enable = true`
- **Implementation**: Uses `networking.nftables.tables` API for declarative rule management
- **Advantages**:
  - More efficient rule evaluation (set-based matching)
  - Atomic rule updates (entire tables replaced atomically)
  - Better performance with complex rulesets
  - Native IPv4/IPv6 family handling

## Automatic Backend Detection

The module automatically detects which firewall backend is active based on your NixOS configuration. **No manual configuration is required** - the appropriate backend is selected automatically.

```nix
# Example 1: Using iptables (default)
{
  networking.firewall.enable = true;  # Uses iptables backend
  
  services.nixtornet = {
    enable = true;
    # ... configuration works identically
  };
}

# Example 2: Using nftables
{
  networking = {
    firewall.enable = true;
    nftables.enable = true;  # Module automatically uses nftables backend
  };
  
  services.nixtornet = {
    enable = true;
    # ... same configuration, different backend
  };
}
```

## Feature Parity

Both backends provide **identical functionality**:

| Feature | iptables | nftables | Implementation |
|---------|----------|----------|----------------|
| Transparent Tor routing | ✅ | ✅ | TCP → TransPort 9040 |
| DNS redirection | ✅ | ✅ | UDP port 53 → DNSPort 9053 |
| IPv6 blocking | ✅ | ✅ | Dedicated IPv6 drop rules |
| Network isolation | ✅ | ✅ | HTTP/HTTPS/DNS filtering |
| Allowed port whitelisting | ✅ | ✅ | Per-network port lists |
| Automatic cleanup | ✅ | ✅ | On service stop/restart |
| Multi-network support | ✅ | ✅ | Multiple Tor networks |

## Verify Your Backend

Check which backend is currently active on your system:

```bash
# Method 1: Check nftables service
systemctl is-active nftables && echo "Using nftables" || echo "Using iptables"

# Method 2: Query NixOS configuration
nixos-option networking.nftables.enable

# Method 3: Check for active rules
# For iptables:
sudo iptables -t nat -L -n | grep -q virbr && echo "iptables is active"

# For nftables:
sudo nft list tables 2>/dev/null | grep -q nixtornet && echo "nftables is active"
```

## Backend-Specific Rule Inspection

### Inspecting iptables Rules

```bash
# View NAT rules for Tor redirection
sudo iptables -t nat -L PREROUTING -v -n | grep virbr

# View forwarding rules
sudo iptables -L FORWARD -v -n | grep virbr

# View IPv6 blocking rules
sudo ip6tables -L FORWARD -v -n | grep virbr

# Export complete ruleset
sudo iptables-save -t nat | grep nixtornet
```

### Inspecting nftables Rules

```bash
# List Tor transparent proxy table
sudo nft list table ip nixtornet-tor

# List network isolation table (if configured)
sudo nft list table ip nixtornet-isolation

# List IPv6 blocking table
sudo nft list table ip6 nixtornet-ipv6

# View all nixtornet tables
sudo nft list ruleset | grep -A 20 "table.*nixtornet"

# Export in different formats
sudo nft -j list table ip nixtornet-tor  # JSON format
sudo nft -nn list table ip nixtornet-tor  # Numeric output
```

## Migration Between Backends

Switching between iptables and nftables is seamless:

```nix
# Current configuration with iptables
{
  networking.firewall.enable = true;
  services.nixtornet.enable = true;
  # ... networks configured
}

# Switch to nftables - just add one line:
{
  networking = {
    firewall.enable = true;
    nftables.enable = true;  # This is all you need to change!
  };
  services.nixtornet.enable = true;
  # ... same network configuration works unchanged
}
```

After rebuilding:
```bash
sudo nixos-rebuild switch
```

The module automatically:
1. Detects the new backend
2. Removes old iptables rules
3. Creates equivalent nftables tables
4. Maintains identical network behavior

## Performance Considerations

### When to Use nftables

**Recommended for:**
- ✅ New NixOS installations (23.05+)
- ✅ Systems with multiple Tor networks configured
- ✅ High-throughput VM environments
- ✅ Complex isolation rules
- ✅ Modern hardware (better CPU utilization)

**Advantages:**
- 30-40% better throughput with many rules
- Lower CPU overhead for rule evaluation
- Atomic updates prevent transient rule gaps
- More efficient set-based matching

### When to Use iptables

**Recommended for:**
- ✅ Existing systems with iptables workflows
- ✅ Compatibility with third-party tools expecting iptables
- ✅ Environments requiring extensive iptables logging tools
- ✅ Legacy system integration

**Advantages:**
- Well-known troubleshooting procedures
- Extensive documentation and examples
- Mature tooling ecosystem
- Predictable behavior

## Troubleshooting Backend Issues

### Rules Not Applied

**For iptables:**
```bash
# Check if extraCommands executed
sudo journalctl -u firewall -n 50 | grep nixtornet

# Manually verify rule exists
sudo iptables -t nat -C PREROUTING -i virbr-tor-dev -p tcp --syn -j REDIRECT --to-ports 9040
# Exit code 0 = rule exists, 1 = rule missing
```

**For nftables:**
```bash
# Check if tables were created
sudo nft list tables | grep nixtornet

# Verify table content
sudo nft list table ip nixtornet-tor | grep -q "redirect to :9040"
# No output with exit 0 = rule exists
```

### Backend Conflict

**Symptoms:** Both iptables and nftables rules present simultaneously

```bash
# Check for conflicts
sudo iptables -t nat -L -n | grep -q virbr && sudo nft list tables | grep -q nixtornet && \
  echo "WARNING: Both backends are active!"
```

**Solution:**
```nix
# Ensure only one backend is configured
{
  networking = {
    firewall.enable = true;
    nftables.enable = false;  # or true, but not both active
  };
}
```

## Technical Implementation Details

### iptables Backend

- **Rule Injection**: `networking.firewall.extraCommands`
- **Cleanup**: `networking.firewall.extraStopCommands`
- **Rule Format**: Shell commands (`iptables`, `ip6tables`)
- **Persistence**: Rules recreated on every firewall reload

### nftables Backend

- **Rule Definition**: `networking.nftables.tables.*`
- **Cleanup**: Automatic (NixOS removes tables when module is disabled)
- **Rule Format**: Declarative table definitions
- **Persistence**: Tables managed by NixOS configuration
- **Table Names**:
  - `nixtornet-tor`: Transparent proxy and NAT rules
  - `nixtornet-isolation`: Network isolation rules
  - `nixtornet-ipv6`: IPv6 blocking rules

## Example: Viewing Active Configuration

```bash
#!/usr/bin/env bash
# show-nixtornet-backend.sh

echo "=== NixTorNet Backend Status ==="
echo

# Detect backend
if systemctl is-active nftables >/dev/null 2>&1; then
    BACKEND="nftables"
    echo "Active Backend: nftables"
    echo
    echo "Tables:"
    sudo nft list tables 2>/dev/null | grep nixtornet || echo "  (none found)"
    echo
    echo "Tor Proxy Rules:"
    sudo nft list table ip nixtornet-tor 2>/dev/null | grep -E "redirect|iifname" || echo "  (table not found)"
else
    BACKEND="iptables"
    echo "Active Backend: iptables"
    echo
    echo "NAT Rules:"
    sudo iptables -t nat -L PREROUTING -n | grep virbr || echo "  (none found)"
    echo
    echo "Forward Rules:"
    sudo iptables -L FORWARD -n | grep virbr | head -5 || echo "  (none found)"
fi

echo
echo "IPv6 Status:"
for iface in $(ls /sys/class/net/ | grep virbr); do
    disabled=$(cat /sys/class/net/$iface/disable_ipv6 2>/dev/null || echo "N/A")
    echo "  $iface: $([ "$disabled" = "1" ] && echo "disabled ✓" || echo "enabled ⚠")"
done
```

Make executable and run:
```bash
chmod +x show-nixtornet-backend.sh
sudo ./show-nixtornet-backend.sh
```
