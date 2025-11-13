# NET-AI-ASSISTANT 🌐
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![FastMCP](https://img.shields.io/badge/FastMCP-2.13+-green.svg)](https://github.com/jlowin/fastmcp)
[![Netmiko](https://img.shields.io/badge/Netmiko-4.0+-orange.svg)](https://github.com/ktbyers/netmiko)
[![MCP Tools](https://img.shields.io/badge/MCP_Tools-74-brightgreen.svg)]()
[![Connectors](https://img.shields.io/badge/Connectors-5-success.svg)]()

A comprehensive MCP (Model Context Protocol) server for network infrastructure management. Execute CLI commands on network devices from 150+ vendors, monitor device health and performance, analyze centralized logs, manage data center fabric, and control wireless infrastructure—all through AI assistants like Claude Desktop and Warp.

**Key Features:**
- **SSH Command Execution**: Direct CLI access to routers, switches, and firewalls (Netmiko)
- **Network Monitoring**: Real-time device, interface, and sensor monitoring (LibreNMS)
- **Log Management**: Centralized log search and analysis (Graylog)
- **Data Center Operations**: Cisco ACI fabric management and analytics (APIC)
- **Wireless Management**: AP monitoring, client tracking, and RF optimization (Aruba)

---

## 🎯 Features

- **Multi-Vendor SSH Support**: Works with Cisco, MikroTik, Palo Alto, Juniper, Aruba, HP, and 150+ other vendors
- **Network Monitoring (LibreNMS)**: Monitor 300+ devices, interfaces, sensors, and events in real-time
- **Log Analytics (Graylog)**: Search and analyze centralized logs across your infrastructure
- **Data Center Fabric (Cisco APIC)**: Manage ACI fabric health, topology, and security policies
- **Wireless Control (Aruba)**: Monitor APs, clients, rogue detection, and RF optimization
- **MCP Integration**: Seamlessly integrates with Claude Desktop, Warp AI, and other MCP-compatible tools
- **Auto-Detection**: Automatically detects device types or allows manual specification
- **Secure**: Credential management via environment variables
- **Fast**: Built with UV for lightning-fast dependency management

---

## 🚀 Quick Start

### Prerequisites

- Python 3.12 or higher
- [UV](https://docs.astral.sh/uv/) package manager
- SSH access to network devices
- Claude Desktop or Warp (for native MCP integration)

### Installation

1. **Clone the repository**
   
   ```bash
   git clone https://github.com/angoran/git-netai.git
   cd git-netai
   ```
   
2. **Sync dependencies with UV**
   ```bash
   uv sync
   ```

3. **Configure credentials**

   Create a `.env` file in the project root:
   ```bash
   # SSH credentials for network devices
   SSH_USERNAME="your_username"
   SSH_PASSWORD="your_password"
   
   # LibreNMS API credentials
   LIBRENMS_URL="https://your-librenms-server"
   LIBRENMS_TOKEN="your_api_token"
   
   # Graylog API credentials
   GRAYLOG_URL="https://your-graylog-server"
   GRAYLOG_TOKEN="your_api_token"
   
   # Cisco APIC API credentials
   APIC_URL="https://your-apic-server"
   APIC_USERNAME="your_username"
   APIC_PASSWORD="your_password"
   
   # Aruba WiFi Controller API credentials
   ARUBA_URL="https://your-aruba-controller:4343"
   ARUBA_USERNAME="your_username"
   ARUBA_PASSWORD='your_password'  # Use single quotes for special characters
   ```

   **Note:** For passwords with special characters (like `$`), use single quotes to prevent environment variable expansion.

---

## 🔧 Configuration

### For Claude Desktop

#### macOS / Linux

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `~/.config/Claude/claude_desktop_config.json` (Linux):

```json
{
  "mcpServers": {
    "NET-AI-ASSISTANT": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/git-netai",
        "run",
        "python",
        "main.py"
      ],
      "env": {
        "PYTHONPATH": "/path/to/git-netai"
      }
    }
  }
}
```

#### Windows

Add to `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "NET-AI-ASSISTANT": {
      "command": "uv",
      "args": [
        "--directory",
        "C:/path_to_git-netai",
        "run",
        "python",
        "main.py"
      ],
      "env": {
        "PYTHONPATH": "C:/path_to_git-netai"
      }
    }
  }
}
```

**Note:** On Windows, use double backslashes (`\\`) in paths or forward slashes (`/`).

### For Warp AI

Add to `~/.warp/mcp_config.json`:

```json
{
  "mcpServers": {
    "NET-AI-ASSISTANT": {
      "command": "uv",
      "args": [
        "run",
        "python",
        "main.py"
      ],
      "env": {
        "PYTHONPATH": "/path/to/git-netai"
      },
      "working_directory": "/path/to/git-netai"
    }
  }
}
```

See [WARP_SETUP.md](WARP_SETUP.md) for detailed instructions.

---

## 📚 Usage

The server provides **74 MCP tools** across 5 categories:

### 1. SSH Command Execution (1 tool)

**`execute_network_device_command`** - Execute CLI commands on network devices via SSH

**Parameters:**
- `ip_address` (string, required): IP address of the target device
- `command` (string, required): CLI command to execute
- `device_type` (string, optional): Netmiko device type (default: "autodetect")

### 2. Network Monitoring - LibreNMS (17 tools)

- Device search and filtering
- Interface monitoring and statistics
- Sensor monitoring (temperature, voltage, etc.)
- Port history and switch port status
- Event logs and location tracking
- Smart queries for devices, interfaces, sensors, and ports

### 3. Log Management - Graylog (4 tools)

- `search_logs` - Search logs with queries
- `get_streams` - List all log streams
- `get_stream_stats` - Get stream statistics
- `get_system_overview` - System health overview

### 4. Data Center Fabric - Cisco APIC (35 tools)

- Fabric health and topology
- Tenant and EPG management
- Multicast and traffic analytics
- Security policies and contracts
- Capacity planning
- Node and endpoint tracking

### 5. Wireless Infrastructure - Aruba (17 tools)

- Access Point monitoring
- Client connectivity tracking
- Rogue AP detection
- RF optimization and channel management
- WLAN/SSID configuration
- QoS and bandwidth control
- License compliance

### Examples

#### In Claude Desktop or Warp

**SSH Commands:**
```
Execute "show version" on device 10.1.1.1 using cisco_ios
```

```
Get interface status from Cisco Nexus 10.1.10.100 with "show ip int br"
```

**Network Monitoring:**
```
Show me all devices from location "datacenter-1"
```

```
Get interface statistics for device "core-switch-01"
```

**Log Analysis:**
```
Search Graylog for "authentication failure" in the last hour
```

**Data Center:**
```
Show me the health status of the APIC fabric
```

**Wireless:**
```
List all connected clients on the Aruba controller
```

#### Direct Python Usage

```python
from connectors import run_network_command

# Cisco IOS
result = run_network_command(
    ip_address="10.1.1.1",
    command="show version",
    device_type="cisco_ios"
)
print(result)

# Cisco Nexus
result = run_network_command(
    ip_address="10.1.10.100",
    command="show ip int br",
    device_type="cisco_nxos"
)

# MikroTik RouterOS
result = run_network_command(
    ip_address="192.168.1.1",
    command="/system resource print",
    device_type="mikrotik_routeros"
)

# Auto-detection
result = run_network_command(
    ip_address="10.1.1.50",
    command="show version"
    # device_type will be auto-detected
)
```

---

## 🛠 Supported Device Types

| Vendor | Device Type | Example Command |
|--------|-------------|-----------------|
| Cisco IOS | `cisco_ios` | `show version` |
| Cisco NX-OS | `cisco_nxos` | `show ip int br` |
| Cisco ASA | `cisco_asa` | `show firewall` |
| MikroTik | `mikrotik_routeros` | `/system resource print` |
| Palo Alto | `paloalto_panos` | `show system info` |
| Juniper | `juniper_junos` | `show version` |
| Aruba | `aruba_os` | `show version` |
| HP Comware | `hp_comware` | `display version` |

For a complete list of 150+ supported devices, see [Netmiko Supported Platforms](https://github.com/ktbyers/netmiko/blob/develop/PLATFORMS.md).

---

## 🌐 API Connectors

### LibreNMS - Network Monitoring
Monitor network devices, interfaces, sensors, and events in real-time through LibreNMS API.

**Available Tools (17):**
- Device management (search, filter, statistics)
- Interface monitoring and port history
- Sensor monitoring (temperature, voltage, power)
- Event logs and location tracking
- Smart queries for optimized data retrieval

### Graylog - Log Management
Search and analyze centralized logs across your infrastructure.

**Available Tools (4):**
- Advanced log search with query syntax
- Stream management and statistics
- System health overview
- Log aggregation analysis

### Cisco APIC - Data Center Fabric
Comprehensive management of Cisco ACI fabric infrastructure.

**Available Tools (35):**
- Fabric health monitoring and topology
- Tenant, EPG, and contract management
- Multicast tree and traffic analytics
- Security policy management
- Capacity planning and resource tracking
- Node and endpoint monitoring

### Aruba WiFi Controller - Wireless Management
Complete wireless infrastructure management through Aruba controller API.

**Available Tools (17):**
- Access Point monitoring and configuration
- Client connectivity and association tracking
- Rogue AP detection and security
- RF optimization and channel management
- WLAN/SSID configuration
- QoS, bandwidth control, and license compliance

**Note:** For passwords containing special characters (like `$`, `!`, `@`), always use single quotes in your `.env` file to prevent shell variable expansion. Example: `ARUBA_PASSWORD='P@$$w0rd'`

---

## 📁 Project Structure

```
git-netai/
├── main.py                    # MCP server entry point
├── connectors/
│   ├── __init__.py           # Package initialization
│   ├── ssh_conn.py           # SSH connection module
│   ├── librenms_con.py       # LibreNMS API connector
│   ├── graylog_con.py        # Graylog API connector
│   ├── apic_con.py           # Cisco APIC API connector
│   └── aruba_con.py          # Aruba WiFi Controller API connector
├── .env                       # Credentials (not committed)
├── .gitignore                 # Git ignore rules
├── pyproject.toml             # Project configuration
├── uv.lock                    # UV lock file
├── test_connectors.py         # Connector smoke tests
└── README.md                  # This file
```

---

## 🧪 Testing

### Test Server Import

```bash
uv run python -c "from main import mcp; print('✓ Server OK:', mcp.name)"
```

**Expected output:**
```
✓ Server OK: NET-AI-ASSISTANT
```

### Test All Connectors

Run the smoke test suite to verify all connectors:

```bash
uv run python test_connectors.py
```

**Expected output:**
```
======================================================================
CONNECTOR SMOKE TESTS
======================================================================

Testing LibreNMS connector...
  ✓ Import successful
  ✓ Connection test passed

Testing Graylog connector...
  ✓ Import successful
  ✓ Connection test passed

Testing Cisco APIC connector...
  ✓ Import successful
  ✓ Connection test passed

Testing Aruba WiFi connector...
  ✓ Import successful
  ✓ Connection test passed

======================================================================
SUMMARY
======================================================================
Connectors tested: 4
Import successful: 4/4
Connection successful: 4/4

✓ All tests passed!
```

### Test Individual Connectors

**SSH Connection:**
```python
from connectors import run_network_command

result = run_network_command(
    ip_address="10.1.10.100",
    command="show ip int br",
    device_type="cisco_nxos"
)
print(result)
```

**LibreNMS:**
```python
from connectors.librenms_con import search_devices

devices = search_devices("location", "datacenter-1")
print(f"Found {len(devices)} devices")
```

**Graylog:**
```python
from connectors.graylog_con import search_logs

logs = search_logs("error", relative_range=3600)
print(logs)
```

**Cisco APIC:**
```python
from connectors.apic_con import get_apic_fabric_health

health = get_apic_fabric_health()
print(health)
```

**Aruba:**
```python
from connectors.aruba_con import ArubaConnector

aruba = ArubaConnector()
info = aruba.get_controller_info()
print(info)
aruba.logout()
```

---

## 🔒 Security

- **Credentials**: Never commit the `.env` file (already in `.gitignore`)
- **Production**: Use a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager, 1Password CLI)
- **Network**: Ensure SSH connections are properly secured and firewalled
- **Permissions**: Use service accounts with minimum required privileges
- **Logging**: Disable session logging in production to avoid credential leakage

---

## 🐛 Troubleshooting

### SSH Connection Errors

```bash
# Test network connectivity
ping 10.1.1.1

# Test SSH manually
ssh username@10.1.1.1

# Check credentials in .env
cat .env
```

### Server Not Starting

```bash
# Verify UV installation
uv --version

# Check Python version (must be 3.12+)
uv run python --version

# Reinstall dependencies
rm -rf .venv
uv sync
```

### Device Type Detection Fails

If auto-detection doesn't work, specify the device type explicitly:

```python
# Instead of:
run_network_command("10.1.1.1", "show version")

# Use:
run_network_command("10.1.1.1", "show version", "cisco_ios")
```

### Enable Debug Logging

Edit `connectors/ssh_conn.py`:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Quick Contribution Guide

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [FastMCP](https://github.com/jlowin/fastmcp) - Fast MCP server framework
- [Netmiko](https://github.com/ktbyers/netmiko) - Multi-vendor network device library
- [UV](https://docs.astral.sh/uv/) - Lightning-fast Python package manager
- [Anthropic](https://www.anthropic.com/) - For the MCP protocol and Claude

---

## 📞 Support

- **Documentation**: See the [docs](docs/) folder
- **Issues**: [GitHub Issues](https://github.com/yourusername/git-netai/issues)
- **Discussions**: [GitHub Discussions](https://github.com/angoran/git-netai)

---

## 🗺️ Roadmap

### ✅ Completed
- [x] SSH connector for 150+ network device vendors (Netmiko)
- [x] LibreNMS API connector - 17 tools for network monitoring
- [x] Graylog API connector - 4 tools for log management
- [x] Cisco APIC API connector - 35 tools for data center fabric
- [x] Aruba WiFi Controller API connector - 17 tools for wireless management

### 🚀 Future Enhancements
- [ ] Add more LibreNMS endpoints (alerts, device groups, inventory)
- [ ] Expand Graylog functionality (alert management, dashboards)
- [ ] Add more APIC endpoints (troubleshooting, change management)
- [ ] Expand Aruba capabilities (RF analytics, heat maps)

---