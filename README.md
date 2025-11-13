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
   # SSH credentials
   SSH_USERNAME="your_username"
   SSH_PASSWORD="your_password"
   
   # API endpoints and credentials
   LIBRENMS_URL="https://your-librenms-server"
   LIBRENMS_TOKEN="your_api_token"
   
   GRAYLOG_URL="https://your-graylog-server"
   GRAYLOG_TOKEN="your_api_token"
   
   APIC_URL="https://your-apic-server"
   APIC_USERNAME="your_username"
   APIC_PASSWORD="your_password"
   
   ARUBA_URL="https://your-aruba-controller:4343"
   ARUBA_USERNAME="your_username"
   ARUBA_PASSWORD='your_password'  # Use single quotes for special chars
   ```

---

## 🔧 MCP Client Configuration

### Claude Desktop

**macOS/Linux:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "NET-AI-ASSISTANT": {
      "command": "uv",
      "args": ["--directory", "/path/to/git-netai", "run", "python", "main.py"],
      "env": {"PYTHONPATH": "/path/to/git-netai"}
    }
  }
}
```

### Warp AI

**Location:** `~/.warp/mcp_config.json`

```json
{
  "mcpServers": {
    "NET-AI-ASSISTANT": {
      "command": "uv",
      "args": ["run", "python", "main.py"],
      "env": {"PYTHONPATH": "/path/to/git-netai"},
      "working_directory": "/path/to/git-netai"
    }
  }
}
```

---

## 📚 Usage

The server provides **74 MCP tools** organized across 5 categories:

### Tool Categories

| Category | Tools | Description |
|----------|-------|-------------|
| **SSH Command Execution** | 1 | Execute CLI commands on 150+ network device types via SSH |
| **Network Monitoring (LibreNMS)** | 17 | Device, interface, sensor monitoring and event tracking |
| **Log Management (Graylog)** | 4 | Centralized log search, streams, and analytics |
| **Data Center Fabric (Cisco APIC)** | 35 | ACI fabric health, tenants, policies, and capacity planning |
| **Wireless Management (Aruba)** | 17 | AP monitoring, client tracking, RF optimization, and QoS |

### Natural Language Examples (Claude Desktop / Warp)

```
Execute "show version" on device 10.1.1.1 using cisco_ios
```

```
Show me all devices from location "datacenter-1"
```

```
Search Graylog for "authentication failure" in the last hour
```

```
List all connected clients on the Aruba controller
```

### Python API Examples

```python
from connectors import run_network_command

# Cisco IOS with auto-detection
result = run_network_command(
    ip_address="10.1.1.1",
    command="show version"
)

# Cisco Nexus (explicit device type)
result = run_network_command(
    ip_address="10.1.10.100",
    command="show ip int br",
    device_type="cisco_nxos"
)
```

```python
from connectors.librenms_con import search_devices

# Search devices by location
devices = search_devices("location", "datacenter-1")
```

```python
from connectors.graylog_con import search_logs

# Search logs in the last hour
logs = search_logs("error", relative_range=3600)
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

### Quick Tests

**Verify server:**
```bash
uv run python -c "from main import mcp; print('✓ Server OK:', mcp.name)"
```

**Test all connectors:**
```bash
uv run python test_connectors.py
```

### Individual Connector Tests

```python
# SSH Connection
from connectors import run_network_command
result = run_network_command("10.1.1.1", "show version", "cisco_ios")

# LibreNMS
from connectors.librenms_con import search_devices
devices = search_devices("location", "datacenter-1")

# Graylog
from connectors.graylog_con import search_logs
logs = search_logs("error", relative_range=3600)

# Cisco APIC
from connectors.apic_con import get_apic_fabric_health
health = get_apic_fabric_health()

# Aruba
from connectors.aruba_con import ArubaConnector
aruba = ArubaConnector()
info = aruba.get_controller_info()
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

| Issue | Solution |
|-------|----------|
| **SSH Connection Fails** | Verify network connectivity with `ping`, test SSH manually, check `.env` credentials |
| **Server Not Starting** | Verify `uv --version` and `python --version` (≥3.12), reinstall with `uv sync` |
| **Auto-detection Fails** | Specify device type explicitly: `run_network_command("10.1.1.1", "show version", "cisco_ios")` |
| **Enable Debug Logs** | Add to connector files: `import logging; logging.basicConfig(level=logging.DEBUG)` |

---

## 🤝 Contributing

Contributions are welcome! Fork the repo, create a feature branch, commit your changes, and open a Pull Request.

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

- **Issues**: [GitHub Issues](https://github.com/angoran/git-netai/issues)

---

## 🗺️ Roadmap

### ✅ Completed
- [x] SSH connector for 150+ network device vendors (Netmiko)
- [x] LibreNMS API connector - 17 tools for network monitoring
- [x] Graylog API connector - 4 tools for log management
- [x] Cisco APIC API connector - 35 tools for data center fabric
- [x] Aruba WiFi Controller API connector - 17 tools for wireless management

### 🚀 Future Enhancements
- [ ] Integration Cisco NDFC API
- [ ] Integration Cisco DNA API
- [ ] Add more LibreNMS endpoints (alerts, device groups, inventory)
- [ ] Expand Graylog functionality (alert management, dashboards)
- [ ] Add more APIC endpoints (troubleshooting, change management)
- [ ] Expand Aruba capabilities (RF analytics, heat maps)

---