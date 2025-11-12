# NET-AI-ASSISTANT 🌐

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![FastMCP](https://img.shields.io/badge/FastMCP-2.13+-green.svg)](https://github.com/jlowin/fastmcp)
[![Netmiko](https://img.shields.io/badge/Netmiko-4.0+-orange.svg)](https://github.com/ktbyers/netmiko)

A powerful MCP (Model Context Protocol) server for network device management via SSH. Execute CLI commands on routers, switches, and firewalls from 200+ vendors directly through AI assistants like Claude Desktop and Warp AI.

---

## 🎯 Features

- **Multi-Vendor Support**: Works with Cisco, MikroTik, Palo Alto, Juniper, Aruba, HP, and 150+ other vendors
- **MCP Integration**: Seamlessly integrates with Claude Desktop, Warp AI, and other MCP-compatible tools
- **Auto-Detection**: Automatically detects device types or allows manual specification
- **Secure**: SSH-based connections with credential management via environment variables
- **Fast**: Built with UV for lightning-fast dependency management
- **Simple**: Clean API with just one powerful tool function

---

## 🚀 Quick Start

### Prerequisites

- Python 3.12 or higher
- [UV](https://docs.astral.sh/uv/) package manager
- SSH access to network devices
- Claude Desktop or Warp AI (for MCP integration)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/git-netai.git
   cd git-netai
   ```

2. **Sync dependencies with UV**
   ```bash
   uv sync
   ```

3. **Configure SSH credentials**

   Create a `.env` file in the project root:
   ```bash
   SSH_USERNAME="your_username"
   SSH_PASSWORD="your_password"
   ```

4. **Test the installation**
   ```bash
   uv run python -c "from main import mcp; print('✓ Server OK:', mcp.name)"
   ```

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

See [CLAUDE_DESKTOP_SETUP.md](CLAUDE_DESKTOP_SETUP.md) for detailed instructions.

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

### MCP Tool: `execute_network_device_command`

Execute CLI commands on network devices via SSH.

**Parameters:**
- `ip_address` (string, required): IP address of the target device
- `command` (string, required): CLI command to execute
- `device_type` (string, optional): Netmiko device type (default: "autodetect")

### Examples

#### In Claude Desktop or Warp AI

```
Execute "show version" on device 10.1.1.1 using cisco_ios
```

```
Get interface status from Cisco Nexus 10.1.10.100 with "show ip int br"
```

```
Run "/system resource print" on MikroTik router 192.168.1.1
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

## 📁 Project Structure

```
git-netai/
├── main.py                    # MCP server entry point
├── connectors/
│   ├── __init__.py           # Package initialization
│   └── ssh_conn.py           # SSH connection module
├── .env                       # SSH credentials (not committed)
├── .gitignore                 # Git ignore rules
├── pyproject.toml             # Project configuration
├── requirements.txt           # Python dependencies
├── uv.lock                    # UV lock file
└── README.md              # This file
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

### Test SSH Connection

```python
from connectors import run_network_command

result = run_network_command(
    ip_address="10.1.10.100",
    command="show ip int br",
    device_type="cisco_nxos"
)
print(result)
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
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/git-netai/discussions)

---

## 🗺️ Roadmap

- [ ] Add support for batch commands
- [ ] Implement configuration backup/restore
- [ ] Add support for SCP/SFTP file transfers
- [ ] Create web dashboard for device management
- [ ] Add support for authentication via SSH keys
- [ ] Implement command templates and macros
- [ ] Add audit logging and compliance reporting

---