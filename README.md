# netai-o 🌐

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![FastMCP](https://img.shields.io/badge/FastMCP-2.13+-green.svg)](https://github.com/jlowin/fastmcp)
[![UV](https://img.shields.io/badge/UV-Package_Manager-orange.svg)](https://docs.astral.sh/uv/)
[![Async](https://img.shields.io/badge/Architecture-100%25_Async-brightgreen.svg)]()

**Asynchronous MCP (Model Context Protocol) server for unified multi-platform network infrastructure management.**

Expose your network devices, WiFi controllers, monitoring systems, and data centers through a unified API accessible by Claude Desktop, Warp AI, and any MCP-compatible client.

---

## 🎯 Key Features

### 100% Asynchronous Architecture
- **Async/await engine**: All I/O operations leverage `asyncio`, `asyncssh`, and `httpx` for optimal performance
- **Parallel execution**: Native support for multi-device operations with timeout protection
- **Persistent sessions**: Reusable HTTP connections with keepalive to minimize latency
- **Smart JWT caching**: Thread-safe authentication token management with automatic renewal

### 9 Specialized Connectors

| Connector | Type | MCP Tools | Description |
|-----------|------|-----------|-------------|
| **Generic SSH** | SSH | 2 | Universal CLI access to any SSH device (Cisco, Juniper, Arista, Linux, etc.) |
| **MikroTik REST** | REST API | 9 | Complete management via REST API (interfaces, BGP, routing, system health) |
| **MikroTik SSH** | SSH | 2 | Specific commands unavailable in REST (route check, custom commands) |
| **Palo Alto** | SSH PTY | 2 | PAN-OS firewalls with PTY interactive sessions (VPN, routing, system) |
| **Aruba WiFi** | REST API | 9 | WiFi controller (APs, clients, rogues, RF, WLANs, statistics) |
| **Graylog** | REST API | 3 | Centralized log search with time filters and streaming |
| **LibreNMS** | REST API | 10 | Network monitoring (inventory, health, ports, sensors, events) |
| **Cisco APIC (ACI)** | REST API | 35 | ACI data center (fabric, tenants, EPGs, VRFs, contracts, topology, analytics) |
| **Cisco NDFC** | REST API | 15 | Nexus Dashboard Fabric Controller (fabrics, switches, networks, VRFs, events) |

**Total: ~100 exposed MCP tools**

---

## 🚀 Installation

### Prerequisites

- **Python 3.12+** (required)
- **[UV](https://docs.astral.sh/uv/)** - Modern ultra-fast package manager
- Network access to target devices/APIs
- MCP client (Claude Desktop, Warp AI, etc.)

### Install with UV

```bash
# 1. Clone the repository
git clone https://github.com/your-repo/netai-o.git
cd netai-o

# 2. Sync dependencies (UV automatically creates virtual environment)
uv sync

# 3. Verify installation
uv run python -c "from server import mcp; print(f'✓ {mcp.name} OK')"
```

---

## ⚙️ Configuration

### Environment Variables

Create a `.env` file at project root:

```bash
# === Generic SSH ===
SSH_USERNAME="admin"
SSH_PASSWORD="your_password"

# === MikroTik REST API ===
MIKROTIK_USERNAME="api_user"
MIKROTIK_PASSWORD="api_password"
MIKROTIK_PORT="443"

# === MikroTik SSH (if different from REST) ===
MIKROTIK_SSH_USERNAME="ssh_user"
MIKROTIK_SSH_PASSWORD="ssh_password"
MIKROTIK_SSH_PORT="22"

# === Palo Alto Firewalls ===
PALOALTO_SSH_USERNAME="admin"
PALOALTO_SSH_PASSWORD="firewall_password"

# === Aruba WiFi Controller ===
ARUBA_IP="10.x.x.x"
ARUBA_USERNAME="admin"
ARUBA_PASSWORD="aruba_password"

# === Graylog ===
GRAYLOG_API_URL="https://graylog.example.com"
GRAYLOG_USERNAME="graylog_user"
GRAYLOG_PASSWORD="graylog_password"

# === LibreNMS ===
LIBRENMS_URL="https://librenms.example.com"
LIBRENMS_API_TOKEN="your_api_token_here"

# === Cisco APIC (ACI) ===
APIC_HOST="https://apic.example.com"
APIC_USERNAME="apic_user"
APIC_PASSWORD="apic_password"
APIC_VERIFY_SSL="false"
APIC_TIMEOUT="30"
APIC_TOKEN_CACHE_DURATION="3540"  # 59 minutes (safety margin)

# === Cisco NDFC ===
NDFC_HOST="https://ndfc.example.com"
NDFC_USER="ndfc_user"
NDFC_PASSWORD="ndfc_password"
NDFC_DOMAIN="DefaultAuth"
NDFC_VERIFY_SSL="false"
NDFC_TIMEOUT="30"
```

**⚠️ Security**: The `.env` file is ignored by Git (`.gitignore`). Never commit credentials.

---

## 🔧 MCP Client Configuration

### Claude Desktop

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`  
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`  
**Linux**: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "netai-o": {
      "command": "uv",
      "args": [
        "--directory",
        "/absolute/path/to/netai-o",
        "run",
        "python",
        "server.py"
      ]
    }
  }
}
```

### Warp AI

**Configuration**: `~/.warp/mcp_config.json`

```json
{
  "mcpServers": {
    "netai-o": {
      "command": "uv",
      "args": ["run", "python", "server.py"],
      "working_directory": "/absolute/path/to/netai-o"
    }
  }
}
```

---

## 📖 Usage

### Manual Start (testing)

```bash
# Launch MCP server in stdio mode
uv run python server.py
```

The server exposes all MCP tools via stdio protocol. MCP clients (Claude Desktop, Warp) launch it automatically.

### Example Commands (natural language with Claude)

#### Generic SSH
```
Execute "show version" on device 192.168.1.1
```

#### MikroTik
```
Show BGP sessions on MikroTik router 10.0.0.1
Check route to 8.8.8.8 on MikroTik 10.0.0.1 via SSH
```

#### Palo Alto
```
Show VPN status on Palo Alto firewall 10.240.203.241
Execute "show system info" on firewalls 10.240.203.241 and 10.240.203.242 in parallel
```

#### Aruba WiFi
```
List all access points on Aruba controller
Show connected WiFi clients
Detect rogue APs
```

#### Graylog
```
Search for "authentication failure" in logs from the last 2 hours
List available Graylog streams
```

#### LibreNMS
```
Show all monitored MikroTik devices
Display health of device router-core-01
List ports on switch-distro-01
```

#### Cisco APIC (ACI)
```
Show overall ACI fabric health
List all APIC tenants
Search for endpoint with IP 10.1.1.50
Analyze connectivity between EPG web and EPG database
Show top talkers in Production tenant
```

#### Cisco NDFC
```
List all NDFC fabrics
Show switches in fabric DC1
Get critical events from the last 24 hours
Show interface details for switch FDO23460MQC
```

---

## 🏗️ Technical Architecture

### Project Structure

```
netai-o/
├── server.py                    # MCP entry point (FastMCP stdio)
├── connectors/                  # Asynchronous connectors
│   ├── ssh_c.py                # Generic SSH (asyncssh)
│   ├── mikrotik_c.py           # MikroTik REST API (httpx)
│   ├── mikrotik_ssh_c.py       # MikroTik SSH (asyncssh)
│   ├── paloalto_c.py           # Palo Alto SSH PTY (asyncssh)
│   ├── aruba_c.py              # Aruba WiFi REST (httpx)
│   ├── graylog_c.py            # Graylog REST (httpx)
│   ├── librenms_c.py           # LibreNMS REST (httpx)
│   ├── apic_c.py               # Cisco APIC REST (httpx) + JWT cache
│   └── ndfc_c.py               # Cisco NDFC REST (httpx) + JWT cache
├── pyproject.toml              # UV configuration and dependencies
├── uv.lock                     # UV lockfile
├── .env                        # Credentials (not versioned)
└── README.md                   # This file
```

### Asynchronous Patterns

#### 1. Persistent HTTP Sessions (Aruba, Graylog, LibreNMS)

```python
async with httpx.AsyncClient(timeout=30) as client:
    response = await client.get(url, headers=headers)
    # HTTP session is reused for all requests in the block
```

#### 2. Thread-Safe JWT Cache (APIC, NDFC)

```python
_token_cache = {"token": None, "expires_at": 0, "lock": asyncio.Lock()}

async def _get_token():
    async with _token_cache["lock"]:  # Concurrency protection
        if time.time() < _token_cache["expires_at"]:
            return _token_cache["token"]
        # Automatic renewal if expired
        return await _authenticate()
```

#### 3. Parallel Execution with Timeout (SSH, Palo Alto)

```python
async def send_custom_command_parallel(targets: List[Dict], timeout: int = 120):
    tasks = [execute_single(target) for target in targets]
    results = await asyncio.wait_for(
        asyncio.gather(*tasks, return_exceptions=True),
        timeout=timeout
    )
    return results
```

#### 4. PTY Interactive Sessions (Palo Alto)

PAN-OS requires a PTY interactive session (non-standard SSH):

```python
async with asyncssh.connect(ip, ...) as conn:
    async with conn.create_process(term_type='vt100') as process:
        await process.stdin.write(command + '\n')
        output = await process.stdout.read()
```

### Key Dependencies

| Library | Usage |
|---------|-------|
| **fastmcp** | MCP server framework (stdio transport) |
| **asyncssh** | Asynchronous SSH client (RFC-compliant + PTY) |
| **httpx** | Async HTTP client with persistent sessions |
| **python-dotenv** | Environment variable management |
| **mcp[cli]** | MCP protocol CLI tools |

---

## 🧪 Testing

### Quick Verification

```bash
# Test MCP server
uv run python -c "from server import mcp; print(f'✓ Server {mcp.name} operational')"

# Test SSH connector
uv run python -c "
import asyncio
from connectors.ssh_c import send_custom_command
result = asyncio.run(send_custom_command('192.168.1.1', 'show version'))
print(result)
"

# Test REST connector (LibreNMS)
uv run python -c "
import asyncio
from connectors.librenms_c import list_devices
result = asyncio.run(list_devices())
print(result)
"
```

### Standardized Response Format

All connectors return a dictionary with this structure:

```python
{
    "success": bool,           # True if operation succeeded
    "output": dict|str|list,   # Response data (variable structure)
    "error": str               # Error message (if success=False)
}
```

---

## 🔒 Security

### Recommendations

| Aspect | Development | Production |
|--------|-------------|------------|
| **Credentials** | Local `.env` file | Secrets manager (Vault, AWS Secrets Manager, 1Password CLI) |
| **SSL Verification** | `VERIFY_SSL=false` (lab) | `VERIFY_SSL=true` + valid certificates |
| **SSH Known Hosts** | Disabled (`known_hosts=None`) | Strict validation with `known_hosts` file |
| **Permissions** | Admin accounts (testing) | Service accounts with minimal privileges (least privilege principle) |
| **Logs** | Active debugging | Disable session logs to prevent credential leakage |
| **Network** | Direct access | Strict firewalling + bastion/jump host |

### Credential Management

```bash
# Production: use a secrets manager
# Example with 1Password CLI
export SSH_USERNAME=$(op read "op://vault/ssh-creds/username")
export SSH_PASSWORD=$(op read "op://vault/ssh-creds/password")

# Then launch server
uv run python server.py
```

---

## 🛠️ Troubleshooting

| Issue | Solution |
|-------|----------|
| **SSH authentication error** | Verify `SSH_USERNAME` and `SSH_PASSWORD` in `.env`, test SSH manually with `ssh user@host` |
| **Connection timeout** | Check network connectivity (`ping`, `telnet host port`), increase `TIMEOUT` in `.env` |
| **SSL/TLS error** | Lab environment: `VERIFY_SSL=false`. Production: install correct CA certificates |
| **JWT token expired (APIC/NDFC)** | Renewal is automatic. If issue persists, check credentials and connectivity |
| **MCP server won't start** | Check `uv --version` (must be installed), `python --version` (≥3.12), re-run `uv sync` |
| **Palo Alto: session timeout** | PAN-OS firewalls have short timeout. Increase `PALOALTO_TIMEOUT` or enable keep-alive |
| **Debug logs** | Add to `server.py`: `import logging; logging.basicConfig(level=logging.DEBUG)` |

---

## 🗺️ Roadmap

### ✅ Implemented

- [x] 100% asynchronous architecture (asyncio/asyncssh/httpx)
- [x] 9 connectors (SSH, MikroTik REST+SSH, Aruba, Palo Alto, Graylog, LibreNMS, APIC, NDFC)
- [x] ~100 exposed MCP tools
- [x] Smart JWT cache with automatic renewal
- [x] Persistent HTTP sessions with keepalive
- [x] Parallel execution with timeout protection
- [x] PTY support for Palo Alto PAN-OS
- [x] Modern UV management (pyproject.toml + uv.lock)

### 🚀 Future Enhancements

- [ ] Cisco DNA Center API
- [ ] Fortinet FortiManager API
- [ ] Juniper Mist API
- [ ] Telemetry support (gNMI, NETCONF)

---

## 📄 License

This project is distributed under the MIT License. See [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **[FastMCP](https://github.com/jlowin/fastmcp)** - Fast and elegant MCP server framework
- **[asyncssh](https://asyncssh.readthedocs.io/)** - Production-quality asynchronous SSH client
- **[httpx](https://www.python-httpx.org/)** - Modern async HTTP client
- **[UV](https://docs.astral.sh/uv/)** - Ultra-fast Python package manager (Rust-based)
- **[Anthropic](https://www.anthropic.com/)** - MCP protocol and Claude

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-repo/netai-o/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-repo/netai-o/discussions)

---

**Built with ❤️ for network engineers and DevOps teams**
