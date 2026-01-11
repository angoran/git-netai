# Network AI Assistant

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![FastMCP](https://img.shields.io/badge/FastMCP-2.13+-green.svg)](https://github.com/jlowin/fastmcp)
[![UV](https://img.shields.io/badge/UV-Package_Manager-orange.svg)](https://docs.astral.sh/uv/)
[![Async](https://img.shields.io/badge/Architecture-100%25_Async-brightgreen.svg)]()

Asynchronous MCP (Model Context Protocol) server for unified multi-platform network infrastructure management.

Expose network devices, WiFi controllers, monitoring systems, and data centers through a unified API accessible by Claude Desktop, Warp AI, and any MCP-compatible client.

---

## Key Features

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

## Installation

### Prerequisites

- Python 3.12 or higher
- [UV](https://docs.astral.sh/uv/) package manager
- Network access to target devices/APIs
- MCP client (Claude Desktop, Warp AI, etc.)

### Install with UV

```bash
# Clone the repository
git clone https://github.com/angoran/git-netai.git
cd git-netai

# Sync dependencies (UV automatically creates virtual environment)
uv sync

# Verify installation
uv run python -c "from server import mcp; print(f'{mcp.name} operational')"
```

---

## Configuration

### Environment Variables

Create a `.env` file at project root with the following variables:

```bash
# Generic SSH
SSH_USERNAME="admin"
SSH_PASSWORD="your_password"

# MikroTik REST API
MIKROTIK_USERNAME="api_user"
MIKROTIK_PASSWORD="api_password"
MIKROTIK_PORT="443"

# MikroTik SSH (if different from REST)
MIKROTIK_SSH_USERNAME="ssh_user"
MIKROTIK_SSH_PASSWORD="ssh_password"
MIKROTIK_SSH_PORT="22"

# Palo Alto Firewalls
PALOALTO_SSH_USERNAME="admin"
PALOALTO_SSH_PASSWORD="firewall_password"

# Aruba WiFi Controller
ARUBA_IP="10.x.x.x"
ARUBA_USERNAME="admin"
ARUBA_PASSWORD="aruba_password"

# Graylog
GRAYLOG_API_URL="https://graylog.example.com"
GRAYLOG_USERNAME="graylog_user"
GRAYLOG_PASSWORD="graylog_password"

# LibreNMS
LIBRENMS_URL="https://librenms.example.com"
LIBRENMS_API_TOKEN="your_api_token_here"

# Cisco APIC (ACI)
APIC_HOST="https://apic.example.com"
APIC_USERNAME="apic_user"
APIC_PASSWORD="apic_password"
APIC_VERIFY_SSL="false"
APIC_TIMEOUT="30"
APIC_TOKEN_CACHE_DURATION="3540"

# Cisco NDFC
NDFC_HOST="https://ndfc.example.com"
NDFC_USER="ndfc_user"
NDFC_PASSWORD="ndfc_password"
NDFC_DOMAIN="DefaultAuth"
NDFC_VERIFY_SSL="false"
NDFC_TIMEOUT="30"
```

**Security Note**: The `.env` file is excluded from version control via `.gitignore`. Never commit credentials to the repository.

---

## MCP Client Configuration

### Claude Desktop

**Configuration file locations:**
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "netai-o": {
      "command": "uv",
      "args": [
        "--directory",
        "/absolute/path/to/netai",
        "run",
        "python",
        "server.py"
      ]
    }
  }
}
```

### Warp AI

**Configuration file:** `~/.warp/mcp_config.json`

```json
{
  "mcpServers": {
    "netai-o": {
      "command": "uv",
      "args": ["run", "python", "server.py"],
      "working_directory": "/absolute/path/to/netai"
    }
  }
}
```

---

## Usage

### Starting the Server

```bash
# Launch MCP server in stdio mode
uv run python server.py
```

The server exposes all MCP tools via stdio protocol. MCP clients (Claude Desktop, Warp) launch the server automatically based on their configuration files.

### Example Commands

The following examples demonstrate natural language commands that can be used with Claude Desktop or Warp AI:

#### Generic SSH Operations
```
Execute "show version" on device 192.168.1.1
Run "show ip route" on devices 192.168.1.1 and 192.168.1.2 in parallel
```

#### MikroTik Management
```
Show BGP sessions on MikroTik router 10.0.0.1
Check route to 8.8.8.8 on MikroTik 10.0.0.1 via SSH
Display interface statistics for 10.0.0.1
```

#### Palo Alto Firewall Operations
```
Show VPN status on Palo Alto firewall 10.240.203.241
Execute "show system info" on firewalls 10.240.203.241 and 10.240.203.242 in parallel
Display routing table on firewall 10.240.203.241
```

#### Aruba WiFi Controller
```
List all access points on Aruba controller
Show connected WiFi clients
Detect rogue access points
Display RF channel utilization
Show WLAN configuration
```

#### Graylog Log Management
```
Search for "authentication failure" in logs from the last 2 hours
List available Graylog streams
Show system overview and statistics
```

#### LibreNMS Network Monitoring
```
Show all monitored MikroTik devices
Display health metrics for device router-core-01
List all ports on switch-distro-01
Show temperature sensors for all devices
Retrieve event logs for the last 24 hours
```

#### Cisco APIC (ACI Data Center)
```
Show overall ACI fabric health
List all APIC tenants
Search for endpoint with IP address 10.1.1.50
Analyze connectivity between EPG web and EPG database
Show top talkers in Production tenant
Display fabric topology
List all contracts in tenant Production
```

#### Cisco NDFC
```
List all NDFC fabrics
Show switches in fabric DC1
Get critical events from the last 24 hours
Show interface details for switch with serial FDO23460MQC
Display VRFs in fabric DC1
Show network deployment status
```

---

## Technical Architecture

### Project Structure

```
git-netai/
├── server.py                    # MCP entry point (FastMCP stdio transport)
├── connectors/                  # Asynchronous connector modules
│   ├── ssh_c.py                # Generic SSH connector (asyncssh)
│   ├── mikrotik_c.py           # MikroTik REST API connector (httpx)
│   ├── mikrotik_ssh_c.py       # MikroTik SSH connector (asyncssh)
│   ├── paloalto_c.py           # Palo Alto SSH PTY connector (asyncssh)
│   ├── aruba_c.py              # Aruba WiFi REST API connector (httpx)
│   ├── graylog_c.py            # Graylog REST API connector (httpx)
│   ├── librenms_c.py           # LibreNMS REST API connector (httpx)
│   ├── apic_c.py               # Cisco APIC REST API connector (httpx + JWT cache)
│   └── ndfc_c.py               # Cisco NDFC REST API connector (httpx + JWT cache)
├── pyproject.toml              # UV project configuration and dependencies
├── uv.lock                     # UV dependency lockfile
├── .env                        # Environment variables (not version controlled)
├── .gitignore                  # Git ignore rules
└── README.md                   # Project documentation
```

### Asynchronous Design Patterns

#### 1. Persistent HTTP Sessions

REST API connectors (Aruba, Graylog, LibreNMS) use persistent HTTP connections to minimize connection overhead:

```python
async with httpx.AsyncClient(timeout=30) as client:
    response = await client.get(url, headers=headers)
    # HTTP session is automatically reused for subsequent requests
```

#### 2. Thread-Safe JWT Token Caching

APIC and NDFC connectors implement thread-safe JWT token caching with automatic renewal:

```python
_token_cache = {"token": None, "expires_at": 0, "lock": asyncio.Lock()}

async def _get_token():
    async with _token_cache["lock"]:
        if time.time() < _token_cache["expires_at"]:
            return _token_cache["token"]
        # Automatic token renewal when expired
        return await _authenticate()
```

**Key features:**
- Async lock prevents concurrent authentication requests
- Configurable token expiration with safety margin
- Automatic renewal on 401 responses
- Zero-downtime token refresh

#### 3. Parallel Execution with Timeout Protection

SSH connectors support parallel command execution across multiple devices:

```python
async def send_custom_command_parallel(targets: List[Dict], timeout: int = 120):
    tasks = [execute_single(target) for target in targets]
    results = await asyncio.wait_for(
        asyncio.gather(*tasks, return_exceptions=True),
        timeout=timeout
    )
    return results
```

**Benefits:**
- Concurrent execution across multiple devices
- Global timeout prevents indefinite hangs
- Exception handling per device
- Results aggregated in single response

#### 4. PTY Interactive Sessions

Palo Alto PAN-OS requires PTY (pseudo-terminal) interactive sessions due to non-standard SSH implementation:

```python
async with asyncssh.connect(ip, ...) as conn:
    async with conn.create_process(term_type='vt100') as process:
        await process.stdin.write(command + '\n')
        output = await process.stdout.read()
```

**Why PTY is required:**
- PAN-OS CLI expects interactive terminal
- Standard SSH exec channels are rejected
- Terminal emulation (vt100) required for proper output formatting

### Key Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| **fastmcp** | 2.13+ | MCP server framework with stdio transport |
| **asyncssh** | 2.21+ | Asynchronous SSH client (RFC-compliant + PTY support) |
| **httpx** | 0.28+ | Async HTTP client with connection pooling |
| **python-dotenv** | 1.2+ | Environment variable management from .env files |
| **mcp[cli]** | 1.23+ | MCP protocol implementation and CLI tools |

---

## Testing

### Quick Verification

```bash
# Verify MCP server loads correctly
uv run python -c "from server import mcp; print(f'{mcp.name} operational')"

# Test SSH connector
uv run python -c "
import asyncio
from connectors.ssh_c import send_custom_command
result = asyncio.run(send_custom_command('192.168.1.1', 'show version'))
print(result)
"

# Test REST API connector (LibreNMS)
uv run python -c "
import asyncio
from connectors.librenms_c import list_devices
result = asyncio.run(list_devices())
print(result)
"
```

### Response Format

All connector functions return a standardized dictionary structure:

```python
{
    "success": bool,           # True if operation completed successfully
    "output": dict|str|list,   # Response data (structure varies by connector)
    "error": str               # Error message if success is False
}
```

**Success response example:**
```python
{
    "success": True,
    "output": {"hostname": "router-01", "version": "7.14.1"},
    "error": None
}
```

**Error response example:**
```python
{
    "success": False,
    "output": None,
    "error": "Connection timeout after 30 seconds"
}
```

---

## Security Considerations

### Development vs Production

| Aspect | Development Environment | Production Environment |
|--------|------------------------|------------------------|
| **Credentials** | Local `.env` file | Secrets manager (HashiCorp Vault, AWS Secrets Manager, 1Password CLI) |
| **SSL Verification** | `VERIFY_SSL=false` (lab devices with self-signed certificates) | `VERIFY_SSL=true` with valid certificate chain |
| **SSH Known Hosts** | Disabled (`known_hosts=None`) for rapid prototyping | Strict validation with maintained `known_hosts` file |
| **Account Permissions** | Admin accounts for full access | Service accounts with minimal required privileges (least privilege principle) |
| **Logging** | Debug logging enabled for troubleshooting | Session logs disabled to prevent credential exposure |
| **Network Access** | Direct device access | Restricted access via bastion host/jump server with firewall rules |

### Production Credential Management

Example using 1Password CLI for secure credential injection:

```bash
# Export credentials from secrets manager
export SSH_USERNAME=$(op read "op://Production/network-automation/username")
export SSH_PASSWORD=$(op read "op://Production/network-automation/password")
export APIC_PASSWORD=$(op read "op://Production/apic-credentials/password")

# Launch server with injected credentials
uv run python server.py
```

### Audit and Compliance

For production deployments:
- Enable audit logging for all MCP tool invocations
- Implement role-based access control (RBAC) at MCP client level
- Rotate service account credentials regularly (90-day maximum)
- Monitor for suspicious command patterns or unauthorized access attempts
- Maintain audit trail of all configuration changes

---

## Troubleshooting

### Common Issues and Solutions

| Issue | Diagnosis | Solution |
|-------|-----------|----------|
| **SSH authentication failure** | Incorrect credentials or account locked | Verify `SSH_USERNAME` and `SSH_PASSWORD` in `.env`. Test manually: `ssh user@host`. Check account status on target device. |
| **Connection timeout** | Network unreachable or firewall blocking | Verify connectivity: `ping <host>`, `telnet <host> <port>`. Check firewall rules and routing. Increase timeout values in `.env`. |
| **SSL/TLS certificate error** | Self-signed certificate or untrusted CA | Development: Set `VERIFY_SSL=false`. Production: Install proper CA certificates or use `certifi` bundle. |
| **JWT token expired (APIC/NDFC)** | Token lifetime exceeded | Token renewal is automatic. If persistent, verify credentials and check APIC/NDFC authentication logs. |
| **MCP server fails to start** | Missing dependencies or Python version mismatch | Check `uv --version` and `python --version` (must be 3.12+). Re-run `uv sync` to reinstall dependencies. |
| **Palo Alto session timeout** | PAN-OS aggressive session timeout | Increase `timeout` parameter in tool calls. Consider implementing keepalive packets. |
| **LibreNMS API 401 error** | Invalid or expired API token | Regenerate API token in LibreNMS web interface under user settings. Update `LIBRENMS_API_TOKEN` in `.env`. |
| **APIC/NDFC 403 forbidden** | Insufficient account permissions | Verify account has required role assignments (admin or fabric-admin for full access). |

### Enabling Debug Logging

Add the following to `server.py` for detailed logging output:

```python
import logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

For production environments, configure logging to external syslog or SIEM:

```python
import logging
from logging.handlers import SysLogHandler

handler = SysLogHandler(address=('syslog.example.com', 514))
logging.basicConfig(handlers=[handler], level=logging.INFO)
```

---

## Roadmap

### Current Implementation

- [x] 100% asynchronous architecture (asyncio/asyncssh/httpx)
- [x] 9 connectors (SSH, MikroTik REST+SSH, Aruba, Palo Alto, Graylog, LibreNMS, APIC, NDFC)
- [x] ~100 exposed MCP tools
- [x] Smart JWT cache with automatic renewal
- [x] Persistent HTTP sessions with keepalive
- [x] Parallel execution with timeout protection
- [x] PTY support for Palo Alto PAN-OS
- [x] Modern UV management (pyproject.toml + uv.lock)

### Planned Enhancements

**Additional Platform Support & more endpoints:**

- [ ] Integration API Panorama
- [ ] Add more LibreNMS endpoints (alerts, device groups, inventory)
- [ ] Add more APIC endpoints (troubleshooting, change management)
- [ ] Expand Aruba capabilities (RF analytics, heat maps)

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for complete terms and conditions.

---

## Acknowledgments

- **FastMCP** - High-performance MCP server framework
- **asyncssh** - Production-grade asynchronous SSH implementation
- **httpx** - Modern async HTTP client with HTTP/2 support
- **UV** - Next-generation Python package manager built in Rust
- **Anthropic** - Model Context Protocol specification and reference implementations

---

## Support

For issues, questions, or contributions:
- **Issue Tracker**: [GitHub Issues](https://github.com/angoran/git-netai/issues)
- **Discussions**: [GitHub Discussions](https://github.com/angoran/git-netai/discussions)

---

**Professional network automation for enterprise environments**
