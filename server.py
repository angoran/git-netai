from mcp.server.fastmcp import FastMCP

# Import the necessary functions
from connectors.ssh_c import send_custom_command as ssh_cli_command
from connectors.mikrotik_c import (get_interfaces, get_ip_address, get_route_by_prefix,
                                   get_system_identity, get_system_health,
                                   get_system_routerboard, get_logs, get_bgp_connections,
                                   get_bgp_sessions)
from connectors.mikrotik_ssh_c import mikrotik_route_check, mikrotik_custom_command
from connectors.graylog_c import search_logs, get_streams, get_system_overview

# Initialize the FastMCP server
mcp = FastMCP("netai-o")

# Overview of MCP tools

# ========== SSH Tool ==========
@mcp.tool()
async def send_custom_command(identifier: str, command: str) -> dict:
    """ Execute a remote SSH command on any RFC-compliant SSH device. """
    return await ssh_cli_command(identifier, command)

# ========== Mikrotik Tools ==========
@mcp.tool()
async def get_mikrotik_interfaces(identifier: str) -> dict:
    """Retrieves the interfaces of a MikroTik router."""
    return await get_interfaces(identifier)

@mcp.tool()
async def get_mikrotik_ipaddresses(identifier: str) -> dict:
    """Retrieves the configured IP addresses."""
    return await get_ip_address(identifier)

@mcp.tool()
async def get_mikrotik_route_prefix(identifier: str, dst_address: str) -> dict:
    """Query routing for a specific prefix on a MikroTik."""
    return await get_route_by_prefix(identifier, dst_address)

@mcp.tool()
async def get_mikrotik_identity(identifier: str) -> dict:
    """Retrieves the name of router."""
    return await get_system_identity(identifier)

@mcp.tool()
async def get_mikrotik_health(identifier: str) -> dict:
    """Retrieves system health (temperature, voltage)."""
    return await get_system_health(identifier)

@mcp.tool()
async def get_mikrotik_routerboard(identifier: str) -> dict:
    """Retrieves the hardware information from the routerboard."""
    return await get_system_routerboard(identifier)

@mcp.tool()
async def get_mikrotik_logs(identifier: str, limit: int = 100) -> dict:
    """Retrieves system logs (default: last 100 logs)."""
    return await get_logs(identifier, limit=limit)

@mcp.tool()
async def get_mikrotik_bgp_connections(identifier: str) -> dict:
    """Retrieves the BGP connection configuration."""
    return await get_bgp_connections(identifier)

@mcp.tool()
async def get_mikrotik_bgp_sessions(identifier: str) -> dict:
    """Retrieves the state of BGP sessions."""
    return await get_bgp_sessions(identifier)

# ========== Mikrotik SSH Tools ==========
@mcp.tool()
async def mikrotik_ssh_route_check(identifier: str, destination_ip: str) -> dict:
    """Check route to destination via SSH (NOT available in REST API)."""
    return await mikrotik_route_check(identifier, destination_ip)

@mcp.tool()
async def mikrotik_ssh_custom(identifier: str, command: str) -> dict:
    """Execute custom MikroTik command via SSH (for LLM flexibility)."""
    return await mikrotik_custom_command(identifier, command)

# ========== Graylog Tools ==========
@mcp.tool()
async def graylog_search_logs(query: str, hours: int = 1, limit: int = 20) -> dict:
    """Search Graylog logs with query filter (ex: 'bgp', 'firewall'). Default: 1h, 20 results."""
    return await search_logs(query, hours, limit)

@mcp.tool()
async def graylog_get_streams() -> dict:
    """Retrieve list of available Graylog log streams."""
    return await get_streams()

@mcp.tool()
async def graylog_system_info() -> dict:
    """Retrieve Graylog system information."""
    return await get_system_overview()

# Entry Point
if __name__ == "__main__":
    mcp.run(transport="stdio")
