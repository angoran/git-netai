from mcp.server.fastmcp import FastMCP
from typing import Optional

# Import the necessary functions
from connectors.ssh_c import send_custom_command as ssh_cli_command, send_custom_command_parallel as ssh_cli_parallel
from connectors.mikrotik_c import (get_interfaces, get_ip_address, get_route_by_prefix,
                                   get_system_identity, get_system_health,
                                   get_system_routerboard, get_logs, get_bgp_connections,
                                   get_bgp_sessions)
from connectors.mikrotik_ssh_c import mikrotik_route_check, mikrotik_custom_command
from connectors.graylog_c import search_logs, get_streams, get_system_overview
from connectors.aruba_c import (get_ap_database, get_client_list, get_rogue_ap_list,
                                get_ap_channel_info, get_wlan_list, get_ap_statistics,
                                get_license_info, get_controller_info, run_custom_command as aruba_custom_cmd)
from connectors.librenms_c import (list_devices, get_devices_by_os, get_device_by_hostname,
                                   get_device_health, get_device_sensors, get_device_ports,
                                   get_locations, get_eventlog, get_device_eventlog, get_device_stats)
from connectors.paloalto_c import palo_send_command, palo_send_command_parallel

# Initialize the FastMCP server
mcp = FastMCP("netai-o")

# Overview of MCP tools

# ========== SSH Tools ==========
@mcp.tool()
async def send_custom_command(identifier: str, command: str) -> dict:
    """
    Execute SSH command on generic network devices (Cisco, Juniper, Arista, Linux, etc.).

    ⚠️ NOT for Palo Alto firewalls - use paloalto_send_command instead.
    Works with standard SSH devices that don't require PTY interactive sessions.
    """
    return await ssh_cli_command(identifier, command)

@mcp.tool()
async def send_custom_command_parallel(targets: list, timeout: int = 120) -> dict:
    """
    Execute SSH commands on multiple generic network devices in parallel.

    ⚠️ NOT for Palo Alto firewalls - use paloalto_send_command_parallel instead.

    Args:
        targets: List of {"ip": "192.168.1.1", "command": "show version"}
        timeout: Global timeout in seconds (default: 30s)

    Example:
        [
            {"ip": "192.168.1.1", "command": "show version"},
            {"ip": "192.168.1.2", "command": "show ip route"}
        ]
    """
    return await ssh_cli_parallel(targets, timeout)

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

# ========== Aruba WiFi Controller Tools ==========
@mcp.tool()
async def aruba_get_ap_database(limit: Optional[int] = None) -> dict:
    """Get complete list of Access Points from Aruba controller."""
    return await get_ap_database(limit)

@mcp.tool()
async def aruba_get_clients(limit: Optional[int] = None) -> dict:
    """Get list of connected WiFi clients."""
    return await get_client_list(limit)

@mcp.tool()
async def aruba_get_rogue_aps(limit: Optional[int] = None) -> dict:
    """Get list of unauthorized/rogue access points (Security)."""
    return await get_rogue_ap_list(limit)

@mcp.tool()
async def aruba_get_channels() -> dict:
    """Get active channel information for RF optimization."""
    return await get_ap_channel_info()

@mcp.tool()
async def aruba_get_wlans() -> dict:
    """Get WLAN/SSID profile configuration."""
    return await get_wlan_list()

@mcp.tool()
async def aruba_get_ap_stats() -> dict:
    """Get AP performance metrics and ARM state."""
    return await get_ap_statistics()

@mcp.tool()
async def aruba_get_licenses() -> dict:
    """Get license compliance information."""
    return await get_license_info()

@mcp.tool()
async def aruba_get_controller_info() -> dict:
    """Get Aruba controller system information and version."""
    return await get_controller_info()

@mcp.tool()
async def aruba_custom_command(command: str) -> dict:
    """Execute custom show command on Aruba controller (e.g., 'show ap database')."""
    return await aruba_custom_cmd(command)

# ========== Palo Alto Firewall Tools ==========
@mcp.tool()
async def paloalto_send_command(ip_address: str, command: str) -> dict:
    """
    Execute SSH command specifically on Palo Alto firewalls.

    🔥 USE THIS for ALL Palo Alto firewall commands (show vpn, show system, show routing, etc.).
    This tool uses PTY interactive sessions required by Palo Alto PAN-OS.

    Examples:
    - "show vpn gateway"
    - "show system info"
    - "show routing route"
    """
    return await palo_send_command(ip_address, command)

@mcp.tool()
async def paloalto_send_command_parallel(targets: list, timeout: int = 120) -> dict:
    """
    Execute SSH commands on multiple Palo Alto firewalls in parallel.

    🔥 USE THIS for batch operations on multiple Palo Alto firewalls.

    Args:
        targets: List of {"ip": "10.240.203.241", "command": "show vpn gateway"}
        timeout: Global timeout in seconds (default: 120s)
    """
    return await palo_send_command_parallel(targets, timeout)

# ========== LibreNMS Tools ==========
@mcp.tool()
async def librenms_list_devices(filter_type: Optional[str] = None, filter_value: Optional[str] = None) -> dict:
    """List all devices or filter by criteria (type, os, location, hostname)."""
    return await list_devices(filter_type, filter_value)

@mcp.tool()
async def librenms_get_devices_by_os(os_name: str) -> dict:
    """Get all devices running a specific OS (e.g., 'routeros', 'ios', 'linux')."""
    return await get_devices_by_os(os_name)

@mcp.tool()
async def librenms_get_device_info(hostname: str) -> dict:
    """Get detailed device information by hostname."""
    return await get_device_by_hostname(hostname)

@mcp.tool()
async def librenms_get_device_health(hostname: str) -> dict:
    """Get device health information including all sensor types."""
    return await get_device_health(hostname)

@mcp.tool()
async def librenms_get_device_sensors(hostname: str, sensor_type: Optional[str] = None) -> dict:
    """Get device sensors with optional filter (temperature, voltage, state, etc.)."""
    return await get_device_sensors(hostname, sensor_type)

@mcp.tool()
async def librenms_get_device_ports(hostname: str) -> dict:
    """Get all ports/interfaces information for a device."""
    return await get_device_ports(hostname)

@mcp.tool()
async def librenms_get_device_stats(hostname: str) -> dict:
    """Get comprehensive device statistics (uptime, ports, availability)."""
    return await get_device_stats(hostname)

@mcp.tool()
async def librenms_get_locations() -> dict:
    """Get all locations configured in LibreNMS."""
    return await get_locations()

@mcp.tool()
async def librenms_get_eventlog(limit: int = 100, sort_order: str = "DESC") -> dict:
    """Get general event logs from LibreNMS."""
    return await get_eventlog(limit, sort_order)

@mcp.tool()
async def librenms_get_device_eventlog(hostname: str, limit: int = 50, sort_order: str = "DESC") -> dict:
    """Get event logs for a specific device."""
    return await get_device_eventlog(hostname, limit, sort_order)

# Entry Point
if __name__ == "__main__":
    mcp.run(transport="stdio")
