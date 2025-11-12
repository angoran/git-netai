"""Main entry point for the NET-AI-ASSISTANT MCP server.

This MCP server provides tools for managing network devices via SSH
(routers, switches, firewalls from multiple vendors).
"""

from mcp.server.fastmcp import FastMCP
from connectors.ssh_conn import run_network_command

# Initialize the FastMCP server
mcp = FastMCP("NET-AI-ASSISTANT")


@mcp.tool()
def execute_network_device_command(
    ip_address: str,
    command: str,
    device_type: str = "autodetect"
) -> str:
    """
    Connect to a network device via SSH and execute a CLI command.

    Supports various device types: Cisco, MikroTik, Palo Alto, etc.

    Args:
        ip_address: IP address of the target network device.
        command: CLI command to execute (e.g., 'show version', 'show interfaces').
        device_type: Netmiko device type (cisco_ios, mikrotik_routeros,
                     paloalto_panos, etc.). Default: 'autodetect'.

    Returns:
        The output of the command executed on the device.
    """
    return run_network_command(ip_address, command, device_type)


# Entry point
if __name__ == "__main__":
    mcp.run(transport="stdio")
