from mcp.server.fastmcp import FastMCP

# Import the necessary functions
from connectors.ssh_c import send_custom_command as ssh_cli_command
from connectors.mikrotik_c import (get_interfaces)

# Initialize the FastMCP server
mcp = FastMCP("netai-o")

# Overview of MCP tools
@mcp.tool
async def send_custom_command(ip_address:str, command:str) -> str:
    """ Execute a remote SSH command on any RFC-compliant SSH device. """
    return await ssh_cli_command(ip_address, command)

@mcp.tool
async def get_mikrotik_interfaces(identifier: str) -> dict:
    """Retrieves the interfaces of a MikroTik router."""
    return get_interfaces(identifier)

# Entry Point
if __name__ == "__main__":
    mcp.run(transport="stdio")
