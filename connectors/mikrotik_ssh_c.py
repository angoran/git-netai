# /connectors/mikrotik_ssh_c.py

import asyncio
import asyncssh
import os
from typing import Dict
from dotenv import load_dotenv

# Loading environment variables (override system env vars)
load_dotenv(override=True)

# Retrieving Mikrotik SSH credentials from the .env file
MIKROTIK_SSH_USERNAME = os.getenv("MIKROTIK_SSH_USERNAME")
MIKROTIK_SSH_PASSWORD = os.getenv("MIKROTIK_SSH_PASSWORD")
MIKROTIK_SSH_PORT = int(os.getenv("MIKROTIK_SSH_PORT", "22"))

async def _mikrotik_ssh_connect(ip_address: str, command: str) -> tuple[bool, str]:
    """
    Connect to MikroTik via SSH and execute a command with auto-quit for pagination.

    Args:
        ip_address: IP address of the MikroTik router
        command: Command to execute

    Returns:
        Tuple (success: bool, output: str)
    """
    if not MIKROTIK_SSH_USERNAME or not MIKROTIK_SSH_PASSWORD:
        return False, "Mikrotik SSH credentials are not set in the .env file."

    try:
        async with asyncssh.connect(
            ip_address,
            port=MIKROTIK_SSH_PORT,
            username=MIKROTIK_SSH_USERNAME,
            password=MIKROTIK_SSH_PASSWORD,
            known_hosts=None
        ) as conn:
            async with conn.create_process() as process:
                process.stdin.write(command + '\n')
                await process.stdin.drain()

                output_lines = []
                try:
                    while True:
                        line = await asyncio.wait_for(process.stdout.readline(), timeout=1.0)
                        if isinstance(line, bytes):
                            line = line.decode('utf-8', errors='replace')
                        output_lines.append(line)

                        if 'Q quit' in line or 'C-z pause' in line:
                            process.stdin.write('q\n')
                            await process.stdin.drain()
                            await asyncio.sleep(0.2)
                            break
                except asyncio.TimeoutError:
                    pass

                return True, ''.join(output_lines)

    except asyncssh.PermissionDenied:
        return False, f"SSH authentication error on {ip_address}"
    except asyncssh.Error as e:
        return False, f"SSH error: {e}"
    except Exception as e:
        return False, f"Unexpected error: {e}"


async def mikrotik_route_check(ip_address: str, destination_ip: str) -> Dict:
    """
    Check route to destination using 'ip route check' command.
    This command is NOT available in the MikroTik REST API.

    Args:
        ip_address: IP address of the MikroTik router
        destination_ip: Destination IP to check routing for

    Returns:
        Dict with route check results
    """
    if not ip_address or not destination_ip:
        return {"error": "Invalid or missing IP address or destination IP"}

    command = f"/ip route check {destination_ip}"
    success, output = await _mikrotik_ssh_connect(ip_address, command)

    if not success:
        return {
            "command": "route_check",
            "router": ip_address,
            "destination": destination_ip,
            "success": False,
            "error": output
        }

    # Parse output
    parsed = {}
    for line in output.strip().split('\n'):
        line = line.strip()
        if line.startswith('--') or 'quit' in line.lower():
            continue
        if ':' in line:
            key, value = line.split(':', 1)
            parsed[key.strip()] = value.strip()

    return {
        "command": "route_check",
        "router": ip_address,
        "destination": destination_ip,
        "success": True,
        "raw_output": output,
        "parsed_data": parsed
    }


async def mikrotik_custom_command(ip_address: str, command: str) -> Dict:
    """
    Execute any custom MikroTik command via SSH (for LLM flexibility).

    Args:
        ip_address: IP address of the MikroTik router
        command: MikroTik command to execute

    Returns:
        Dict with command execution results
    """
    if not ip_address or not command:
        return {"error": "Invalid or missing IP address or command"}

    success, output = await _mikrotik_ssh_connect(ip_address, command)

    return {
        "command": command,
        "router": ip_address,
        "success": success,
        "output": output if success else None,
        "error": None if success else output
    }
