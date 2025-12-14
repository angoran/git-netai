# /connectors/ssh_c.py

import asyncssh
import os
from typing import Tuple
from dotenv import load_dotenv

# Loading environment variables (override system env vars)
load_dotenv(override=True)

# Retrieving SSH credentials from the .env file
SSH_USERNAME = os.getenv("SSH_USERNAME")
SSH_PASSWORD = os.getenv("SSH_PASSWORD")

async def connect_ssh(ip_address: str, command: str) -> Tuple[bool, str]:
    """
    Connects to any SSH-enabled device that implements the SSH protocol according to the RFC specifications.

    Args:
        ip_address (str): The IP address of the SSH device.
        command (str): The command to execute on the SSH server.

    Returns:
        A tuple (success: bool, result: str).
        The result is stdout in case of success, or the error message in case of failure.
    """
    
    # Verify that credentials are not None
    if (not SSH_USERNAME) or (not SSH_PASSWORD):
        return False, "SSH credentials are not set in the .env file."
    
    try:
        # The management of known_hosts is disabled.
        # WARNING: Do NOT use in production for safety reasons.
        async with asyncssh.connect(ip_address,
            username=SSH_USERNAME,
            password=SSH_PASSWORD,
            known_hosts=None) as conn:
            result = await conn.run(command, check=True)
            stdout = result.stdout or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode('utf-8', errors='replace')
            return True, stdout
    except asyncssh.PermissionDenied:
        err_msg = f"SSH authentication error on {ip_address}: Check your credentials."
        print(err_msg)
        return False, err_msg
    except asyncssh.Error as e:
        err_msg = f"SSH Error on {ip_address}: {e}"
        print(err_msg) # For server-side logging
        return False, err_msg
    except Exception as e:
        err_msg = f"An unexpected error has occurred: {str(e)}"
        return False, err_msg

# MCP tool for executing SSH commands
async def send_custom_command(ip_address: str, command: str) -> dict:
    """Execute a remote SSH command on any RFC-compliant SSH device."""
    success, output = await connect_ssh(ip_address, command)
    return {
        "success": success,
        "output": output
    }
