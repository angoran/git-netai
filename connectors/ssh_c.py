# /connectors/ssh_c.py

import asyncssh
import asyncio
import os
from typing import Tuple, List, Dict
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


async def send_custom_command_parallel(targets: List[Dict[str, str]], timeout: int = 30) -> Dict:
    """
    Execute SSH commands on multiple devices in parallel.

    Args:
        targets: List of target dictionaries with "ip" and "command" keys.
                 Example: [{"ip": "192.168.1.1", "command": "show version"}, ...]
        timeout: Global timeout in seconds for all operations (default: 30s)

    Returns:
        Dict mapping each IP to its result: {"192.168.1.1": {"success": bool, "output": str}, ...}
    """
    async def execute_single(target: Dict[str, str]) -> Tuple[str, Dict]:
        """Execute command on a single target and return (ip, result)."""
        ip = target.get("ip", "")
        command = target.get("command", "")

        if not ip or not command:
            return ip, {"success": False, "output": "Missing ip or command in target"}

        try:
            success, output = await connect_ssh(ip, command)
            return ip, {"success": success, "output": output}
        except Exception as e:
            return ip, {"success": False, "output": f"Execution error: {str(e)}"}

    # Execute all commands in parallel with timeout protection
    try:
        tasks = [execute_single(target) for target in targets]
        results = await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            timeout=timeout
        )

        # Build result dictionary
        result_dict = {}
        for result in results:
            if isinstance(result, Exception):
                # Handle exceptions from gather
                result_dict["unknown"] = {"success": False, "output": f"Task exception: {str(result)}"}
            elif isinstance(result, tuple) and len(result) == 2:
                ip, output = result
                result_dict[ip] = output

        return result_dict

    except asyncio.TimeoutError:
        return {"error": f"Global timeout ({timeout}s) exceeded for parallel execution"}
    except Exception as e:
        return {"error": f"Parallel execution error: {str(e)}"}
