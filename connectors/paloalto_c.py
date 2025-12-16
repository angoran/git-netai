# /connectors/paloalto_c.py

import asyncio
import asyncssh
import os
import re
from typing import Tuple, List, Dict
from dotenv import load_dotenv

# Loading environment variables (override system env vars)
load_dotenv(override=True)

# Retrieving SSH credentials from the .env file
SSH_USERNAME = os.getenv("SSH_USERNAME")
SSH_PASSWORD = os.getenv("SSH_PASSWORD")

# Palo Alto specific settings
PALO_COMMAND_TIMEOUT = 30  # Timeout for command execution
PALO_PROMPT_PATTERN = r'[\w\-]+@[\w\-]+\([\w\-]+\)>\s*$'  # Pattern: user@hostname(mode)>


async def _connect_palo(ip_address: str, command: str) -> Tuple[bool, str]:
    """
    Connect to Palo Alto firewall in SSH and execute a command using PTY (interactive session).

    Palo Alto firewalls require a PTY (pseudo-terminal) for interactive sessions.

    Args:
        ip_address: The IP address of the Palo Alto firewall
        command: The command to execute

    Returns:
        Tuple (success: bool, output: str)
    """
    # Verify credentials
    if not SSH_USERNAME or not SSH_PASSWORD:
        return False, "SSH credentials are not set in the .env file."

    try:
        # Establish SSH connection
        async with asyncssh.connect(
            ip_address,
            username=SSH_USERNAME,
            password=SSH_PASSWORD,
            known_hosts=None,
            client_keys=None
        ) as conn:

            # Create interactive process with PTY (required for Palo Alto)
            async with conn.create_process(term_type='vt100') as process:
                # Wait for initial prompt (banner + prompt)
                await asyncio.sleep(1.5)

                # Clear any initial output (login banner)
                initial_output = ""
                try:
                    while True:
                        chunk = await asyncio.wait_for(
                            process.stdout.read(8192),
                            timeout=0.5
                        )
                        if chunk:
                            initial_output += chunk
                        else:
                            break
                except asyncio.TimeoutError:
                    pass  # No more initial data

                # Send command
                process.stdin.write(command + '\n')
                await process.stdin.drain()

                # Collect output until we see the prompt again
                output = ""
                start_time = asyncio.get_event_loop().time()

                while True:
                    elapsed = asyncio.get_event_loop().time() - start_time
                    if elapsed > PALO_COMMAND_TIMEOUT:
                        break

                    try:
                        chunk = await asyncio.wait_for(
                            process.stdout.read(4096),
                            timeout=2.0
                        )

                        if chunk:
                            output += chunk

                            # Check if we got the prompt back (end of command output)
                            # Palo Alto prompt format: user@hostname(mode)>
                            if re.search(PALO_PROMPT_PATTERN, output[-100:], re.MULTILINE):
                                break
                        else:
                            # EOF
                            break

                    except asyncio.TimeoutError:
                        # No more data for 2 seconds
                        if output:
                            break
                        continue

                # Send exit command to close session cleanly
                process.stdin.write('exit\n')
                await process.stdin.drain()

                # Clean output: remove echoed command and prompt
                cleaned_output = _clean_palo_output(output, command)

                return True, cleaned_output

    except asyncssh.PermissionDenied:
        err_msg = f"SSH authentication error on {ip_address}: Check your credentials."
        return False, err_msg

    except asyncssh.DisconnectError as e:
        err_msg = f"SSH connection disconnected on {ip_address}: {e}"
        return False, err_msg

    except asyncssh.Error as e:
        err_msg = f"SSH Error on {ip_address}: {e}"
        return False, err_msg

    except asyncio.TimeoutError:
        err_msg = f"Command timeout on {ip_address}: Command took longer than {PALO_COMMAND_TIMEOUT}s"
        return False, err_msg

    except Exception as e:
        err_msg = f"Unexpected error on {ip_address}: {str(e)}"
        return False, err_msg


def _clean_palo_output(output: str, command: str) -> str:
    """
    Clean Palo Alto command output by removing:
    - ANSI escape codes (colors, cursor movement, etc.)
    - The echoed command
    - The prompt at the end
    - Extra whitespace and control characters

    Args:
        output: Raw output from Palo Alto
        command: The command that was executed

    Returns:
        Cleaned output string
    """
    # Remove ANSI escape sequences (colors, cursor movement, etc.)
    # Pattern matches: ESC[...m, ESC[K, ESC[?...h, ESC=, etc.
    ansi_escape = re.compile(r'\x1b\[[0-9;]*[mKHJsu]|\x1b\[[?][0-9;]*[hl]|\x1b[=>]|\x1b\([B0]')
    output = ansi_escape.sub('', output)

    # Remove backspace characters and the character before them
    output = re.sub(r'.\x08', '', output)

    # Remove null bytes
    output = output.replace('\x00', '')

    # Remove carriage returns (keep newlines)
    output = output.replace('\r', '')

    # Split into lines
    lines = output.split('\n')

    # Find and remove the command line and prompts
    cleaned_lines = []
    data_started = False

    for line in lines:
        # Skip the echoed command and any prompt before data
        if not data_started:
            # Skip prompt lines
            if re.search(PALO_PROMPT_PATTERN, line):
                continue
            # Skip empty lines
            if not line.strip():
                continue
            # Skip lines that contain the command echoed multiple times
            if command in line:
                continue
            # If we reach here, data has started
            data_started = True

        # Skip prompt lines anywhere
        if re.search(PALO_PROMPT_PATTERN, line):
            continue

        # Skip lines that are just "lines X-Y" (pager indicator)
        if re.match(r'^\s*lines\s+\d+-\d+\s*$', line):
            continue

        # Skip lines ending with "lines 1-9" or similar (partial pager text)
        line_stripped = line.rstrip()
        if re.search(r'lines\s+\d+-\d+$', line_stripped):
            # Remove the pager text from the end
            line_stripped = re.sub(r'lines\s+\d+-\d+$', '', line_stripped).rstrip()
            if line_stripped:
                cleaned_lines.append(line_stripped)
            continue

        cleaned_lines.append(line)

    # Remove trailing empty lines
    while cleaned_lines and not cleaned_lines[-1].strip():
        cleaned_lines.pop()

    return '\n'.join(cleaned_lines)


# ========== Public Functions ==========

async def palo_send_command(ip_address: str, command: str) -> Dict:
    """
    Execute a command on a Palo Alto firewall.

    Args:
        ip_address: IP address of the Palo Alto firewall
        command: Command to execute (e.g., 'show vpn gateway')

    Returns:
        Dict with success status and output
    """
    success, output = await _connect_palo(ip_address, command)

    return {
        "ip": ip_address,
        "command": command,
        "success": success,
        "output": output
    }


async def palo_send_command_parallel(targets: List[Dict[str, str]], timeout: int = 120) -> Dict:
    """
    Execute commands on multiple Palo Alto firewalls in parallel.

    Args:
        targets: List of {"ip": "10.240.203.241", "command": "show vpn gateway"}
        timeout: Global timeout in seconds (default: 120s)

    Returns:
        Dict mapping each IP to its result
    """
    async def execute_single(target: Dict[str, str]) -> Tuple[str, Dict]:
        """Execute command on a single firewall."""
        ip = target.get("ip", "")
        command = target.get("command", "")

        if not ip or not command:
            return ip, {
                "success": False,
                "output": "Missing ip or command in target",
                "command": command
            }

        try:
            success, output = await _connect_palo(ip, command)
            return ip, {
                "success": success,
                "output": output,
                "command": command
            }
        except Exception as e:
            return ip, {
                "success": False,
                "output": f"Execution error: {str(e)}",
                "command": command
            }

    try:
        # Execute all commands in parallel
        tasks = [execute_single(target) for target in targets]
        results = await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            timeout=timeout
        )

        # Build result dictionary
        result_dict = {}
        for result in results:
            if isinstance(result, Exception):
                result_dict["unknown"] = {
                    "success": False,
                    "output": f"Task exception: {str(result)}"
                }
            elif isinstance(result, tuple) and len(result) == 2:
                ip, output = result
                result_dict[ip] = output

        return result_dict

    except asyncio.TimeoutError:
        return {
            "error": f"Global timeout ({timeout}s) exceeded for parallel execution"
        }
