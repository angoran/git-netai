"""SSH connection module for network device management.

This module provides functions to connect via SSH to various network
devices (routers, switches, firewalls) and execute CLI commands.
"""

import os
import logging
from typing import Tuple, Optional, Dict, Any
from netmiko import ConnectHandler
from netmiko.ssh_autodetect import SSHDetect
from dotenv import load_dotenv

# Configure logging
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Get SSH credentials from .env file
SSH_USERNAME = os.getenv("SSH_USERNAME")
SSH_PASSWORD = os.getenv("SSH_PASSWORD")


def detect_device_type(
    ip_address: str,
    username: str,
    password: str,
    timeout: int = 30
) -> Optional[str]:
    """
    Auto-detect the device type using Netmiko's SSHDetect.

    Args:
        ip_address: IP address of the target network device.
        username: SSH username.
        password: SSH password.
        timeout: Connection timeout in seconds. Default: 30.

    Returns:
        The detected device type (e.g., 'cisco_ios', 'cisco_nxos') or None if detection fails.
    """
    try:
        # Configure device for auto-detection
        device_params: Dict[str, Any] = {
            "device_type": "autodetect",
            "host": ip_address,
            "username": username,
            "password": password,
            "timeout": timeout,
        }

        logger.info(f"Starting device type auto-detection for {ip_address}")

        # Use SSHDetect to identify the device type
        detector = SSHDetect(**device_params)
        detected_type = detector.autodetect()

        if detected_type:
            logger.info(f"Device type detected: {detected_type} for {ip_address}")
        else:
            logger.warning(f"Unable to auto-detect device type for {ip_address}")

        return detected_type

    except Exception as e:
        logger.error(f"Auto-detection failed for {ip_address}: {str(e)}")
        return None


def execute_network_command(
    ip_address: str,
    command: str,
    device_type: str = "autodetect",
    timeout: int = 30
) -> Tuple[bool, str]:
    """
    Connect to a network device via SSH and execute a command.

    Args:
        ip_address: IP address of the target network device.
        command: CLI command to execute (e.g., 'show system info', 'show version').
        device_type: Netmiko device type (e.g., 'cisco_ios', 'mikrotik_routeros',
                     'paloalto_panos', 'autodetect'). Default: 'autodetect'.
        timeout: Connection timeout in seconds. Default: 30.

    Returns:
        A tuple (success: bool, result: str).
        The result is stdout on success, or error message on failure.

    Raises:
        ValueError: If SSH credentials are not configured.
    """
    # Check if credentials are defined
    if not SSH_USERNAME or not SSH_PASSWORD:
        error_msg = (
            "Error: SSH_USERNAME and SSH_PASSWORD must be "
            "defined in the .env file"
        )
        logger.error(error_msg)
        return False, error_msg

    try:
        # Handle auto-detection if requested
        actual_device_type = device_type
        if device_type == "autodetect":
            logger.info(f"Auto-detection requested for {ip_address}")
            detected = detect_device_type(ip_address, SSH_USERNAME, SSH_PASSWORD, timeout)

            if detected:
                actual_device_type = detected
                logger.info(f"Using detected device type: {actual_device_type}")
            else:
                error_msg = f"Failed to auto-detect device type for {ip_address}"
                logger.error(error_msg)
                return False, error_msg

        # Configure the target network device
        target_device: Dict[str, Any] = {
            "device_type": actual_device_type,
            "host": ip_address,
            "username": SSH_USERNAME,
            "password": SSH_PASSWORD,
            "timeout": timeout,
            "session_log": None,  # Can be enabled for debugging
        }

        # Connect and execute the command
        logger.info(f"SSH connection to device {ip_address} (type: {actual_device_type})")
        with ConnectHandler(**target_device) as net_connect:
            result = net_connect.send_command(command, read_timeout=timeout)
            # Ensure output is always a string
            output = str(result) if not isinstance(result, str) else result
            logger.info(f"Command executed successfully on {ip_address}")
            return True, output

    except Exception as e:
        error_message = f"Connection error to device {ip_address}: {str(e)}"
        logger.error(error_message)
        return False, error_message


def run_network_command(
    ip_address: str,
    command: str,
    device_type: str = "autodetect"
) -> str:
    """
    Wrapper function for MCP integration.

    Executes a command on a network device and returns the result.

    Args:
        ip_address: IP address of the target network device.
        command: CLI command to execute.
        device_type: Netmiko device type. Default: 'autodetect'.

    Returns:
        The command result (stdout or error message).
    """
    _, result = execute_network_command(ip_address, command, device_type)
    return result
