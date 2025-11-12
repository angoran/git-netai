"""Connectors package for network device management.

This package provides modules to connect to various types of network
devices (routers, switches, firewalls) via SSH.
"""

from .ssh_conn import run_network_command, execute_network_command

__all__ = ["run_network_command", "execute_network_command"]
