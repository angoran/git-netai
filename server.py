from typing import Optional

from mcp.server.fastmcp import FastMCP

from connectors.apic_c import (
    analyze_apic_connectivity,
    get_apic_audit_logs,
    get_apic_bridge_domain_multicast_by_tenant,
    get_apic_bridge_domains_multicast,
    get_apic_capacity_metrics,
    get_apic_contracts,
    get_apic_cpu_utilization,
    get_apic_endpoint_tracker,
    get_apic_epg_endpoints,
    get_apic_epgs,
    get_apic_events,
    get_apic_fabric_topology,
    get_apic_faults,
    get_apic_gipo_pool_config,
    get_apic_health_scores,
    get_apic_interface_statistics,
    get_apic_lldp_neighbors,
    get_apic_nodes_inventory,
    get_apic_path_analysis,
    get_apic_physical_interfaces,
    get_apic_resource_utilization,
    get_apic_tenants,
    get_apic_top_talkers,
    get_apic_traffic_analysis,
    get_apic_vrfs,
    get_fabric_health,
    search_apic_by_ip,
)
from connectors.apic_c import test_connection as apic_test
from connectors.aruba_c import (
    get_ap_channel_info,
    get_ap_database,
    get_ap_statistics,
    get_client_list,
    get_controller_info,
    get_license_info,
    get_rogue_ap_list,
    get_wlan_list,
)
from connectors.aruba_c import run_custom_command as aruba_custom_cmd
from connectors.graylog_c import get_streams, get_system_overview, search_logs
from connectors.librenms_c import (
    get_device_by_hostname,
    get_device_eventlog,
    get_device_health,
    get_device_ports,
    get_device_sensors,
    get_device_stats,
    get_devices_by_os,
    get_eventlog,
    get_locations,
    list_devices,
)
from connectors.mikrotik_c import (
    get_bgp_connections,
    get_bgp_sessions,
    get_interfaces,
    get_ip_address,
    get_logs,
    get_route_by_prefix,
    get_system_health,
    get_system_identity,
    get_system_routerboard,
)
from connectors.mikrotik_ssh_c import mikrotik_custom_command, mikrotik_route_check
from connectors.paloalto_c import palo_send_command, palo_send_command_parallel
from connectors.ndfc_c import (
    get_all_switches,
    get_deployment_history,
    get_event_records,
    get_fabric_summary,
    get_fabrics,
    get_interface_details,
    get_network_preview,
    get_network_status,
    get_networks,
    get_sites,
    get_switches,
    get_vrfs,
    login as ndfc_login_func,
    logout as ndfc_logout_func,
)

# Import the necessary functions
from connectors.ssh_c import send_custom_command as ssh_cli_command
from connectors.ssh_c import send_custom_command_parallel as ssh_cli_parallel

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
async def librenms_list_devices(
    filter_type: Optional[str] = None, filter_value: Optional[str] = None
) -> dict:
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
async def librenms_get_device_sensors(
    hostname: str, sensor_type: Optional[str] = None
) -> dict:
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
async def librenms_get_device_eventlog(
    hostname: str, limit: int = 50, sort_order: str = "DESC"
) -> dict:
    """Get event logs for a specific device."""
    return await get_device_eventlog(hostname, limit, sort_order)


# ========== Cisco APIC (ACI) Tools ==========
@mcp.tool()
async def apic_test_connection() -> dict:
    """Test connection to Cisco APIC controller."""
    return await apic_test()


@mcp.tool()
async def apic_get_fabric_health() -> dict:
    """
    Get ACI fabric overall health status.

    Returns health summary including critical faults count, controller status,
    and details of the 5 most recent critical faults.
    """
    return await get_fabric_health()


@mcp.tool()
async def apic_get_tenants() -> dict:
    """
    List all tenants configured on the Cisco APIC.

    Returns list of tenants with name, DN, description, and status.
    Tenants are sorted alphabetically by name.
    """
    return await get_apic_tenants()


@mcp.tool()
async def apic_get_faults() -> dict:
    """
    Retrieve active faults from the Cisco APIC system.

    Returns list of active faults with severity breakdown (critical, major, minor, warning, info).
    Faults are sorted by severity and creation time (most recent first).
    Limited to 50 most recent/critical faults.
    """
    return await get_apic_faults()


@mcp.tool()
async def apic_get_nodes_inventory() -> dict:
    """
    Retrieve ACI fabric nodes inventory.

    Returns complete inventory of fabric nodes including controllers, leafs, and spines.
    Includes node ID, name, serial number, model, role, version, IP address, and fabric status.
    """
    return await get_apic_nodes_inventory()


@mcp.tool()
async def apic_get_epgs(tenant: Optional[str] = None) -> dict:
    """
    Retrieve Endpoint Groups (EPGs) from APIC.

    Args:
        tenant: Optional tenant name filter. If not specified, returns EPGs from all tenants.

    Returns EPGs with tenant, application, name, description, and policy details.
    """
    return await get_apic_epgs(tenant)


@mcp.tool()
async def apic_get_vrfs(tenant: Optional[str] = None) -> dict:
    """
    Retrieve VRFs (Virtual Routing and Forwarding instances) from APIC.

    Args:
        tenant: Optional tenant name filter. If not specified, returns VRFs from all tenants.

    Returns VRFs with tenant, name, description, and policy control settings.
    """
    return await get_apic_vrfs(tenant)


@mcp.tool()
async def apic_get_contracts(tenant: Optional[str] = None) -> dict:
    """
    Retrieve security contracts from APIC.

    Args:
        tenant: Optional tenant name filter. If not specified, returns contracts from all tenants.

    Returns contracts with tenant, name, description, scope, priority, and DSCP settings.
    """
    return await get_apic_contracts(tenant)


@mcp.tool()
async def apic_get_events(time_range: int = 24) -> dict:
    """
    Retrieve recent events from APIC event log.

    Args:
        time_range: Time range in hours (default: 24h)

    Returns recent events with severity breakdown, sorted by creation time.
    Limited to 100 most recent events.
    """
    return await get_apic_events(time_range)


@mcp.tool()
async def apic_get_cpu_utilization() -> dict:
    """
    Retrieve CPU utilization for all fabric nodes.

    Returns CPU usage statistics per node including average, max, and min utilization.
    Shows user, kernel, idle, and wait times for each node.
    """
    return await get_apic_cpu_utilization()


@mcp.tool()
async def apic_get_audit_logs(hours: int = 24) -> dict:
    """
    Retrieve audit logs of configuration changes.

    Args:
        hours: Number of hours back to retrieve logs (default: 24h)

    Returns audit logs with user activity breakdown and configuration changes.
    Limited to 50 most recent changes.
    """
    return await get_apic_audit_logs(hours)


@mcp.tool()
async def apic_get_fabric_topology() -> dict:
    """
    Retrieve ACI fabric topology with nodes and links.

    Returns complete fabric topology including all nodes (controllers, leafs, spines)
    and fabric links between them. Useful for understanding physical connectivity.
    """
    return await get_apic_fabric_topology()


@mcp.tool()
async def apic_get_epg_endpoints(tenant: str, application: str, epg: str) -> dict:
    """
    Retrieve endpoints from a specific EPG.

    Args:
        tenant: Tenant name
        application: Application profile name
        epg: Endpoint Group name

    Returns all endpoints in the EPG with MAC, IP, encapsulation, and location details.
    """
    return await get_apic_epg_endpoints(tenant, application, epg)


@mcp.tool()
async def apic_track_endpoint(mac_or_ip: str) -> dict:
    """
    Track a specific endpoint by MAC or IP address.

    Args:
        mac_or_ip: MAC address (format: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX) or IP address

    Returns endpoint location including tenant, application, EPG, encapsulation, and other details.
    Useful for troubleshooting connectivity issues.
    """
    return await get_apic_endpoint_tracker(mac_or_ip)


@mcp.tool()
async def apic_search_by_ip(ip_address: str) -> dict:
    """
    Search APIC objects by IP address.

    Args:
        ip_address: IP address to search

    Returns matching endpoints and subnets that contain or use this IP address.
    Comprehensive search across the fabric.
    """
    return await search_apic_by_ip(ip_address)


@mcp.tool()
async def apic_get_health_scores() -> dict:
    """
    Retrieve health scores of APIC objects.

    Returns health scores of monitored objects with severity classification.
    Objects are classified as healthy (>=90), minor (75-89), major (50-74), or critical (<50).
    """
    return await get_apic_health_scores()


@mcp.tool()
async def apic_get_physical_interfaces(node_id: Optional[str] = None) -> dict:
    """
    Retrieve physical interfaces from a specific node or all nodes.

    Args:
        node_id: Optional node ID filter. If not specified, returns interfaces from all nodes (limited to 100).

    Returns list of physical interfaces with admin state, operational state, speed, usage, and MTU.
    """
    return await get_apic_physical_interfaces(node_id)


@mcp.tool()
async def apic_get_interface_statistics(node_id: Optional[str] = None, interface: Optional[str] = None) -> dict:
    """
    Retrieve interface statistics for specific node and/or interface.

    Args:
        node_id: Optional node ID filter
        interface: Optional specific interface name

    Returns interface statistics including operational state, speed, and usage.
    Useful for monitoring interface health and performance.
    """
    return await get_apic_interface_statistics(node_id, interface)


@mcp.tool()
async def apic_get_lldp_neighbors(node_id: Optional[str] = None) -> dict:
    """
    Retrieve LLDP neighbors discovered on fabric nodes.

    Args:
        node_id: Optional node ID filter. If not specified, returns neighbors from all nodes (limited to 50).

    Returns LLDP neighbor information including remote system name, port description,
    chassis ID, and management IP. Useful for understanding physical topology.
    """
    return await get_apic_lldp_neighbors(node_id)


@mcp.tool()
async def apic_get_gipo_pool_config() -> dict:
    """
    Retrieve GIPo (Group IP Outer) multicast pool configuration.

    Returns GIPo pool configuration for bridge domains and VRFs.
    GIPo addresses are used for BUM (Broadcast, Unknown unicast, Multicast) traffic in the fabric.
    """
    return await get_apic_gipo_pool_config()


@mcp.tool()
async def apic_get_bridge_domains_multicast() -> dict:
    """
    Retrieve multicast information for all bridge domains.

    Returns comprehensive multicast configuration including:
    - GIPo multicast addresses (bcastP) for BUM traffic
    - IGMP snooping configuration
    - Multicast flooding settings
    - IPv6 multicast support
    - Discovered IGMP groups
    - Static multicast groups
    """
    return await get_apic_bridge_domains_multicast()


@mcp.tool()
async def apic_get_bridge_domain_multicast_by_tenant(tenant: str) -> dict:
    """
    Retrieve multicast information for bridge domains of a specific tenant.

    Args:
        tenant: Tenant name to filter bridge domains

    Returns multicast configuration for the tenant's bridge domains including GIPo addresses.
    """
    return await get_apic_bridge_domain_multicast_by_tenant(tenant)


@mcp.tool()
async def apic_get_capacity_metrics() -> dict:
    """
    Retrieve fabric capacity metrics.

    Returns capacity information for each node including:
    - Current usage
    - Maximum capacity
    - Utilization percentage
    - Context information

    Useful for capacity planning and resource monitoring.
    """
    return await get_apic_capacity_metrics()


@mcp.tool()
async def apic_get_resource_utilization() -> dict:
    """
    Analyze CPU and memory resource utilization across the fabric.

    Returns:
    - CPU utilization per node
    - Memory utilization per node
    - Average CPU and memory usage
    - Nodes with high utilization (>80% CPU, >85% memory)

    Essential for performance monitoring and capacity planning.
    """
    return await get_apic_resource_utilization()


@mcp.tool()
async def apic_get_traffic_analysis(tenant: Optional[str] = None, epg: Optional[str] = None) -> dict:
    """
    Analyze network traffic for a tenant or EPG.

    Args:
        tenant: Optional tenant name to filter traffic
        epg: Optional EPG name to filter traffic (requires tenant)

    Returns traffic statistics including:
    - Bytes average, max, and min
    - Traffic data over 5-minute intervals
    - Total bytes transferred

    Useful for traffic monitoring and troubleshooting.
    """
    return await get_apic_traffic_analysis(tenant, epg)


@mcp.tool()
async def apic_get_top_talkers() -> dict:
    """
    Identify top network conversations (top talkers).

    Returns the top 20 traffic generators including:
    - Tenant and EPG information
    - Bytes and packets transferred
    - Utilization percentage
    - Traffic ranking

    Useful for identifying bandwidth consumers and traffic patterns.
    """
    return await get_apic_top_talkers()


@mcp.tool()
async def apic_analyze_path(src_epg: str, dst_epg: str) -> dict:
    """
    Analyze network paths between two EPGs.

    Args:
        src_epg: Source EPG DN or name
        dst_epg: Destination EPG DN or name

    Returns:
    - Contracts found between EPGs
    - Consumer/provider relationships
    - Connectivity status

    Useful for troubleshooting connectivity issues and validating security policies.
    """
    return await get_apic_path_analysis(src_epg, dst_epg)


@mcp.tool()
async def apic_analyze_connectivity() -> dict:
    """
    Perform comprehensive connectivity and health analysis of the APIC infrastructure.

    Returns complete analysis including:
    - APIC controller connectivity and version
    - Fabric health (nodes online, critical faults)
    - Capacity metrics and high-utilization nodes
    - Multicast configuration summary

    This is a composite function that provides an overall health check of the entire fabric.
    """
    return await analyze_apic_connectivity()


# ========== Cisco NDFC (Nexus Dashboard Fabric Controller) Tools ==========
@mcp.tool()
async def ndfc_login() -> dict:
    """
    Authenticate to NDFC and obtain JWT token.
    Token is valid for 3600 seconds (1 hour).

    Returns:
        Dict with success status and authentication information
    """
    return await ndfc_login_func()


@mcp.tool()
async def ndfc_logout() -> dict:
    """
    Logout from NDFC and clear JWT token.

    Returns:
        Dict with success status
    """
    return await ndfc_logout_func()


@mcp.tool()
async def ndfc_get_sites() -> dict:
    """
    Get list of NDFC sites/fabrics.

    Returns:
        Dict with sites information
    """
    return await get_sites()


@mcp.tool()
async def ndfc_get_fabrics() -> dict:
    """
    Get list of fabric configurations.

    Returns:
        Dict with fabrics information including fabric names, types, and status
    """
    return await get_fabrics()


@mcp.tool()
async def ndfc_get_switches(fabric_name: str) -> dict:
    """
    Get list of switches in a specific fabric.

    Args:
        fabric_name: Name of the fabric

    Returns:
        Dict with switches information including serial numbers, IP addresses, and status
    """
    return await get_switches(fabric_name)


@mcp.tool()
async def ndfc_get_networks(fabric_name: str) -> dict:
    """
    Get list of networks in a specific fabric.

    Args:
        fabric_name: Name of the fabric

    Returns:
        Dict with networks information including network names, VLANs, and configuration
    """
    return await get_networks(fabric_name)


@mcp.tool()
async def ndfc_get_vrfs(fabric_name: str) -> dict:
    """
    Get list of VRFs (Virtual Routing and Forwarding instances) in a specific fabric.

    Args:
        fabric_name: Name of the fabric

    Returns:
        Dict with VRFs information including VRF names and configuration
    """
    return await get_vrfs(fabric_name)


@mcp.tool()
async def ndfc_get_fabric_summary() -> dict:
    """
    Get summary of all fabric associations (MSD fabric-member relationships).

    Returns:
        Dict with fabric summary and associations
    """
    return await get_fabric_summary()


@mcp.tool()
async def ndfc_get_deployment_history(fabric_name: str) -> dict:
    """
    Get configuration deployment history for a specific fabric.

    Args:
        fabric_name: Name of the fabric

    Returns:
        Dict with deployment history records including timestamps and status
    """
    return await get_deployment_history(fabric_name)


@mcp.tool()
async def ndfc_get_network_status(fabric_name: str, network_name: str) -> dict:
    """
    Get deployment status for a specific network in a fabric.

    Args:
        fabric_name: Name of the fabric
        network_name: Name of the network

    Returns:
        Dict with network status details including deployment state and errors
    """
    return await get_network_status(fabric_name, network_name)


@mcp.tool()
async def ndfc_get_network_preview(fabric_name: str, network_name: str) -> dict:
    """
    Get configuration preview for a specific network deployment.

    Args:
        fabric_name: Name of the fabric
        network_name: Name of the network

    Returns:
        Dict with configuration preview for each switch showing what will be deployed
    """
    return await get_network_preview(fabric_name, network_name)


@mcp.tool()
async def ndfc_get_interface_details(serial_number: str) -> dict:
    """
    Get detailed interface information for a specific switch by serial number.

    Args:
        serial_number: Serial number of the switch (e.g., "FDO23460MQC")

    Returns:
        Dict with list of all interfaces and their details (status, VLAN, compliance, etc.)
    """
    return await get_interface_details(serial_number)


@mcp.tool()
async def ndfc_get_all_switches() -> dict:
    """
    Get list of all switches across all fabrics.

    Returns:
        Dict with list of switches including serial numbers, fabric, IP addresses, etc.
    """
    return await get_all_switches()


@mcp.tool()
async def ndfc_get_event_records(limit: Optional[int] = None, severity: Optional[str] = None) -> dict:
    """
    Get event records from Nexus Dashboard event monitoring.
    This endpoint provides critical events, alarms, and system notifications.

    Args:
        limit: Optional maximum number of events to return
        severity: Optional filter by severity (critical, error, warning, info)

    Returns:
        Dict with event records including metadata and items with severity, description, timestamps, etc.
    """
    return await get_event_records(limit, severity)


# Entry Point
if __name__ == "__main__":
    mcp.run(transport="stdio")
