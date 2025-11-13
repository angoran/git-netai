"""Main entry point for the NET-AI-ASSISTANT MCP server.

This MCP server provides tools for managing network devices via SSH
(routers, switches, firewalls from multiple vendors).
"""

from mcp.server.fastmcp import FastMCP
from connectors.ssh_conn import run_network_command

# Import new connector functions
from connectors.librenms_con import (
    search_devices, filter_devices, get_statistics_by_field,
    get_device_interfaces as librenms_get_interfaces,
    get_device_sensors as librenms_get_sensors,
    get_port_history, get_device_uptime, get_switch_ports_status,
    get_device_info_smart, get_interfaces_smart,
    get_sensors_smart, get_ports_smart, get_locations, get_eventlog,
    get_device_eventlog_smart
)
from connectors.graylog_con import (
    search_logs, get_streams, get_stream_stats, get_system_overview
)
from connectors.apic_con import (
    test_apic_connection, get_apic_fabric_health, get_apic_tenants,
    get_apic_faults, get_apic_nodes_inventory, get_apic_epgs,
    get_apic_interface_statistics, get_apic_events, get_apic_contracts,
    get_apic_cpu_utilization, get_apic_epg_endpoints, get_apic_fabric_topology,
    get_apic_traffic_analysis, get_apic_lldp_neighbors, get_apic_audit_logs,
    get_apic_endpoint_tracker, get_apic_path_analysis, get_apic_top_talkers,
    get_apic_resource_utilization, get_apic_bridge_domains_multicast,
    get_apic_bridge_domain_multicast_by_tenant,
    get_apic_vrfs, get_apic_physical_interfaces, search_apic_by_ip,
    get_apic_capacity_metrics, get_apic_health_scores, analyze_apic_connectivity,
    get_apic_gipo_pool_config
)
from connectors.aruba_con import ArubaConnector

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


# ========== LIBRENMS TOOLS ==========

@mcp.tool()
async def search_librenms_devices(criteria: str, value: str) -> list:
    """
    Search LibreNMS devices by hostname, sysName, sysDescr, or IP address.

    Args:
        criteria: Search criterion (hostname, sysName, sysDescr, ip, device_id)
        value: Value to search for

    Returns:
        List of matching devices
    """
    return search_devices(criteria, value)

@mcp.tool()
async def filter_librenms_devices(criteria: str, value: str) -> list:
    """
    Filter LibreNMS devices by OS, hardware, features, or location.

    Args:
        criteria: Filter criterion (os, hardware, features, location)
        value: Value to filter by

    Returns:
        List of filtered devices
    """
    return filter_devices(criteria, value)

@mcp.tool()
async def get_librenms_statistics(field: str) -> dict:
    """
    Get exact statistics of LibreNMS devices by any field (os, hardware, type, etc.).

    Args:
        field: Field to analyze for statistics

    Returns:
        Dictionary with total count and breakdown by field values
    """
    return get_statistics_by_field(field)

@mcp.tool()
async def get_device_interfaces_api(device_id: str) -> dict:
    """
    Retrieve interface status of a device via LibreNMS API.

    Args:
        device_id: Device ID in LibreNMS

    Returns:
        Dictionary with interface information (name, status, speed, description)
    """
    return librenms_get_interfaces(device_id)

@mcp.tool()
async def get_device_sensors_api(device_id: str) -> dict:
    """
    Retrieve sensor status of a device via LibreNMS API.

    Args:
        device_id: Device ID in LibreNMS

    Returns:
        Dictionary with sensor information (temperature, voltage, etc.)
    """
    return librenms_get_sensors(device_id)

@mcp.tool()
async def get_port_history_api(device_id: str, port_id: str, period: str = "day") -> dict:
    """
    Retrieve port history via LibreNMS API.

    Args:
        device_id: Device ID in LibreNMS
        port_id: Port ID
        period: Time period (hour, day, week, month)

    Returns:
        Dictionary with port history data
    """
    return get_port_history(device_id, port_id, period)

@mcp.tool()
async def get_device_uptime_api(device_id: str) -> dict:
    """
    Retrieve device uptime and availability via LibreNMS API.

    Args:
        device_id: Device ID in LibreNMS

    Returns:
        Dictionary with uptime and availability information
    """
    return get_device_uptime(device_id)

@mcp.tool()
async def get_switch_ports_status_api(device_id: str) -> dict:
    """
    Retrieve detailed port status of a switch via LibreNMS API.

    Args:
        device_id: Device ID in LibreNMS

    Returns:
        Dictionary with detailed port status (VLAN, trunk, speed, etc.)
    """
    return get_switch_ports_status(device_id)

@mcp.tool()
async def get_device_info(identifier: str) -> dict:
    """
    Get device information by NAME or ID (uptime, status). Automatic resolution.

    Args:
        identifier: Device name, hostname, or ID

    Returns:
        Dictionary with device information
    """
    return get_device_info_smart(identifier)

@mcp.tool()
async def get_device_interfaces(identifier: str) -> dict:
    """
    Get interface status by device NAME or ID. Automatic resolution.

    Args:
        identifier: Device name, hostname, or ID

    Returns:
        Dictionary with interface status
    """
    return get_interfaces_smart(identifier)

@mcp.tool()
async def get_device_sensors(identifier: str) -> dict:
    """
    Get sensor status by device NAME or ID. Automatic resolution.

    Args:
        identifier: Device name, hostname, or ID

    Returns:
        Dictionary with sensor status
    """
    return get_sensors_smart(identifier)

@mcp.tool()
async def get_device_ports(identifier: str) -> dict:
    """
    Get port status by device NAME or ID. Automatic resolution.

    Args:
        identifier: Device name, hostname, or ID

    Returns:
        Dictionary with port status
    """
    return get_ports_smart(identifier)

@mcp.tool()
async def get_librenms_locations() -> dict:
    """
    List all LibreNMS device locations with coordinates.

    Returns:
        Dictionary with location information (ID, name, latitude, longitude)
    """
    return get_locations()

@mcp.tool()
async def get_librenms_eventlog(limit: int = 100, sortorder: str = "DESC") -> dict:
    """
    Retrieve general LibreNMS event logs with pagination.

    Args:
        limit: Maximum number of logs to return (default: 100)
        sortorder: Sort order DESC or ASC (default: DESC)

    Returns:
        Dictionary with event logs
    """
    return get_eventlog(limit, sortorder)

@mcp.tool()
async def get_device_eventlog(identifier: str, limit: int = 50, sortorder: str = "DESC") -> dict:
    """
    Get event logs by device name with automatic resolution.

    Args:
        identifier: Device name, hostname, or ID
        limit: Maximum number of logs to return (default: 50)
        sortorder: Sort order DESC or ASC (default: DESC)

    Returns:
        Dictionary with device-specific event logs
    """
    return get_device_eventlog_smart(identifier, limit, sortorder)

# ========== GRAYLOG TOOLS ==========

@mcp.tool()
async def search_graylog_logs(query: str, hours: int = 24, limit: int = 100) -> dict:
    """
    Search log messages in Graylog with query and time period.

    Args:
        query: Search query string
        hours: Number of hours to search back (default: 24)
        limit: Maximum number of results (default: 100)

    Returns:
        Dictionary with matching log messages
    """
    return search_logs(query, hours, limit)

@mcp.tool()
async def get_graylog_streams() -> dict:
    """
    List all available log streams in Graylog.

    Returns:
        Dictionary with stream information (ID, title, description, status)
    """
    return get_streams()

@mcp.tool()
async def get_graylog_stream_statistics(stream_id: str, hours: int = 24) -> dict:
    """
    Get statistics of a specific Graylog stream over a time period.

    Args:
        stream_id: Stream ID in Graylog
        hours: Number of hours to analyze (default: 24)

    Returns:
        Dictionary with stream statistics
    """
    return get_stream_stats(stream_id, hours)

@mcp.tool()
async def get_graylog_system_status() -> dict:
    """
    Get overall Graylog system status (nodes, version, status).

    Returns:
        Dictionary with system information
    """
    return get_system_overview()

# ========== CISCO APIC TOOLS ==========

@mcp.tool()
async def test_cisco_apic_connection() -> dict:
    """
    Test connection to Cisco APIC controller.

    Returns:
        Dictionary with connection test result
    """
    return test_apic_connection()

@mcp.tool()
async def get_cisco_apic_fabric_health() -> dict:
    """
    Get overall health status of Cisco ACI fabric.

    Returns:
        Dictionary with fabric health information and critical faults
    """
    return get_apic_fabric_health()

@mcp.tool()
async def get_cisco_apic_tenants() -> dict:
    """
    List all tenants configured on APIC.

    Returns:
        Dictionary with tenant information
    """
    return get_apic_tenants()

@mcp.tool()
async def get_cisco_apic_faults() -> dict:
    """
    Retrieve active faults from APIC system.

    Returns:
        Dictionary with fault information including severity breakdown
    """
    return get_apic_faults()

@mcp.tool()
async def get_cisco_apic_nodes_inventory() -> dict:
    """
    Get fabric node inventory (controllers, leaf, spine).

    Returns:
        Dictionary with node inventory including role breakdown
    """
    return get_apic_nodes_inventory()

@mcp.tool()
async def get_cisco_apic_epgs(tenant: str = None) -> dict:
    """
    Get EPGs from a tenant or all tenants.

    Args:
        tenant: Tenant name (optional, returns all if not specified)

    Returns:
        Dictionary with EPG information
    """
    return get_apic_epgs(tenant)

@mcp.tool()
async def get_cisco_apic_interface_statistics(node_id: str = None, interface: str = None) -> dict:
    """
    Get interface statistics for a specific node.

    Args:
        node_id: Node ID (optional)
        interface: Interface name (optional)

    Returns:
        Dictionary with interface statistics
    """
    return get_apic_interface_statistics(node_id, interface)

@mcp.tool()
async def get_cisco_apic_events(time_range: int = 24) -> dict:
    """
    Get recent events from APIC log.

    Args:
        time_range: Time range in hours (default: 24)

    Returns:
        Dictionary with event information
    """
    return get_apic_events(time_range)

@mcp.tool()
async def get_cisco_apic_contracts(tenant: str = None) -> dict:
    """
    Get security contracts from a tenant or all tenants.

    Args:
        tenant: Tenant name (optional)

    Returns:
        Dictionary with contract information
    """
    return get_apic_contracts(tenant)

@mcp.tool()
async def get_cisco_apic_cpu_utilization() -> dict:
    """
    Get CPU utilization of all fabric nodes.

    Returns:
        Dictionary with CPU utilization per node
    """
    return get_apic_cpu_utilization()

@mcp.tool()
async def get_cisco_apic_epg_endpoints(tenant: str, application: str, epg: str) -> dict:
    """
    Get endpoints of a specific EPG.

    Args:
        tenant: Tenant name
        application: Application profile name
        epg: EPG name

    Returns:
        Dictionary with endpoint information
    """
    return get_apic_epg_endpoints(tenant, application, epg)

@mcp.tool()
async def get_cisco_apic_fabric_topology() -> dict:
    """
    Get complete topology of ACI fabric.

    Returns:
        Dictionary with topology information (nodes and links)
    """
    return get_apic_fabric_topology()

@mcp.tool()
async def get_cisco_apic_traffic_analysis(tenant: str = None, epg: str = None) -> dict:
    """
    Analyze traffic for a specific tenant or EPG.

    Args:
        tenant: Tenant name (optional)
        epg: EPG name (optional)

    Returns:
        Dictionary with traffic analysis data
    """
    return get_apic_traffic_analysis(tenant, epg)

@mcp.tool()
async def get_cisco_apic_lldp_neighbors(node_id: str = None) -> dict:
    """
    Get LLDP neighbors for a node or all nodes.

    Args:
        node_id: Node ID (optional)

    Returns:
        Dictionary with LLDP neighbor information
    """
    return get_apic_lldp_neighbors(node_id)

@mcp.tool()
async def get_cisco_apic_audit_logs(hours: int = 24) -> dict:
    """
    Get audit logs of configuration changes.

    Args:
        hours: Number of hours to retrieve (default: 24)

    Returns:
        Dictionary with audit log information
    """
    return get_apic_audit_logs(hours)

@mcp.tool()
async def get_cisco_apic_endpoint_tracker(mac_or_ip: str) -> dict:
    """
    Track a specific endpoint by MAC or IP address.

    Args:
        mac_or_ip: MAC address (XX:XX:XX:XX:XX:XX) or IP address

    Returns:
        Dictionary with endpoint tracking information
    """
    return get_apic_endpoint_tracker(mac_or_ip)

@mcp.tool()
async def get_cisco_apic_path_analysis(src_epg: str, dst_epg: str) -> dict:
    """
    Analyze network paths between two EPGs.

    Args:
        src_epg: Source EPG DN or name
        dst_epg: Destination EPG DN or name

    Returns:
        Dictionary with path analysis
    """
    return get_apic_path_analysis(src_epg, dst_epg)

@mcp.tool()
async def get_cisco_apic_top_talkers() -> dict:
    """
    Get top network conversations (top talkers).

    Returns:
        Dictionary with top talker information
    """
    return get_apic_top_talkers()

@mcp.tool()
async def get_cisco_apic_resource_utilization() -> dict:
    """
    Get resource utilization for capacity planning.

    Returns:
        Dictionary with CPU and memory utilization per node
    """
    return get_apic_resource_utilization()

@mcp.tool()
async def get_cisco_apic_bridge_domains_multicast() -> dict:
    """
    Retrieve multicast addresses and configuration of bridge domains.

    Returns:
        Dictionary with bridge domain multicast information including GIPo addresses
    """
    return get_apic_bridge_domains_multicast()

@mcp.tool()
async def get_cisco_apic_bridge_domain_multicast_by_tenant(tenant: str) -> dict:
    """
    Get multicast addresses of bridge domains for a specific tenant.

    Args:
        tenant: Tenant name

    Returns:
        Dictionary with bridge domain multicast information for the tenant
    """
    return get_apic_bridge_domain_multicast_by_tenant(tenant)

@mcp.tool()
async def get_cisco_apic_vrfs(tenant: str = None) -> dict:
    """
    Retrieve VRFs from a tenant or all tenants.

    Args:
        tenant: Tenant name (optional)

    Returns:
        Dictionary with VRF information
    """
    return get_apic_vrfs(tenant)

@mcp.tool()
async def get_cisco_apic_physical_interfaces(node_id: str = None) -> dict:
    """
    Get physical interfaces of a node or all fabric nodes.

    Args:
        node_id: Node ID (optional)

    Returns:
        Dictionary with physical interface information
    """
    return get_apic_physical_interfaces(node_id)

@mcp.tool()
async def search_cisco_apic_by_ip(ip_address: str) -> dict:
    """
    Complete search of APIC objects by IP address (endpoints, subnets).

    Args:
        ip_address: IP address to search for

    Returns:
        Dictionary with search results (endpoints, subnets, interfaces)
    """
    return search_apic_by_ip(ip_address)

@mcp.tool()
async def get_cisco_apic_capacity_metrics() -> dict:
    """
    Get capacity and utilization metrics of APIC fabric.

    Returns:
        Dictionary with capacity metrics per node
    """
    return get_apic_capacity_metrics()

@mcp.tool()
async def get_cisco_apic_health_scores() -> dict:
    """
    Get detailed health scores of APIC objects.

    Returns:
        Dictionary with health scores and issue breakdown
    """
    return get_apic_health_scores()

@mcp.tool()
async def analyze_cisco_apic_connectivity() -> dict:
    """
    Complete connectivity and health analysis of APIC infrastructure.

    Returns:
        Dictionary with comprehensive connectivity analysis
    """
    return analyze_apic_connectivity()

@mcp.tool()
async def get_cisco_apic_gipo_pool_config() -> dict:
    """
    Get global GIPo pool configuration (fabric multicast addresses).

    Returns:
        Dictionary with GIPo pool configuration
    """
    return get_apic_gipo_pool_config()

# ========== ARUBA WIFI TOOLS ==========

# Initialize ARUBA connector
aruba_connector = ArubaConnector()

@mcp.tool()
async def get_aruba_ap_database(limit: int = None) -> dict:
    """
    Get complete list of ARUBA Access Points.

    Args:
        limit: Optional limit on number of APs to return (for testing)

    Returns:
        Dictionary with AP database
    """
    result = aruba_connector.get_ap_database(limit)
    return result

@mcp.tool()
async def get_aruba_client_list(limit: int = None) -> dict:
    """
    Get list of WiFi clients connected to ARUBA APs.

    Args:
        limit: Optional limit on number of clients to return (for testing)

    Returns:
        Dictionary with user table
    """
    result = aruba_connector.get_client_list(limit)
    return result

@mcp.tool()
async def get_aruba_rogue_ap_list(limit: int = None) -> dict:
    """
    Get list of unauthorized access points detected (security).

    Args:
        limit: Optional limit on number of rogue APs to return (for testing)

    Returns:
        Dictionary with rogue AP list
    """
    result = aruba_connector.get_rogue_ap_list(limit)
    return result

@mcp.tool()
async def get_aruba_ap_channel_info() -> dict:
    """
    Get information on active channels for RF optimization.

    Returns:
        Dictionary with AP channel information
    """
    result = aruba_connector.get_ap_channel_info()
    return result

@mcp.tool()
async def get_aruba_wlan_list() -> dict:
    """
    Get WLAN/SSID profile configuration.

    Returns:
        Dictionary with WLAN configuration
    """
    result = aruba_connector.get_wlan_list()
    return result

@mcp.tool()
async def get_aruba_ap_statistics() -> dict:
    """
    Get performance metrics and ARM state of APs.

    Returns:
        Dictionary with AP statistics
    """
    result = aruba_connector.get_ap_statistics()
    return result

@mcp.tool()
async def get_aruba_license_info() -> dict:
    """
    Get ARUBA license compliance information.

    Returns:
        Dictionary with license information
    """
    result = aruba_connector.get_license_info()
    return result

@mcp.tool()
async def get_aruba_vlan_info() -> dict:
    """
    Get VLAN network configuration.

    Returns:
        Dictionary with VLAN information
    """
    result = aruba_connector.get_vlan_info()
    return result

@mcp.tool()
async def get_aruba_cluster_info() -> dict:
    """
    Get High Availability cluster status.

    Returns:
        Dictionary with cluster information
    """
    result = aruba_connector.get_cluster_info()
    return result

@mcp.tool()
async def get_aruba_bandwidth_contracts() -> dict:
    """
    Get QoS bandwidth contracts for users.

    Returns:
        Dictionary with bandwidth contract information
    """
    result = aruba_connector.get_bandwidth_contracts()
    return result

@mcp.tool()
async def get_aruba_controller_info() -> dict:
    """
    Get ARUBA controller system information.

    Returns:
        Dictionary with controller information
    """
    result = aruba_connector.get_controller_info()
    return result

@mcp.tool()
async def get_aruba_ap_details(ap_name: str) -> dict:
    """
    Get detailed information for a specific Access Point.

    Args:
        ap_name: Access Point name

    Returns:
        Dictionary with AP details
    """
    result = aruba_connector.get_ap_details(ap_name)
    return result

@mcp.tool()
async def get_aruba_radio_summary() -> dict:
    """
    Get radio summary for all APs.

    Returns:
        Dictionary with radio summary
    """
    result = aruba_connector.get_radio_summary()
    return result

@mcp.tool()
async def get_aruba_client_debug(client_mac: str) -> dict:
    """
    Get debug information for a specific client.

    Args:
        client_mac: Client MAC address

    Returns:
        Dictionary with client debug information
    """
    result = aruba_connector.get_ap_debug_client(client_mac)
    return result

@mcp.tool()
async def run_aruba_custom_command(command: str) -> dict:
    """
    Execute a custom show command on ARUBA controller.

    Args:
        command: CLI command to execute (e.g., "show ap database")

    Returns:
        Dictionary with command output
    """
    result = aruba_connector.run_custom_command(command)
    return result


# Entry point
if __name__ == "__main__":
    mcp.run(transport="stdio")
