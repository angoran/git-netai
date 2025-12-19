# /connectors/librenms_c.py

import os
from typing import Dict, Optional
from dotenv import load_dotenv
import httpx

# Loading environment variables (override system env vars)
load_dotenv(override=True)

# Retrieving LibreNMS API credentials from the .env file
LIBRENMS_API_URL = os.getenv("LIBRENMS_API_URL")
LIBRENMS_TOKEN = os.getenv("LIBRENMS_TOKEN")
LIBRENMS_TIMEOUT = int(os.getenv("LIBRENMS_TIMEOUT", "30"))

# Global persistent HTTP client
_http_client: Optional[httpx.AsyncClient] = None


def _get_http_client() -> httpx.AsyncClient:
    """
    Get or create the global persistent HTTP client.
    This client maintains connections for better performance.

    Returns:
        Persistent httpx.AsyncClient instance
    """
    global _http_client

    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            timeout=LIBRENMS_TIMEOUT,
            follow_redirects=True,
            headers={"X-Auth-Token": LIBRENMS_TOKEN} if LIBRENMS_TOKEN else {}
        )

    return _http_client


async def _api_request(endpoint: str) -> Optional[Dict]:
    """
    Performs an asynchronous LibreNMS API request via persistent httpx client.

    Args:
        endpoint: API endpoint path (e.g., "devices" or "devices/123")

    Returns:
        JSON response or dict with error
    """
    if not LIBRENMS_API_URL or not LIBRENMS_TOKEN:
        return {"error": "LibreNMS API credentials not configured"}

    url = f"{LIBRENMS_API_URL}/{endpoint}"

    try:
        client = _get_http_client()
        response = await client.get(url)
        response.raise_for_status()

        try:
            return response.json()
        except ValueError:
            return {"_text": response.text, "_raw_response": True}

    except httpx.HTTPStatusError as e:
        return {"error": f"HTTP {e.response.status_code}: {e.response.text[:200]}"}
    except httpx.RequestError as e:
        return {"error": f"Request error: {str(e)}"}
    except Exception as e:
        return {"error": str(e)}


# ========== Device Query Functions ==========

async def list_devices(filter_type: Optional[str] = None, filter_value: Optional[str] = None) -> Dict:
    """
    List all devices or filter by specific criteria.

    Args:
        filter_type: Optional filter type ('type', 'os', 'location', 'hostname')
        filter_value: Optional filter value for the specified type

    Returns:
        Dict with devices list and total count
    """
    endpoint = "devices"

    # Add filters if provided
    if filter_type and filter_value:
        endpoint = f"devices?type={filter_type}&query={filter_value}"

    data = await _api_request(endpoint)

    if not data or "error" in data:
        return data or {"error": "No response from LibreNMS API"}

    devices = data.get("devices", [])

    # Extract relevant information
    device_list = []
    for device in devices:
        device_list.append({
            "device_id": device.get("device_id"),
            "hostname": device.get("hostname"),
            "sysName": device.get("sysName"),
            "ip": device.get("ip"),
            "os": device.get("os"),
            "hardware": device.get("hardware"),
            "version": device.get("version"),
            "status": "up" if device.get("status") == 1 else "down",
            "uptime": device.get("uptime"),
            "location": device.get("location")
        })

    return {
        "total": len(device_list),
        "devices": device_list
    }


async def get_devices_by_os(os_name: str) -> Dict:
    """
    Get all devices running a specific operating system.

    Args:
        os_name: Operating system name (e.g., 'routeros', 'ios', 'linux')

    Returns:
        Dict with filtered devices list
    """
    data = await _api_request("devices")

    if not data or "error" in data:
        return data or {"error": "No response from LibreNMS API"}

    devices = data.get("devices", [])

    # Filter by OS
    filtered_devices = []
    for device in devices:
        device_os = device.get("os", "").lower()
        if os_name.lower() in device_os:
            filtered_devices.append({
                "device_id": device.get("device_id"),
                "hostname": device.get("hostname"),
                "sysName": device.get("sysName"),
                "ip": device.get("ip"),
                "os": device.get("os"),
                "hardware": device.get("hardware"),
                "version": device.get("version"),
                "status": "up" if device.get("status") == 1 else "down",
                "uptime": device.get("uptime"),
                "location": device.get("location")
            })

    return {
        "os": os_name,
        "total": len(filtered_devices),
        "devices": filtered_devices
    }


async def get_device_by_hostname(hostname: str) -> Dict:
    """
    Get device information by hostname.

    Args:
        hostname: Device hostname

    Returns:
        Dict with device information
    """
    data = await _api_request(f"devices/{hostname}")

    if not data or "error" in data:
        return data or {"error": "No response from LibreNMS API"}

    devices = data.get("devices", [])
    if not devices:
        return {"error": f"Device '{hostname}' not found"}

    device = devices[0]

    return {
        "device_id": device.get("device_id"),
        "hostname": device.get("hostname"),
        "sysName": device.get("sysName"),
        "ip": device.get("ip"),
        "os": device.get("os"),
        "hardware": device.get("hardware"),
        "version": device.get("version"),
        "features": device.get("features"),
        "status": "up" if device.get("status") == 1 else "down",
        "uptime": device.get("uptime"),
        "uptime_days": device.get("uptime", 0) // 86400,
        "location": device.get("location"),
        "lat": device.get("lat"),
        "lng": device.get("lng"),
        "last_polled": device.get("last_polled")
    }


# ========== Device Health & Sensors ==========

async def get_device_health(hostname: str) -> Dict:
    """
    Get device health information including available health graphs.

    Args:
        hostname: Device hostname

    Returns:
        Dict with status, available health graphs (temperature, processors, storage, etc.), and count
    """
    data = await _api_request(f"devices/{hostname}/health")

    if not data or "error" in data:
        return data or {"error": "No response from LibreNMS API"}

    # Return the raw response which contains status, graphs list, and count
    return data


async def get_device_sensors(hostname: str, sensor_type: Optional[str] = None) -> Dict:
    """
    Get specific sensor type data from device.

    Args:
        hostname: Device hostname
        sensor_type: Optional sensor type filter ('temperature', 'voltage', 'state', etc.)

    Returns:
        Dict with sensor data
    """
    # First, get available sensor types
    health_data = await _api_request(f"devices/{hostname}/health")

    if not health_data or "error" in health_data:
        return health_data or {"error": "No response from LibreNMS API"}

    # Get available graphs (sensor types)
    graphs = health_data.get("graphs", [])
    if not isinstance(graphs, list):
        return {"error": "Invalid health data format"}

    sensors = []

    # For each available sensor type, fetch sensor list
    for graph in graphs:
        graph_name = graph.get("name", "")
        graph_desc = graph.get("desc", "")

        # Filter by sensor type if specified
        if sensor_type and sensor_type.lower() not in graph_desc.lower():
            continue

        # Fetch specific sensor type data
        sensor_data = await _api_request(f"devices/{hostname}/health/{graph_name}")

        if sensor_data and "error" not in sensor_data:
            # Extract sensor list (LibreNMS returns sensors in 'graphs' key)
            sensor_list = sensor_data.get("graphs", [])
            for sensor in sensor_list:
                sensors.append({
                    "sensor_id": sensor.get("sensor_id"),
                    "description": sensor.get("desc"),
                    "type": graph_desc,
                    "unit": _get_sensor_unit_from_type(graph_desc)
                })

    return {
        "hostname": hostname,
        "sensor_type": sensor_type or "all",
        "total_sensors": len(sensors),
        "sensors": sensors
    }


def _get_sensor_unit_from_type(sensor_type: Optional[str]) -> str:
    """Get appropriate unit from sensor type description."""
    if not sensor_type:
        return ""

    sensor_type_lower = sensor_type.lower()

    if "temperature" in sensor_type_lower:
        return "°C"
    elif "voltage" in sensor_type_lower:
        return "V"
    elif "current" in sensor_type_lower:
        return "A"
    elif "power" in sensor_type_lower:
        return "W"
    elif "frequency" in sensor_type_lower:
        return "Hz"
    elif "humidity" in sensor_type_lower:
        return "%"
    elif "fanspeed" in sensor_type_lower:
        return "RPM"
    elif "dbm" in sensor_type_lower:
        return "dBm"
    else:
        return ""


# ========== Device Interfaces/Ports ==========

async def get_device_ports(hostname: str) -> Dict:
    """
    Get all ports/interfaces information for a device.

    Args:
        hostname: Device hostname

    Returns:
        Dict with ports information
    """
    data = await _api_request(f"devices/{hostname}/ports")

    if not data or "error" in data:
        return data or {"error": "No response from LibreNMS API"}

    ports = []
    for port in data.get("ports", []):
        ports.append({
            "port_id": port.get("port_id"),
            "ifIndex": port.get("ifIndex"),
            "ifName": port.get("ifName"),
            "ifDescr": port.get("ifDescr"),
            "ifAlias": port.get("ifAlias"),
            "ifType": port.get("ifType"),
            "ifOperStatus": port.get("ifOperStatus"),
            "ifAdminStatus": port.get("ifAdminStatus"),
            "ifSpeed": f"{port.get('ifSpeed', 0) // 1000000} Mbps" if port.get('ifSpeed') else "N/A",
            "ifMtu": port.get("ifMtu"),
            "ifVlan": port.get("ifVlan")
        })

    # Calculate statistics
    ports_up = sum(1 for p in data.get("ports", []) if p.get("ifOperStatus") == "up")
    ports_down = sum(1 for p in data.get("ports", []) if p.get("ifOperStatus") == "down")

    return {
        "hostname": hostname,
        "total_ports": len(ports),
        "ports_up": ports_up,
        "ports_down": ports_down,
        "ports": ports
    }


# ========== Locations ==========

async def get_locations() -> Dict:
    """
    Get all locations configured in LibreNMS.

    Returns:
        Dict with locations list
    """
    data = await _api_request("resources/locations")

    if not data or "error" in data:
        return data or {"error": "No response from LibreNMS API"}

    locations = []
    for location in data.get("locations", []):
        locations.append({
            "id": location.get("id"),
            "name": location.get("location"),
            "latitude": location.get("lat"),
            "longitude": location.get("lng"),
            "has_coordinates": location.get("lat") is not None and location.get("lng") is not None,
            "timestamp": location.get("timestamp")
        })

    return {
        "total_locations": len(locations),
        "locations": locations
    }


# ========== Event Logs ==========

async def get_eventlog(limit: int = 100, sort_order: str = "DESC") -> Dict:
    """
    Get general event logs from LibreNMS.

    Args:
        limit: Maximum number of logs to retrieve (default: 100)
        sort_order: Sort order 'DESC' or 'ASC' (default: DESC)

    Returns:
        Dict with event logs
    """
    endpoint = f"logs/eventlog?limit={limit}&sortorder={sort_order}"
    data = await _api_request(endpoint)

    if not data or "error" in data:
        return data or {"error": "No response from LibreNMS API"}

    logs = []
    for log in data.get("logs", []):
        message = log.get("message", "")
        message_preview = message.split('\n')[0][:150] + "..." if len(message) > 150 else message

        logs.append({
            "event_id": log.get("event_id"),
            "datetime": log.get("datetime"),
            "hostname": log.get("hostname"),
            "sysName": log.get("sysName"),
            "device_id": log.get("device_id"),
            "type": log.get("type"),
            "severity": log.get("severity"),
            "severity_text": _get_severity_text(log.get("severity", 0)),
            "username": log.get("username"),
            "message_preview": message_preview
        })

    return {
        "total_logs": len(logs),
        "parameters": {"limit": limit, "sort_order": sort_order},
        "logs": logs
    }


async def get_device_eventlog(hostname: str, limit: int = 50, sort_order: str = "DESC") -> Dict:
    """
    Get event logs for a specific device.

    Args:
        hostname: Device hostname
        limit: Maximum number of logs (default: 50)
        sort_order: Sort order 'DESC' or 'ASC' (default: DESC)

    Returns:
        Dict with device event logs
    """
    endpoint = f"logs/eventlog/{hostname}?limit={limit}&sortorder={sort_order}"
    data = await _api_request(endpoint)

    if not data or "error" in data:
        return data or {"error": "No response from LibreNMS API"}

    logs = []
    for log in data.get("logs", []):
        message = log.get("message", "")
        message_preview = message.split('\n')[0][:150] + "..." if len(message) > 150 else message

        logs.append({
            "event_id": log.get("event_id"),
            "datetime": log.get("datetime"),
            "type": log.get("type"),
            "severity": log.get("severity"),
            "severity_text": _get_severity_text(log.get("severity", 0)),
            "username": log.get("username"),
            "message_preview": message_preview
        })

    return {
        "hostname": hostname,
        "total_logs": len(logs),
        "recent_activity": logs[0].get("datetime") if logs else "No activity",
        "parameters": {"limit": limit, "sort_order": sort_order},
        "logs": logs
    }


def _get_severity_text(severity: int) -> str:
    """Convert numeric severity level to text."""
    severity_map = {
        0: "emergency",
        1: "alert",
        2: "critical",
        3: "error",
        4: "warning",
        5: "notice",
        6: "info",
        7: "debug"
    }
    return severity_map.get(severity, "unknown")


# ========== Device Statistics ==========

async def get_device_stats(hostname: str) -> Dict:
    """
    Get comprehensive device statistics.

    Args:
        hostname: Device hostname

    Returns:
        Dict with device statistics (uptime, availability, ports summary)
    """
    # Get basic device info
    device_info = await get_device_by_hostname(hostname)
    if "error" in device_info:
        return device_info

    # Get ports info
    ports_info = await get_device_ports(hostname)

    return {
        "hostname": hostname,
        "device_id": device_info.get("device_id"),
        "status": device_info.get("status"),
        "uptime_days": device_info.get("uptime_days"),
        "os": device_info.get("os"),
        "hardware": device_info.get("hardware"),
        "version": device_info.get("version"),
        "location": device_info.get("location"),
        "total_ports": ports_info.get("total_ports", 0),
        "ports_up": ports_info.get("ports_up", 0),
        "ports_down": ports_info.get("ports_down", 0),
        "last_polled": device_info.get("last_polled")
    }
