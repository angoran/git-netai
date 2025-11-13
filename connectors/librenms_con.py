# /connectors/librenms_con.py

import json
import os
from typing import List, Dict, Optional
import urllib.request
import urllib.error
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

# Configuration API LibreNMS
API_URL = os.getenv("LIBRENMS_API_URL")
API_TOKEN = os.getenv("LIBRENMS_TOKEN")
API_TIMEOUT = int(os.getenv("LIBRENMS_TIMEOUT", "30"))

def _api_request(endpoint: str) -> Dict:
    """
    Performs a LibreNMS API request.

    Args:
        endpoint: API endpoint

    Returns:
        Dictionary with JSON response or error
    """
    if not API_URL or not API_TOKEN:
        return {"error": "API credentials not configured"}

    try:
        req = urllib.request.Request(
            f"{API_URL}/{endpoint}",
            headers={"X-Auth-Token": API_TOKEN}
        )
        with urllib.request.urlopen(req, timeout=API_TIMEOUT) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.reason}"}
    except Exception as e:
        return {"error": str(e)}

def search_devices(criteria: str, value: str) -> List[Dict]:
    """
    Search for devices in LibreNMS via API.

    Args:
        criteria: 'device_id', 'hostname', 'sysName', 'sysDescr', or 'ip'
        value: Value to search for (partial search)

    Returns:
        List of found devices with ID, hostname, sysName, IP
    """
    # Query all devices from API
    data = _api_request("devices")
    if "error" in data:
        return []

    results = []
    devices = data.get("devices", [])

    for device in devices:
        field_value = device.get(criteria, "")

        # Exact search for device_id
        if criteria == "device_id":
            match = str(field_value) == value
        else:
            # Partial case-insensitive search for other criteria
            match = value.lower() in str(field_value).lower()

        if match:
            results.append({
                "device_id": device.get("device_id"),
                "hostname": device.get("hostname"),
                "sysName": device.get("sysName"),
                "ip": device.get("ip"),
                "os": device.get("os"),
                "hardware": device.get("hardware")
            })

    return results

def filter_devices(criteria: str, value: str) -> List[Dict]:
    """
    Filter devices by specific criteria.

    Args:
        criteria: 'os', 'hardware', 'features', or 'location'
        value: Exact or partial value to filter

    Returns:
        List of filtered devices
    """
    # Query all devices from API
    data = _api_request("devices")
    if "error" in data:
        return []

    results = []
    devices = data.get("devices", [])

    for device in devices:
        field_value = device.get(criteria, "")

        # Exact search for device_id
        if criteria == "device_id":
            match = str(field_value) == value
        else:
            # Partial case-insensitive search for other criteria
            match = value.lower() in str(field_value).lower()

        if match:
            results.append({
                "device_id": device.get("device_id"),
                "hostname": device.get("hostname"),
                "sysName": device.get("sysName"),
                "ip": device.get("ip"),
                "os": device.get("os"),
                "hardware": device.get("hardware"),
                "features": device.get("features"),
                "location_id": device.get("location_id")
            })

    return results

def get_statistics_by_field(field: str) -> Dict:
    """
    Get exact statistics of devices by any field.

    Args:
        field: Field to analyze (os, hardware, location_id, type, etc.)

    Returns:
        Dictionary with total and breakdown by field value
    """
    # Query all devices from API
    data = _api_request("devices")
    if "error" in data:
        return {"total": 0, "field": field, "count": {}, "error": data["error"]}

    devices = data.get("devices", [])
    count = {}

    for device in devices:
        value = device.get(field, "N/A")
        count[value] = count.get(value, 0) + 1

    return {
        "total": len(devices),
        "field": field,
        "count": dict(sorted(count.items(), key=lambda x: x[1], reverse=True))
    }

# ========== MODULE API LibreNMS ==========

def get_device_interfaces(device_id: str) -> Dict:
    """
    Retrieve interface status of a device.

    Args:
        device_id: Device ID

    Returns:
        Dictionary with interfaces (name, status, speed)
    """
    data = _api_request(f"devices/{device_id}/ports")
    if "error" in data:
        return data
    
    interfaces = []
    for port in data.get("ports", []):
        interfaces.append({
            "name": port.get("ifName", ""),
            "status": "up" if port.get("ifOperStatus") == "up" else "down",
            "speed": port.get("ifSpeed", 0) // 1000000,  # Convert to Mbps
            "description": port.get("ifAlias", "")
        })
    
    return {"device_id": device_id, "interfaces": interfaces}


def get_device_sensors(device_id: str) -> Dict:
    """
    Retrieve sensor status of a device.

    Args:
        device_id: Device ID

    Returns:
        Dictionary with sensors (temperature, voltage, etc.)
    """
    data = _api_request(f"devices/{device_id}/health")
    if "error" in data:
        return data
    
    sensors = {}
    for graph in data.get("graphs", {}).values():
        sensor_type = graph.get("sensor_class", "unknown")
        if sensor_type not in sensors:
            sensors[sensor_type] = []
        
        sensors[sensor_type].append({
            "description": graph.get("sensor_descr", ""),
            "value": graph.get("sensor_current", 0),
            "unit": graph.get("unit", "")
        })
    
    return {"device_id": device_id, "sensors": sensors}

def get_port_history(device_id: str, port_id: str, period: str = "day") -> Dict:
    """
    Retrieve history of a specific port.

    Args:
        device_id: Device ID
        port_id: Port ID
        period: Period (hour, day, week, month)

    Returns:
        Dictionary with port history
    """
    data = _api_request(f"devices/{device_id}/ports/{port_id}/port_bits?period={period}")
    if "error" in data:
        return data
    
    return {
        "device_id": device_id,
        "port_id": port_id,
        "period": period,
        "data": data
    }

def get_device_uptime(device_id: str) -> Dict:
    """
    Retrieve uptime and availability of a device.

    Args:
        device_id: Device ID

    Returns:
        Dictionary with uptime and availability
    """
    data = _api_request(f"devices/{device_id}")
    if "error" in data:
        return data
    
    device = data.get("devices", [{}])[0]
    
    return {
        "device_id": device_id,
        "hostname": device.get("hostname", ""),
        "uptime": device.get("uptime", 0),
        "uptime_human": f"{device.get('uptime', 0) // 86400} jours",
        "last_polled": device.get("last_polled", ""),
        "status": "up" if device.get("status") == 1 else "down"
    }

def get_switch_ports_status(device_id: str) -> Dict:
    """
    Retrieve detailed port status of a switch.

    Args:
        device_id: Switch device ID

    Returns:
        Dictionary with detailed port status (VLAN, trunk, etc.)
    """
    data = _api_request(f"devices/{device_id}/ports")
    if "error" in data:
        return data
    
    ports = []
    for port in data.get("ports", []):
        ports.append({
            "name": port.get("ifName", ""),
            "status": port.get("ifOperStatus", ""),
            "vlan": port.get("ifVlan", ""),
            "type": port.get("port_type", ""),
            "speed": f"{port.get('ifSpeed', 0) // 1000000} Mbps",
            "description": port.get("ifAlias", "")
        })
    
    return {
        "device_id": device_id,
        "total_ports": len(ports),
        "ports": ports
    }

# ========== FONCTIONS INTELLIGENTES (nom → ID) ==========

def _resolve_device_id(identifier: str) -> Optional[str]:
    """
    Resolve a device name to its ID.
    Searches in hostname, sysName (partial search).

    Args:
        identifier: Device name, hostname, sysName, or ID

    Returns:
        Device ID as string or None if not found
    """
    # Query all devices from API
    data = _api_request("devices")
    if "error" in data:
        return None

    identifier_lower = identifier.lower()
    devices = data.get("devices", [])

    # Exact search first
    for device in devices:
        if (str(device.get("device_id")) == identifier or
            device.get("hostname", "").lower() == identifier_lower or
            device.get("sysName", "").lower() == identifier_lower):
            return str(device.get("device_id"))

    # Partial search if not found
    for device in devices:
        if (identifier_lower in device.get("hostname", "").lower() or
            identifier_lower in device.get("sysName", "").lower()):
            return str(device.get("device_id"))

    return None

def get_device_info_smart(identifier: str) -> Dict:
    """
    Get device information by name or ID (uptime, status).

    Args:
        identifier: Name (full/partial), hostname, or device ID

    Returns:
        Dictionary with uptime, status, hostname
    """
    device_id = _resolve_device_id(identifier)
    if not device_id:
        return {"error": f"Device '{identifier}' not found"}

    return get_device_uptime(device_id)

def get_interfaces_smart(identifier: str) -> Dict:
    """
    Get interface status by device name or ID.

    Args:
        identifier: Name (full/partial), hostname, or device ID

    Returns:
        Dictionary with interfaces (name, status, speed)
    """
    device_id = _resolve_device_id(identifier)
    if not device_id:
        return {"error": f"Device '{identifier}' not found"}

    return get_device_interfaces(device_id)


def get_sensors_smart(identifier: str) -> Dict:
    """
    Get sensor status by device name or ID.

    Args:
        identifier: Name (full/partial), hostname, or device ID

    Returns:
        Dictionary with sensors (temperature, voltage, etc.)
    """
    device_id = _resolve_device_id(identifier)
    if not device_id:
        return {"error": f"Device '{identifier}' not found"}

    return get_device_sensors(device_id)

def get_ports_smart(identifier: str) -> Dict:
    """
    Get port status by device name or ID.

    Args:
        identifier: Name (full/partial), hostname, or device ID

    Returns:
        Dictionary with ports (name, status, VLAN, speed)
    """
    device_id = _resolve_device_id(identifier)
    if not device_id:
        return {"error": f"Device '{identifier}' not found"}

    return get_switch_ports_status(device_id)

# ========== NOUVEAUX ENDPOINTS ==========

def get_locations() -> Dict:
    """
    Retrieve all LibreNMS device locations.

    Returns:
        Dictionary with locations (ID, name, coordinates)
    """
    data = _api_request("resources/locations")
    if "error" in data:
        return data
    
    locations = []
    for location in data.get("locations", []):
        locations.append({
            "id": location.get("id"),
            "name": location.get("location", ""),
            "latitude": location.get("lat"),
            "longitude": location.get("lng"),
            "created": location.get("timestamp", ""),
            "has_coordinates": location.get("lat") is not None and location.get("lng") is not None
        })
    
    return {
        "total_locations": len(locations),
        "locations": locations
    }

def get_eventlog(limit: int = 100, sortorder: str = "DESC") -> Dict:
    """
    Retrieve general LibreNMS event logs.

    Args:
        limit: Maximum number of logs (default: 100)
        sortorder: Sort order DESC/ASC (default: DESC)

    Returns:
        Dictionary with event logs
    """
    params = f"limit={limit}&sortorder={sortorder}"
    data = _api_request(f"logs/eventlog?{params}")
    if "error" in data:
        return data
    
    logs = []
    for log in data.get("logs", []):
        # Nettoyer le message SNMP pour l'affichage
        message = log.get("message", "")
        message_preview = message.split('\n')[0][:100] + "..." if len(message) > 100 else message
        
        logs.append({
            "event_id": log.get("event_id"),
            "datetime": log.get("datetime", ""),
            "hostname": log.get("hostname", ""),
            "sysName": log.get("sysName", ""),
            "device_id": log.get("device_id"),
            "type": log.get("type", ""),
            "severity": log.get("severity", 0),
            "severity_text": _get_severity_text(log.get("severity", 0)),
            "username": log.get("username", ""),
            "message_preview": message_preview,
            "full_message": message
        })
    
    return {
        "total_logs": len(logs),
        "logs": logs,
        "parameters": {"limit": limit, "sortorder": sortorder}
    }

def get_device_eventlog_smart(identifier: str, limit: int = 50, sortorder: str = "DESC") -> Dict:
    """
    Get event logs by device name or ID with automatic resolution.

    Args:
        identifier: Name, hostname, or device ID
        limit: Maximum number of logs (default: 50)
        sortorder: Sort order DESC/ASC (default: DESC)

    Returns:
        Dictionary with device event logs
    """
    # Resolve identifier to hostname
    hostname = _resolve_device_hostname(identifier)
    if not hostname:
        return {"error": f"Device '{identifier}' not found"}
    
    params = f"limit={limit}&sortorder={sortorder}"
    data = _api_request(f"logs/eventlog/{hostname}?{params}")
    if "error" in data:
        return data
    
    logs = []
    for log in data.get("logs", []):
        # Nettoyer le message SNMP
        message = log.get("message", "")
        message_preview = message.split('\n')[0][:150] + "..." if len(message) > 150 else message
        
        logs.append({
            "event_id": log.get("event_id"),
            "datetime": log.get("datetime", ""),
            "type": log.get("type", ""),
            "severity": log.get("severity", 0),
            "severity_text": _get_severity_text(log.get("severity", 0)),
            "username": log.get("username", ""),
            "message_preview": message_preview,
            "full_message": message
        })
    
    recent_activity = logs[0].get("datetime", "") if logs else "Aucune activité"
    
    return {
        "hostname": hostname,
        "device_id": logs[0].get("device_id") if logs else None,
        "sysName": logs[0].get("sysName") if logs else None,
        "total_logs": len(logs),
        "recent_activity": recent_activity,
        "logs": logs,
        "parameters": {"limit": limit, "sortorder": sortorder}
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

def _resolve_device_hostname(identifier: str) -> Optional[str]:
    """
    Resolve a device name to its hostname for eventlog API.
    Searches in hostname, sysName (partial search).

    Args:
        identifier: Device name, hostname, sysName, or ID

    Returns:
        Device hostname as string or None if not found
    """
    # Query all devices from API
    data = _api_request("devices")
    if "error" in data:
        return None

    identifier_lower = identifier.lower()
    devices = data.get("devices", [])

    # Exact search first
    for device in devices:
        if (str(device.get("device_id")) == identifier or
            device.get("hostname", "").lower() == identifier_lower or
            device.get("sysName", "").lower() == identifier_lower):
            return device.get("hostname")

    # Partial search if not found
    for device in devices:
        if (identifier_lower in device.get("hostname", "").lower() or
            identifier_lower in device.get("sysName", "").lower()):
            return device.get("hostname")

    return None