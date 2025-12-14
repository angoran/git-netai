# /connectors/mikrotik_c.py

import os
from typing import Dict, Optional
from dotenv import load_dotenv
import httpx

# Loading environment variables (override system env vars)
load_dotenv(override=True)

# Retrieving Mikrotik API Rest Credentials from the .env file
MIKROTIK_USERNAME = os.getenv("MIKROTIK_USERNAME")
MIKROTIK_PASSWORD = os.getenv("MIKROTIK_PASSWORD")
MIKROTIK_PORT = os.getenv("MIKROTIK_PORT", "80")

async def _mikrotik_request(ip_address: str, endpoint: str, params: Optional [Dict] = None) -> Optional[Dict]:
    """
    Performs an asynchronous MikroTik REST API request via httpx.AsyncClient.
    Returns JSON or a dict {“error”: ...}.
    """
    if not MIKROTIK_USERNAME or not MIKROTIK_PASSWORD:
        return {"error": "Mikrotik credentials not configured"}
    
    url = f"http://{ip_address}:{MIKROTIK_PORT}/rest/{endpoint}"
    
    timeout = httpx.Timeout(10.0)
    
    try:
        async with httpx.AsyncClient(timeout=timeout,
                                     follow_redirects=True,
                                     auth=httpx.BasicAuth(MIKROTIK_USERNAME, MIKROTIK_PASSWORD)) as client:
            response = await client.get(url, params=params, headers={"Accept": "application/json"})
            response.raise_for_status()
            return response.json()
        
    except httpx.HTTPStatusError as e:
        return {"error": f"HTTP {e.response.status_code}: {e.response.text}"}
    
    except httpx.RequestError as e:
        return {"error": f"Request error: {str(e)}"}

    except ValueError as e:
        return {"error": f"JSON decode error: {str(e)}"}

    except Exception as e:
        return {"error": str(e)}

# ========== API FUNCTIONS MIKROTIK (ASYNC) ==========

async def get_interfaces(ip_address: str) -> Dict:
    """
    Retrieves the list and status of interfaces (async).
    The `ip_address` parameter must be a direct IP address of the router.
    """
    
    if not ip_address:
        return {"error": "Invalid or missing IP address"}

    data = await _mikrotik_request(ip_address, "interface")
    if isinstance(data, dict) and "error" in data:
        return data

    interfaces = []
    for iface in data if isinstance(data, list) else []:
        interfaces.append({
            "name": iface.get("name", ""),
            "type": iface.get("type", ""),
            "running": iface.get("running", False),
            "disabled": iface.get("disabled", False),
            "mtu": iface.get("mtu", 0),
            "mac_address": iface.get("mac-address", ""),
            "last-link-down-time": iface.get("last-link-down-time", ""),
            "last-link-up-time": iface.get("last-link-up-time", ""),
            "link-downs": iface.get("link-downs", "")
            
        })

    return {
        "interfaces": interfaces
    }

async def get_ip_address(ip_address: str) -> Dict:
    """
    Retrieves the configured IP addresses (async).
    The `ip_address` parameter must be a direct IP address of the router.
    """
    if not ip_address:
        return {"error": "Invalid or missing IP address"}
    
    data = await _mikrotik_request(ip_address, "ip/address")
    if isinstance(data, dict) and "error" in data:
        return data
    
    addresses = []
    for addr in data if isinstance(data, list) else[]:
        addresses.append({
            "address":addr.get("address", ""),
            "interface":addr.get("interface", ""),
            "network": addr.get("network", ""),
            "disabled": addr.get("disabled", False)
        })
    
    return {
        "addresses": addresses      
    }

async def get_route_by_prefix(ip_address: str, dst_address: str) -> Dict:
    """
    Retrieves routing information for a specific prefix.
    
    Args:
        ip_address: IP of the MikroTik router
        dst_address: Prefix to search for (e.g., ‘8.8.8.O/24’)
    
    Returns:
        Dict with routes corresponding to the prefix
    """
    if not ip_address or not dst_address:
        return {"error": "Invalid or missing IP address or missing prefix"}
    
    data = await _mikrotik_request(ip_address, f"routing/route?dst-address={dst_address}")
    if isinstance(data, dict) and "error" in data:
        return data
    
    routes = []
    for route in data if isinstance(data, list) else[]:
        routes.append({
            "dst-address":route.get("dst-address", ""),
            "gateway":route.get("gateway", ""),
            "distance": route.get("distance", ""),
            "active": route.get("active", False),
            "bgp": route.get("bgp", False),
            "bgp.as-path": route.get("bgp.as-path", ""),
            "bgp.communities": route.get("bgp.communities", ""),
            "bgp.local-pref":route.get("bgp.local-pref","")
        })
    
    return {
        "routes":routes      
    }
    
async def get_system_identity(ip_address: str) -> Dict:
    """
    Retrieves the name of router.
    The `ip_address` parameter must be a direct IP address of the router.
    """
    if not ip_address:
        return {"error": "Invalid or missing IP address."}
    
    data = await _mikrotik_request(ip_address, "system/identity")
    if isinstance(data, dict) and "error" in data:
        return data

    identity = data[0] if isinstance(data, list) and data else data

    if not identity or not isinstance(identity, dict):
        return {"error": "Invalid identity data received"}

    return {
        "name": identity.get("name", "")
    }

async def get_system_health(ip_address: str) -> Dict:
    """
    Retrieves system health (temperature, voltage).
    The `ip_address` parameter must be a direct IP address of the router.    
    """
    
    if not ip_address:
        return {"error": "Invalid or missing IP address."}
    
    data = await _mikrotik_request(ip_address, "system/health")
    if isinstance(data, dict) and "error" in data:
        return data
    
    health_data = []
    for item in data if isinstance(data, list) else []:
        health_data.append({
            "name": item.get("name", ""),
            "value": item.get("value", ""),
            "type": item.get("type", "")
        })
    
    return {
    "health_sensors": health_data
    }

async def get_system_routerboard(ip_address: str) -> Dict:
    """
    Retrieves the hardware information from the routerboard.
    
    Args:
        ip_address: must be a direct IP address of the Mikrotik router.
    
    Returns:
        Dict with hardware information
    """
    if not ip_address:
        return {"error": "Invalid or missing IP address."}

    data = await _mikrotik_request(ip_address, "system/routerboard")
    if isinstance(data, dict) and "error" in data:
        return data

    rb = data[0] if isinstance(data, list) and data else data

    if not rb or not isinstance(rb, dict):
        return {"error": "Invalid routerboard data received"}

    return {
        "router_ip": ip_address,
        "model": rb.get("model", ""),
        "serial_number": rb.get("serial-number", ""),
        "firmware": rb.get("upgrade-firmware", ""),
        "factory_firmware": rb.get("factory-firmware", ""),
        "current_firmware": rb.get("current-firmware", ""),
        "firmware_type": rb.get("firmware-type", "")
    }

async def get_logs(ip_address: str, topics: str = "", limit: int = 100) -> Dict:
    """
    Retrieve system logs.
    
    Args:
        ip_address: MikroTik router IP address
        topics: Log topics to filter (optional)
        limit: Maximum number of logs to return (default: 100, 0 = all logs)
    
    Returns:
        Dict with logs
    """
    if not ip_address:
        return {"error": "Invalid or missing IP address."}
    
    params = {"topics": topics} if topics else None
    data = await _mikrotik_request(ip_address, "log", params)
    if isinstance(data, dict) and "error" in data:
        return data
    
    logs = []
    for log in data if isinstance(data, list) else []:
        logs.append({
            "time": log.get("time", ""),
            "topics": log.get("topics", ""),
            "message": log.get("message", "")
        })
    
    # Limit to the last N logs if limit > 0
    total_logs = len(logs)
    if limit > 0 and len(logs) > limit:
        logs = logs[-limit:]
    
    return {
        "total_logs": total_logs,
        "returned_logs": len(logs),
        "logs": logs
    }

async def get_bgp_connections(ip_address: str) -> Dict:
    """
    Retrieves the BGP connection configuration.

    Args:
        ip_address: IP address of the MikroTik router

    Returns:
        Dict with configured BGP connections
    """
    if not ip_address:
        return {"error": "Invalid or missing IP address"}
    
    data = await _mikrotik_request(ip_address, "routing/bgp/connection")
    if isinstance(data, dict) and "error" in data:
        return data
    
    connections = []
    for conn in data if isinstance(data, list) else []:
        connections.append({
            "name": conn.get("name", ""),
            "remote_address": conn.get("remote.address", ""),
            "remote_as": conn.get("remote.as", ""),
            "local_address": conn.get("local.address", ""),
            "local_as": conn.get("local.as", ""),
            "router_id": conn.get("router-id", ""),
            "disabled": conn.get("disabled", False),
            "multihop": conn.get("multihop", False),
            "input_affinity": conn.get("input.affinity", ""),
            "output_affinity": conn.get("output.affinity", ""),
            "nexthop_choice": conn.get("nexthop-choice", ""),
            "input_network": conn.get("input.network", ""),
            "output_network": conn.get("output.network", ""),
            "local_role": conn.get("local.role", "")
        })
    
    return {
        "bgp_connections": connections
    }
    
async def get_bgp_sessions(ip_address: str) -> Dict:
    """
    Retrieves the state of BGP sessions.

    Args:
        identifier: sysName or IP address of the MikroTik router

    Returns:
        Dictate containing the state of the BGP sessions
    """
    
    if not ip_address:
        return {"error": "Invalid or missing IP address"}
    
    data = await _mikrotik_request(ip_address, "routing/bgp/session")
    if isinstance(data, dict) and "error" in data:
        return data
    
    sessions = []
    for session in data if isinstance(data, list) else []:
        sessions.append({
            "name": session.get("name", ""),
            "remote_address": session.get("remote.address", ""),
            "remote_as": session.get("remote.as", ""),
            "local_as": session.get("local.as", ""),
            "state": session.get("state", ""),
            "uptime": session.get("uptime", ""),
            "prefix_count": session.get("prefix-count", 0),
            "established": session.get("established", False),
            "disabled": session.get("disabled", False),
            "last_started": session.get("last-started", ""),
            "local_address": session.get("local.address", "")
        })
    
    return {
        "bgp_sessions": sessions
    }