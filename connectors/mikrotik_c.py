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
            "mac_address": iface.get("mac-address", "")
        })

    return {"router_ip": ip_address,
            "total_interfaces": len(interfaces),
            "interfaces": interfaces}

async def get_ip_address(ip_address: str) -> Dict:
    """
    Retrieve the configured IP addresses (async).
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
        "router_ip":ip_address,
        "total_addresses": len(addresses),
        "addresses": addresses      
    }