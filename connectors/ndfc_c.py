"""
NDFC (Nexus Dashboard Fabric Controller) Asynchronous Connector
Provides async connectivity to Cisco NDFC via REST API
Supports authentication with JWT token management and API operations
"""

import asyncio
import logging
import os
import time
from typing import Dict, Any, Optional

import httpx
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# NDFC Configuration from environment
NDFC_HOST = os.getenv("NDFC_HOST", "https://mgmt-nd1.p.priv.ina")
NDFC_USERNAME = os.getenv("NDFC_USER", "airun")
NDFC_PASSWORD = os.getenv("NDFC_PASSWORD", "")
NDFC_DOMAIN = os.getenv("NDFC_DOMAIN", "DefaultAuth")
NDFC_TIMEOUT = int(os.getenv("NDFC_TIMEOUT", "30"))
NDFC_VERIFY_SSL = os.getenv("NDFC_VERIFY_SSL", "false").lower() == "true"

# JWT token cache with async lock
_token_cache: Dict[str, Any] = {"token": None, "expires_at": 0, "lock": asyncio.Lock()}


async def _authenticate() -> Optional[str]:
    """
    Authenticate to NDFC and retrieve JWT token.
    Token is valid for 3600 seconds (1 hour)

    Returns:
        JWT token string or None on error
    """
    if not NDFC_HOST or not NDFC_USERNAME or not NDFC_PASSWORD:
        logger.error("NDFC credentials not configured in environment")
        return None

    login_url = f"{NDFC_HOST}/login"
    headers = {"Content-Type": "application/json"}
    payload = {
        "userName": NDFC_USERNAME,
        "userPasswd": NDFC_PASSWORD,
        "domain": NDFC_DOMAIN
    }

    try:
        logger.info("Attempting to authenticate to NDFC")
        async with httpx.AsyncClient(
            verify=NDFC_VERIFY_SSL,
            timeout=NDFC_TIMEOUT,
            follow_redirects=True
        ) as client:
            response = await client.post(login_url, headers=headers, json=payload)
            response.raise_for_status()

            result = response.json()

            # Extract JWT token from response
            if "jwttoken" in result:
                token = result["jwttoken"]
                logger.info("Successfully authenticated to NDFC")
                return token
            else:
                logger.error("Authentication failed: JWT token not found in response")
                return None

    except httpx.TimeoutException:
        logger.error("Timeout error during NDFC authentication")
        return None
    except httpx.RequestError as e:
        logger.error(f"Connection error during NDFC authentication: {e}")
        return None
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error during NDFC authentication: {e.response.status_code}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during NDFC authentication: {e}")
        return None


async def _get_token() -> Optional[str]:
    """
    Get valid JWT token with async-safe cache management.

    Returns:
        Valid JWT token string or None on error
    """
    async with _token_cache["lock"]:
        current_time = time.time()

        # Check if cached token is still valid (with 60s safety margin)
        if _token_cache["token"] and current_time < _token_cache["expires_at"]:
            return _token_cache["token"]

        # Authenticate if token expired or missing
        token = await _authenticate()
        if token:
            _token_cache["token"] = token
            # Token is valid for 3600 seconds, cache for 3540 seconds (60s margin)
            _token_cache["expires_at"] = current_time + 3540
            return token

        return None


async def _clear_token() -> None:
    """
    Clear the cached JWT token.
    """
    async with _token_cache["lock"]:
        _token_cache["token"] = None
        _token_cache["expires_at"] = 0


async def _make_request(
    endpoint: str,
    method: str = "GET",
    data: Optional[Dict] = None,
    params: Optional[Dict] = None
) -> Dict[str, Any]:
    """
    Generic method to make authenticated API requests to NDFC.

    Args:
        endpoint: API endpoint path (e.g., "/mso/api/v1/sites")
        method: HTTP method (GET, POST, PUT, DELETE)
        data: Optional request body data
        params: Optional query parameters

    Returns:
        Dict with success status, data, and optional error message
    """
    # Get valid token
    token = await _get_token()
    if not token:
        return {"success": False, "error": "Authentication failed", "data": None}

    # Build full URL
    url = f"{NDFC_HOST}{endpoint}"

    # Set Cookie header with AuthCookie (NDFC uses Cookie-based auth, not Bearer)
    headers = {
        "Content-Type": "application/json",
        "Cookie": f"AuthCookie={token}"
    }

    logger.info(f"Making {method} request to {endpoint}")

    try:
        async with httpx.AsyncClient(
            verify=NDFC_VERIFY_SSL,
            timeout=NDFC_TIMEOUT,
            follow_redirects=True
        ) as client:
            # Make initial request
            if method.upper() == "GET":
                response = await client.get(url, headers=headers, params=params)
            elif method.upper() == "POST":
                response = await client.post(url, headers=headers, json=data, params=params)
            elif method.upper() == "PUT":
                response = await client.put(url, headers=headers, json=data, params=params)
            elif method.upper() == "DELETE":
                response = await client.delete(url, headers=headers, params=params)
            else:
                return {"success": False, "error": f"Unsupported method: {method}", "data": None}

            # Check if token expired (401), re-authenticate once
            if response.status_code == 401:
                logger.warning("JWT token expired, re-authenticating")
                await _clear_token()
                token = await _get_token()
                if not token:
                    return {"success": False, "error": "Re-authentication failed", "data": None}

                # Retry request with new token
                headers["Cookie"] = f"AuthCookie={token}"
                if method.upper() == "GET":
                    response = await client.get(url, headers=headers, params=params)
                elif method.upper() == "POST":
                    response = await client.post(url, headers=headers, json=data, params=params)
                elif method.upper() == "PUT":
                    response = await client.put(url, headers=headers, json=data, params=params)
                elif method.upper() == "DELETE":
                    response = await client.delete(url, headers=headers, params=params)

            response.raise_for_status()

            # Try to parse JSON response
            try:
                result = response.json()
            except ValueError:
                # If response is not JSON, return the text content
                logger.warning("Response is not JSON, returning text")
                return {"success": True, "error": None, "data": {"_text": response.text, "_raw_response": True}}

            return {"success": True, "error": None, "data": result}

    except httpx.TimeoutException:
        logger.error(f"Timeout error in request to {endpoint}")
        return {"success": False, "error": "Request timeout", "data": None}
    except httpx.RequestError as e:
        logger.error(f"Connection error in request to {endpoint}: {e}")
        return {"success": False, "error": "Connection failed", "data": None}
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error in request to {endpoint}: {e.response.status_code}")
        return {"success": False, "error": f"HTTP error: {e.response.status_code} - {e.response.text}", "data": None}
    except Exception as e:
        logger.error(f"Unexpected error in request to {endpoint}: {e}")
        return {"success": False, "error": str(e), "data": None}


# ============================================================================
# NDFC API ENDPOINTS
# ============================================================================

async def login() -> Dict[str, Any]:
    """
    Authenticate to NDFC and obtain JWT token.
    Token is valid for 3600 seconds (1 hour)

    Returns:
        Dict with success status and optional error message
    """
    token = await _authenticate()
    if token:
        return {"success": True, "error": None, "data": {"authenticated": True}}
    else:
        return {"success": False, "error": "Authentication failed", "data": None}


async def logout() -> Dict[str, Any]:
    """
    Logout from NDFC and clear JWT token.

    Returns:
        Dict with success status
    """
    await _clear_token()
    logger.info("Successfully logged out from NDFC")
    return {"success": True, "error": None, "data": {"logged_out": True}}


async def get_sites() -> Dict[str, Any]:
    """
    Get list of NDFC sites/fabrics.

    Returns:
        Dict with sites information
    """
    return await _make_request("/mso/api/v1/sites", method="GET")


async def get_fabrics() -> Dict[str, Any]:
    """
    Get list of fabric configurations.

    Returns:
        Dict with fabrics information
    """
    return await _make_request("/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics", method="GET")


async def get_switches(fabric_name: str) -> Dict[str, Any]:
    """
    Get list of switches in a specific fabric.

    Args:
        fabric_name: Name of the fabric

    Returns:
        Dict with switches information
    """
    endpoint = f"/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/inventory/allswitches/{fabric_name}"
    return await _make_request(endpoint, method="GET")


async def get_networks(fabric_name: str) -> Dict[str, Any]:
    """
    Get list of networks in a specific fabric.

    Args:
        fabric_name: Name of the fabric

    Returns:
        Dict with networks information
    """
    endpoint = f"/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/{fabric_name}/networks"
    return await _make_request(endpoint, method="GET")


async def get_vrfs(fabric_name: str) -> Dict[str, Any]:
    """
    Get list of VRFs in a specific fabric.

    Args:
        fabric_name: Name of the fabric

    Returns:
        Dict with VRFs information
    """
    endpoint = f"/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/{fabric_name}/vrfs"
    return await _make_request(endpoint, method="GET")


async def get_fabric_summary() -> Dict[str, Any]:
    """
    Get summary of all fabric associations (MSD fabric-member relationships).

    Returns:
        Dict with fabric summary and associations
    """
    endpoint = "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics/msd/fabric-associations"
    return await _make_request(endpoint, method="GET")


async def get_deployment_history(fabric_name: str) -> Dict[str, Any]:
    """
    Get configuration deployment history for a specific fabric.

    Args:
        fabric_name: Name of the fabric

    Returns:
        Dict with deployment history records
    """
    endpoint = f"/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/config/delivery/deployerHistoryByFabric/{fabric_name}"
    return await _make_request(endpoint, method="GET")


async def get_network_status(fabric_name: str, network_name: str) -> Dict[str, Any]:
    """
    Get deployment status for a specific network in a fabric.

    Args:
        fabric_name: Name of the fabric
        network_name: Name of the network

    Returns:
        Dict with network status details
    """
    endpoint = f"/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/{fabric_name}/networks/{network_name}/status"
    return await _make_request(endpoint, method="GET")


async def get_network_preview(fabric_name: str, network_name: str) -> Dict[str, Any]:
    """
    Get configuration preview for a specific network deployment.

    Args:
        fabric_name: Name of the fabric
        network_name: Name of the network

    Returns:
        Dict with configuration preview for each switch
    """
    endpoint = f"/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/{fabric_name}/networks/{network_name}/preview"
    return await _make_request(endpoint, method="GET")


async def get_interface_details(serial_number: str) -> Dict[str, Any]:
    """
    Get detailed interface information for a specific switch by serial number.

    Args:
        serial_number: Serial number of the switch (e.g., "FDO23460MQC")

    Returns:
        Dict with list of all interfaces and their details (status, VLAN, compliance, etc.)
    """
    endpoint = f"/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/interface/detail?serialNumber={serial_number}"
    return await _make_request(endpoint, method="GET")


async def get_all_switches() -> Dict[str, Any]:
    """
    Get list of all switches across all fabrics.

    Returns:
        Dict with list of switches (serial numbers, fabric, IP addresses, etc.)
    """
    endpoint = "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/inventory/allswitches"
    return await _make_request(endpoint, method="GET")


async def get_event_records(limit: Optional[int] = 50, severity: Optional[str] = None) -> Dict[str, Any]:
    """
    Get event records from Nexus Dashboard event monitoring.
    This endpoint provides critical events, alarms, and system notifications.

    Args:
        limit: Maximum number of events to return (default: 50, max recommended: 1000)
        severity: Optional filter by severity (critical, error, warning, info)

    Returns:
        Dict with event records including:
        - metadata: Event metadata
        - items: List of event records with severity, description, timestamps, etc.
        Note: Results are limited client-side if API returns more than requested.

    Example response structure:
        {
            "metadata": {...},
            "items": [
                {
                    "spec": {
                        "recordId": "...",
                        "alertState": "Cleared",
                        "acked": false
                    },
                    "status": {
                        "eventOccurrence": {
                            "severity": "critical",
                            "alertDescription": "...",
                            "eventCount": 5,
                            "clearedTime": "2025-07-16T02:03:32Z"
                        }
                    }
                }
            ]
        }
    """
    endpoint = "/nexus/infra/api/eventmonitoring/v1/eventrecords"

    # Set default limit if not provided (prevent huge responses)
    if limit is None:
        limit = 50
    
    # Cap limit at reasonable maximum to prevent excessive data transfer
    max_limit = 1000
    if limit > max_limit:
        logger.warning(f"Limit {limit} exceeds maximum {max_limit}, capping to {max_limit}")
        limit = max_limit

    # Build query parameters
    params = {}
    if limit:
        params["limit"] = limit
    if severity:
        params["severity"] = severity

    result = await _make_request(endpoint, method="GET", params=params if params else None)
    
    # If request succeeded, limit results client-side if API returned more than requested
    if result.get("success") and result.get("data"):
        data = result["data"]
        if isinstance(data, dict) and "items" in data and isinstance(data["items"], list):
            items = data["items"]
            if len(items) > limit:
                logger.info(f"API returned {len(items)} items, limiting to {limit} client-side")
                data["items"] = items[:limit]
                # Update metadata if present
                if "metadata" in data and isinstance(data["metadata"], dict):
                    data["metadata"]["totalItems"] = len(items)
                    data["metadata"]["returnedItems"] = limit
                result["data"] = data
    
    return result

