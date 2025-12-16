# /connectors/aruba_c.py

import os
from typing import Dict, Optional
from dotenv import load_dotenv
import httpx

# Loading environment variables (override system env vars)
load_dotenv(override=True)

# Retrieving Aruba API credentials from the .env file
ARUBA_URL = os.getenv("ARUBA_URL", "https://ctrl-aruba-vrrp.priv.ina:4343")
ARUBA_USERNAME = os.getenv("ARUBA_USERNAME")
ARUBA_PASSWORD = os.getenv("ARUBA_PASSWORD")
ARUBA_TIMEOUT = int(os.getenv("ARUBA_TIMEOUT", "30"))

# Global persistent HTTP client (maintains cookies like requests.Session())
_http_client: Optional[httpx.AsyncClient] = None
_session_token: Optional[str] = None


def _get_http_client() -> httpx.AsyncClient:
    """
    Get or create the global persistent HTTP client.
    This client maintains cookies across requests (like requests.Session()).

    Returns:
        Persistent httpx.AsyncClient instance
    """
    global _http_client

    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            verify=False,
            timeout=ARUBA_TIMEOUT,
            follow_redirects=True
        )

    return _http_client


async def _aruba_login() -> Optional[str]:
    """
    Authenticate to Aruba controller and obtain session token.
    The persistent client maintains the SESSION cookie automatically.

    Returns:
        Session token (UIDARUBA) or None if authentication fails
    """
    global _session_token

    if not ARUBA_USERNAME or not ARUBA_PASSWORD:
        return None

    login_url = f"{ARUBA_URL}/v1/api/login"
    form_data = {
        "username": ARUBA_USERNAME,
        "password": ARUBA_PASSWORD
    }

    try:
        client = _get_http_client()
        response = await client.post(login_url, data=form_data)
        response.raise_for_status()
        result = response.json()

        if result.get("_global_result", {}).get("status") == "0":
            _session_token = result["_global_result"]["UIDARUBA"]
            return _session_token

        return None

    except Exception:
        return None


async def _aruba_request(endpoint: str, command: Optional[str] = None) -> Optional[Dict]:
    """
    Performs an asynchronous Aruba REST API request via persistent httpx client.
    The persistent client maintains SESSION cookies automatically (like requests.Session()).

    Args:
        endpoint: API endpoint path (e.g., "/v1/configuration/showcommand")
        command: Optional CLI command for showcommand endpoint

    Returns:
        JSON response or dict with error
    """
    global _session_token

    if not ARUBA_URL:
        return {"error": "Aruba URL not configured"}

    # Ensure authenticated
    if not _session_token:
        _session_token = await _aruba_login()
        if not _session_token:
            return {"error": "Authentication failed"}

    # Build URL with token
    separator = "&" if "?" in endpoint else "?"
    url = f"{ARUBA_URL}{endpoint}{separator}UIDARUBA={_session_token}"

    # Add command parameter if provided
    if command:
        url = f"{url}&command={command}"

    try:
        client = _get_http_client()
        response = await client.get(url)

        # Handle token expiration (401/403)
        if response.status_code in [401, 403]:
            _session_token = None
            _session_token = await _aruba_login()
            if not _session_token:
                return {"error": "Re-authentication failed"}

            # Retry with new token
            separator = "&" if "?" in endpoint else "?"
            url = f"{ARUBA_URL}{endpoint}{separator}UIDARUBA={_session_token}"
            if command:
                url = f"{url}&command={command}"
            response = await client.get(url)

        response.raise_for_status()

        # Parse JSON response
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


# ========== API Functions (Async) ==========

async def get_ap_database(limit: Optional[int] = None) -> Dict:
    """
    Get complete list of Access Points.

    Args:
        limit: Optional limit on number of APs to return

    Returns:
        Dict with AP database information
    """
    data = await _aruba_request("/v1/configuration/showcommand", command="show ap database")

    if not data or "error" in data:
        return data or {"error": "No response from Aruba API"}

    # Apply limit if specified
    if limit and isinstance(data, dict) and "AP Database" in data:
        ap_list = data.get("AP Database", [])
        if isinstance(ap_list, list) and len(ap_list) > limit:
            data["AP Database"] = ap_list[:limit]

    return data


async def get_client_list(limit: Optional[int] = None) -> Dict:
    """
    Get list of connected clients.

    Args:
        limit: Optional limit on number of clients to return

    Returns:
        Dict with user table information
    """
    data = await _aruba_request("/v1/configuration/showcommand", command="show user-table")

    if not data or "error" in data:
        return data or {"error": "No response from Aruba API"}

    # Apply limit if specified
    if limit and isinstance(data, dict) and "Users" in data:
        user_list = data.get("Users", [])
        if isinstance(user_list, list) and len(user_list) > limit:
            data["Users"] = user_list[:limit]

    return data


async def get_rogue_ap_list(limit: Optional[int] = None) -> Dict:
    """
    Get list of unauthorized/rogue access points (Security).

    Args:
        limit: Optional limit on number of rogue APs to return

    Returns:
        Dict with rogue AP information
    """
    data = await _aruba_request("/v1/configuration/showcommand", command="show ap monitor rogue-ap-list")

    if not data or "error" in data:
        return data or {"error": "No response from Aruba API"}

    # Apply limit if specified
    if limit and isinstance(data, dict) and "Rogue APs" in data:
        rogue_list = data.get("Rogue APs", [])
        if isinstance(rogue_list, list) and len(rogue_list) > limit:
            data["Rogue APs"] = rogue_list[:limit]

    return data


async def get_ap_channel_info() -> Dict:
    """
    Get active channel information for RF optimization.

    Returns:
        Dict with AP channel information
    """
    data = await _aruba_request("/v1/configuration/showcommand", command="show ap active channel")
    return data or {"error": "No response from Aruba API"}


async def get_wlan_list() -> Dict:
    """
    Get WLAN/SSID profile configuration.

    Returns:
        Dict with WLAN SSID profiles
    """
    data = await _aruba_request("/v1/configuration/showcommand", command="show wlan ssid-profile")
    return data or {"error": "No response from Aruba API"}


async def get_ap_statistics() -> Dict:
    """
    Get AP performance metrics and ARM state.

    Returns:
        Dict with AP statistics
    """
    data = await _aruba_request("/v1/configuration/showcommand", command="show ap arm state")
    return data or {"error": "No response from Aruba API"}


async def get_license_info() -> Dict:
    """
    Get license compliance information.

    Returns:
        Dict with license information
    """
    data = await _aruba_request("/v1/configuration/showcommand", command="show license")
    return data or {"error": "No response from Aruba API"}


async def get_controller_info() -> Dict:
    """
    Get controller system information.

    Returns:
        Dict with controller system information
    """
    data = await _aruba_request("/v1/configuration/showcommand", command="show version")
    return data or {"error": "No response from Aruba API"}


async def run_custom_command(command: str) -> Dict:
    """
    Execute a custom show command on Aruba controller.

    Args:
        command: CLI command to execute (e.g., "show ap database")

    Returns:
        Dict with command output
    """
    if not command:
        return {"error": "Command cannot be empty"}

    data = await _aruba_request("/v1/configuration/showcommand", command=command)
    return data or {"error": "No response from Aruba API"}
