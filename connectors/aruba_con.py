"""
ARUBA WiFi Controller Connector
Provides connectivity to ARUBA Mobility Controller via REST API
Supports authentication, session management, and command execution
"""

import os
import json
import logging
import requests
import urllib3
from typing import Dict, Any, Optional
from functools import wraps
from dotenv import load_dotenv

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()


def handle_aruba_errors(func):
    """Decorator for unified error handling across ARUBA API calls"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except requests.exceptions.Timeout:
            logger.error(f"Timeout error in {func.__name__}")
            return {"success": False, "error": "Request timeout", "data": None}
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error in {func.__name__}")
            return {"success": False, "error": "Connection failed", "data": None}
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error in {func.__name__}: {e}")
            return {"success": False, "error": f"HTTP error: {str(e)}", "data": None}
        except Exception as e:
            logger.error(f"Unexpected error in {func.__name__}: {e}")
            return {"success": False, "error": str(e), "data": None}
    return wrapper


class ArubaConnector:
    """
    ARUBA Mobility Controller API Connector
    Handles authentication, session management, and API requests
    """

    def __init__(self):
        """Initialize ARUBA connector with configuration from environment"""
        self.base_url = os.getenv("ARUBA_URL", "")
        self.username = os.getenv("ARUBA_USERNAME", "")
        self.password = os.getenv("ARUBA_PASSWORD", "")
        self.timeout = int(os.getenv("ARUBA_TIMEOUT", "30"))

        self.session_token = None
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification for self-signed certificates

        logger.info(f"ARUBA Connector initialized for {self.base_url}")

    def login(self) -> bool:
        """
        Authenticate to ARUBA controller and obtain session token

        Returns:
            bool: True if authentication successful, False otherwise
        """
        try:
            login_url = f"{self.base_url}/v1/api/login"
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            data = f"username={self.username}&password={self.password}"

            logger.info("Attempting to authenticate to ARUBA controller")
            response = self.session.post(
                login_url,
                headers=headers,
                data=data,
                timeout=self.timeout
            )
            response.raise_for_status()

            result = response.json()

            if result.get("_global_result", {}).get("status") == "0":
                self.session_token = result["_global_result"]["UIDARUBA"]
                logger.info("Successfully authenticated to ARUBA controller")
                return True
            else:
                logger.error(f"Authentication failed: {result.get('_global_result', {}).get('status_str')}")
                return False

        except Exception as e:
            logger.error(f"Login error: {e}")
            return False

    def logout(self) -> bool:
        """
        Logout from ARUBA controller and clear session token

        Returns:
            bool: True if logout successful, False otherwise
        """
        try:
            if not self.session_token:
                logger.warning("No active session to logout from")
                return True

            logout_url = f"{self.base_url}/v1/api/logout?UIDARUBA={self.session_token}"

            logger.info("Logging out from ARUBA controller")
            response = self.session.post(logout_url, timeout=self.timeout)
            response.raise_for_status()

            self.session_token = None
            logger.info("Successfully logged out from ARUBA controller")
            return True

        except Exception as e:
            logger.error(f"Logout error: {e}")
            self.session_token = None  # Clear token anyway
            return False

    def _ensure_authenticated(self) -> bool:
        """
        Ensure we have a valid session token, login if needed

        Returns:
            bool: True if authenticated, False otherwise
        """
        if not self.session_token:
            return self.login()
        return True

    @handle_aruba_errors
    def _make_request(self, endpoint: str, method: str = "GET", data: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Generic method to make authenticated API requests to ARUBA controller

        Args:
            endpoint: API endpoint path (e.g., "/v1/configuration/showcommand")
            method: HTTP method (GET, POST, etc.)
            data: Optional request body data

        Returns:
            Dict with success status, data, and optional error message
        """
        if not self._ensure_authenticated():
            return {"success": False, "error": "Authentication failed", "data": None}

        # Add UIDARUBA token as URL parameter
        separator = "&" if "?" in endpoint else "?"
        url = f"{self.base_url}{endpoint}{separator}UIDARUBA={self.session_token}"

        logger.info(f"Making {method} request to {endpoint}")

        try:
            if method.upper() == "GET":
                response = self.session.get(url, timeout=self.timeout)
            elif method.upper() == "POST":
                response = self.session.post(url, json=data, timeout=self.timeout)
            else:
                return {"success": False, "error": f"Unsupported method: {method}", "data": None}

            # Check if token expired (401 or 403), re-authenticate once
            if response.status_code in [401, 403]:
                logger.warning("Session token expired, re-authenticating")
                self.session_token = None
                if self.login():
                    # Rebuild URL with new token
                    url = f"{self.base_url}{endpoint}{separator}UIDARUBA={self.session_token}"
                    if method.upper() == "GET":
                        response = self.session.get(url, timeout=self.timeout)
                    elif method.upper() == "POST":
                        response = self.session.post(url, json=data, timeout=self.timeout)
                else:
                    return {"success": False, "error": "Re-authentication failed", "data": None}

            response.raise_for_status()

            # Try to parse JSON response
            try:
                result = response.json()
            except ValueError as e:
                # If response is not JSON, return the text content
                logger.warning(f"Response is not JSON, returning text: {e}")
                return {"success": True, "error": None, "data": {"_text": response.text, "_raw_response": True}}

            return {"success": True, "error": None, "data": result}

        except requests.exceptions.RequestException as e:
            logger.error(f"Request error: {e}")
            raise  # Let decorator handle it

    @handle_aruba_errors
    def run_custom_command(self, command: str) -> Dict[str, Any]:
        """
        Execute a custom show command on ARUBA controller

        Args:
            command: CLI command to execute (e.g., "show ap database")

        Returns:
            Dict with command output
        """
        endpoint = f"/v1/configuration/showcommand?command={command}"
        return self._make_request(endpoint, method="GET")

    # ============================================================================
    # CRITICAL PRIORITY ENDPOINTS
    # ============================================================================

    @handle_aruba_errors
    def get_ap_database(self, limit: Optional[int] = None) -> Dict[str, Any]:
        """
        Get complete list of Access Points
        Priority: CRITICAL

        Args:
            limit: Optional limit on number of APs to return (for testing)

        Returns:
            Dict with AP database information
        """
        result = self.run_custom_command("show ap database")

        # Apply limit if specified (for testing)
        if limit and result.get("success") and result.get("data"):
            data = result["data"]
            if isinstance(data, dict) and "AP Database" in data:
                ap_list = data["AP Database"]
                if isinstance(ap_list, list) and len(ap_list) > limit:
                    data["AP Database"] = ap_list[:limit]
                    result["data"] = data

        return result

    @handle_aruba_errors
    def get_client_list(self, limit: Optional[int] = None) -> Dict[str, Any]:
        """
        Get list of connected clients
        Priority: CRITICAL

        Args:
            limit: Optional limit on number of clients to return (for testing)

        Returns:
            Dict with user table information
        """
        result = self.run_custom_command("show user-table")

        # Apply limit if specified (for testing)
        if limit and result.get("success") and result.get("data"):
            data = result["data"]
            if isinstance(data, dict) and "Users" in data:
                user_list = data["Users"]
                if isinstance(user_list, list) and len(user_list) > limit:
                    data["Users"] = user_list[:limit]
                    result["data"] = data

        return result

    @handle_aruba_errors
    def get_rogue_ap_list(self, limit: Optional[int] = None) -> Dict[str, Any]:
        """
        Get list of unauthorized/rogue access points (Security)
        Priority: CRITICAL

        Args:
            limit: Optional limit on number of rogue APs to return (for testing)

        Returns:
            Dict with rogue AP information
        """
        result = self.run_custom_command("show ap monitor rogue-ap-list")

        # Apply limit if specified (for testing)
        if limit and result.get("success") and result.get("data"):
            data = result["data"]
            if isinstance(data, dict) and "Rogue APs" in data:
                rogue_list = data["Rogue APs"]
                if isinstance(rogue_list, list) and len(rogue_list) > limit:
                    data["Rogue APs"] = rogue_list[:limit]
                    result["data"] = data

        return result

    # ============================================================================
    # IMPORTANT PRIORITY ENDPOINTS
    # ============================================================================

    @handle_aruba_errors
    def get_ap_channel_info(self) -> Dict[str, Any]:
        """
        Get active channel information for RF optimization
        Priority: IMPORTANT

        Returns:
            Dict with AP channel information
        """
        return self.run_custom_command("show ap active channel")

    @handle_aruba_errors
    def get_wlan_list(self) -> Dict[str, Any]:
        """
        Get WLAN/SSID profile configuration
        Priority: IMPORTANT

        Returns:
            Dict with WLAN SSID profiles
        """
        return self.run_custom_command("show wlan ssid-profile")

    @handle_aruba_errors
    def get_ap_statistics(self) -> Dict[str, Any]:
        """
        Get AP performance metrics and ARM state
        Priority: IMPORTANT

        Returns:
            Dict with AP statistics
        """
        return self.run_custom_command("show ap arm state")

    # ============================================================================
    # NORMAL PRIORITY ENDPOINTS
    # ============================================================================

    @handle_aruba_errors
    def get_license_info(self) -> Dict[str, Any]:
        """
        Get license compliance information
        Priority: NORMAL

        Returns:
            Dict with license information
        """
        return self.run_custom_command("show license")

    @handle_aruba_errors
    def get_vlan_info(self) -> Dict[str, Any]:
        """
        Get VLAN network configuration
        Priority: NORMAL

        Returns:
            Dict with VLAN information
        """
        return self.run_custom_command("show vlan")

    @handle_aruba_errors
    def get_cluster_info(self) -> Dict[str, Any]:
        """
        Get High Availability cluster status
        Priority: NORMAL

        Returns:
            Dict with cluster membership information
        """
        return self.run_custom_command("show lc-cluster group-membership")

    @handle_aruba_errors
    def get_bandwidth_contracts(self) -> Dict[str, Any]:
        """
        Get QoS bandwidth contracts for users
        Priority: NORMAL

        Returns:
            Dict with bandwidth contract information
        """
        return self.run_custom_command("show aaa bandwidth-contract")

    # ============================================================================
    # ADDITIONAL USEFUL ENDPOINTS
    # ============================================================================

    @handle_aruba_errors
    def get_controller_info(self) -> Dict[str, Any]:
        """
        Get controller system information

        Returns:
            Dict with controller system information
        """
        return self.run_custom_command("show version")

    @handle_aruba_errors
    def get_ap_details(self, ap_name: str) -> Dict[str, Any]:
        """
        Get detailed information for a specific AP

        Args:
            ap_name: Name of the Access Point

        Returns:
            Dict with AP details
        """
        return self.run_custom_command(f"show ap details {ap_name}")

    @handle_aruba_errors
    def get_radio_summary(self) -> Dict[str, Any]:
        """
        Get radio summary for all APs

        Returns:
            Dict with radio summary
        """
        return self.run_custom_command("show ap radio-summary")

    @handle_aruba_errors
    def get_ap_debug_client(self, client_mac: str) -> Dict[str, Any]:
        """
        Get debug information for a specific client

        Args:
            client_mac: MAC address of the client

        Returns:
            Dict with client debug information
        """
        return self.run_custom_command(f"show ap debug client-table {client_mac}")


def format_response(result: Dict[str, Any], command_name: str) -> str:
    """
    Format ARUBA API response for user-friendly output

    Args:
        result: Response dictionary from connector
        command_name: Name of the command executed

    Returns:
        Formatted string for display
    """
    if not result.get("success"):
        return f"❌ Error executing {command_name}: {result.get('error', 'Unknown error')}"

    data = result.get("data")
    if not data:
        return f"⚠️ No data returned from {command_name}"

    try:
        return f"✅ {command_name} successful:\n{json.dumps(data, indent=2)}"
    except Exception as e:
        return f"⚠️ {command_name} returned data but formatting failed: {str(e)}\nRaw data: {data}"


# Example usage
if __name__ == "__main__":
    # Initialize connector
    connector = ArubaConnector()

    # Test authentication
    if connector.login():
        print("✅ Authentication successful")

        # Test critical endpoints
        print("\n=== Testing Critical Endpoints ===")

        print("\n1. AP Database (limited to 3):")
        ap_result = connector.get_ap_database(limit=3)
        print(format_response(ap_result, "get_ap_database"))

        print("\n2. Client List (limited to 3):")
        client_result = connector.get_client_list(limit=3)
        print(format_response(client_result, "get_client_list"))

        print("\n3. Rogue AP List (limited to 3):")
        rogue_result = connector.get_rogue_ap_list(limit=3)
        print(format_response(rogue_result, "get_rogue_ap_list"))

        # Cleanup
        connector.logout()
        print("\n✅ Logged out successfully")
    else:
        print("❌ Authentication failed")
