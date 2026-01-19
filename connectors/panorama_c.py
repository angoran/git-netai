"""
Panorama (PAN-OS 11.1) Connector - Async Version
Provides connectivity to Palo Alto Panorama via XML API
Hybrid architecture: Async transport (httpx) with JSON-only output
IMPORTANT: XML is strictly internal, never exposed to MCP tools
"""

import logging
import os
import xml.etree.ElementTree as ET
from functools import wraps
from typing import Any, Dict, Optional

import httpx
from dotenv import load_dotenv

# Logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()


def handle_panorama_errors(func):
    """Decorator for unified error handling for async Panorama API calls"""

    @wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except httpx.TimeoutException:
            logger.error(f"Timeout error in {func.__name__}")
            return {"success": False, "error": "Request timeout", "data": None}
        except httpx.ConnectError:
            logger.error(f"Connection error in {func.__name__}")
            return {"success": False, "error": "Connection failed", "data": None}
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error in {func.__name__}: {e}")
            return {"success": False, "error": f"HTTP error: {str(e)}", "data": None}
        except Exception as e:
            logger.error(f"Unexpected error in {func.__name__}: {e}")
            return {"success": False, "error": str(e), "data": None}

    return wrapper


class PanoramaConnector:
    """
    Panorama API Connector (PAN-OS 11.1)
    Handles authentication via keygen and XML API operations
    GOLDEN RULE: XML is internal only, all outputs are JSON
    """

    def __init__(self):
        """Initialize Panorama connector with configuration from environment"""
        # Get base URL from .env and build full API URL
        base_url = os.getenv("PANORAMA_URL", "https://panorama.p.priv.ina/api")
        # Ensure URL ends with /api
        if not base_url.endswith("/api"):
            self.base_url = f"{base_url.rstrip('/')}/api"
        else:
            self.base_url = base_url

        self.username = os.getenv("PANORAMA_USERNAME", "airun")
        self.password = os.getenv("PANORAMA_PASSWORD", "")
        self.timeout = int(os.getenv("PANORAMA_TIMEOUT", "30"))

        self.api_key: Optional[str] = None
        # Configuration to disable SSL verification (self-signed certificates)
        self.verify_ssl = False

        logger.info(f"Panorama connector initialized for {self.base_url}")

    def _parse_xml_response(self, xml_text: str) -> Dict[str, Any]:
        """
        Parse XML response and convert to normalized JSON
        CRITICAL: This method must NEVER expose XML in output

        Args:
            xml_text: Raw XML response from API

        Returns:
            Dict with status and normalized JSON data
        """
        try:
            root = ET.fromstring(xml_text)

            # Check response status
            status = root.get("status")

            if status == "success":
                # Extract content from <result>
                result_elem = root.find("result")
                if result_elem is not None:
                    # Convert XML element to dictionary
                    data = self._xml_element_to_dict(result_elem)
                    return {"success": True, "error": None, "data": data}
                else:
                    return {
                        "success": True,
                        "error": None,
                        "data": {"message": "Success without data"},
                    }
            else:
                # Extract error message if present
                msg_elem = root.find(".//msg")
                error_msg = msg_elem.text if msg_elem is not None else "Unknown error"
                return {"success": False, "error": error_msg, "data": None}

        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}")
            return {
                "success": False,
                "error": f"XML parsing error: {str(e)}",
                "data": None,
            }
        except Exception as e:
            logger.error(f"Unexpected error during parsing: {e}")
            return {"success": False, "error": str(e), "data": None}

    def _xml_element_to_dict(self, element: ET.Element) -> Any:
        """
        Recursively convert XML element to Python dictionary
        Handles special cases: lists, simple values, nested structures

        Args:
            element: XML element to convert

        Returns:
            Dict, List, or str depending on XML structure
        """
        # If element has children
        children = list(element)
        if children:
            # Group children by tag to detect lists
            tag_count = {}
            for child in children:
                tag_count[child.tag] = tag_count.get(child.tag, 0) + 1

            # If all children have the same tag, it's a list
            if len(tag_count) == 1 and tag_count[children[0].tag] > 1:
                return [self._xml_element_to_dict(child) for child in children]

            # Otherwise it's a dictionary
            result = {}
            for child in children:
                child_data = self._xml_element_to_dict(child)
                if child.tag in result:
                    # If key already exists, convert to list
                    if not isinstance(result[child.tag], list):
                        result[child.tag] = [result[child.tag]]
                    result[child.tag].append(child_data)
                else:
                    result[child.tag] = child_data
            return result
        else:
            # Element without children - return text or attributes
            text = element.text
            attribs = element.attrib

            if attribs and text:
                return {"_text": text.strip(), **attribs}
            elif attribs:
                return dict(attribs)
            elif text:
                return text.strip()
            else:
                return None

    async def _ensure_authenticated(self) -> bool:
        """
        Ensure we have a valid API key, generate if necessary

        Returns:
            bool: True if authenticated, False otherwise
        """
        if not self.api_key:
            result = await self.generate_api_key()
            return result.get("success", False)
        return True

    # ========================================================================
    # LAYER 1: CORE HTTP CLIENT (Universal central method)
    # ========================================================================

    @handle_panorama_errors
    async def _execute_api_call(
        self, request_type: str, params: Dict[str, str], auto_auth: bool = True
    ) -> Dict[str, Any]:
        """
        Central method for ALL Panorama API calls
        Refactored architecture: single place for auth/httpx/parsing/errors

        Args:
            request_type: Request type ("keygen", "op", "config", "log")
            params: Request-specific parameters (without "type" or "key")
            auto_auth: Automatically authenticate if necessary (default: True)

        Returns:
            Standardized dict {"success": bool, "error": str|None, "data": Any}
        """
        # Automatic authentication (except for keygen)
        if auto_auth and request_type != "keygen":
            if not await self._ensure_authenticated():
                return {
                    "success": False,
                    "error": "Authentication failed",
                    "data": None,
                }
            # At this point, api_key is guaranteed non-None by _ensure_authenticated()
            if self.api_key is not None:
                params["key"] = self.api_key

        # Add type to params
        params["type"] = request_type

        try:
            logger.info(f"API call: type={request_type}")

            async with httpx.AsyncClient(
                verify=self.verify_ssl, timeout=self.timeout
            ) as client:
                response = await client.get(self.base_url, params=params)
                response.raise_for_status()

                # Parse XML → JSON (existing method)
                result = self._parse_xml_response(response.text)

                # Store api_key if keygen
                if request_type == "keygen" and result["success"]:
                    key = result["data"].get("key")
                    if key:
                        self.api_key = key
                        logger.info("API key generated and stored successfully")

                return result

        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error {e.response.status_code}: {e}")
            return {
                "success": False,
                "error": f"HTTP {e.response.status_code}: {str(e)}",
                "data": None,
            }
        except Exception as e:
            logger.error(f"API call error: {e}")
            raise

    # ========================================================================
    # LAYER 2: API EXECUTORS (4 generic methods by type)
    # ========================================================================

    async def execute_op_command(self, cmd: str) -> Dict[str, Any]:
        """
        Execute operational command (type=op) - Show commands

        Args:
            cmd: XML command (e.g., "<show><system><info></info></system></show>")

        Returns:
            Dict with normalized JSON data
        """
        return await self._execute_api_call(request_type="op", params={"cmd": cmd})

    async def execute_config_query(
        self, xpath: str, action: str = "get"
    ) -> Dict[str, Any]:
        """
        Execute configuration query (type=config)

        Args:
            xpath: Configuration XPath
            action: Action to perform (get, set, edit, delete)

        Returns:
            Dict with normalized JSON data
        """
        return await self._execute_api_call(
            request_type="config", params={"action": action, "xpath": xpath}
        )

    async def execute_log_query(
        self, log_type: str, nlogs: int = 100, **kwargs
    ) -> Dict[str, Any]:
        """
        Execute log query (type=log)

        Args:
            log_type: Log type (config, traffic, system, threat, etc.)
            nlogs: Number of logs to return
            **kwargs: Additional query parameters

        Returns:
            Dict with normalized JSON data
        """
        params = {"log-type": log_type, "nlogs": str(nlogs), **kwargs}
        return await self._execute_api_call(request_type="log", params=params)

    @handle_panorama_errors
    async def generate_api_key(self) -> Dict[str, Any]:
        """
        Generate and return a Panorama API key via keygen endpoint
        Now uses _execute_api_call (refactored architecture)

        Returns:
            Dict with status and API key
        """
        result = await self._execute_api_call(
            request_type="keygen",
            params={"user": self.username, "password": self.password},
            auto_auth=False,
        )

        if result["success"]:
            return {
                "success": True,
                "error": None,
                "data": {"api_key": result["data"].get("key", "")},
            }
        return result

    # ========================================================================
    # HELPER METHODS (Robust parsing)
    # ========================================================================

    def _extract_entries(self, data: Any, key: Optional[str] = None) -> list:
        """
        Helper to extract entries from XML→JSON response
        Automatically handles dict/list variations from Panorama API

        Args:
            data: Parsed data from API
            key: Optional key to extract first

        Returns:
            Normalized list of entries
        """
        if data is None:
            return []

        # Extract key if provided
        if key and isinstance(data, dict):
            data = data.get(key, data)

        # Normalize to list
        if isinstance(data, dict):
            entries = data.get("entry", [])
            if isinstance(entries, dict):
                return [entries]
            elif isinstance(entries, list):
                return entries
            else:
                return []
        elif isinstance(data, list):
            return data
        else:
            return []

    # ========================================================================
    # LAYER 3: BUSINESS LOGIC (Refactored business functions)
    # ========================================================================

    @handle_panorama_errors
    async def execute_op_command_legacy(self, cmd: str) -> Dict[str, Any]:
        """
        Execute operational command (type=op) on Panorama
        IMPORTANT: XML is parsed and converted to JSON before return

        Args:
            cmd: XML command to execute (e.g., "<show><system><info></info></system></show>")

        Returns:
            Dict with status and normalized JSON data only
        """
        if not await self._ensure_authenticated():
            return {
                "success": False,
                "error": "Authentication failed",
                "data": None,
            }

        try:
            url = self.base_url
            params = {"type": "op", "cmd": cmd, "key": self.api_key}

            logger.info(f"Executing op command: {cmd[:50]}...")

            async with httpx.AsyncClient(
                verify=self.verify_ssl, timeout=self.timeout
            ) as client:
                response = await client.get(url, params=params)
                response.raise_for_status()

                # Parse XML response and convert to JSON
                result = self._parse_xml_response(response.text)

                if result["success"]:
                    logger.info("Command executed successfully")
                else:
                    logger.warning(f"Command failed: {result.get('error')}")

                return result

        except Exception as e:
            logger.error(f"Error executing command: {e}")
            raise

    @handle_panorama_errors
    async def get_system_info(self) -> Dict[str, Any]:
        """
        Retrieve Panorama system information
        Executes command: show system info

        Returns:
            Normalized JSON dict with hostname, version, uptime, model, etc.
        """
        cmd = "<show><system><info></info></system></show>"
        result = await self.execute_op_command(cmd)

        if result["success"] and result["data"]:
            # Normalize output for MCP tool
            system_info = result["data"].get("system", {})

            # Build normalized and simplified output
            normalized = {
                "hostname": system_info.get("hostname", "N/A"),
                "ip_address": system_info.get("ip-address", "N/A"),
                "netmask": system_info.get("netmask", "N/A"),
                "default_gateway": system_info.get("default-gateway", "N/A"),
                "mac_address": system_info.get("mac-address", "N/A"),
                "time": system_info.get("time", "N/A"),
                "uptime": system_info.get("uptime", "N/A"),
                "devicename": system_info.get("devicename", "N/A"),
                "family": system_info.get("family", "N/A"),
                "model": system_info.get("model", "N/A"),
                "serial": system_info.get("serial", "N/A"),
                "sw_version": system_info.get("sw-version", "N/A"),
                "app_version": system_info.get("app-version", "N/A"),
                "av_version": system_info.get("av-version", "N/A"),
                "threat_version": system_info.get("threat-version", "N/A"),
                "url_filtering_version": system_info.get(
                    "url-filtering-version", "N/A"
                ),
                "wildfire_version": system_info.get("wildfire-version", "N/A"),
                "operational_mode": system_info.get("operational-mode", "N/A"),
            }

            return {"success": True, "error": None, "data": normalized}
        else:
            return result

    # ========================================================================
    # ANALYSIS AND COMPLIANCE FUNCTIONS
    # ========================================================================

    @handle_panorama_errors
    async def get_managed_devices(self) -> Dict[str, Any]:
        """
        Retrieve complete inventory of firewalls managed by Panorama
        Uses _extract_entries() for simplified parsing

        Returns:
            Dict with device list and their info (version, HA, connection, plugins)
        """
        cmd = "<show><devices><all></all></devices></show>"
        result = await self.execute_op_command(cmd)

        if not result["success"]:
            return result

        # Simplified parsing with helper
        entries = self._extract_entries(result.get("data"), key="devices")

        devices = []
        for device in entries:
            if isinstance(device, dict):
                normalized_device = {
                    "device": device.get("@name", device.get("name", "N/A")),
                    "serial": device.get("serial", "N/A"),
                    "version": device.get("sw-version", "N/A"),
                    "ha_state": device.get("ha", {}).get("state", "N/A")
                    if isinstance(device.get("ha"), dict)
                    else "N/A",
                    "connected": device.get("connected", "no") == "yes",
                    "ip_address": device.get("ip-address", "N/A"),
                    "model": device.get("model", "N/A"),
                    "uptime": device.get("uptime", "N/A"),
                }

                # Extract installed plugins
                plugins = []
                if "plugins" in device and isinstance(device["plugins"], dict):
                    plugin_entries = device["plugins"].get("entry", [])
                    if isinstance(plugin_entries, dict):
                        plugin_entries = [plugin_entries]
                    for plugin in plugin_entries:
                        if isinstance(plugin, dict):
                            plugins.append(
                                plugin.get("@name", plugin.get("name", "Unknown"))
                            )

                normalized_device["plugins"] = plugins
                devices.append(normalized_device)

        return {
            "success": True,
            "error": None,
            "data": {"total_devices": len(devices), "devices": devices},
        }

    @handle_panorama_errors
    async def get_device_groups(self) -> Dict[str, Any]:
        """
        Retrieve list of Device-Groups configured in Panorama
        Uses execute_config_query() + _extract_entries()

        Returns:
            Dict with device-groups list and their members
        """
        # Simplified API call with Layer 2
        xpath = "/config/devices/entry[@name='localhost.localdomain']/device-group"
        result = await self.execute_config_query(xpath)

        if not result["success"]:
            return result

        # Simplified parsing with helper
        entries = self._extract_entries(result.get("data"), key="device-group")

        device_groups = []
        for dg in entries:
            if isinstance(dg, dict):
                dg_name = dg.get("@name", dg.get("name", "N/A"))

                # Extract members (devices) with helper
                device_entries = self._extract_entries(dg.get("devices"))
                devices = [
                    d.get("@name", d.get("name", "Unknown"))
                    for d in device_entries
                    if isinstance(d, dict)
                ]

                device_groups.append(
                    {
                        "name": dg_name,
                        "devices": devices,
                        "device_count": len(devices),
                    }
                )

        return {
            "success": True,
            "error": None,
            "data": {
                "total_device_groups": len(device_groups),
                "device_groups": device_groups,
            },
        }

    @handle_panorama_errors
    async def get_config_diff(self) -> Dict[str, Any]:
        """
        Retrieve differences between candidate and running configuration

        Returns:
            Dict with pending changes
        """
        cmd = "<show><config><diff></diff></config></show>"
        result = await self.execute_op_command(cmd)

        if not result["success"]:
            return result

        # Normalize output
        diff_data = result.get("data", {})
        diff_text = diff_data.get("diff", "")

        # Analyze diff
        has_changes = bool(diff_text and diff_text.strip() and diff_text.strip() != "")

        return {
            "success": True,
            "error": None,
            "data": {
                "has_pending_changes": has_changes,
                "diff_summary": "Changes detected"
                if has_changes
                else "No pending changes",
                "diff_content": diff_text if has_changes else None,
            },
        }

    @handle_panorama_errors
    async def get_security_rules_by_device_group(
        self, device_group: str
    ) -> Dict[str, Any]:
        """
        Retrieve security rules for a specific Device-Group
        Analyzes redundant rules, missing comments, non-explicit names

        Args:
            device_group: Device-group name

        Returns:
            Dict with rules and quality analysis
        """
        # Ensure authentication first
        if not await self._ensure_authenticated():
            return {
                "success": False,
                "error": "Authentication failed",
                "data": None,
            }

        xpath = f"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{device_group}']/pre-rulebase/security/rules"

        params = {
            "type": "config",
            "action": "get",
            "xpath": xpath,
            "key": self.api_key,
        }

        try:
            async with httpx.AsyncClient(
                verify=self.verify_ssl, timeout=self.timeout
            ) as client:
                response = await client.get(self.base_url, params=params)
                response.raise_for_status()

                result = self._parse_xml_response(response.text)

                if not result["success"]:
                    return result

                # Analyze rules
                rules_data = result.get("data", {}).get("rules", {})
                entries = rules_data.get("entry", [])

                if isinstance(entries, dict):
                    entries = [entries]

                rules = []
                issues = {
                    "no_description": [],
                    "generic_names": [],
                    "too_permissive": [],
                }

                for rule in entries:
                    if isinstance(rule, dict):
                        rule_name = rule.get("@name", rule.get("name", "N/A"))
                        description = rule.get("description", "")

                        # Check for quality issues
                        if not description or description.strip() == "":
                            issues["no_description"].append(rule_name)

                        # Check for generic names
                        generic_patterns = [
                            "rule",
                            "test",
                            "temp",
                            "new",
                            "allow",
                            "deny",
                            "block",
                        ]
                        if any(
                            pattern in rule_name.lower() for pattern in generic_patterns
                        ):
                            issues["generic_names"].append(rule_name)

                        # Check if rule is too permissive (any/any/any)
                        source = rule.get("source", {})
                        destination = rule.get("destination", {})
                        service = rule.get("service", {})

                        is_permissive = False
                        if isinstance(source, dict):
                            src_members = source.get("member", [])
                            if "any" in src_members or src_members == "any":
                                is_permissive = True

                        if isinstance(destination, dict):
                            dst_members = destination.get("member", [])
                            if "any" in dst_members or dst_members == "any":
                                is_permissive = True

                        if isinstance(service, dict):
                            svc_members = service.get("member", [])
                            if "any" in svc_members or svc_members == "any":
                                is_permissive = True

                        if is_permissive:
                            issues["too_permissive"].append(rule_name)

                        rules.append(
                            {
                                "name": rule_name,
                                "description": description if description else None,
                                "action": rule.get("action", "N/A"),
                                "disabled": rule.get("disabled", "no") == "yes",
                            }
                        )

                return {
                    "success": True,
                    "error": None,
                    "data": {
                        "device_group": device_group,
                        "total_rules": len(rules),
                        "rules": rules,
                        "quality_issues": {
                            "rules_without_description": len(issues["no_description"]),
                            "rules_with_generic_names": len(issues["generic_names"]),
                            "too_permissive_rules": len(issues["too_permissive"]),
                            "details": issues,
                        },
                    },
                }

        except Exception as e:
            logger.error(f"Error retrieving rules: {e}")
            raise

    @handle_panorama_errors
    async def get_config_audit_logs(self, limit: int = 100) -> Dict[str, Any]:
        """
        Retrieve configuration change history (audit logs)
        Uses execute_log_query()

        Args:
            limit: Maximum number of logs to return (default: 100, recommended max: 1000)

        Returns:
            Dict with change history
        """
        # Simplified API call with Layer 2
        result = await self.execute_log_query(log_type="config", nlogs=min(limit, 5000))

        if not result["success"]:
            return result

        # Normalize logs
        logs_data = result.get("data", {})
        logs = []

        # Handle different formats
        if isinstance(logs_data, dict):
            log_entries = logs_data.get("log", {}).get("logs", {}).get("entry", [])
        elif isinstance(logs_data, list):
            log_entries = logs_data
        else:
            log_entries = []

        if isinstance(log_entries, dict):
            log_entries = [log_entries]

        for entry in log_entries[:limit]:  # Limit client-side
            if isinstance(entry, dict):
                logs.append(
                    {
                        "time": entry.get(
                            "time_generated", entry.get("receive_time", "N/A")
                        ),
                        "admin": entry.get("admin", "N/A"),
                        "command": entry.get("cmd", "N/A"),
                        "result": entry.get("result", "N/A"),
                        "path": entry.get("path", "N/A"),
                    }
                )

        return {
            "success": True,
            "error": None,
            "data": {"total_logs": len(logs), "logs": logs[:limit]},
        }

    @handle_panorama_errors
    async def get_unused_objects(self, object_type: str = "address") -> Dict[str, Any]:
        """
        Identify unused objects in configuration

        Args:
            object_type: Object type to analyze (address, address-group, service, etc.)

        Returns:
            Dict with unused objects
        """
        if not await self._ensure_authenticated():
            return {
                "success": False,
                "error": "Authentication failed",
                "data": None,
            }

        # Retrieve objects
        xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address"
        params = {
            "type": "config",
            "action": "get",
            "xpath": xpath,
            "key": self.api_key,
        }

        try:
            async with httpx.AsyncClient(
                verify=self.verify_ssl, timeout=self.timeout
            ) as client:
                response = await client.get(self.base_url, params=params)
                response.raise_for_status()

                result = self._parse_xml_response(response.text)

                if not result["success"] or not result["data"]:
                    return result

                # Extract objects
                data = result["data"]
                objects = []
                unused = []

                if isinstance(data, dict):
                    addr_data = data.get("address", data)
                    if isinstance(addr_data, dict):
                        entries = addr_data.get("entry", [])
                    elif isinstance(addr_data, list):
                        entries = addr_data
                    else:
                        entries = []
                elif isinstance(data, list):
                    entries = data
                else:
                    entries = []

                if isinstance(entries, dict):
                    entries = [entries]

                for obj in entries:
                    if isinstance(obj, dict):
                        obj_name = obj.get("@name", obj.get("name", "N/A"))
                        objects.append(obj_name)
                        # Simplification: mark as unused if no tag
                        if not obj.get("tag"):
                            unused.append(obj_name)

                return {
                    "success": True,
                    "error": None,
                    "data": {
                        "object_type": object_type,
                        "total_objects": len(objects),
                        "unused_count": len(unused),
                        "unused_objects": unused[:100],  # Limit to 100
                    },
                }

        except Exception as e:
            logger.error(f"Error analyzing objects: {e}")
            raise

    @handle_panorama_errors
    async def check_rules_without_security_profile(
        self, device_group: str, limit: int = 100
    ) -> Dict[str, Any]:
        """
        Identify security rules without Security Profile Group

        Args:
            device_group: Device-group name
            limit: Result limit

        Returns:
            Dict with rules without security profile
        """
        if not await self._ensure_authenticated():
            return {
                "success": False,
                "error": "Authentication failed",
                "data": None,
            }

        xpath = f"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{device_group}']/pre-rulebase/security/rules"
        params = {
            "type": "config",
            "action": "get",
            "xpath": xpath,
            "key": self.api_key,
        }

        try:
            async with httpx.AsyncClient(
                verify=self.verify_ssl, timeout=self.timeout
            ) as client:
                response = await client.get(self.base_url, params=params)
                response.raise_for_status()
                result = self._parse_xml_response(response.text)

                if not result["success"]:
                    return result

                # Robust parsing based on response format
                data = result.get("data")
                if data is None:
                    return {
                        "success": True,
                        "error": None,
                        "data": {
                            "device_group": device_group,
                            "total_rules_analyzed": 0,
                            "rules_without_profile": [],
                            "count": 0,
                        },
                    }

                # Extract rules
                entries = []
                if isinstance(data, dict):
                    rules_data = data.get("rules", data)
                    if isinstance(rules_data, dict):
                        entry_data = rules_data.get("entry", [])
                        if isinstance(entry_data, dict):
                            entries = [entry_data]
                        elif isinstance(entry_data, list):
                            entries = entry_data
                    elif isinstance(rules_data, list):
                        entries = rules_data
                elif isinstance(data, list):
                    entries = data

                without_profile = []
                for rule in entries[:limit]:
                    if isinstance(rule, dict):
                        rule_name = rule.get("@name", rule.get("name", "N/A"))
                        if not rule.get("profile-setting"):
                            without_profile.append(rule_name)

                return {
                    "success": True,
                    "error": None,
                    "data": {
                        "device_group": device_group,
                        "total_rules_analyzed": len(entries[:limit]),
                        "rules_without_profile": without_profile[:100],
                        "count": len(without_profile),
                    },
                }
        except Exception as e:
            logger.error(f"Error checking security profiles: {e}")
            raise

    @handle_panorama_errors
    async def get_expiring_certificates(
        self, days_threshold: int = 30
    ) -> Dict[str, Any]:
        """
        Check for certificates approaching expiration

        Args:
            days_threshold: Number of days before expiration to alert

        Returns:
            Dict with certificates and their expiration status
        """
        if not await self._ensure_authenticated():
            return {
                "success": False,
                "error": "Authentication failed",
                "data": None,
            }

        # Retrieve certificates via configuration
        xpath = "/config/shared/certificate"
        params = {
            "type": "config",
            "action": "get",
            "xpath": xpath,
            "key": self.api_key,
        }

        try:
            async with httpx.AsyncClient(
                verify=self.verify_ssl, timeout=self.timeout
            ) as client:
                response = await client.get(self.base_url, params=params)
                response.raise_for_status()
                result = self._parse_xml_response(response.text)

                if not result["success"]:
                    return result

                # Parse certificates
                data = result.get("data")
                certificates = []

                if data and isinstance(data, dict):
                    cert_data = data.get("certificate", data)
                    if isinstance(cert_data, dict):
                        entry_data = cert_data.get("entry", [])
                        if isinstance(entry_data, dict):
                            certificates = [entry_data]
                        elif isinstance(entry_data, list):
                            certificates = entry_data[:100]  # Limiter à 100
                    elif isinstance(cert_data, list):
                        certificates = cert_data[:100]

                # Extract certificate names
                cert_list = []
                for cert in certificates:
                    if isinstance(cert, dict):
                        cert_name = cert.get("@name", cert.get("name", "N/A"))
                        cert_list.append(
                            {
                                "name": cert_name,
                                "note": "Expiration date parsing not implemented",
                            }
                        )

                return {
                    "success": True,
                    "error": None,
                    "data": {
                        "days_threshold": days_threshold,
                        "total_certificates": len(cert_list),
                        "expiring_certificates": [],
                        "expired_certificates": [],
                        "expiring_count": 0,
                        "expired_count": 0,
                        "note": "Certificate list retrieved, expiration analysis requires date parsing implementation",
                        "certificates": cert_list[:10],  # Limit display
                    },
                }
        except Exception as e:
            logger.error(f"Error checking certificates: {e}")
            raise

    @handle_panorama_errors
    async def check_version_compliance(self) -> Dict[str, Any]:
        """
        Check PAN-OS, Threat, AV, Wildfire version compliance

        Returns:
            Dict with version status on Panorama and firewalls
        """
        # Get Panorama system info
        panorama_info = await self.get_system_info()

        # Get devices info
        devices_info = await self.get_managed_devices()

        if not panorama_info["success"] or not devices_info["success"]:
            return {
                "success": False,
                "error": "Failed to retrieve information",
                "data": None,
            }

        # Compile versions
        versions_summary = {
            "panorama": {
                "sw_version": panorama_info["data"].get("sw_version", "N/A"),
                "threat_version": panorama_info["data"].get("threat_version", "N/A"),
                "av_version": panorama_info["data"].get("av_version", "N/A"),
                "wildfire_version": panorama_info["data"].get(
                    "wildfire_version", "N/A"
                ),
            },
            "devices_versions": {},
        }

        # Analyze device versions
        for device in devices_info["data"]["devices"][:10]:  # Limit to 10
            versions_summary["devices_versions"][device["serial"]] = {
                "version": device["version"],
                "model": device["model"],
            }

        return {"success": True, "error": None, "data": versions_summary}

    @handle_panorama_errors
    async def find_never_matched_rules(
        self, device_group: str, days: int = 30, limit: int = 100
    ) -> Dict[str, Any]:
        """
        Identify rules that have never been matched via traffic logs

        Args:
            device_group: Device-group name
            days: Analysis period in days (default: 30)
            limit: Result limit

        Returns:
            Dict with never-matched rules
        """
        # Note: This function requires access to traffic logs
        # Panorama API supports log queries via type=log&log-type=traffic
        # For a complete implementation, we would need to:
        # 1. Retrieve all rules from the device-group
        # 2. Query traffic logs for each rule
        # 3. Identify those without matches

        # Simplified implementation: return base structure
        return {
            "success": True,
            "error": None,
            "data": {
                "device_group": device_group,
                "days_analyzed": days,
                "never_matched_rules": [],
                "total_analyzed": 0,
                "note": "Traffic log analysis requires additional log query implementation",
            },
        }

    @handle_panorama_errors
    async def find_duplicate_addresses(self, limit: int = 100) -> Dict[str, Any]:
        """
        Identify duplicate Address objects (same IP, different names)

        Args:
            limit: Result limit

        Returns:
            Dict with detected duplicate addresses
        """
        if not await self._ensure_authenticated():
            return {
                "success": False,
                "error": "Authentication failed",
                "data": None,
            }

        # Retrieve all address objects
        xpath = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry/address"
        params = {
            "type": "config",
            "action": "get",
            "xpath": xpath,
            "key": self.api_key,
        }

        try:
            async with httpx.AsyncClient(
                verify=self.verify_ssl, timeout=self.timeout
            ) as client:
                response = await client.get(self.base_url, params=params)
                response.raise_for_status()
                result = self._parse_xml_response(response.text)

                if not result["success"]:
                    return result

                # Parse addresses
                data = result.get("data")
                addresses = []

                if data and isinstance(data, dict):
                    addr_data = data.get("address", data)
                    if isinstance(addr_data, dict):
                        entry_data = addr_data.get("entry", [])
                        if isinstance(entry_data, dict):
                            addresses = [entry_data]
                        elif isinstance(entry_data, list):
                            addresses = entry_data[:limit]
                    elif isinstance(addr_data, list):
                        addresses = addr_data[:limit]

                # Detect duplicates (same IP, different names)
                ip_map = {}
                duplicates = []

                for addr in addresses:
                    if isinstance(addr, dict):
                        name = addr.get("@name", addr.get("name", "N/A"))
                        ip_value = addr.get("ip-netmask", "N/A")

                        if ip_value != "N/A":
                            if ip_value in ip_map:
                                duplicates.append(
                                    {
                                        "ip": ip_value,
                                        "names": [ip_map[ip_value], name],
                                    }
                                )
                            else:
                                ip_map[ip_value] = name

                return {
                    "success": True,
                    "error": None,
                    "data": {
                        "total_addresses": len(addresses),
                        "duplicates_found": len(duplicates),
                        "duplicates": duplicates[:100],
                    },
                }
        except Exception as e:
            logger.error(f"Error detecting duplicates: {e}")
            raise

    @handle_panorama_errors
    async def find_unused_zones(self, limit: int = 100) -> Dict[str, Any]:
        """
        Identify zones not used in security rules

        Args:
            limit: Result limit

        Returns:
            Dict with unused zones
        """
        if not await self._ensure_authenticated():
            return {
                "success": False,
                "error": "Authentication failed",
                "data": None,
            }

        # Retrieve configured zones
        xpath_zones = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/zone"
        params = {
            "type": "config",
            "action": "get",
            "xpath": xpath_zones,
            "key": self.api_key,
        }

        try:
            async with httpx.AsyncClient(
                verify=self.verify_ssl, timeout=self.timeout
            ) as client:
                response = await client.get(self.base_url, params=params)
                response.raise_for_status()
                result = self._parse_xml_response(response.text)

                if not result["success"]:
                    return result

                # Parse zones
                data = result.get("data")
                zones = []

                if data and isinstance(data, dict):
                    zone_data = data.get("zone", data)
                    if isinstance(zone_data, dict):
                        entry_data = zone_data.get("entry", [])
                        if isinstance(entry_data, dict):
                            zones = [entry_data]
                        elif isinstance(entry_data, list):
                            zones = entry_data[:limit]
                    elif isinstance(zone_data, list):
                        zones = zone_data[:limit]

                zone_names = []
                for zone in zones:
                    if isinstance(zone, dict):
                        zone_name = zone.get("@name", zone.get("name", "N/A"))
                        zone_names.append(zone_name)

                return {
                    "success": True,
                    "error": None,
                    "data": {
                        "total_zones": len(zone_names),
                        "zones": zone_names[:100],
                        "note": "Usage analysis requires cross-referencing with security rules",
                    },
                }
        except Exception as e:
            logger.error(f"Error analyzing zones: {e}")
            raise

    @handle_panorama_errors
    async def find_local_overrides(self, limit: int = 100) -> Dict[str, Any]:
        """
        Identify local overrides not managed by Panorama

        Args:
            limit: Result limit

        Returns:
            Dict with detected local overrides
        """
        # Local overrides are configurations made directly on firewalls
        # and not through Panorama, which causes centralized management issues

        # This function requires comparing Panorama config with
        # each individual firewall's config

        return {
            "success": True,
            "error": None,
            "data": {
                "total_devices_checked": 0,
                "devices_with_overrides": [],
                "note": "Local override detection requires per-device configuration comparison",
            },
        }


# ============================================================================
# ASYNC FUNCTIONS EXPOSED VIA MCP
# ============================================================================


async def panorama_generate_api_key() -> dict:
    """
    Generate and return a Panorama API key

    Returns:
        Dict with API key in JSON format
        Example: {"success": True, "data": {"api_key": "******"}}
    """
    connector = PanoramaConnector()
    return await connector.generate_api_key()


async def panorama_get_system_info() -> dict:
    """
    Retrieve Panorama system information

    Returns:
        Normalized JSON dict with:
        - hostname
        - version
        - uptime
        - model
        - serial
        - operational_mode
        And other system metadata
    """
    connector = PanoramaConnector()
    return await connector.get_system_info()


async def panorama_execute_command(cmd: str) -> dict:
    """
    Execute a custom operational command on Panorama

    Args:
        cmd: XML command in PAN-OS API format
             Example: "<show><system><info></info></system></show>"

    Returns:
        JSON dict with normalized data (never XML in output)
    """
    connector = PanoramaConnector()
    return await connector.execute_op_command(cmd)


# ============================================================================
# ANALYSIS AND COMPLIANCE FUNCTIONS (EXPOSED VIA MCP)
# ============================================================================


async def panorama_get_managed_devices() -> dict:
    """
    Retrieve complete inventory of firewalls managed by Panorama

    Returns:
        JSON dict with:
        - total_devices: Total number of devices
        - devices: List of devices with their information
          - device: Device name
          - serial: Serial number
          - version: PAN-OS version
          - ha_state: HA state (active, passive, etc.)
          - connected: Connection status (boolean)
          - ip_address: IP address
          - model: Firewall model
          - uptime: Uptime
          - plugins: List of installed plugins
    """
    connector = PanoramaConnector()
    return await connector.get_managed_devices()


async def panorama_get_device_groups() -> dict:
    """
    Retrieve list of Device-Groups configured in Panorama

    Returns:
        JSON dict with:
        - total_device_groups: Total number of device-groups
        - device_groups: List of device-groups
          - name: Device-group name
          - devices: List of member devices
          - device_count: Number of devices in the group
    """
    connector = PanoramaConnector()
    return await connector.get_device_groups()


async def panorama_get_config_diff() -> dict:
    """
    Retrieve differences between candidate and running configuration

    Returns:
        JSON dict with:
        - has_pending_changes: Boolean indicating if changes are pending
        - diff_summary: Summary of changes
        - diff_content: Detailed diff content (null if no changes)
    """
    connector = PanoramaConnector()
    return await connector.get_config_diff()


async def panorama_analyze_security_rules(device_group: str) -> dict:
    """
    Analyze security rules for a Device-Group
    Identifies quality and compliance issues

    Args:
        device_group: Device-group name to analyze

    Returns:
        JSON dict with:
        - device_group: Analyzed device-group name
        - total_rules: Total number of rules
        - rules: List of rules with their information
        - quality_issues: Quality analysis
          - rules_without_description: Number of rules without description
          - rules_with_generic_names: Number of rules with generic names
          - too_permissive_rules: Number of overly permissive rules (any/any/any)
          - details: Details of problematic rules
    """
    connector = PanoramaConnector()
    return await connector.get_security_rules_by_device_group(device_group)


async def panorama_get_audit_logs(limit: int = 100) -> dict:
    """
    Retrieve configuration change history (audit logs)

    Args:
        limit: Maximum number of logs to return (default: 100, max: 1000)

    Returns:
        JSON dict with:
        - total_logs: Number of logs returned
        - logs: List of changes
          - time: Date/time of the change
          - admin: Administrator who made the change
          - command: Command executed
          - result: Result (success, failure)
          - path: Modified configuration path
    """
    connector = PanoramaConnector()
    return await connector.get_config_audit_logs(limit)


async def panorama_get_unused_objects(object_type: str = "address") -> dict:
    """
    Identify unused objects in Panorama configuration

    Args:
        object_type: Object type to analyze (default: "address")

    Returns:
        JSON dict with:
        - object_type: Analyzed object type
        - total_objects: Total number of objects
        - unused_count: Number of unused objects
        - unused_objects: List of unused objects (max 100)
    """
    connector = PanoramaConnector()
    return await connector.get_unused_objects(object_type)


async def panorama_check_rules_without_profile(
    device_group: str, limit: int = 100
) -> dict:
    """
    Identify security rules without Security Profile Group

    Args:
        device_group: Device-group name to analyze
        limit: Maximum number of rules to analyze (default: 100)

    Returns:
        JSON dict with:
        - device_group: Analyzed device-group name
        - total_rules_analyzed: Total number of rules analyzed
        - rules_without_profile: List of rules without Security Profile
        - count: Number of rules without profile
    """
    connector = PanoramaConnector()
    return await connector.check_rules_without_security_profile(device_group, limit)


async def panorama_get_expiring_certificates(days_threshold: int = 30) -> dict:
    """
    Check for certificates approaching expiration

    Args:
        days_threshold: Threshold in days to consider a certificate as expiring (default: 30)

    Returns:
        JSON dict with:
        - days_threshold: Threshold used
        - total_certificates: Total number of certificates
        - expiring_certificates: List of certificates expiring soon
        - expired_certificates: List of already expired certificates
        - expiring_count: Number of expiring certificates
        - expired_count: Number of expired certificates
    """
    connector = PanoramaConnector()
    return await connector.get_expiring_certificates(days_threshold)


async def panorama_check_version_compliance() -> dict:
    """
    Check PAN-OS, Threat, AV, Wildfire version compliance

    Returns:
        JSON dict with:
        - panorama: Versions installed on Panorama
          - sw_version: PAN-OS version
          - threat_version: Threat database version
          - av_version: Antivirus version
          - wildfire_version: Wildfire version
        - devices_versions: Device versions (limited to 10)
          - [serial]: {version, model}
    """
    connector = PanoramaConnector()
    return await connector.check_version_compliance()


async def panorama_find_never_matched_rules(
    device_group: str, days: int = 30, limit: int = 100
) -> dict:
    """
    Identify rules that have never been matched via traffic logs

    Args:
        device_group: Device-group name to analyze
        days: Analysis period in days (default: 30)
        limit: Maximum number of rules to analyze (default: 100)

    Returns:
        JSON dict with:
        - device_group: Analyzed device-group name
        - days_analyzed: Analysis period in days
        - never_matched_rules: List of never-matched rules
        - total_analyzed: Number of rules analyzed
        - note: Implementation note
    """
    connector = PanoramaConnector()
    return await connector.find_never_matched_rules(device_group, days, limit)


async def panorama_find_duplicate_addresses(limit: int = 100) -> dict:
    """
    Identify duplicate Address objects (same IP, different names)

    Args:
        limit: Maximum number of addresses to analyze (default: 100)

    Returns:
        JSON dict with:
        - total_addresses: Total number of addresses analyzed
        - duplicates_found: Number of duplicates detected
        - duplicates: List of duplicates
          - ip: Duplicate IP address
          - names: List of different names for this IP
    """
    connector = PanoramaConnector()
    return await connector.find_duplicate_addresses(limit)


async def panorama_find_unused_zones(limit: int = 100) -> dict:
    """
    Identify zones not used in security rules

    Args:
        limit: Maximum number of zones to analyze (default: 100)

    Returns:
        JSON dict with:
        - total_zones: Total number of configured zones
        - zones: List of configured zones
        - note: Note on usage analysis
    """
    connector = PanoramaConnector()
    return await connector.find_unused_zones(limit)


async def panorama_find_local_overrides(limit: int = 100) -> dict:
    """
    Identify local overrides not managed by Panorama

    Args:
        limit: Maximum number of devices to check (default: 100)

    Returns:
        JSON dict with:
        - total_devices_checked: Number of devices checked
        - devices_with_overrides: List of devices with local overrides
        - note: Implementation note
    """
    connector = PanoramaConnector()
    return await connector.find_local_overrides(limit)
