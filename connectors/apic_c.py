"""
Cisco APIC (ACI) Asynchronous Connector

This module provides async operations for Cisco APIC using httpx.
Includes JWT token caching and thread-safe authentication.
"""

import asyncio
import ipaddress
import os
import time
from typing import Any, Dict, Optional

import httpx
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# APIC Configuration
APIC_HOST = os.getenv("APIC_HOST")
APIC_USERNAME = os.getenv("APIC_USERNAME")
APIC_PASSWORD = os.getenv("APIC_PASSWORD")
APIC_VERIFY_SSL = os.getenv("APIC_VERIFY_SSL", "false").lower() == "true"
APIC_TIMEOUT = int(os.getenv("APIC_TIMEOUT", "30"))
APIC_TOKEN_CACHE_DURATION = int(os.getenv("APIC_TOKEN_CACHE_DURATION", "3600"))

_token_cache: Dict[str, Any] = {"token": None, "expires_at": 0, "lock": asyncio.Lock()}


def _get_base_url() -> str:
    """
    Build APIC base URL.

    Returns:
        Base URL string (HTTPS)
    """
    return f"https://{APIC_HOST}"


async def _authenticate() -> Optional[str]:
    """
    Authenticate to APIC and retrieve JWT token.

    Returns:
        JWT token or None on error
    """
    if not APIC_HOST or not APIC_USERNAME or not APIC_PASSWORD:
        return None

    auth_payload = {
        "aaaUser": {"attributes": {"name": APIC_USERNAME, "pwd": APIC_PASSWORD}}
    }

    url = f"{_get_base_url()}/api/aaaLogin.json"

    try:
        async with httpx.AsyncClient(
            verify=APIC_VERIFY_SSL, timeout=APIC_TIMEOUT
        ) as client:
            response = await client.post(url, json=auth_payload)
            response.raise_for_status()

            result = response.json()

            # Extract token from response
            if "imdata" in result and len(result["imdata"]) > 0:
                login_data = result["imdata"][0]
                if "aaaLogin" in login_data and "attributes" in login_data["aaaLogin"]:
                    return login_data["aaaLogin"]["attributes"].get("token")

            return None

    except Exception as e:
        print(f"APIC authentication error: {e}")
        return None


async def _get_token() -> Optional[str]:
    """
    Get valid JWT token with async-safe cache management.

    Returns:
        Valid JWT token or None on error
    """
    async with _token_cache["lock"]:
        current_time = time.time()

        # Check if cached token is still valid
        if _token_cache["token"] and current_time < _token_cache["expires_at"]:
            return _token_cache["token"]

        # Authenticate if token expired or missing
        token = await _authenticate()
        if token:
            _token_cache["token"] = token
            _token_cache["expires_at"] = (
                current_time + APIC_TOKEN_CACHE_DURATION - 60
            )  # 60s safety margin
            return token

        return None


async def _apic_request(
    endpoint: str,
    method: str = "GET",
    params: Optional[Dict] = None,
    json_data: Optional[Dict] = None,
) -> Dict[str, Any]:
    """
    Perform APIC API request with JWT token management.

    Args:
        endpoint: API endpoint (e.g., 'api/node/class/fabricNode.json')
        method: HTTP method (GET, POST, etc.)
        params: Optional query parameters
        json_data: Optional JSON body for POST/PUT

    Returns:
        Response JSON dict or error dict
    """
    token = await _get_token()
    if not token:
        return {"error": "Unable to obtain APIC authentication token"}

    url = f"{_get_base_url()}/{endpoint.lstrip('/')}"

    headers = {
        "Cookie": f"APIC-cookie={token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    try:
        async with httpx.AsyncClient(
            verify=APIC_VERIFY_SSL, timeout=APIC_TIMEOUT
        ) as client:
            response = await client.request(
                method=method, url=url, headers=headers, params=params, json=json_data
            )
            response.raise_for_status()
            return response.json()

    except httpx.HTTPStatusError as e:
        error_msg = f"HTTP error {e.response.status_code}: {e.response.reason_phrase}"
        try:
            error_data = e.response.json()
            if "imdata" in error_data and len(error_data["imdata"]) > 0:
                error_info = error_data["imdata"][0]
                if "error" in error_info:
                    error_text = (
                        error_info["error"].get("attributes", {}).get("text", "")
                    )
                    if error_text:
                        error_msg += f" - {error_text}"
        except Exception:
            pass
        return {"error": error_msg}

    except Exception as e:
        return {"error": f"APIC connection error: {str(e)}"}


# ========== PUBLIC API FUNCTIONS ==========


async def test_connection() -> Dict[str, Any]:
    """
    Test APIC API connection.

    Returns:
        Connection test result dict
    """
    token = await _get_token()
    if token:
        # Test with simple query
        result = await _apic_request(
            "api/node/class/topSystem.json",
            params={"query-target-filter": 'eq(topSystem.role,"controller")'},
        )
        if "error" not in result:
            return {
                "status": "success",
                "message": "APIC connection established successfully",
                "host": APIC_HOST,
                "token_cached": bool(_token_cache["token"]),
            }
        else:
            return {
                "status": "error",
                "message": f"Connection established but API error: {result['error']}",
                "host": APIC_HOST,
            }
    else:
        return {
            "status": "error",
            "message": "Unable to authenticate to APIC",
            "host": APIC_HOST,
        }


async def get_fabric_health() -> Dict[str, Any]:
    """
    Retrieve ACI fabric overall health status.

    Returns:
        Fabric health summary with critical faults and controller status
    """
    # Fetch critical faults
    faults_result = await _apic_request(
        "api/node/class/faultInst.json",
        params={
            "query-target-filter": 'eq(faultInst.severity,"critical")',
            "order-by": "faultInst.created|desc",
        },
    )

    if "error" in faults_result:
        return faults_result

    critical_faults = faults_result.get("imdata", [])

    # Fetch controller status
    controllers_result = await _apic_request(
        "api/node/class/topSystem.json",
        params={"query-target-filter": 'eq(topSystem.role,"controller")'},
    )

    controllers = (
        controllers_result.get("imdata", [])
        if "error" not in controllers_result
        else []
    )

    # Analyze overall health
    health_status = "healthy" if len(critical_faults) == 0 else "critical"

    controllers_online = sum(
        1
        for c in controllers
        if c.get("topSystem", {}).get("attributes", {}).get("state") == "in-service"
    )

    return {
        "overall_health": health_status,
        "critical_faults_count": len(critical_faults),
        "controllers_count": len(controllers),
        "controllers_online": controllers_online,
        "critical_faults": [
            {
                "dn": fault.get("faultInst", {}).get("attributes", {}).get("dn", ""),
                "description": fault.get("faultInst", {})
                .get("attributes", {})
                .get("descr", ""),
                "severity": fault.get("faultInst", {})
                .get("attributes", {})
                .get("severity", ""),
                "created": fault.get("faultInst", {})
                .get("attributes", {})
                .get("created", ""),
            }
            for fault in critical_faults[:5]  # Limit to 5 most recent faults
        ],
    }


async def get_apic_tenants() -> Dict[str, Any]:
    """
    List all tenants configured on the APIC.

    Returns:
        Dict with tenants list including name, DN, description, and status
    """
    result = await _apic_request("api/node/class/fvTenant.json")

    if "error" in result:
        return result

    tenants = []
    for item in result.get("imdata", []):
        tenant_data = item.get("fvTenant", {}).get("attributes", {})
        tenants.append({
            "name": tenant_data.get("name", ""),
            "dn": tenant_data.get("dn", ""),
            "description": tenant_data.get("descr", ""),
            "status": tenant_data.get("status", "")
        })

    return {
        "total_tenants": len(tenants),
        "tenants": sorted(tenants, key=lambda x: x["name"])
    }


async def get_apic_faults() -> Dict[str, Any]:
    """
    Retrieve active faults from the APIC system.

    Returns:
        Dict with active faults and severity breakdown
    """
    result = await _apic_request("api/node/class/faultInst.json", params={
        "order-by": "faultInst.severity|desc,faultInst.created|desc",
        "page-size": "50"
    })

    if "error" in result:
        return result

    faults = []
    severity_count = {"critical": 0, "major": 0, "minor": 0, "warning": 0, "info": 0}

    for item in result.get("imdata", []):
        fault_data = item.get("faultInst", {}).get("attributes", {})
        severity = fault_data.get("severity", "info")

        faults.append({
            "dn": fault_data.get("dn", ""),
            "code": fault_data.get("code", ""),
            "description": fault_data.get("descr", ""),
            "severity": severity,
            "created": fault_data.get("created", ""),
            "last_transition": fault_data.get("lastTransition", ""),
            "cause": fault_data.get("cause", ""),
            "type": fault_data.get("type", "")
        })

        if severity in severity_count:
            severity_count[severity] += 1

    return {
        "total_faults": len(faults),
        "severity_breakdown": severity_count,
        "faults": faults
    }


async def get_apic_nodes_inventory() -> Dict[str, Any]:
    """
    Retrieve fabric nodes inventory.

    Returns:
        Dict with nodes inventory including controllers, leafs, and spines
    """
    result = await _apic_request("api/node/class/fabricNode.json")

    if "error" in result:
        return result

    nodes = []
    role_count = {"controller": 0, "leaf": 0, "spine": 0, "unknown": 0}

    for item in result.get("imdata", []):
        node_data = item.get("fabricNode", {}).get("attributes", {})
        role = node_data.get("role", "unknown")

        nodes.append({
            "id": node_data.get("id", ""),
            "name": node_data.get("name", ""),
            "serial": node_data.get("serial", ""),
            "model": node_data.get("model", ""),
            "role": role,
            "version": node_data.get("version", ""),
            "address": node_data.get("address", ""),
            "fabric_st": node_data.get("fabricSt", "")
        })

        if role in role_count:
            role_count[role] += 1
        else:
            role_count["unknown"] += 1

    return {
        "total_nodes": len(nodes),
        "role_breakdown": role_count,
        "nodes": sorted(nodes, key=lambda x: int(x["id"]) if x["id"].isdigit() else 0)
    }


async def get_apic_epgs(tenant: Optional[str] = None) -> Dict[str, Any]:
    """
    Retrieve Endpoint Groups (EPGs) from a tenant or all tenants.

    Args:
        tenant: Tenant name (optional, all if not specified)

    Returns:
        Dict with EPGs list
    """
    if tenant:
        endpoint = f"api/node/mo/uni/tn-{tenant}.json"
        params = {
            "query-target": "subtree",
            "target-subtree-class": "fvAEPg"
        }
    else:
        endpoint = "api/node/class/fvAEPg.json"
        params = {}

    result = await _apic_request(endpoint, params=params)

    if "error" in result:
        return result

    epgs = []
    for item in result.get("imdata", []):
        epg_data = item.get("fvAEPg", {}).get("attributes", {})
        dn = epg_data.get("dn", "")

        # Extract tenant and application from DN
        dn_parts = dn.split("/")
        tenant_name = ""
        app_name = ""

        for part in dn_parts:
            if part.startswith("tn-"):
                tenant_name = part[3:]
            elif part.startswith("ap-"):
                app_name = part[3:]

        epgs.append({
            "name": epg_data.get("name", ""),
            "dn": dn,
            "tenant": tenant_name,
            "application": app_name,
            "description": epg_data.get("descr", ""),
            "pc_enfp_ref": epg_data.get("pcEnfPref", ""),
            "prio": epg_data.get("prio", ""),
            "scope": epg_data.get("scope", "")
        })

    return {
        "total_epgs": len(epgs),
        "tenant_filter": tenant,
        "epgs": sorted(epgs, key=lambda x: (x["tenant"], x["application"], x["name"]))
    }


async def get_apic_vrfs(tenant: Optional[str] = None) -> Dict[str, Any]:
    """
    Retrieve VRFs (Virtual Routing and Forwarding) from a tenant or all tenants.

    Args:
        tenant: Tenant name (optional)

    Returns:
        Dict with VRFs list
    """
    if tenant:
        result = await _apic_request(f"api/node/mo/uni/tn-{tenant}.json", params={
            "query-target": "children",
            "target-subtree-class": "fvCtx"
        })
    else:
        result = await _apic_request("api/node/class/fvCtx.json")

    if "error" in result:
        return result

    vrfs = []
    for item in result.get("imdata", []):
        vrf_data = item.get("fvCtx", {}).get("attributes", {})
        dn = vrf_data.get("dn", "")

        # Extract tenant from DN
        tenant_name = ""
        dn_parts = dn.split("/")
        for part in dn_parts:
            if part.startswith("tn-"):
                tenant_name = part[3:]
                break

        vrfs.append({
            "name": vrf_data.get("name", ""),
            "dn": dn,
            "tenant": tenant_name,
            "description": vrf_data.get("descr", ""),
            "policy_control_enforcement": vrf_data.get("pcEnfPref", ""),
            "policy_control_direction": vrf_data.get("pcEnfDir", "")
        })

    return {
        "total_vrfs": len(vrfs),
        "tenant_filter": tenant,
        "vrfs": sorted(vrfs, key=lambda x: (x["tenant"], x["name"]))
    }


async def get_apic_contracts(tenant: Optional[str] = None) -> Dict[str, Any]:
    """
    Retrieve security contracts from a tenant or all tenants.

    Args:
        tenant: Tenant name (optional)

    Returns:
        Dict with contracts list
    """
    if tenant:
        endpoint = f"api/node/mo/uni/tn-{tenant}.json"
        params = {
            "query-target": "subtree",
            "target-subtree-class": "vzBrCP"
        }
    else:
        endpoint = "api/node/class/vzBrCP.json"
        params = {}

    result = await _apic_request(endpoint, params=params)

    if "error" in result:
        return result

    contracts = []
    for item in result.get("imdata", []):
        contract_data = item.get("vzBrCP", {}).get("attributes", {})
        dn = contract_data.get("dn", "")

        # Extract tenant from DN
        tenant_name = ""
        dn_parts = dn.split("/")
        for part in dn_parts:
            if part.startswith("tn-"):
                tenant_name = part[3:]
                break

        contracts.append({
            "name": contract_data.get("name", ""),
            "dn": dn,
            "tenant": tenant_name,
            "description": contract_data.get("descr", ""),
            "scope": contract_data.get("scope", ""),
            "prio": contract_data.get("prio", ""),
            "target_dscp": contract_data.get("targetDscp", "")
        })

    return {
        "total_contracts": len(contracts),
        "tenant_filter": tenant,
        "contracts": sorted(contracts, key=lambda x: (x["tenant"], x["name"]))
    }


async def get_apic_events(time_range: int = 24) -> Dict[str, Any]:
    """
    Retrieve recent events from the APIC event log.

    Args:
        time_range: Time range in hours (default: 24h)

    Returns:
        Dict with recent events
    """
    import datetime

    end_time = datetime.datetime.now()
    start_time = end_time - datetime.timedelta(hours=time_range)
    start_ts = start_time.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")

    result = await _apic_request("api/node/class/eventRecord.json", params={
        "query-target-filter": f'gt(eventRecord.created,"{start_ts}")',
        "order-by": "eventRecord.created|desc",
        "page-size": "100"
    })

    if "error" in result:
        return result

    events = []
    severity_count = {"critical": 0, "major": 0, "minor": 0, "warning": 0, "info": 0}

    for item in result.get("imdata", []):
        event_data = item.get("eventRecord", {}).get("attributes", {})
        severity = event_data.get("severity", "info")

        events.append({
            "id": event_data.get("id", ""),
            "dn": event_data.get("dn", ""),
            "code": event_data.get("code", ""),
            "description": event_data.get("descr", ""),
            "severity": severity,
            "created": event_data.get("created", ""),
            "cause": event_data.get("cause", ""),
            "change_set": event_data.get("changeSet", ""),
            "user": event_data.get("user", "")
        })

        if severity in severity_count:
            severity_count[severity] += 1

    return {
        "time_range_hours": time_range,
        "total_events": len(events),
        "severity_breakdown": severity_count,
        "events": events
    }


async def get_apic_cpu_utilization() -> Dict[str, Any]:
    """
    Retrieve CPU utilization for all fabric nodes.

    Returns:
        Dict with CPU utilization per node
    """
    result = await _apic_request("api/node/class/procSysCPU5min.json", params={
        "order-by": "procSysCPU5min.dn"
    })

    if "error" in result:
        return result

    cpu_data = []
    for item in result.get("imdata", []):
        cpu_info = item.get("procSysCPU5min", {}).get("attributes", {})
        dn = cpu_info.get("dn", "")

        # Extract node ID from DN
        node_id = ""
        if "/sys/procsys/CDprocSysCPU5min" in dn:
            node_part = dn.split("/node-")[1].split("/")[0] if "/node-" in dn else ""
            node_id = node_part

        cpu_data.append({
            "node_id": node_id,
            "dn": dn,
            "user_avg": float(cpu_info.get("userAvg", 0)),
            "kernel_avg": float(cpu_info.get("kernelAvg", 0)),
            "idle_avg": float(cpu_info.get("idleAvg", 0)),
            "wait_avg": float(cpu_info.get("waitAvg", 0)),
            "total_usage": round(100 - float(cpu_info.get("idleAvg", 100)), 2),
            "last_update": cpu_info.get("lastCollOffset", "")
        })

    # Calculate global averages
    if cpu_data:
        avg_total = sum(item["total_usage"] for item in cpu_data) / len(cpu_data)
        max_usage = max(item["total_usage"] for item in cpu_data)
        min_usage = min(item["total_usage"] for item in cpu_data)
    else:
        avg_total = max_usage = min_usage = 0

    return {
        "total_nodes": len(cpu_data),
        "average_cpu_usage": round(avg_total, 2),
        "max_cpu_usage": max_usage,
        "min_cpu_usage": min_usage,
        "nodes": sorted(cpu_data, key=lambda x: x.get("node_id", ""))
    }


async def get_apic_audit_logs(hours: int = 24) -> Dict[str, Any]:
    """
    Retrieve audit logs of configuration changes.

    Args:
        hours: Number of hours back (default: 24h)

    Returns:
        Dict with audit logs
    """
    import datetime

    end_time = datetime.datetime.now()
    start_time = end_time - datetime.timedelta(hours=hours)
    start_ts = start_time.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")

    result = await _apic_request("api/node/class/aaaModLR.json", params={
        "query-target-filter": f'gt(aaaModLR.created,"{start_ts}")',
        "order-by": "aaaModLR.created|desc",
        "page-size": "50"
    })

    if "error" in result:
        return result

    audit_entries = []
    user_activity = {}

    for item in result.get("imdata", []):
        audit_data = item.get("aaaModLR", {}).get("attributes", {})
        user = audit_data.get("user", "system")

        audit_entries.append({
            "user": user,
            "session": audit_data.get("sess", ""),
            "dn": audit_data.get("dn", ""),
            "affected_dn": audit_data.get("affectedDN", ""),
            "change_set": audit_data.get("changeSet", ""),
            "trigger": audit_data.get("trigger", ""),
            "created": audit_data.get("created", ""),
            "txid": audit_data.get("txId", "")
        })

        # Count activity per user
        user_activity[user] = user_activity.get(user, 0) + 1

    return {
        "time_range_hours": hours,
        "total_changes": len(audit_entries),
        "unique_users": len(user_activity),
        "user_activity": dict(sorted(user_activity.items(), key=lambda x: x[1], reverse=True)),
        "audit_logs": audit_entries
    }


async def get_apic_epg_endpoints(tenant: str, application: str, epg: str) -> Dict[str, Any]:
    """
    Retrieve endpoints from a specific EPG.

    Args:
        tenant: Tenant name
        application: Application name
        epg: EPG name

    Returns:
        Dict with EPG endpoints
    """
    endpoint = f"api/node/mo/uni/tn-{tenant}/ap-{application}/epg-{epg}.json"
    params = {
        "query-target": "subtree",
        "target-subtree-class": "fvCEp"
    }

    result = await _apic_request(endpoint, params=params)

    if "error" in result:
        return result

    endpoints = []
    for item in result.get("imdata", []):
        ep_data = item.get("fvCEp", {}).get("attributes", {})
        endpoints.append({
            "name": ep_data.get("name", ""),
            "dn": ep_data.get("dn", ""),
            "mac": ep_data.get("mac", ""),
            "ip": ep_data.get("ip", ""),
            "encap": ep_data.get("encap", ""),
            "lcown": ep_data.get("lcOwn", ""),
            "type": ep_data.get("type", ""),
            "uuid": ep_data.get("uuid", "")
        })

    return {
        "tenant": tenant,
        "application": application,
        "epg": epg,
        "total_endpoints": len(endpoints),
        "endpoints": endpoints
    }


async def get_apic_fabric_topology() -> Dict[str, Any]:
    """
    Retrieve ACI fabric topology.

    Returns:
        Dict with fabric topology including nodes and links
    """
    # Retrieve nodes
    nodes_result = await _apic_request("api/node/class/fabricNode.json")
    if "error" in nodes_result:
        return nodes_result

    # Retrieve links
    links_result = await _apic_request("api/node/class/fabricLink.json")

    nodes = []
    for item in nodes_result.get("imdata", []):
        node_data = item.get("fabricNode", {}).get("attributes", {})
        nodes.append({
            "id": node_data.get("id", ""),
            "name": node_data.get("name", ""),
            "role": node_data.get("role", ""),
            "model": node_data.get("model", ""),
            "serial": node_data.get("serial", ""),
            "address": node_data.get("address", ""),
            "fabric_st": node_data.get("fabricSt", "")
        })

    links = []
    if "error" not in links_result:
        for item in links_result.get("imdata", []):
            link_data = item.get("fabricLink", {}).get("attributes", {})
            links.append({
                "dn": link_data.get("dn", ""),
                "n1": link_data.get("n1", ""),
                "n2": link_data.get("n2", ""),
                "s1": link_data.get("s1", ""),
                "s2": link_data.get("s2", ""),
                "status": link_data.get("status", "")
            })

    return {
        "total_nodes": len(nodes),
        "total_links": len(links),
        "nodes": nodes,
        "links": links
    }


async def get_apic_endpoint_tracker(mac_or_ip: str) -> Dict[str, Any]:
    """
    Track a specific endpoint by MAC or IP address.

    Args:
        mac_or_ip: MAC or IP address of the endpoint

    Returns:
        Dict with endpoint tracking information
    """
    # Determine if it's a MAC or IP
    is_mac = ":" in mac_or_ip or "-" in mac_or_ip

    if is_mac:
        # Normalize MAC address (APIC format: XX:XX:XX:XX:XX:XX)
        mac_clean = mac_or_ip.replace("-", ":").upper()
        filter_query = f'eq(fvCEp.mac,"{mac_clean}")'
    else:
        # Search by IP
        filter_query = f'eq(fvCEp.ip,"{mac_or_ip}")'

    result = await _apic_request("api/node/class/fvCEp.json", params={
        "query-target-filter": filter_query
    })

    if "error" in result:
        return result

    endpoints = []
    for item in result.get("imdata", []):
        ep_data = item.get("fvCEp", {}).get("attributes", {})
        dn = ep_data.get("dn", "")

        # Extract tenant, app, epg from DN
        tenant = app = epg = ""
        dn_parts = dn.split("/")
        for part in dn_parts:
            if part.startswith("tn-"):
                tenant = part[3:]
            elif part.startswith("ap-"):
                app = part[3:]
            elif part.startswith("epg-"):
                epg = part[3:]

        endpoints.append({
            "name": ep_data.get("name", ""),
            "mac": ep_data.get("mac", ""),
            "ip": ep_data.get("ip", ""),
            "tenant": tenant,
            "application": app,
            "epg": epg,
            "encap": ep_data.get("encap", ""),
            "type": ep_data.get("type", ""),
            "uuid": ep_data.get("uuid", ""),
            "lcown": ep_data.get("lcOwn", ""),
            "dn": dn
        })

    return {
        "search_criteria": mac_or_ip,
        "search_type": "MAC" if is_mac else "IP",
        "endpoints_found": len(endpoints),
        "endpoints": endpoints
    }


async def search_apic_by_ip(ip_address: str) -> Dict[str, Any]:
    """
    Search APIC objects by IP address.

    Args:
        ip_address: IP address to search

    Returns:
        Dict with search results including endpoints and subnets
    """
    results = {
        "ip_searched": ip_address,
        "endpoints": [],
        "subnets": []
    }

    # Search endpoints with this IP
    endpoints_result = await _apic_request("api/node/class/fvCEp.json", params={
        "query-target-filter": f'eq(fvCEp.ip,"{ip_address}")'
    })

    if "error" not in endpoints_result:
        for item in endpoints_result.get("imdata", []):
            ep_data = item.get("fvCEp", {}).get("attributes", {})
            dn = ep_data.get("dn", "")

            # Extract tenant, app, epg from DN
            tenant = app = epg = ""
            dn_parts = dn.split("/")
            for part in dn_parts:
                if part.startswith("tn-"):
                    tenant = part[3:]
                elif part.startswith("ap-"):
                    app = part[3:]
                elif part.startswith("epg-"):
                    epg = part[3:]

            results["endpoints"].append({
                "name": ep_data.get("name", ""),
                "mac": ep_data.get("mac", ""),
                "tenant": tenant,
                "application": app,
                "epg": epg,
                "encap": ep_data.get("encap", ""),
                "dn": dn
            })

    # Search subnets containing this IP
    subnets_result = await _apic_request("api/node/class/fvSubnet.json", params={
        "query-target-filter": f'wcard(fvSubnet.ip,"{ip_address.split(".")[0]}.{ip_address.split(".")[1]}")'
    })

    if "error" not in subnets_result:
        for item in subnets_result.get("imdata", []):
            subnet_data = item.get("fvSubnet", {}).get("attributes", {})
            subnet_ip = subnet_data.get("ip", "")

            # Check if IP is in this subnet
            try:
                subnet_net = ipaddress.ip_network(subnet_ip, strict=False)
                search_ip = ipaddress.ip_address(ip_address)
                if search_ip in subnet_net:
                    dn = subnet_data.get("dn", "")

                    # Extract tenant and BD from DN
                    tenant = bd = ""
                    dn_parts = dn.split("/")
                    for part in dn_parts:
                        if part.startswith("tn-"):
                            tenant = part[3:]
                        elif part.startswith("BD-"):
                            bd = part[3:]

                    results["subnets"].append({
                        "subnet": subnet_ip,
                        "tenant": tenant,
                        "bridge_domain": bd,
                        "scope": subnet_data.get("scope", ""),
                        "description": subnet_data.get("descr", ""),
                        "dn": dn
                    })
            except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError):
                pass

    return results


async def get_apic_bridge_domains_multicast() -> Dict[str, Any]:
    """
    Retrieve multicast information for bridge domains (fvBD) with
    GIPo multicast addresses (bcastP) and multicast configuration.

    Returns:
        Dict with multicast information for bridge domains including bcastP
    """
    # Retrieve bridge domains with full multicast attributes
    result = await _apic_request("api/node/class/fvBD.json", params={
        "rsp-subtree": "full",
        "rsp-subtree-include": "required"
    })

    if "error" in result:
        return result

    bridge_domains = []
    multicast_enabled_count = 0
    igmp_enabled_count = 0
    pim_enabled_count = 0

    for item in result.get("imdata", []):
        bd_data = item.get("fvBD", {}).get("attributes", {})
        dn = bd_data.get("dn", "")

        # Extract tenant from DN
        tenant_name = ""
        dn_parts = dn.split("/")
        for part in dn_parts:
            if part.startswith("tn-"):
                tenant_name = part[3:]
                break

        # Basic bridge domain information with GIPo
        gipo_address = bd_data.get("bcastP", "")

        bd_info = {
            "name": bd_data.get("name", ""),
            "dn": dn,
            "tenant": tenant_name,
            "description": bd_data.get("descr", ""),
            "gipo_multicast_address": gipo_address,  # GIPo multicast address (/28)
            "multicast_allow": bd_data.get("multiDstPktAct", "bd-flood"),
            "unk_mac_ucast_act": bd_data.get("unkMacUcastAct", "proxy"),
            "unk_mcast_act": bd_data.get("unkMcastAct", "flood"),
            "ipv6_mcast_allow": bd_data.get("ipv6McastAllow", "no"),
            "ip_learning": bd_data.get("ipLearning", "yes"),
            "limit_ip_learn_to_subnets": bd_data.get("limitIpLearnToSubnets", "yes"),
            "arp_flood": bd_data.get("arpFlood", "no"),
            "ep_move_detect_mode": bd_data.get("epMoveDetectMode", ""),
            "subnets": [],
            "multicast_addresses": [],
            "multicast_enabled": False,
            "gipo_configured": bool(gipo_address.strip())
        }

        # Analyze children (subnets)
        children = item.get("fvBD", {}).get("children", [])
        for child in children:
            # Subnets
            if "fvSubnet" in child:
                subnet_data = child["fvSubnet"]["attributes"]
                bd_info["subnets"].append({
                    "ip": subnet_data.get("ip", ""),
                    "description": subnet_data.get("descr", ""),
                    "scope": subnet_data.get("scope", ""),
                    "virtual": subnet_data.get("virtual", "no"),
                    "preferred": subnet_data.get("preferred", "no")
                })

                # Check if it's a multicast address (224.0.0.0/4 for IPv4)
                ip_addr = subnet_data.get("ip", "").split("/")[0]
                if ip_addr:
                    try:
                        ip_obj = ipaddress.ip_address(ip_addr)
                        if ip_obj.is_multicast:
                            bd_info["multicast_addresses"].append({
                                "address": ip_addr,
                                "subnet": subnet_data.get("ip", ""),
                                "description": subnet_data.get("descr", ""),
                                "type": "subnet_multicast"
                            })
                    except (ValueError, ipaddress.AddressValueError):
                        pass

        # Add GIPo address as multicast address if it exists
        if gipo_address:
            bd_info["multicast_addresses"].append({
                "address": gipo_address.split("/")[0] if "/" in gipo_address else gipo_address,
                "subnet": gipo_address,
                "description": "GIPo (Group IP Outer) - BUM traffic forwarding",
                "type": "gipo"
            })

        # Determine if multicast is enabled on this BD
        bd_info["multicast_enabled"] = (
            bd_info["multicast_allow"] in ["bd-flood", "encap-flood"] or
            len(bd_info["multicast_addresses"]) > 0 or
            bd_info["unk_mcast_act"] == "flood" or
            bd_info["ipv6_mcast_allow"] == "yes" or
            bd_info["gipo_configured"]
        )

        # Count BDs with multicast enabled
        if bd_info["multicast_enabled"]:
            multicast_enabled_count += 1

        # IGMP snooping enabled by default on ACI
        if bd_info["unk_mcast_act"] == "flood":
            igmp_enabled_count += 1

        bridge_domains.append(bd_info)

    # Also retrieve separately configured multicast groups
    multicast_groups_result = await _apic_request("api/node/class/igmpGroup.json")
    igmp_groups = []
    if "error" not in multicast_groups_result:
        for item in multicast_groups_result.get("imdata", []):
            group_data = item.get("igmpGroup", {}).get("attributes", {})
            igmp_groups.append({
                "group_address": group_data.get("addr", ""),
                "source": group_data.get("src", ""),
                "dn": group_data.get("dn", "")
            })

    # Retrieve static multicast addresses
    static_mcast_result = await _apic_request("api/node/class/igmpStaticGroup.json")
    static_groups = []
    if "error" not in static_mcast_result:
        for item in static_mcast_result.get("imdata", []):
            group_data = item.get("igmpStaticGroup", {}).get("attributes", {})
            static_groups.append({
                "group_address": group_data.get("grpAddr", ""),
                "source": group_data.get("srcAddr", ""),
                "dn": group_data.get("dn", "")
            })

    return {
        "total_bridge_domains": len(bridge_domains),
        "multicast_enabled_domains": multicast_enabled_count,
        "igmp_enabled_domains": igmp_enabled_count,
        "pim_enabled_domains": pim_enabled_count,
        "igmp_groups_learned": len(igmp_groups),
        "static_multicast_groups": len(static_groups),
        "bridge_domains": sorted(bridge_domains, key=lambda x: (x["tenant"], x["name"])),
        "discovered_igmp_groups": igmp_groups[:10],  # Limit to 10 for display
        "configured_static_groups": static_groups
    }


async def get_apic_bridge_domain_multicast_by_tenant(tenant: str) -> Dict[str, Any]:
    """
    Retrieve multicast information for bridge domains of a specific tenant.

    Args:
        tenant: Tenant name

    Returns:
        Dict with multicast information for the tenant's bridge domains
    """
    endpoint = f"api/node/mo/uni/tn-{tenant}.json"
    params = {
        "query-target": "subtree",
        "target-subtree-class": "fvBD",
        "rsp-subtree": "full",
        "rsp-subtree-include": "required"
    }

    result = await _apic_request(endpoint, params=params)

    if "error" in result:
        return result

    bridge_domains = []
    multicast_addresses_total = 0

    for item in result.get("imdata", []):
        if "fvBD" not in item:
            continue

        bd_data = item["fvBD"]["attributes"]
        gipo_address = bd_data.get("bcastP", "")

        bd_info = {
            "name": bd_data.get("name", ""),
            "dn": bd_data.get("dn", ""),
            "tenant": tenant,
            "gipo_multicast_address": gipo_address,
            "multicast_addresses": [],
            "igmp_snooping": bd_data.get("igmpSnoopPol", "") != "",
            "ipv6_multicast": bd_data.get("ipv6McastAllow", "no") == "yes",
            "multicast_flooding": bd_data.get("multiDstPktAct", "bd-flood"),
            "gipo_configured": bool(gipo_address.strip()),
            "subnets_with_multicast": []
        }

        # Analyze subnets for multicast addresses
        children = item["fvBD"].get("children", [])
        for child in children:
            if "fvSubnet" in child:
                subnet_data = child["fvSubnet"]["attributes"]
                ip_addr = subnet_data.get("ip", "").split("/")[0]

                if ip_addr:
                    try:
                        ip_obj = ipaddress.ip_address(ip_addr)
                        if ip_obj.is_multicast:
                            multicast_info = {
                                "address": ip_addr,
                                "subnet": subnet_data.get("ip", ""),
                                "description": subnet_data.get("descr", ""),
                                "scope": subnet_data.get("scope", ""),
                                "virtual": subnet_data.get("virtual", "no") == "yes",
                                "type": "subnet_multicast"
                            }
                            bd_info["multicast_addresses"].append(multicast_info)
                            bd_info["subnets_with_multicast"].append(multicast_info)
                            multicast_addresses_total += 1
                    except (ValueError, ipaddress.AddressValueError):
                        pass

        # Add GIPo address as primary multicast address
        if gipo_address:
            gipo_info = {
                "address": gipo_address.split("/")[0] if "/" in gipo_address else gipo_address,
                "subnet": gipo_address,
                "description": "GIPo (Group IP Outer) - Multicast address for BUM traffic",
                "scope": "fabric",
                "virtual": False,
                "type": "gipo"
            }
            bd_info["multicast_addresses"].append(gipo_info)
            bd_info["subnets_with_multicast"].append(gipo_info)
            multicast_addresses_total += 1

        bridge_domains.append(bd_info)

    return {
        "tenant": tenant,
        "total_bridge_domains": len(bridge_domains),
        "total_multicast_addresses": multicast_addresses_total,
        "domains_with_multicast": len([bd for bd in bridge_domains if bd["multicast_addresses"]]),
        "bridge_domains": bridge_domains
    }


async def get_apic_capacity_metrics() -> Dict[str, Any]:
    """
    Retrieve fabric capacity metrics from APIC.

    Returns:
        Dict with capacity metrics
    """
    result = await _apic_request("api/node/class/eqptcapacityEntity.json")

    if "error" in result:
        return result

    capacity_metrics = []
    for item in result.get("imdata", []):
        cap_data = item.get("eqptcapacityEntity", {}).get("attributes", {})
        dn = cap_data.get("dn", "")

        # Extract node ID
        node_id = ""
        if "/node-" in dn:
            node_id = dn.split("/node-")[1].split("/")[0]

        capacity_metrics.append({
            "node_id": node_id,
            "context": cap_data.get("context", ""),
            "current_usage": int(cap_data.get("currentUsage", 0)),
            "max_capacity": int(cap_data.get("maxCapacity", 0)),
            "utilization_percent": round(
                (int(cap_data.get("currentUsage", 0)) / max(int(cap_data.get("maxCapacity", 1)), 1)) * 100, 2
            ),
            "dn": dn
        })

    return {
        "total_metrics": len(capacity_metrics),
        "capacity_metrics": sorted(capacity_metrics, key=lambda x: x["node_id"])
    }


async def get_apic_resource_utilization() -> Dict[str, Any]:
    """
    Analyze resource utilization for capacity planning.

    Returns:
        Dict with resource utilization
    """
    # Retrieve system statistics
    cpu_result = await _apic_request("api/node/class/procSysCPU5min.json")
    memory_result = await _apic_request("api/node/class/procSysMem5min.json")

    resource_data = {
        "cpu_utilization": [],
        "memory_utilization": [],
        "summary": {
            "nodes_monitored": 0,
            "avg_cpu_usage": 0,
            "avg_memory_usage": 0,
            "high_cpu_nodes": [],
            "high_memory_nodes": []
        }
    }

    # Process CPU data
    if "error" not in cpu_result:
        cpu_total = 0
        cpu_count = 0

        for item in cpu_result.get("imdata", []):
            cpu_info = item.get("procSysCPU5min", {}).get("attributes", {})
            dn = cpu_info.get("dn", "")
            idle_avg = float(cpu_info.get("idleAvg", 100))
            cpu_usage = round(100 - idle_avg, 2)

            # Extract node ID
            node_id = ""
            if "/node-" in dn:
                node_id = dn.split("/node-")[1].split("/")[0]

            cpu_data = {
                "node_id": node_id,
                "cpu_usage": cpu_usage,
                "user_avg": float(cpu_info.get("userAvg", 0)),
                "kernel_avg": float(cpu_info.get("kernelAvg", 0))
            }

            resource_data["cpu_utilization"].append(cpu_data)
            cpu_total += cpu_usage
            cpu_count += 1

            # Identify nodes with high CPU utilization (>80%)
            if cpu_usage > 80:
                resource_data["summary"]["high_cpu_nodes"].append({
                    "node_id": node_id,
                    "cpu_usage": cpu_usage
                })

        if cpu_count > 0:
            resource_data["summary"]["avg_cpu_usage"] = round(cpu_total / cpu_count, 2)
            resource_data["summary"]["nodes_monitored"] = cpu_count

    # Process memory data
    if "error" not in memory_result:
        memory_total = 0
        memory_count = 0

        for item in memory_result.get("imdata", []):
            mem_info = item.get("procSysMem5min", {}).get("attributes", {})
            dn = mem_info.get("dn", "")

            used = float(mem_info.get("usedAvg", 0))
            free = float(mem_info.get("freeAvg", 0))
            total = used + free

            if total > 0:
                memory_usage = round((used / total) * 100, 2)

                # Extract node ID
                node_id = ""
                if "/node-" in dn:
                    node_id = dn.split("/node-")[1].split("/")[0]

                mem_data = {
                    "node_id": node_id,
                    "memory_usage": memory_usage,
                    "used_avg": used,
                    "free_avg": free,
                    "total": total
                }

                resource_data["memory_utilization"].append(mem_data)
                memory_total += memory_usage
                memory_count += 1

                # Identify nodes with high memory utilization (>85%)
                if memory_usage > 85:
                    resource_data["summary"]["high_memory_nodes"].append({
                        "node_id": node_id,
                        "memory_usage": memory_usage
                    })

        if memory_count > 0:
            resource_data["summary"]["avg_memory_usage"] = round(memory_total / memory_count, 2)

    return resource_data


async def get_apic_traffic_analysis(tenant: Optional[str] = None, epg: Optional[str] = None) -> Dict[str, Any]:
    """
    Analyze traffic for a specific tenant or EPG.

    Args:
        tenant: Tenant name (optional)
        epg: EPG name (optional)

    Returns:
        Dict with traffic analysis
    """
    if tenant and epg:
        # Statistics specific to an EPG
        endpoint = "api/node/class/l2IngrBytesAg5min.json"
        params = {
            "query-target-filter": f"and(wcard(l2IngrBytesAg5min.dn,\"tn-{tenant}\"),wcard(l2IngrBytesAg5min.dn,\"epg-{epg}\"))"
        }
    elif tenant:
        # Tenant statistics
        endpoint = "api/node/class/l2IngrBytesAg5min.json"
        params = {
            "query-target-filter": f"wcard(l2IngrBytesAg5min.dn,\"tn-{tenant}\")"
        }
    else:
        # Limited global view
        endpoint = "api/node/class/l2IngrBytesAg5min.json"
        params = {"page-size": "20"}

    result = await _apic_request(endpoint, params=params)

    if "error" in result:
        return result

    traffic_data = []
    total_bytes = 0

    for item in result.get("imdata", []):
        stats = item.get("l2IngrBytesAg5min", {}).get("attributes", {})
        bytes_val = int(stats.get("bytesAvg", 0))
        total_bytes += bytes_val

        traffic_data.append({
            "dn": stats.get("dn", ""),
            "bytes_avg": bytes_val,
            "bytes_max": int(stats.get("bytesMax", 0)),
            "bytes_min": int(stats.get("bytesMin", 0)),
            "last_update": stats.get("lastCollOffset", "")
        })

    return {
        "tenant_filter": tenant,
        "epg_filter": epg,
        "total_entries": len(traffic_data),
        "total_bytes_avg": total_bytes,
        "traffic_data": traffic_data
    }


async def get_apic_top_talkers() -> Dict[str, Any]:
    """
    Identify top network conversations (top talkers).

    Returns:
        Dict with top talkers
    """
    # Retrieve recent traffic statistics (without order-by to avoid API error)
    result = await _apic_request("api/node/class/l2IngrBytesAg5min.json", params={
        "page-size": "100"
    })

    if "error" in result:
        return result

    top_talkers = []
    total_traffic = 0

    for item in result.get("imdata", []):
        stats = item.get("l2IngrBytesAg5min", {}).get("attributes", {})
        bytes_avg = int(stats.get("bytesAvg", 0))
        total_traffic += bytes_avg

        dn = stats.get("dn", "")

        # Extract information from DN
        tenant = epg = ""
        dn_parts = dn.split("/")
        for part in dn_parts:
            if part.startswith("tn-"):
                tenant = part[3:]
            elif part.startswith("epg-"):
                epg = part[4:]

        top_talkers.append({
            "dn": dn,
            "tenant": tenant,
            "epg": epg,
            "bytes_avg": bytes_avg,
            "bytes_max": int(stats.get("bytesMax", 0)),
            "packets_avg": int(stats.get("pktsAvg", 0)),
            "utilization_pct": 0  # Calculated after
        })

    # Calculate utilization percentages
    if total_traffic > 0:
        for talker in top_talkers:
            talker["utilization_pct"] = round((talker["bytes_avg"] / total_traffic) * 100, 2)

    # Sort by bytes_avg descending and limit to top 20
    top_talkers_sorted = sorted(top_talkers, key=lambda x: x["bytes_avg"], reverse=True)[:20]

    return {
        "total_entries": len(top_talkers_sorted),
        "total_traffic_bytes": total_traffic,
        "top_talkers": top_talkers_sorted
    }


async def get_apic_path_analysis(src_epg: str, dst_epg: str) -> Dict[str, Any]:
    """
    Analyze network paths between two EPGs.

    Args:
        src_epg: Source EPG DN or name
        dst_epg: Destination EPG DN or name

    Returns:
        Dict with path analysis
    """
    # This function requires more complex analysis
    # For now, retrieve contracts between EPGs

    # Retrieve all contracts
    contracts_result = await _apic_request("api/node/class/vzBrCP.json")
    if "error" in contracts_result:
        return contracts_result

    # Retrieve consumer/provider relationships
    consumer_result = await _apic_request("api/node/class/fvRsCons.json")
    provider_result = await _apic_request("api/node/class/fvRsProv.json")

    path_info = {
        "source_epg": src_epg,
        "destination_epg": dst_epg,
        "contracts_found": [],
        "connectivity_status": "unknown"
    }

    if "error" not in consumer_result and "error" not in provider_result:
        consumers = consumer_result.get("imdata", [])
        providers = provider_result.get("imdata", [])

        # Analyze relationships (simplified for this version)
        for consumer in consumers:
            cons_data = consumer.get("fvRsCons", {}).get("attributes", {})
            if src_epg in cons_data.get("dn", ""):
                contract_name = cons_data.get("tnVzBrCPName", "")
                if contract_name:
                    path_info["contracts_found"].append({
                        "contract": contract_name,
                        "relationship": "consumer",
                        "dn": cons_data.get("dn", "")
                    })

        for provider in providers:
            prov_data = provider.get("fvRsProv", {}).get("attributes", {})
            if dst_epg in prov_data.get("dn", ""):
                contract_name = prov_data.get("tnVzBrCPName", "")
                if contract_name:
                    path_info["contracts_found"].append({
                        "contract": contract_name,
                        "relationship": "provider",
                        "dn": prov_data.get("dn", "")
                    })

    # Determine connectivity status
    if path_info["contracts_found"]:
        path_info["connectivity_status"] = "contracts_exist"
    else:
        path_info["connectivity_status"] = "no_contracts_found"

    return path_info


async def analyze_apic_connectivity() -> Dict[str, Any]:
    """
    Comprehensive connectivity and health analysis of APIC infrastructure.

    Returns:
        Dict with comprehensive analysis
    """
    from datetime import datetime

    analysis = {
        "timestamp": datetime.now().isoformat(),
        "status": "success",
        "connectivity": {},
        "fabric_health": {},
        "capacity": {},
        "multicast": {}
    }

    try:
        # Basic connectivity test
        system_info = await _apic_request("api/node/class/topSystem.json", params={
            "query-target-filter": 'eq(topSystem.role,"controller")'
        })

        if "error" not in system_info:
            controllers = system_info.get("imdata", [])
            analysis["connectivity"]["controllers_count"] = len(controllers)
            analysis["connectivity"]["apic_reachable"] = True

            if controllers:
                first_controller = controllers[0].get("topSystem", {}).get("attributes", {})
                analysis["connectivity"]["apic_version"] = first_controller.get("version", "Unknown")

        # Retrieve fabric health
        fabric_nodes = await _apic_request("api/node/class/fabricNode.json")
        if "error" not in fabric_nodes:
            nodes = fabric_nodes.get("imdata", [])
            analysis["fabric_health"]["total_nodes"] = len(nodes)
            analysis["fabric_health"]["nodes_online"] = sum(
                1 for node in nodes
                if node.get("fabricNode", {}).get("attributes", {}).get("fabricSt") == "active"
            )

        # Retrieve critical faults
        critical_faults = await get_apic_faults()
        if "error" not in critical_faults:
            analysis["fabric_health"]["critical_faults"] = critical_faults.get("severity_breakdown", {}).get("critical", 0)
            analysis["fabric_health"]["total_faults"] = critical_faults.get("total_faults", 0)

        # Multicast analysis
        multicast_summary = await get_apic_bridge_domains_multicast()
        if "error" not in multicast_summary:
            total_bds = multicast_summary.get("total_bridge_domains", 0)
            enabled_bds = multicast_summary.get("multicast_enabled_domains", 0)
            analysis["multicast"] = {
                "enabled_domains": enabled_bds,
                "total_domains": total_bds,
                "percentage_enabled": round((enabled_bds / total_bds * 100) if total_bds > 0 else 0, 2)
            }

        # Capacity analysis (if available)
        try:
            capacity_metrics = await get_apic_capacity_metrics()
            if "error" not in capacity_metrics:
                metrics = capacity_metrics.get("capacity_metrics", [])
                if metrics:
                    avg_utilization = sum(m["utilization_percent"] for m in metrics) / len(metrics)
                    analysis["capacity"]["average_utilization"] = round(avg_utilization, 2)
                    analysis["capacity"]["high_utilization_nodes"] = [
                        m["node_id"] for m in metrics if m["utilization_percent"] > 80
                    ]
        except Exception:
            analysis["capacity"]["status"] = "unavailable"

    except Exception as e:
        analysis["status"] = "error"
        analysis["error_message"] = str(e)

    return analysis


async def get_apic_health_scores() -> Dict[str, Any]:
    """
    Retrieve health scores of APIC objects.

    Returns:
        Dict with health scores classified by severity level
    """
    result = await _apic_request("api/node/class/healthInst.json", params={
        "order-by": "healthInst.chng|desc",
        "page-size": "50"
    })

    if "error" in result:
        return result

    health_scores = []
    critical_count = major_count = minor_count = 0

    for item in result.get("imdata", []):
        health_data = item.get("healthInst", {}).get("attributes", {})
        current_score = int(health_data.get("cur", 100))

        # Health classification
        health_level = "healthy"
        if current_score < 50:
            health_level = "critical"
            critical_count += 1
        elif current_score < 75:
            health_level = "major"
            major_count += 1
        elif current_score < 90:
            health_level = "minor"
            minor_count += 1

        health_scores.append({
            "dn": health_data.get("dn", ""),
            "current_score": current_score,
            "previous_score": int(health_data.get("prev", 100)),
            "change": int(health_data.get("chng", 0)),
            "health_level": health_level,
            "last_update": health_data.get("updTs", "")
        })

    return {
        "total_objects": len(health_scores),
        "critical_health": critical_count,
        "major_issues": major_count,
        "minor_issues": minor_count,
        "healthy_objects": len(health_scores) - critical_count - major_count - minor_count,
        "health_scores": health_scores
    }


async def get_apic_physical_interfaces(node_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Retrieve physical interfaces from a node or all nodes.

    Args:
        node_id: Node ID (optional)

    Returns:
        Dict with physical interfaces list
    """
    if node_id:
        result = await _apic_request(f"api/node/mo/topology/pod-1/node-{node_id}.json", params={
            "query-target": "children",
            "target-subtree-class": "l1PhysIf"
        })
    else:
        result = await _apic_request("api/node/class/l1PhysIf.json", params={"page-size": "100"})

    if "error" in result:
        return result

    interfaces = []
    for item in result.get("imdata", []):
        if_data = item.get("l1PhysIf", {}).get("attributes", {})
        dn = if_data.get("dn", "")

        # Extract node ID from DN
        interface_node_id = ""
        if "/node-" in dn:
            interface_node_id = dn.split("/node-")[1].split("/")[0]

        interfaces.append({
            "id": if_data.get("id", ""),
            "node_id": interface_node_id,
            "admin_state": if_data.get("adminSt", ""),
            "operational_state": if_data.get("operSt", ""),
            "speed": if_data.get("speed", ""),
            "usage": if_data.get("usage", ""),
            "mtu": if_data.get("mtu", ""),
            "auto_negotiation": if_data.get("autoNeg", ""),
            "dn": dn
        })

    return {
        "node_filter": node_id,
        "total_interfaces": len(interfaces),
        "interfaces": sorted(interfaces, key=lambda x: (x["node_id"], x["id"]))
    }


async def get_apic_interface_statistics(node_id: Optional[str] = None, interface: Optional[str] = None) -> Dict[str, Any]:
    """
    Retrieve interface statistics for a specific node.

    Args:
        node_id: Node ID (optional)
        interface: Specific interface name (optional)

    Returns:
        Dict with interface statistics
    """
    if node_id and interface:
        # Specific interface
        endpoint = f"api/node/mo/topology/pod-1/node-{node_id}/sys/phys-[{interface}].json"
        params = {"rsp-subtree-include": "stats"}
    elif node_id:
        # All interfaces of a node
        endpoint = f"api/node/mo/topology/pod-1/node-{node_id}/sys.json"
        params = {
            "query-target": "subtree",
            "target-subtree-class": "l1PhysIf",
            "rsp-subtree-include": "stats"
        }
    else:
        # Global view - all nodes interfaces (limited)
        endpoint = "api/node/class/l1PhysIf.json"
        params = {
            "rsp-subtree-include": "stats",
            "page-size": "20"
        }

    result = await _apic_request(endpoint, params=params)

    if "error" in result:
        return result

    interfaces = []
    for item in result.get("imdata", []):
        if "l1PhysIf" in item:
            iface_data = item["l1PhysIf"]["attributes"]
            interfaces.append({
                "dn": iface_data.get("dn", ""),
                "id": iface_data.get("id", ""),
                "admin_st": iface_data.get("adminSt", ""),
                "oper_st": iface_data.get("operSt", ""),
                "usage": iface_data.get("usage", ""),
                "speed": iface_data.get("speed", ""),
                "mtu": iface_data.get("mtu", "")
            })

    return {
        "node_id": node_id,
        "interface_filter": interface,
        "total_interfaces": len(interfaces),
        "interfaces": interfaces
    }


async def get_apic_lldp_neighbors(node_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Retrieve LLDP neighbors for a node or all nodes.

    Args:
        node_id: Node ID (optional)

    Returns:
        Dict with LLDP neighbors information
    """
    if node_id:
        endpoint = f"api/node/mo/topology/pod-1/node-{node_id}/sys/lldp/inst.json"
        params = {
            "query-target": "subtree",
            "target-subtree-class": "lldpAdjEp"
        }
    else:
        endpoint = "api/node/class/lldpAdjEp.json"
        params = {"page-size": "50"}

    result = await _apic_request(endpoint, params=params)

    if "error" in result:
        return result

    neighbors = []
    for item in result.get("imdata", []):
        adj_data = item.get("lldpAdjEp", {}).get("attributes", {})
        dn = adj_data.get("dn", "")

        # Extract node ID and interface from DN
        local_node = ""
        local_interface = ""
        if "/node-" in dn and "/if-[" in dn:
            node_part = dn.split("/node-")[1].split("/")[0]
            local_node = node_part
            if_part = dn.split("/if-[")[1].split("]")[0]
            local_interface = if_part

        neighbors.append({
            "local_node": local_node,
            "local_interface": local_interface,
            "remote_system_name": adj_data.get("sysName", ""),
            "remote_port_desc": adj_data.get("portDesc", ""),
            "remote_port_id": adj_data.get("portId", ""),
            "remote_chassis_id": adj_data.get("chassisId", ""),
            "mgmt_ip": adj_data.get("mgmtIp", ""),
            "capability": adj_data.get("capability", ""),
            "dn": dn
        })

    return {
        "node_filter": node_id,
        "total_neighbors": len(neighbors),
        "neighbors": sorted(neighbors, key=lambda x: (x["local_node"], x["local_interface"]))
    }


async def get_apic_gipo_pool_config() -> Dict[str, Any]:
    """
    Retrieve GIPo multicast pool configuration from fabricSetupP.

    Returns:
        Dict with GIPo pool configuration (BD and VRF pools)
    """
    result = await _apic_request("api/node/class/fabricSetupP.json")

    if "error" in result:
        return result

    gipo_config = {
        "pool_configured": False,
        "gipo_pool": "",
        "bd_gipo_pool": "",
        "vrf_gipo_pool": "",
        "config_details": []
    }

    for item in result.get("imdata", []):
        setup_data = item.get("fabricSetupP", {}).get("attributes", {})

        pool_info = {
            "dn": setup_data.get("dn", ""),
            "bd_gipo_pool": setup_data.get("bdGiPoPool", ""),
            "vrf_gipo_pool": setup_data.get("vrfGiPoPool", ""),
            "pod_id": setup_data.get("podId", ""),
            "setup_id": setup_data.get("setupId", "")
        }

        gipo_config["config_details"].append(pool_info)

        # Get main pools
        if pool_info["bd_gipo_pool"]:
            gipo_config["bd_gipo_pool"] = pool_info["bd_gipo_pool"]
            gipo_config["pool_configured"] = True

        if pool_info["vrf_gipo_pool"]:
            gipo_config["vrf_gipo_pool"] = pool_info["vrf_gipo_pool"]

        # General pool (uses BD GIPo by default)
        if not gipo_config["gipo_pool"] and pool_info["bd_gipo_pool"]:
            gipo_config["gipo_pool"] = pool_info["bd_gipo_pool"]

    return gipo_config
