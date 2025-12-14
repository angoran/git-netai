# /connectors/graylog_c.py

import os
from typing import Dict, Optional
from dotenv import load_dotenv
import httpx

# Loading environment variables (override system env vars)
load_dotenv(override=True)

# Retrieving Graylog API credentials from the .env file
GRAYLOG_API_URL = os.getenv("GRAYLOG_API_URL")
GRAYLOG_USERNAME = os.getenv("GRAYLOG_USERNAME")
GRAYLOG_PASSWORD = os.getenv("GRAYLOG_PASSWORD")

async def _graylog_request(endpoint: str, params: Optional[Dict] = None) -> Optional[Dict]:
    """
    Performs an asynchronous Graylog REST API request via httpx.AsyncClient.
    Returns JSON or a dict {"error": ...}.
    """
    if not GRAYLOG_API_URL or not GRAYLOG_USERNAME or not GRAYLOG_PASSWORD:
        return {"error": "Graylog API credentials not configured"}

    url = f"{GRAYLOG_API_URL.rstrip('/')}/{endpoint}"
    timeout = httpx.Timeout(30.0)

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            auth=httpx.BasicAuth(GRAYLOG_USERNAME, GRAYLOG_PASSWORD)
        ) as client:
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


async def search_logs(query: str, hours: int = 1, limit: int = 20) -> Dict:
    """
    Search log messages with a query and time period.

    Args:
        query: Search query (ex: 'bgp' or 'firewall')
        hours: Number of hours in the past (default: 1h)
        limit: Maximum number of results (default: 20)

    Returns:
        Dict with found log messages
    """
    params = {
        "query": query,
        "range": hours * 3600,  # Convert to seconds
        "limit": limit,
        "sort": "timestamp:desc"
    }

    data = await _graylog_request("search/universal/relative", params)
    if isinstance(data, dict) and "error" in data:
        return data

    if not data or not isinstance(data, dict):
        return {"error": "Invalid response from Graylog API"}

    messages = []
    for msg in data.get("messages", []):
        message_data = msg.get("message", {})
        messages.append({
            "timestamp": message_data.get("timestamp", ""),
            "source": message_data.get("source", ""),
            "message": message_data.get("message", ""),
            "level": message_data.get("level", ""),
            "facility": message_data.get("facility", "")
        })

    return {
        "query": query,
        "period_hours": hours,
        "total_results": data.get("total_results", 0),
        "returned_results": len(messages),
        "messages": messages
    }

async def get_streams() -> Dict:
    """
    Retrieve the list of available log streams.

    Returns:
        Dict with list of streams
    """
    data = await _graylog_request("streams")
    if isinstance(data, dict) and "error" in data:
        return data

    if not data or not isinstance(data, dict):
        return {"error": "Invalid response from Graylog API"}

    streams = []
    for stream in data.get("streams", []):
        streams.append({
            "id": stream.get("id", ""),
            "title": stream.get("title", ""),
            "description": stream.get("description", ""),
            "disabled": stream.get("disabled", False)
        })

    return {
        "total_streams": len(streams),
        "streams": streams
    }

async def get_system_overview() -> Dict:
    """
    Retrieve Graylog system overview.

    Returns:
        Dict with system information
    """
    data = await _graylog_request("system")
    if isinstance(data, dict) and "error" in data:
        return data

    if not data or not isinstance(data, dict):
        return {"error": "Invalid response from Graylog API"}

    return {
        "hostname": data.get("hostname", ""),
        "node_id": data.get("node_id", ""),
        "version": data.get("version", ""),
        "timezone": data.get("timezone", ""),
        "is_processing": data.get("is_processing", False)
    }
