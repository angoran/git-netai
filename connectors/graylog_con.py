# /connectors/graylog_con.py

import json
import os
import base64
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, List, Optional
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

# Configuration API Graylog
GRAYLOG_API_URL = os.getenv("GRAYLOG_API_URL")
GRAYLOG_USERNAME = os.getenv("GRAYLOG_USERNAME")
GRAYLOG_PASSWORD = os.getenv("GRAYLOG_PASSWORD")

def _graylog_request(endpoint: str, params: Optional[Dict] = None) -> Optional[Dict]:
    """
    Effectue une requete API Graylog avec authentification Basic.
    
    Args:
        endpoint: Endpoint de l'API (ex: 'streams', 'search/universal/relative')
        params: Parametres de requete optionnels
    
    Returns:
        Dict avec la reponse JSON ou erreur
    """
    if not GRAYLOG_API_URL or not GRAYLOG_USERNAME or not GRAYLOG_PASSWORD:
        return {"error": "Graylog API credentials not configured"}
    
    try:
        # Construction de l'URL
        url = f"{GRAYLOG_API_URL.rstrip('/')}/{endpoint}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        
        # Authentification Basic
        credentials = f"{GRAYLOG_USERNAME}:{GRAYLOG_PASSWORD}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Basic {encoded_credentials}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
        )
        
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.loads(response.read())
            
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.reason}"}
    except Exception as e:
        return {"error": str(e)}

def search_logs(query: str, hours: int = 24, limit: int = 100) -> Dict:
    """
    Recherche des messages de log avec une requete et une periode.
    
    Args:
        query: Requete de recherche (ex: 'Authentication failed')
        hours: Nombre d'heures dans le passe (defaut: 24h)
        limit: Nombre maximum de resultats (defaut: 100)
    
    Returns:
        Dict avec les messages de log trouves
    """
    params = {
        "query": query,
        "range": hours * 3600,  # Conversion en secondes
        "limit": limit,
        "sort": "timestamp:desc"
    }
    
    data = _graylog_request("search/universal/relative", params)
    if "error" in data:
        return data
    
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
        "messages": messages
    }

def get_streams() -> Dict:
    """
    Recupere la liste des streams de logs disponibles.
    
    Returns:
        Dict avec la liste des streams
    """
    data = _graylog_request("streams")
    if "error" in data:
        return data
    
    streams = []
    for stream in data.get("streams", []):
        streams.append({
            "id": stream.get("id", ""),
            "title": stream.get("title", ""),
            "description": stream.get("description", ""),
            "disabled": stream.get("disabled", False),
            "matching_type": stream.get("matching_type", "")
        })
    
    return {
        "total_streams": len(streams),
        "streams": streams
    }

def get_stream_stats(stream_id: str, hours: int = 24) -> Dict:
    """
    Recupere les statistiques d'un stream specifique.
    
    Args:
        stream_id: ID du stream
        hours: Periode d'analyse en heures (defaut: 24h)
    
    Returns:
        Dict avec les statistiques du stream
    """
    params = {
        "range": hours * 3600
    }
    
    data = _graylog_request(f"streams/{stream_id}/messages", params)
    if "error" in data:
        return data
    
    return {
        "stream_id": stream_id,
        "period_hours": hours,
        "total_messages": data.get("total_results", 0),
        "query_time": data.get("time", 0)
    }

def get_system_overview() -> Dict:
    """
    Recupere l'etat general du systeme Graylog.
    
    Returns:
        Dict avec les informations systeme
    """
    data = _graylog_request("system")
    if "error" in data:
        return data
    
    return {
        "hostname": data.get("hostname", ""),
        "node_id": data.get("node_id", ""),
        "version": data.get("version", ""),
        "operating_system": data.get("operating_system", ""),
        "timezone": data.get("timezone", ""),
        "is_processing": data.get("is_processing", False),
        "lifecycle": data.get("lifecycle", "")
    }