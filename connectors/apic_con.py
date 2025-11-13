# /connectors/apic_con.py

import json
import os
import time
import threading
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, Optional, List, Any
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

# Configuration API APIC
APIC_HOST = os.getenv("APIC_HOST")
APIC_USERNAME = os.getenv("APIC_USERNAME")
APIC_PASSWORD = os.getenv("APIC_PASSWORD")
APIC_VERIFY_SSL = os.getenv("APIC_VERIFY_SSL", "false").lower() == "true"
APIC_TIMEOUT = int(os.getenv("APIC_TIMEOUT", "30"))
APIC_TOKEN_CACHE_DURATION = int(os.getenv("APIC_TOKEN_CACHE_DURATION", "3600"))

# Cache global pour le token JWT (thread-safe)
_token_cache = {
    "token": None,
    "expires_at": 0,
    "lock": threading.Lock()
}

def _get_base_url() -> str:
    """Construit l'URL de base de l'API APIC."""
    protocol = "https" if APIC_VERIFY_SSL else "https"  # APIC utilise HTTPS par défaut
    return f"{protocol}://{APIC_HOST}"

def _authenticate() -> Optional[str]:
    """
    Authentifie auprès de l'APIC et récupère un token JWT.
    
    Returns:
        Token JWT ou None en cas d'erreur
    """
    if not APIC_HOST or not APIC_USERNAME or not APIC_PASSWORD:
        return None
    
    try:
        # Construire la requête d'authentification
        auth_data = {
            "aaaUser": {
                "attributes": {
                    "name": APIC_USERNAME,
                    "pwd": APIC_PASSWORD
                }
            }
        }
        
        url = f"{_get_base_url()}/api/aaaLogin.json"
        data = json.dumps(auth_data).encode('utf-8')
        
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
        )
        
        # Désactiver la vérification SSL si configuré
        if not APIC_VERIFY_SSL:
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(req, timeout=APIC_TIMEOUT, context=context) as response:
                result = json.loads(response.read().decode())
        else:
            with urllib.request.urlopen(req, timeout=APIC_TIMEOUT) as response:
                result = json.loads(response.read().decode())
        
        # Extraire le token de la réponse
        if "imdata" in result and len(result["imdata"]) > 0:
            login_data = result["imdata"][0]
            if "aaaLogin" in login_data and "attributes" in login_data["aaaLogin"]:
                return login_data["aaaLogin"]["attributes"].get("token")
        
        return None
        
    except Exception as e:
        print(f"Erreur d'authentification APIC: {e}")
        return None

def _get_token() -> Optional[str]:
    """
    Récupère un token JWT valide avec gestion de cache thread-safe.
    
    Returns:
        Token JWT valide ou None en cas d'erreur
    """
    with _token_cache["lock"]:
        current_time = time.time()
        
        # Vérifier si le token en cache est encore valide
        if (_token_cache["token"] and 
            current_time < _token_cache["expires_at"]):
            return _token_cache["token"]
        
        # Authentification requise
        token = _authenticate()
        if token:
            _token_cache["token"] = token
            _token_cache["expires_at"] = current_time + APIC_TOKEN_CACHE_DURATION - 60  # 60s de marge
            return token
        
        return None

def _apic_request(endpoint: str, method: str = "GET", params: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Effectue une requête API APIC avec gestion du token JWT.
    
    Args:
        endpoint: Endpoint de l'API (ex: 'api/node/class/fabricNode.json')
        method: Méthode HTTP (GET, POST, etc.)
        params: Paramètres de requête optionnels
    
    Returns:
        Dict avec la réponse JSON ou erreur
    """
    token = _get_token()
    if not token:
        return {"error": "Impossible d'obtenir un token d'authentification APIC"}
    
    try:
        # Construire l'URL complète
        url = f"{_get_base_url()}/{endpoint.lstrip('/')}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        
        # Construire la requête
        headers = {
            "Cookie": f"APIC-cookie={token}",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
        req = urllib.request.Request(url, headers=headers)
        req.get_method = lambda: method
        
        # Effectuer la requête
        if not APIC_VERIFY_SSL:
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(req, timeout=APIC_TIMEOUT, context=context) as response:
                return json.loads(response.read().decode())
        else:
            with urllib.request.urlopen(req, timeout=APIC_TIMEOUT) as response:
                return json.loads(response.read().decode())
                
    except urllib.error.HTTPError as e:
        error_msg = f"Erreur HTTP {e.code}: {e.reason}"
        try:
            error_detail = e.read().decode()
            error_data = json.loads(error_detail)
            if "imdata" in error_data and len(error_data["imdata"]) > 0:
                error_info = error_data["imdata"][0]
                if "error" in error_info:
                    error_msg += f" - {error_info['error'].get('attributes', {}).get('text', '')}"
        except Exception:
            pass
        return {"error": error_msg}
    except Exception as e:
        return {"error": f"Erreur de connexion APIC: {str(e)}"}

def test_apic_connection() -> Dict[str, Any]:
    """
    Teste la connexion à l'API APIC.
    
    Returns:
        Dict avec le résultat du test de connexion
    """
    token = _get_token()
    if token:
        # Test avec une requête simple
        result = _apic_request("api/node/class/topSystem.json", params={"query-target-filter": "eq(topSystem.role,\"controller\")"})
        if "error" not in result:
            return {
                "status": "success",
                "message": "Connexion APIC établie avec succès",
                "host": APIC_HOST,
                "token_cached": bool(_token_cache["token"])
            }
        else:
            return {
                "status": "error", 
                "message": f"Connexion établie mais erreur API: {result['error']}",
                "host": APIC_HOST
            }
    else:
        return {
            "status": "error",
            "message": "Impossible de s'authentifier auprès de l'APIC",
            "host": APIC_HOST
        }

# ========== PHASE 1: FONCTIONS ESSENTIELLES ==========

def get_apic_fabric_health() -> Dict[str, Any]:
    """
    Récupère l'état général de santé du fabric ACI.
    
    Returns:
        Dict avec l'état de santé du fabric
    """
    # Récupérer les faults critiques
    result = _apic_request("api/node/class/faultInst.json", params={
        "query-target-filter": "eq(faultInst.severity,\"critical\")",
        "order-by": "faultInst.created|desc"
    })
    
    if "error" in result:
        return result
    
    critical_faults = result.get("imdata", [])
    
    # Récupérer l'état des contrôleurs
    controllers_result = _apic_request("api/node/class/topSystem.json", params={
        "query-target-filter": "eq(topSystem.role,\"controller\")"
    })
    
    controllers = controllers_result.get("imdata", []) if "error" not in controllers_result else []
    
    # Analyser la santé globale
    health_status = "healthy"
    if len(critical_faults) > 0:
        health_status = "critical"
    elif len(critical_faults) == 0:
        health_status = "healthy"
    
    return {
        "overall_health": health_status,
        "critical_faults_count": len(critical_faults),
        "controllers_count": len(controllers),
        "controllers_online": sum(1 for c in controllers if c.get("topSystem", {}).get("attributes", {}).get("state") == "in-service"),
        "critical_faults": [
            {
                "dn": fault.get("faultInst", {}).get("attributes", {}).get("dn", ""),
                "description": fault.get("faultInst", {}).get("attributes", {}).get("descr", ""),
                "severity": fault.get("faultInst", {}).get("attributes", {}).get("severity", ""),
                "created": fault.get("faultInst", {}).get("attributes", {}).get("created", "")
            }
            for fault in critical_faults[:5]  # Limiter à 5 faults les plus récentes
        ]
    }

def get_apic_tenants() -> Dict[str, Any]:
    """
    Liste tous les tenants configurés sur l'APIC.
    
    Returns:
        Dict avec la liste des tenants
    """
    result = _apic_request("api/node/class/fvTenant.json")
    
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

def get_apic_faults() -> Dict[str, Any]:
    """
    Récupère les faults actives du système APIC.
    
    Returns:
        Dict avec les faults actives
    """
    result = _apic_request("api/node/class/faultInst.json", params={
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

def get_apic_nodes_inventory() -> Dict[str, Any]:
    """
    Récupère l'inventaire des nœuds du fabric.
    
    Returns:
        Dict avec l'inventaire des nœuds
    """
    result = _apic_request("api/node/class/fabricNode.json")
    
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

def get_apic_epgs(tenant: str = None) -> Dict[str, Any]:
    """
    Récupère les Endpoint Groups (EPGs) d'un tenant ou de tous les tenants.
    
    Args:
        tenant: Nom du tenant (optionnel, tous si non spécifié)
    
    Returns:
        Dict avec les EPGs
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
    
    result = _apic_request(endpoint, params=params)
    
    if "error" in result:
        return result
    
    epgs = []
    for item in result.get("imdata", []):
        epg_data = item.get("fvAEPg", {}).get("attributes", {})
        dn = epg_data.get("dn", "")
        
        # Extraire tenant et application du DN
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

def get_apic_interface_statistics(node_id: str = None, interface: str = None) -> Dict[str, Any]:
    """
    Récupère les statistiques d'interface pour un nœud spécifique.
    
    Args:
        node_id: ID du nœud (optionnel)
        interface: Interface spécifique (optionnel)
    
    Returns:
        Dict avec les statistiques d'interface
    """
    if node_id and interface:
        # Interface spécifique
        endpoint = f"api/node/mo/topology/pod-1/node-{node_id}/sys/phys-[{interface}].json"
        params = {"rsp-subtree-include": "stats"}
    elif node_id:
        # Toutes les interfaces d'un nœud
        endpoint = f"api/node/mo/topology/pod-1/node-{node_id}/sys.json"
        params = {
            "query-target": "subtree",
            "target-subtree-class": "l1PhysIf",
            "rsp-subtree-include": "stats"
        }
    else:
        # Vue globale - interfaces de tous les nœuds (limité)
        endpoint = "api/node/class/l1PhysIf.json"
        params = {
            "rsp-subtree-include": "stats",
            "page-size": "20"
        }
    
    result = _apic_request(endpoint, params=params)
    
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

def get_apic_events(time_range: int = 24) -> Dict[str, Any]:
    """
    Récupère les événements récents du journal APIC.
    
    Args:
        time_range: Plage temporelle en heures (défaut: 24h)
    
    Returns:
        Dict avec les événements récents
    """
    # Calculer le timestamp de début (time_range heures en arrière)
    import datetime
    end_time = datetime.datetime.now()
    start_time = end_time - datetime.timedelta(hours=time_range)
    
    # Format timestamp APIC
    start_ts = start_time.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
    
    result = _apic_request("api/node/class/eventRecord.json", params={
        "query-target-filter": f"gt(eventRecord.created,\"{start_ts}\")",
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

def get_apic_contracts(tenant: str = None) -> Dict[str, Any]:
    """
    Récupère les contrats de sécurité d'un tenant ou de tous les tenants.
    
    Args:
        tenant: Nom du tenant (optionnel)
    
    Returns:
        Dict avec les contrats
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
    
    result = _apic_request(endpoint, params=params)
    
    if "error" in result:
        return result
    
    contracts = []
    for item in result.get("imdata", []):
        contract_data = item.get("vzBrCP", {}).get("attributes", {})
        dn = contract_data.get("dn", "")
        
        # Extraire le tenant du DN
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

# ========== PHASE 2: MONITORING AVANCÉ ==========

def get_apic_cpu_utilization() -> Dict[str, Any]:
    """
    Récupère l'utilisation CPU de tous les nœuds du fabric.
    
    Returns:
        Dict avec l'utilisation CPU par nœud
    """
    result = _apic_request("api/node/class/procSysCPU5min.json", params={
        "order-by": "procSysCPU5min.dn"
    })
    
    if "error" in result:
        return result
    
    cpu_data = []
    for item in result.get("imdata", []):
        cpu_info = item.get("procSysCPU5min", {}).get("attributes", {})
        dn = cpu_info.get("dn", "")
        
        # Extraire l'ID du nœud du DN
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
    
    # Calculer les moyennes globales
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

def get_apic_epg_endpoints(tenant: str, application: str, epg: str) -> Dict[str, Any]:
    """
    Récupère les endpoints d'un EPG spécifique.
    
    Args:
        tenant: Nom du tenant
        application: Nom de l'application
        epg: Nom de l'EPG
    
    Returns:
        Dict avec les endpoints de l'EPG
    """
    endpoint = f"api/node/mo/uni/tn-{tenant}/ap-{application}/epg-{epg}.json"
    params = {
        "query-target": "subtree",
        "target-subtree-class": "fvCEp"
    }
    
    result = _apic_request(endpoint, params=params)
    
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

def get_apic_fabric_topology() -> Dict[str, Any]:
    """
    Récupère la topologie du fabric ACI.
    
    Returns:
        Dict avec la topologie du fabric
    """
    # Récupérer les nœuds
    nodes_result = _apic_request("api/node/class/fabricNode.json")
    if "error" in nodes_result:
        return nodes_result
    
    # Récupérer les liens
    links_result = _apic_request("api/node/class/fabricLink.json")
    
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

def get_apic_traffic_analysis(tenant: str = None, epg: str = None) -> Dict[str, Any]:
    """
    Analyse le trafic pour un tenant ou EPG spécifique.
    
    Args:
        tenant: Nom du tenant (optionnel)
        epg: Nom de l'EPG (optionnel)
    
    Returns:
        Dict avec l'analyse de trafic
    """
    if tenant and epg:
        # Statistiques spécifiques à un EPG
        endpoint = f"api/node/class/l2IngrBytesAg5min.json"
        params = {
            "query-target-filter": f"and(wcard(l2IngrBytesAg5min.dn,\"tn-{tenant}\"),wcard(l2IngrBytesAg5min.dn,\"epg-{epg}\"))"
        }
    elif tenant:
        # Statistiques du tenant
        endpoint = f"api/node/class/l2IngrBytesAg5min.json"
        params = {
            "query-target-filter": f"wcard(l2IngrBytesAg5min.dn,\"tn-{tenant}\")"
        }
    else:
        # Vue globale limitée
        endpoint = "api/node/class/l2IngrBytesAg5min.json"
        params = {"page-size": "20"}
    
    result = _apic_request(endpoint, params=params)
    
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

def get_apic_lldp_neighbors(node_id: str = None) -> Dict[str, Any]:
    """
    Récupère les voisins LLDP pour un nœud ou tous les nœuds.
    
    Args:
        node_id: ID du nœud (optionnel)
    
    Returns:
        Dict avec les voisins LLDP
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
    
    result = _apic_request(endpoint, params=params)
    
    if "error" in result:
        return result
    
    neighbors = []
    for item in result.get("imdata", []):
        adj_data = item.get("lldpAdjEp", {}).get("attributes", {})
        dn = adj_data.get("dn", "")
        
        # Extraire l'ID du nœud et l'interface du DN
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

def get_apic_audit_logs(hours: int = 24) -> Dict[str, Any]:
    """
    Récupère les logs d'audit des changements de configuration.
    
    Args:
        hours: Nombre d'heures en arrière (défaut: 24h)
    
    Returns:
        Dict avec les logs d'audit
    """
    # Calculer le timestamp
    import datetime
    end_time = datetime.datetime.now()
    start_time = end_time - datetime.timedelta(hours=hours)
    start_ts = start_time.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
    
    result = _apic_request("api/node/class/aaaModLR.json", params={
        "query-target-filter": f"gt(aaaModLR.created,\"{start_ts}\")",
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
        
        # Compter l'activité par utilisateur
        user_activity[user] = user_activity.get(user, 0) + 1
    
    return {
        "time_range_hours": hours,
        "total_changes": len(audit_entries),
        "unique_users": len(user_activity),
        "user_activity": dict(sorted(user_activity.items(), key=lambda x: x[1], reverse=True)),
        "audit_logs": audit_entries
    }

# ========== PHASE 3: ANALYTIQUE ==========

def get_apic_endpoint_tracker(mac_or_ip: str) -> Dict[str, Any]:
    """
    Suit un endpoint spécifique par son adresse MAC ou IP.
    
    Args:
        mac_or_ip: Adresse MAC ou IP de l'endpoint
    
    Returns:
        Dict avec les informations de tracking de l'endpoint
    """
    # Déterminer si c'est une MAC ou une IP
    is_mac = ":" in mac_or_ip or "-" in mac_or_ip
    
    if is_mac:
        # Normaliser l'adresse MAC (format APIC : XX:XX:XX:XX:XX:XX)
        mac_clean = mac_or_ip.replace("-", ":").upper()
        filter_query = f"eq(fvCEp.mac,\"{mac_clean}\")"
    else:
        # Recherche par IP
        filter_query = f"eq(fvCEp.ip,\"{mac_or_ip}\")"
    
    result = _apic_request("api/node/class/fvCEp.json", params={
        "query-target-filter": filter_query
    })
    
    if "error" in result:
        return result
    
    endpoints = []
    for item in result.get("imdata", []):
        ep_data = item.get("fvCEp", {}).get("attributes", {})
        dn = ep_data.get("dn", "")
        
        # Extraire tenant, app, epg du DN
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

def get_apic_path_analysis(src_epg: str, dst_epg: str) -> Dict[str, Any]:
    """
    Analyse les chemins réseau entre deux EPGs.
    
    Args:
        src_epg: DN ou nom de l'EPG source
        dst_epg: DN ou nom de l'EPG destination
    
    Returns:
        Dict avec l'analyse des chemins
    """
    # Cette fonction nécessite une analyse plus complexe
    # Pour l'instant, on récupère les contrats entre les EPGs
    
    # Récupérer tous les contrats
    contracts_result = _apic_request("api/node/class/vzBrCP.json")
    if "error" in contracts_result:
        return contracts_result
    
    # Récupérer les relations consumer/provider
    consumer_result = _apic_request("api/node/class/fvRsCons.json")
    provider_result = _apic_request("api/node/class/fvRsProv.json")
    
    path_info = {
        "source_epg": src_epg,
        "destination_epg": dst_epg,
        "contracts_found": [],
        "connectivity_status": "unknown"
    }
    
    if "error" not in consumer_result and "error" not in provider_result:
        consumers = consumer_result.get("imdata", [])
        providers = provider_result.get("imdata", [])
        
        # Analyser les relations (simplifié pour cette version)
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
    
    # Déterminer le statut de connectivité
    if path_info["contracts_found"]:
        path_info["connectivity_status"] = "contracts_exist"
    else:
        path_info["connectivity_status"] = "no_contracts_found"
    
    return path_info

def get_apic_top_talkers() -> Dict[str, Any]:
    """
    Identifie les principales conversations réseau (top talkers).
    
    Returns:
        Dict avec les top talkers
    """
    # Récupérer les statistiques de trafic récentes
    result = _apic_request("api/node/class/l2IngrBytesAg5min.json", params={
        "order-by": "l2IngrBytesAg5min.bytesAvg|desc",
        "page-size": "20"
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
        
        # Extraire des informations du DN
        tenant = epg = ""
        dn_parts = dn.split("/")
        for part in dn_parts:
            if part.startswith("tn-"):
                tenant = part[3:]
            elif part.startswith("epg-"):
                epg = part[3:]
        
        top_talkers.append({
            "dn": dn,
            "tenant": tenant,
            "epg": epg,
            "bytes_avg": bytes_avg,
            "bytes_max": int(stats.get("bytesMax", 0)),
            "packets_avg": int(stats.get("pktsAvg", 0)),
            "utilization_pct": 0  # Calculé après
        })
    
    # Calculer les pourcentages d'utilisation
    if total_traffic > 0:
        for talker in top_talkers:
            talker["utilization_pct"] = round((talker["bytes_avg"] / total_traffic) * 100, 2)
    
    return {
        "total_entries": len(top_talkers),
        "total_traffic_bytes": total_traffic,
        "top_talkers": top_talkers
    }

def get_apic_resource_utilization() -> Dict[str, Any]:
    """
    Analyse l'utilisation des ressources pour la planification de capacité.
    
    Returns:
        Dict avec l'utilisation des ressources
    """
    # Récupérer les statistiques système
    cpu_result = _apic_request("api/node/class/procSysCPU5min.json")
    memory_result = _apic_request("api/node/class/procSysMem5min.json")
    
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
    
    # Traiter les données CPU
    if "error" not in cpu_result:
        cpu_total = 0
        cpu_count = 0
        
        for item in cpu_result.get("imdata", []):
            cpu_info = item.get("procSysCPU5min", {}).get("attributes", {})
            dn = cpu_info.get("dn", "")
            idle_avg = float(cpu_info.get("idleAvg", 100))
            cpu_usage = round(100 - idle_avg, 2)
            
            # Extraire l'ID du nœud
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
            
            # Identifier les nœuds à forte utilisation CPU (>80%)
            if cpu_usage > 80:
                resource_data["summary"]["high_cpu_nodes"].append({
                    "node_id": node_id,
                    "cpu_usage": cpu_usage
                })
        
        if cpu_count > 0:
            resource_data["summary"]["avg_cpu_usage"] = round(cpu_total / cpu_count, 2)
            resource_data["summary"]["nodes_monitored"] = cpu_count
    
    # Traiter les données mémoire
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
                
                # Extraire l'ID du nœud
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
                
                # Identifier les nœuds à forte utilisation mémoire (>85%)
                if memory_usage > 85:
                    resource_data["summary"]["high_memory_nodes"].append({
                        "node_id": node_id,
                        "memory_usage": memory_usage
                    })
        
        if memory_count > 0:
            resource_data["summary"]["avg_memory_usage"] = round(memory_total / memory_count, 2)
    
    return resource_data

# ========== FONCTIONNALITE MULTICAST BRIDGE DOMAINS ==========

def get_apic_bridge_domains_multicast() -> Dict[str, Any]:
    """
    Récupère les informations multicast des bridge domaines (fvBD) avec
    les adresses GIPo multicast (bcastP) et configuration multicast.

    Returns:
        Dict avec les informations multicast des bridge domaines incluant bcastP
    """
    # Récupérer les bridge domains avec attributs multicast complets
    result = _apic_request("api/node/class/fvBD.json", params={
        "rsp-subtree": "full",
        "rsp-subtree-include": "required"
    })

    if "error" in result:
        return result

    bridge_domains = []
    multicast_enabled_count = 0
    igmp_enabled_count = 0

    for item in result.get("imdata", []):
        bd_data = item.get("fvBD", {}).get("attributes", {})
        dn = bd_data.get("dn", "")

        # Extraire tenant du DN
        tenant_name = ""
        dn_parts = dn.split("/")
        for part in dn_parts:
            if part.startswith("tn-"):
                tenant_name = part[3:]
                break

        # Informations de base du bridge domain avec GIPo
        gipo_address = bd_data.get("bcastP", "")

        bd_info = {
            "name": bd_data.get("name", ""),
            "dn": dn,
            "tenant": tenant_name,
            "description": bd_data.get("descr", ""),
            "gipo_multicast_address": gipo_address,  # Adresse GIPo multicast (/28)
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

        # Analyser les enfants (subnets)
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

                # Vérifier si c'est une adresse multicast (224.0.0.0/4 pour IPv4)
                ip_addr = subnet_data.get("ip", "").split("/")[0]
                if ip_addr:
                    try:
                        import ipaddress
                        ip_obj = ipaddress.ip_address(ip_addr)
                        if ip_obj.is_multicast:
                            bd_info["multicast_addresses"].append({
                                "address": ip_addr,
                                "subnet": subnet_data.get("ip", ""),
                                "description": subnet_data.get("descr", ""),
                                "type": "subnet_multicast"
                            })
                    except (ValueError, KeyError):
                        pass

        # Ajouter l'adresse GIPo comme adresse multicast si elle existe
        if gipo_address:
            bd_info["multicast_addresses"].append({
                "address": gipo_address.split("/")[0] if "/" in gipo_address else gipo_address,
                "subnet": gipo_address,
                "description": "GIPo (Group IP Outer) - BUM traffic forwarding",
                "type": "gipo"
            })

        # Déterminer si le multicast est activé sur ce BD
        bd_info["multicast_enabled"] = (
            bd_info["multicast_allow"] in ["bd-flood", "encap-flood"] or
            len(bd_info["multicast_addresses"]) > 0 or
            bd_info["unk_mcast_act"] == "flood" or
            bd_info["ipv6_mcast_allow"] == "yes" or
            bd_info["gipo_configured"]
        )

        # Compter les BDs avec multicast activé
        if bd_info["multicast_enabled"]:
            multicast_enabled_count += 1

        # IGMP snooping activé par défaut sur ACI
        if bd_info["unk_mcast_act"] == "flood":
            igmp_enabled_count += 1

        bridge_domains.append(bd_info)

    # Récupérer aussi les groupes multicast configurés séparément
    multicast_groups_result = _apic_request("api/node/class/igmpGroup.json")
    igmp_groups = []
    if "error" not in multicast_groups_result:
        for item in multicast_groups_result.get("imdata", []):
            group_data = item.get("igmpGroup", {}).get("attributes", {})
            igmp_groups.append({
                "group_address": group_data.get("addr", ""),
                "source": group_data.get("src", ""),
                "dn": group_data.get("dn", "")
            })

    # Récupérer les adresses multicast statiques
    static_mcast_result = _apic_request("api/node/class/igmpStaticGroup.json")
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
        "igmp_groups_learned": len(igmp_groups),
        "static_multicast_groups": len(static_groups),
        "bridge_domains": sorted(bridge_domains, key=lambda x: (x["tenant"], x["name"])),
        "discovered_igmp_groups": igmp_groups[:10],  # Limiter à 10 pour l'affichage
        "configured_static_groups": static_groups
    }

def get_apic_bridge_domain_multicast_by_tenant(tenant: str) -> Dict[str, Any]:
    """
    Récupère les informations multicast des bridge domaines pour un tenant spécifique.

    Args:
        tenant: Nom du tenant

    Returns:
        Dict avec les informations multicast des bridge domaines du tenant
    """
    endpoint = f"api/node/mo/uni/tn-{tenant}.json"
    params = {
        "query-target": "subtree",
        "target-subtree-class": "fvBD",
        "rsp-subtree": "full",
        "rsp-subtree-include": "required"
    }

    result = _apic_request(endpoint, params=params)

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

        # Analyser les subnets pour les adresses multicast
        children = item["fvBD"].get("children", [])
        for child in children:
            if "fvSubnet" in child:
                subnet_data = child["fvSubnet"]["attributes"]
                ip_addr = subnet_data.get("ip", "").split("/")[0]

                if ip_addr:
                    try:
                        import ipaddress
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
                    except (ValueError, KeyError):
                        pass

        # Ajouter l'adresse GIPo comme adresse multicast principale
        if gipo_address:
            gipo_info = {
                "address": gipo_address.split("/")[0] if "/" in gipo_address else gipo_address,
                "subnet": gipo_address,
                "description": "GIPo (Group IP Outer) - Adresse multicast pour trafic BUM",
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

# Ancienne fonction multicast_summary supprimée - remplacée par les fonctions GIPo corrigées

# Ancienne fonction multicast_addresses supprimée - ne récupérait pas les GIPo correctement

# Ancienne fonction multicast_statistics supprimée - données incomplètes sans les GIPo

def get_apic_gipo_pool_config() -> Dict[str, Any]:
    """
    Récupère la configuration du pool GIPo global depuis fabricSetupP.

    Returns:
        Dict avec la configuration du pool multicast GIPo
    """
    result = _apic_request("api/node/class/fabricSetupP.json")

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

        # Récupérer les pools principaux
        if pool_info["bd_gipo_pool"]:
            gipo_config["bd_gipo_pool"] = pool_info["bd_gipo_pool"]
            gipo_config["pool_configured"] = True

        if pool_info["vrf_gipo_pool"]:
            gipo_config["vrf_gipo_pool"] = pool_info["vrf_gipo_pool"]

        # Pool général (utilise BD GIPo par défaut)
        if not gipo_config["gipo_pool"] and pool_info["bd_gipo_pool"]:
            gipo_config["gipo_pool"] = pool_info["bd_gipo_pool"]

    return gipo_config

# ========== FONCTIONS MANQUANTES DU CONNECTEUR AVANCE ==========

def get_apic_vrfs(tenant: str = None) -> Dict[str, Any]:
    """
    Récupère les VRFs (Virtual Routing and Forwarding) d'un tenant ou tous.

    Args:
        tenant: Nom du tenant (optionnel)

    Returns:
        Dict avec les VRFs
    """
    if tenant:
        result = _apic_request(f"api/node/mo/uni/tn-{tenant}.json", params={
            "query-target": "children",
            "target-subtree-class": "fvCtx"
        })
    else:
        result = _apic_request("api/node/class/fvCtx.json")

    if "error" in result:
        return result

    vrfs = []
    for item in result.get("imdata", []):
        vrf_data = item.get("fvCtx", {}).get("attributes", {})
        dn = vrf_data.get("dn", "")

        # Extraire le tenant du DN
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

def get_apic_physical_interfaces(node_id: str = None) -> Dict[str, Any]:
    """
    Récupère les interfaces physiques d'un nœud ou de tous les nœuds.

    Args:
        node_id: ID du nœud (optionnel)

    Returns:
        Dict avec les interfaces physiques
    """
    if node_id:
        result = _apic_request(f"api/node/mo/topology/pod-1/node-{node_id}.json", params={
            "query-target": "children",
            "target-subtree-class": "l1PhysIf"
        })
    else:
        result = _apic_request("api/node/class/l1PhysIf.json", params={"page-size": "100"})

    if "error" in result:
        return result

    interfaces = []
    for item in result.get("imdata", []):
        if_data = item.get("l1PhysIf", {}).get("attributes", {})
        dn = if_data.get("dn", "")

        # Extraire l'ID du nœud du DN
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

def search_apic_by_ip(ip_address: str) -> Dict[str, Any]:
    """
    Recherche des objets APIC par adresse IP.

    Args:
        ip_address: Adresse IP à rechercher

    Returns:
        Dict avec les résultats de recherche
    """
    results = {
        "ip_searched": ip_address,
        "endpoints": [],
        "subnets": [],
        "interfaces": []
    }

    # Rechercher les endpoints avec cette IP
    endpoints_result = _apic_request("api/node/class/fvCEp.json", params={
        "query-target-filter": f'eq(fvCEp.ip,"{ip_address}")'
    })

    if "error" not in endpoints_result:
        for item in endpoints_result.get("imdata", []):
            ep_data = item.get("fvCEp", {}).get("attributes", {})
            dn = ep_data.get("dn", "")

            # Extraire tenant, app, epg du DN
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

    # Rechercher les subnets contenant cette IP
    subnets_result = _apic_request("api/node/class/fvSubnet.json", params={
        "query-target-filter": f'wcard(fvSubnet.ip,"{ip_address.split(".")[0]}.{ip_address.split(".")[1]}")'
    })

    if "error" not in subnets_result:
        for item in subnets_result.get("imdata", []):
            subnet_data = item.get("fvSubnet", {}).get("attributes", {})
            subnet_ip = subnet_data.get("ip", "")

            # Vérifier si l'IP est dans ce subnet
            try:
                import ipaddress
                subnet_net = ipaddress.ip_network(subnet_ip, strict=False)
                search_ip = ipaddress.ip_address(ip_address)
                if search_ip in subnet_net:
                    dn = subnet_data.get("dn", "")

                    # Extraire tenant et BD du DN
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
            except (ValueError, KeyError, IndexError):
                pass

    return results

def get_apic_capacity_metrics() -> Dict[str, Any]:
    """
    Récupère les métriques de capacité du fabric APIC.

    Returns:
        Dict avec les métriques de capacité
    """
    result = _apic_request("api/node/class/eqptcapacityEntity.json")

    if "error" in result:
        return result

    capacity_metrics = []
    for item in result.get("imdata", []):
        cap_data = item.get("eqptcapacityEntity", {}).get("attributes", {})
        dn = cap_data.get("dn", "")

        # Extraire l'ID du nœud
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

def get_apic_health_scores() -> Dict[str, Any]:
    """
    Récupère les scores de santé des objets APIC.

    Returns:
        Dict avec les scores de santé
    """
    result = _apic_request("api/node/class/healthInst.json", params={
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

        # Classification de santé
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

def analyze_apic_connectivity() -> Dict[str, Any]:
    """
    Analyse complète de la connectivité et santé de l'infrastructure APIC.

    Returns:
        Dict avec l'analyse complète
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
        # Test de connectivité de base
        system_info = _apic_request("api/node/class/topSystem.json", params={
            "query-target-filter": 'eq(topSystem.role,"controller")'
        })

        if "error" not in system_info:
            controllers = system_info.get("imdata", [])
            analysis["connectivity"]["controllers_count"] = len(controllers)
            analysis["connectivity"]["apic_reachable"] = True

            if controllers:
                first_controller = controllers[0].get("topSystem", {}).get("attributes", {})
                analysis["connectivity"]["apic_version"] = first_controller.get("version", "Unknown")

        # Récupérer la santé du fabric
        fabric_nodes = _apic_request("api/node/class/fabricNode.json")
        if "error" not in fabric_nodes:
            nodes = fabric_nodes.get("imdata", [])
            analysis["fabric_health"]["total_nodes"] = len(nodes)
            analysis["fabric_health"]["nodes_online"] = sum(
                1 for node in nodes
                if node.get("fabricNode", {}).get("attributes", {}).get("fabricSt") == "active"
            )

        # Récupérer les faults critiques
        critical_faults = get_apic_faults()
        if "error" not in critical_faults:
            analysis["fabric_health"]["critical_faults"] = critical_faults.get("severity_breakdown", {}).get("critical", 0)
            analysis["fabric_health"]["total_faults"] = critical_faults.get("total_faults", 0)

        # Analyse multicast
        multicast_summary = get_apic_bridge_domains_multicast()
        if "error" not in multicast_summary:
            analysis["multicast"] = {
                "enabled_domains": multicast_summary.get("multicast_enabled_domains", 0),
                "total_domains": multicast_summary.get("total_bridge_domains", 0),
                "percentage_enabled": round(
                    (multicast_summary.get("multicast_enabled_domains", 0) /
                     max(multicast_summary.get("total_bridge_domains", 1), 1)) * 100, 2
                )
            }

        # Analyse de capacité (si disponible)
        try:
            capacity_metrics = get_apic_capacity_metrics()
            if "error" not in capacity_metrics:
                metrics = capacity_metrics.get("capacity_metrics", [])
                if metrics:
                    avg_utilization = sum(m["utilization_percent"] for m in metrics) / len(metrics)
                    analysis["capacity"]["average_utilization"] = round(avg_utilization, 2)
                    analysis["capacity"]["high_utilization_nodes"] = [
                        m["node_id"] for m in metrics if m["utilization_percent"] > 80
                    ]
        except Exception as e:
            analysis["capacity"]["status"] = f"unavailable: {str(e)}"

    except Exception as e:
        analysis["status"] = "error"
        analysis["error_message"] = str(e)

    return analysis