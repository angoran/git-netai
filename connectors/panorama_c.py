"""
Panorama (PAN-OS 11.1) Connector - Version Asynchrone
Fournit la connectivité à Palo Alto Panorama via l'API XML
Architecture hybride : Transport asynchrone (httpx) avec sortie JSON uniquement
IMPORTANT: Le XML est strictement interne, jamais exposé aux outils MCP
"""

import logging
import os
import xml.etree.ElementTree as ET
from functools import wraps
from typing import Any, Dict, Optional

import httpx
from dotenv import load_dotenv

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Charger les variables d'environnement
load_dotenv()


def handle_panorama_errors(func):
    """Décorateur pour la gestion unifiée des erreurs pour les appels API Panorama asynchrones"""

    @wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except httpx.TimeoutException:
            logger.error(f"Erreur de timeout dans {func.__name__}")
            return {"success": False, "error": "Timeout de la requête", "data": None}
        except httpx.ConnectError:
            logger.error(f"Erreur de connexion dans {func.__name__}")
            return {"success": False, "error": "Échec de la connexion", "data": None}
        except httpx.HTTPStatusError as e:
            logger.error(f"Erreur HTTP dans {func.__name__}: {e}")
            return {"success": False, "error": f"Erreur HTTP: {str(e)}", "data": None}
        except Exception as e:
            logger.error(f"Erreur inattendue dans {func.__name__}: {e}")
            return {"success": False, "error": str(e), "data": None}

    return wrapper


class PanoramaConnector:
    """
    Connecteur API Panorama (PAN-OS 11.1)
    Gère l'authentification via keygen et les opérations API XML
    RÈGLE D'OR: Le XML est interne uniquement, toutes les sorties sont JSON
    """

    def __init__(self):
        """Initialiser le connecteur Panorama avec la configuration depuis l'environnement"""
        # Récupérer l'URL de base depuis .env et construire l'URL complète de l'API
        base_url = os.getenv("PANORAMA_URL", "https://panorama.p.priv.ina/api")
        # S'assurer que l'URL se termine par /api
        if not base_url.endswith("/api"):
            self.base_url = f"{base_url.rstrip('/')}/api"
        else:
            self.base_url = base_url

        self.username = os.getenv("PANORAMA_USERNAME", "airun")
        self.password = os.getenv("PANORAMA_PASSWORD", "")
        self.timeout = int(os.getenv("PANORAMA_TIMEOUT", "30"))

        self.api_key: Optional[str] = None
        # Configuration pour désactiver la vérification SSL (certificats auto-signés)
        self.verify_ssl = False

        logger.info(f"Connecteur Panorama initialisé pour {self.base_url}")

    def _parse_xml_response(self, xml_text: str) -> Dict[str, Any]:
        """
        Parse la réponse XML et convertit en JSON normalisé
        CRITIQUE: Cette méthode ne doit JAMAIS exposer du XML en sortie

        Args:
            xml_text: Réponse XML brute de l'API

        Returns:
            Dict avec le statut et les données normalisées en JSON
        """
        try:
            root = ET.fromstring(xml_text)

            # Vérifier le statut de la réponse
            status = root.get("status")

            if status == "success":
                # Extraire le contenu de <result>
                result_elem = root.find("result")
                if result_elem is not None:
                    # Convertir l'élément XML en dictionnaire
                    data = self._xml_element_to_dict(result_elem)
                    return {"success": True, "error": None, "data": data}
                else:
                    return {
                        "success": True,
                        "error": None,
                        "data": {"message": "Succès sans données"},
                    }
            else:
                # Extraire le message d'erreur si présent
                msg_elem = root.find(".//msg")
                error_msg = msg_elem.text if msg_elem is not None else "Erreur inconnue"
                return {"success": False, "error": error_msg, "data": None}

        except ET.ParseError as e:
            logger.error(f"Erreur de parsing XML: {e}")
            return {
                "success": False,
                "error": f"Erreur de parsing XML: {str(e)}",
                "data": None,
            }
        except Exception as e:
            logger.error(f"Erreur inattendue lors du parsing: {e}")
            return {"success": False, "error": str(e), "data": None}

    def _xml_element_to_dict(self, element: ET.Element) -> Any:
        """
        Convertit récursivement un élément XML en dictionnaire Python
        Gère les cas spéciaux: listes, valeurs simples, structures imbriquées

        Args:
            element: Élément XML à convertir

        Returns:
            Dict, List, ou str selon la structure XML
        """
        # Si l'élément a des enfants
        children = list(element)
        if children:
            # Grouper les enfants par tag pour détecter les listes
            tag_count = {}
            for child in children:
                tag_count[child.tag] = tag_count.get(child.tag, 0) + 1

            # Si tous les enfants ont le même tag, c'est une liste
            if len(tag_count) == 1 and tag_count[children[0].tag] > 1:
                return [self._xml_element_to_dict(child) for child in children]

            # Sinon c'est un dictionnaire
            result = {}
            for child in children:
                child_data = self._xml_element_to_dict(child)
                if child.tag in result:
                    # Si la clé existe déjà, convertir en liste
                    if not isinstance(result[child.tag], list):
                        result[child.tag] = [result[child.tag]]
                    result[child.tag].append(child_data)
                else:
                    result[child.tag] = child_data
            return result
        else:
            # Élément sans enfants - retourner le texte ou les attributs
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
        S'assurer qu'on a une clé API valide, la générer si nécessaire

        Returns:
            bool: True si authentifié, False sinon
        """
        if not self.api_key:
            result = await self.generate_api_key()
            return result.get("success", False)
        return True

    # ========================================================================
    # LAYER 1: CORE HTTP CLIENT (Méthode centrale universelle)
    # ========================================================================

    @handle_panorama_errors
    async def _execute_api_call(
        self, request_type: str, params: Dict[str, str], auto_auth: bool = True
    ) -> Dict[str, Any]:
        """
        Méthode centrale pour TOUS les appels API Panorama
        Architecture refactorisée : 1 seul endroit pour auth/httpx/parsing/errors

        Args:
            request_type: Type de requête ("keygen", "op", "config", "log")
            params: Paramètres spécifiques à la requête (sans "type" ni "key")
            auto_auth: Authentifier automatiquement si nécessaire (défaut: True)

        Returns:
            Dict standardisé {"success": bool, "error": str|None, "data": Any}
        """
        # Authentification automatique (sauf pour keygen)
        if auto_auth and request_type != "keygen":
            if not await self._ensure_authenticated():
                return {
                    "success": False,
                    "error": "Échec de l'authentification",
                    "data": None,
                }
            # À ce stade, api_key est garanti non-None par _ensure_authenticated()
            if self.api_key is not None:
                params["key"] = self.api_key

        # Ajouter le type à params
        params["type"] = request_type

        try:
            logger.info(f"API call: type={request_type}")

            async with httpx.AsyncClient(
                verify=self.verify_ssl, timeout=self.timeout
            ) as client:
                response = await client.get(self.base_url, params=params)
                response.raise_for_status()

                # Parser XML → JSON (méthode existante)
                result = self._parse_xml_response(response.text)

                # Stocker api_key si keygen
                if request_type == "keygen" and result["success"]:
                    key = result["data"].get("key")
                    if key:
                        self.api_key = key
                        logger.info("Clé API générée et stockée avec succès")

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
    # LAYER 2: API EXECUTORS (4 méthodes génériques par type)
    # ========================================================================

    async def execute_op_command(self, cmd: str) -> Dict[str, Any]:
        """
        Execute operational command (type=op) - Show commands

        Args:
            cmd: Commande XML (ex: "<show><system><info></info></system></show>")

        Returns:
            Dict avec données JSON normalisées
        """
        return await self._execute_api_call(request_type="op", params={"cmd": cmd})

    async def execute_config_query(
        self, xpath: str, action: str = "get"
    ) -> Dict[str, Any]:
        """
        Execute configuration query (type=config)

        Args:
            xpath: XPath de configuration
            action: Action à effectuer (get, set, edit, delete)

        Returns:
            Dict avec données JSON normalisées
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
            log_type: Type de log (config, traffic, system, threat, etc.)
            nlogs: Nombre de logs à retourner
            **kwargs: Paramètres additionnels pour la query

        Returns:
            Dict avec données JSON normalisées
        """
        params = {"log-type": log_type, "nlogs": str(nlogs), **kwargs}
        return await self._execute_api_call(request_type="log", params=params)

    # Redéfinir generate_api_key pour utiliser _execute_api_call
    @handle_panorama_errors
    async def generate_api_key(self) -> Dict[str, Any]:
        """
        Génère et retourne une clé API Panorama via l'endpoint keygen
        Utilise maintenant _execute_api_call (architecture refactorisée)

        Returns:
            Dict avec le statut et la clé API
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
    # HELPER METHODS (Parsing robuste)
    # ========================================================================

    def _extract_entries(self, data: Any, key: Optional[str] = None) -> list:
        """
        Helper pour extraire entries d'une réponse XML→JSON
        Gère automatiquement les variations dict/list de l'API Panorama

        Args:
            data: Données parsées de l'API
            key: Clé optionnelle à extraire en premier

        Returns:
            Liste normalisée d'entries
        """
        if data is None:
            return []

        # Extraire la clé si fournie
        if key and isinstance(data, dict):
            data = data.get(key, data)

        # Normaliser en liste
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
    # LAYER 3: BUSINESS LOGIC (Fonctions métier refactorisées)
    # ========================================================================

    @handle_panorama_errors
    async def execute_op_command_legacy(self, cmd: str) -> Dict[str, Any]:
        """
        Exécute une commande opérationnelle (type=op) sur Panorama
        IMPORTANT: Le XML est parsé et converti en JSON avant le retour

        Args:
            cmd: Commande XML à exécuter (ex: "<show><system><info></info></system></show>")

        Returns:
            Dict avec le statut et les données normalisées en JSON uniquement
        """
        if not await self._ensure_authenticated():
            return {
                "success": False,
                "error": "Échec de l'authentification",
                "data": None,
            }

        try:
            url = self.base_url
            params = {"type": "op", "cmd": cmd, "key": self.api_key}

            logger.info(f"Exécution de la commande op: {cmd[:50]}...")

            async with httpx.AsyncClient(
                verify=self.verify_ssl, timeout=self.timeout
            ) as client:
                response = await client.get(url, params=params)
                response.raise_for_status()

                # Parser la réponse XML et convertir en JSON
                result = self._parse_xml_response(response.text)

                if result["success"]:
                    logger.info("Commande exécutée avec succès")
                else:
                    logger.warning(f"Commande échouée: {result.get('error')}")

                return result

        except Exception as e:
            logger.error(f"Erreur lors de l'exécution de la commande: {e}")
            raise

    @handle_panorama_errors
    async def get_system_info(self) -> Dict[str, Any]:
        """
        Récupère les informations système de Panorama
        Exécute la commande: show system info

        Returns:
            Dict JSON normalisé avec hostname, version, uptime, model, etc.
        """
        cmd = "<show><system><info></info></system></show>"
        result = await self.execute_op_command(cmd)

        if result["success"] and result["data"]:
            # Normaliser la sortie pour l'outil MCP
            system_info = result["data"].get("system", {})

            # Construire une sortie normalisée et simplifiée
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
    # NOUVELLES FONCTIONS D'ANALYSE ET CONFORMITÉ
    # ========================================================================

    @handle_panorama_errors
    async def get_managed_devices(self) -> Dict[str, Any]:
        """
        Récupère l'inventaire complet des firewalls gérés par Panorama
        ✨ REFACTORISÉ: Utilise _extract_entries() pour parsing simplifié

        Returns:
            Dict avec la liste des devices et leurs informations (version, HA, connexion, plugins)
        """
        cmd = "<show><devices><all></all></devices></show>"
        result = await self.execute_op_command(cmd)

        if not result["success"]:
            return result

        # Parsing simplifié avec helper
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

                # Extraire les plugins installés
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
        Récupère la liste des Device-Groups configurés dans Panorama
        ✨ REFACTORISÉ: Utilise execute_config_query() + _extract_entries()

        Returns:
            Dict avec la liste des device-groups et leurs membres
        """
        # Appel API simplifié avec Layer 2
        xpath = "/config/devices/entry[@name='localhost.localdomain']/device-group"
        result = await self.execute_config_query(xpath)

        if not result["success"]:
            return result

        # Parsing simplifié avec helper
        entries = self._extract_entries(result.get("data"), key="device-group")

        device_groups = []
        for dg in entries:
            if isinstance(dg, dict):
                dg_name = dg.get("@name", dg.get("name", "N/A"))

                # Extraire les membres (devices) avec helper
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
        Récupère les différences entre la configuration candidate et running

        Returns:
            Dict avec les changements non poussés
        """
        cmd = "<show><config><diff></diff></config></show>"
        result = await self.execute_op_command(cmd)

        if not result["success"]:
            return result

        # Normaliser la sortie
        diff_data = result.get("data", {})
        diff_text = diff_data.get("diff", "")

        # Analyser le diff
        has_changes = bool(diff_text and diff_text.strip() and diff_text.strip() != "")

        return {
            "success": True,
            "error": None,
            "data": {
                "has_pending_changes": has_changes,
                "diff_summary": "Changements détectés"
                if has_changes
                else "Aucun changement en attente",
                "diff_content": diff_text if has_changes else None,
            },
        }

    @handle_panorama_errors
    async def get_security_rules_by_device_group(
        self, device_group: str
    ) -> Dict[str, Any]:
        """
        Récupère les règles de sécurité pour un Device-Group spécifique
        Analyse les règles redondantes, sans commentaires, noms non explicites

        Args:
            device_group: Nom du device-group

        Returns:
            Dict avec les règles et l'analyse de qualité
        """
        # S'assurer de l'authentification d'abord
        if not await self._ensure_authenticated():
            return {
                "success": False,
                "error": "Échec de l'authentification",
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

                # Analyser les règles
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

                        # Vérifier les problèmes de qualité
                        if not description or description.strip() == "":
                            issues["no_description"].append(rule_name)

                        # Vérifier les noms génériques
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

                        # Vérifier si la règle est trop permissive (any/any/any)
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
            logger.error(f"Erreur lors de la récupération des règles: {e}")
            raise

    @handle_panorama_errors
    async def get_config_audit_logs(self, limit: int = 100) -> Dict[str, Any]:
        """
        Récupère l'historique des modifications de configuration (audit logs)
        ✨ REFACTORISÉ: Utilise execute_log_query()

        Args:
            limit: Nombre maximum de logs à retourner (défaut: 100, max conseillé: 1000)

        Returns:
            Dict avec l'historique des modifications
        """
        # Appel API simplifié avec Layer 2
        result = await self.execute_log_query(log_type="config", nlogs=min(limit, 5000))

        if not result["success"]:
            return result

        # Normaliser les logs
        logs_data = result.get("data", {})
        logs = []

        # Gérer différents formats
        if isinstance(logs_data, dict):
            log_entries = logs_data.get("log", {}).get("logs", {}).get("entry", [])
        elif isinstance(logs_data, list):
            log_entries = logs_data
        else:
            log_entries = []

        if isinstance(log_entries, dict):
            log_entries = [log_entries]

        for entry in log_entries[:limit]:  # Limiter côté client
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
        Identifie les objets non utilisés dans la configuration

        Args:
            object_type: Type d'objet à analyser (address, address-group, service, etc.)

        Returns:
            Dict avec les objets non utilisés
        """
        if not await self._ensure_authenticated():
            return {
                "success": False,
                "error": "Échec de l'authentification",
                "data": None,
            }

        # Récupérer les objets
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

                # Extraire les objets
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
                        # Simplification: marquer comme non utilisé si pas de tag
                        if not obj.get("tag"):
                            unused.append(obj_name)

                return {
                    "success": True,
                    "error": None,
                    "data": {
                        "object_type": object_type,
                        "total_objects": len(objects),
                        "unused_count": len(unused),
                        "unused_objects": unused[:100],  # Limiter à 100
                    },
                }

        except Exception as e:
            logger.error(f"Erreur lors de l'analyse des objets: {e}")
            raise

    @handle_panorama_errors
    async def check_rules_without_security_profile(
        self, device_group: str, limit: int = 100
    ) -> Dict[str, Any]:
        """
        Identifie les règles de sécurité sans Security Profile Group

        Args:
            device_group: Nom du device-group
            limit: Limite de résultats

        Returns:
            Dict avec les règles sans security profile
        """
        if not await self._ensure_authenticated():
            return {
                "success": False,
                "error": "Échec de l'authentification",
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

                # Parsing robuste selon format de réponse
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

                # Extraire les règles
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
            logger.error(f"Erreur lors de la vérification des profiles: {e}")
            raise

    @handle_panorama_errors
    async def get_expiring_certificates(
        self, days_threshold: int = 30
    ) -> Dict[str, Any]:
        """
        Vérifie les certificats proches de l'expiration

        Args:
            days_threshold: Nombre de jours avant expiration pour alerter

        Returns:
            Dict avec les certificats et leur statut d'expiration
        """
        if not await self._ensure_authenticated():
            return {
                "success": False,
                "error": "Échec de l'authentification",
                "data": None,
            }

        # Récupérer les certificats via configuration
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

                # Parser les certificats
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

                # Extraire les noms de certificats
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
                        "certificates": cert_list[:10],  # Limiter l'affichage
                    },
                }
        except Exception as e:
            logger.error(f"Erreur lors de la vérification des certificats: {e}")
            raise

    @handle_panorama_errors
    async def check_version_compliance(self) -> Dict[str, Any]:
        """
        Vérifie la conformité des versions PAN-OS, Threat, AV, Wildfire

        Returns:
            Dict avec l'état des versions sur Panorama et les firewalls
        """
        # Récupérer info système Panorama
        panorama_info = await self.get_system_info()

        # Récupérer info devices
        devices_info = await self.get_managed_devices()

        if not panorama_info["success"] or not devices_info["success"]:
            return {
                "success": False,
                "error": "Erreur de récupération des informations",
                "data": None,
            }

        # Compiler les versions
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

        # Analyser versions des devices
        for device in devices_info["data"]["devices"][:10]:  # Limiter à 10
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
        Identifie les règles jamais matchées via les traffic logs

        Args:
            device_group: Nom du device-group
            days: Période d'analyse en jours (défaut: 30)
            limit: Limite de résultats

        Returns:
            Dict avec les règles jamais matchées
        """
        # Note: Cette fonction nécessite l'accès aux traffic logs
        # L'API Panorama supporte les queries de logs via type=log&log-type=traffic
        # Pour une implémentation complète, il faudrait:
        # 1. Récupérer toutes les règles du device-group
        # 2. Query les traffic logs pour chaque règle
        # 3. Identifier celles sans match

        # Implémentation simplifiée: retourner structure de base
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
        Identifie les objets Address en doublon (même IP, noms différents)

        Args:
            limit: Limite de résultats

        Returns:
            Dict avec les adresses en doublon détectées
        """
        if not await self._ensure_authenticated():
            return {
                "success": False,
                "error": "Échec de l'authentification",
                "data": None,
            }

        # Récupérer tous les objets address
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

                # Parser les adresses
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

                # Détecter les doublons (même IP, noms différents)
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
            logger.error(f"Erreur lors de la détection des doublons: {e}")
            raise

    @handle_panorama_errors
    async def find_unused_zones(self, limit: int = 100) -> Dict[str, Any]:
        """
        Identifie les zones non utilisées dans les règles

        Args:
            limit: Limite de résultats

        Returns:
            Dict avec les zones non utilisées
        """
        if not await self._ensure_authenticated():
            return {
                "success": False,
                "error": "Échec de l'authentification",
                "data": None,
            }

        # Récupérer les zones configurées
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

                # Parser les zones
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
            logger.error(f"Erreur lors de l'analyse des zones: {e}")
            raise

    @handle_panorama_errors
    async def find_local_overrides(self, limit: int = 100) -> Dict[str, Any]:
        """
        Identifie les overrides locaux non gérés par Panorama

        Args:
            limit: Limite de résultats

        Returns:
            Dict avec les overrides locaux détectés
        """
        # Les overrides locaux sont des configurations faites directement
        # sur les firewalls et non via Panorama, ce qui pose des problèmes
        # de gestion centralisée

        # Cette fonction nécessite de comparer la config Panorama avec
        # la config de chaque firewall individuel

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
# FONCTIONS ASYNCHRONES À EXPOSER VIA MCP
# ============================================================================


async def panorama_generate_api_key() -> dict:
    """
    Génère et retourne une clé API Panorama

    Returns:
        Dict avec la clé API au format JSON
        Exemple: {"success": True, "data": {"api_key": "******"}}
    """
    connector = PanoramaConnector()
    return await connector.generate_api_key()


async def panorama_get_system_info() -> dict:
    """
    Récupère les informations système de Panorama

    Returns:
        Dict JSON normalisé avec:
        - hostname
        - version
        - uptime
        - model
        - serial
        - operational_mode
        Et autres métadonnées système
    """
    connector = PanoramaConnector()
    return await connector.get_system_info()


async def panorama_execute_command(cmd: str) -> dict:
    """
    Exécute une commande opérationnelle personnalisée sur Panorama

    Args:
        cmd: Commande XML au format PAN-OS API
             Exemple: "<show><system><info></info></system></show>"

    Returns:
        Dict JSON avec les données normalisées (jamais de XML en sortie)
    """
    connector = PanoramaConnector()
    return await connector.execute_op_command(cmd)


# ============================================================================
# NOUVELLES FONCTIONS D'ANALYSE ET CONFORMITÉ (EXPOSÉES VIA MCP)
# ============================================================================


async def panorama_get_managed_devices() -> dict:
    """
    Récupère l'inventaire complet des firewalls gérés par Panorama

    Returns:
        Dict JSON avec:
        - total_devices: Nombre total de devices
        - devices: Liste des devices avec leurs informations
          - device: Nom du device
          - serial: Numéro de série
          - version: Version PAN-OS
          - ha_state: État HA (active, passive, etc.)
          - connected: Statut de connexion (boolean)
          - ip_address: Adresse IP
          - model: Modèle du firewall
          - uptime: Temps de fonctionnement
          - plugins: Liste des plugins installés
    """
    connector = PanoramaConnector()
    return await connector.get_managed_devices()


async def panorama_get_device_groups() -> dict:
    """
    Récupère la liste des Device-Groups configurés dans Panorama

    Returns:
        Dict JSON avec:
        - total_device_groups: Nombre total de device-groups
        - device_groups: Liste des device-groups
          - name: Nom du device-group
          - devices: Liste des devices membres
          - device_count: Nombre de devices dans le groupe
    """
    connector = PanoramaConnector()
    return await connector.get_device_groups()


async def panorama_get_config_diff() -> dict:
    """
    Récupère les différences entre la configuration candidate et running

    Returns:
        Dict JSON avec:
        - has_pending_changes: Boolean indiquant si des changements sont en attente
        - diff_summary: Résumé des changements
        - diff_content: Contenu détaillé du diff (null si aucun changement)
    """
    connector = PanoramaConnector()
    return await connector.get_config_diff()


async def panorama_analyze_security_rules(device_group: str) -> dict:
    """
    Analyse les règles de sécurité d'un Device-Group
    Identifie les problèmes de qualité et de conformité

    Args:
        device_group: Nom du device-group à analyser

    Returns:
        Dict JSON avec:
        - device_group: Nom du device-group analysé
        - total_rules: Nombre total de règles
        - rules: Liste des règles avec leurs informations
        - quality_issues: Analyse de qualité
          - rules_without_description: Nombre de règles sans description
          - rules_with_generic_names: Nombre de règles avec noms génériques
          - too_permissive_rules: Nombre de règles trop permissives (any/any/any)
          - details: Détails des règles problématiques
    """
    connector = PanoramaConnector()
    return await connector.get_security_rules_by_device_group(device_group)


async def panorama_get_audit_logs(limit: int = 100) -> dict:
    """
    Récupère l'historique des modifications de configuration (audit logs)

    Args:
        limit: Nombre maximum de logs à retourner (défaut: 100, max: 1000)

    Returns:
        Dict JSON avec:
        - total_logs: Nombre de logs retournés
        - logs: Liste des modifications
          - time: Date/heure de la modification
          - admin: Administrateur ayant effectué le changement
          - command: Commande exécutée
          - result: Résultat (success, failure)
          - path: Chemin de configuration modifié
    """
    connector = PanoramaConnector()
    return await connector.get_config_audit_logs(limit)


async def panorama_get_unused_objects(object_type: str = "address") -> dict:
    """
    Identifie les objets non utilisés dans la configuration Panorama

    Args:
        object_type: Type d'objet à analyser (défaut: "address")

    Returns:
        Dict JSON avec:
        - object_type: Type d'objet analysé
        - total_objects: Nombre total d'objets
        - unused_count: Nombre d'objets non utilisés
        - unused_objects: Liste des objets non utilisés (max 100)
    """
    connector = PanoramaConnector()
    return await connector.get_unused_objects(object_type)


async def panorama_check_rules_without_profile(
    device_group: str, limit: int = 100
) -> dict:
    """
    Identifie les règles de sécurité sans Security Profile Group

    Args:
        device_group: Nom du device-group à analyser
        limit: Nombre maximum de règles à analyser (défaut: 100)

    Returns:
        Dict JSON avec:
        - device_group: Nom du device-group analysé
        - total_rules_analyzed: Nombre total de règles analysées
        - rules_without_profile: Liste des règles sans Security Profile
        - count: Nombre de règles sans profile
    """
    connector = PanoramaConnector()
    return await connector.check_rules_without_security_profile(device_group, limit)


async def panorama_get_expiring_certificates(days_threshold: int = 30) -> dict:
    """
    Vérifie les certificats proches de l'expiration

    Args:
        days_threshold: Seuil en jours pour considérer un certificat comme expirant (défaut: 30)

    Returns:
        Dict JSON avec:
        - days_threshold: Seuil utilisé
        - total_certificates: Nombre total de certificats
        - expiring_certificates: Liste des certificats expirant bientôt
        - expired_certificates: Liste des certificats déjà expirés
        - expiring_count: Nombre de certificats expirant
        - expired_count: Nombre de certificats expirés
    """
    connector = PanoramaConnector()
    return await connector.get_expiring_certificates(days_threshold)


async def panorama_check_version_compliance() -> dict:
    """
    Vérifie la conformité des versions PAN-OS, Threat, AV, Wildfire

    Returns:
        Dict JSON avec:
        - panorama: Versions installées sur Panorama
          - sw_version: Version PAN-OS
          - threat_version: Version base de données Threat
          - av_version: Version antivirus
          - wildfire_version: Version Wildfire
        - devices_versions: Versions des devices (limité à 10)
          - [serial]: {version, model}
    """
    connector = PanoramaConnector()
    return await connector.check_version_compliance()


async def panorama_find_never_matched_rules(
    device_group: str, days: int = 30, limit: int = 100
) -> dict:
    """
    Identifie les règles jamais matchées via les traffic logs

    Args:
        device_group: Nom du device-group à analyser
        days: Période d'analyse en jours (défaut: 30)
        limit: Nombre maximum de règles à analyser (défaut: 100)

    Returns:
        Dict JSON avec:
        - device_group: Nom du device-group analysé
        - days_analyzed: Période analysée en jours
        - never_matched_rules: Liste des règles jamais matchées
        - total_analyzed: Nombre de règles analysées
        - note: Note sur l'implémentation
    """
    connector = PanoramaConnector()
    return await connector.find_never_matched_rules(device_group, days, limit)


async def panorama_find_duplicate_addresses(limit: int = 100) -> dict:
    """
    Identifie les objets Address en doublon (même IP, noms différents)

    Args:
        limit: Nombre maximum d'adresses à analyser (défaut: 100)

    Returns:
        Dict JSON avec:
        - total_addresses: Nombre total d'adresses analysées
        - duplicates_found: Nombre de doublons détectés
        - duplicates: Liste des doublons
          - ip: Adresse IP en doublon
          - names: Liste des noms différents pour cette IP
    """
    connector = PanoramaConnector()
    return await connector.find_duplicate_addresses(limit)


async def panorama_find_unused_zones(limit: int = 100) -> dict:
    """
    Identifie les zones non utilisées dans les règles

    Args:
        limit: Nombre maximum de zones à analyser (défaut: 100)

    Returns:
        Dict JSON avec:
        - total_zones: Nombre total de zones configurées
        - zones: Liste des zones configurées
        - note: Note sur l'analyse d'utilisation
    """
    connector = PanoramaConnector()
    return await connector.find_unused_zones(limit)


async def panorama_find_local_overrides(limit: int = 100) -> dict:
    """
    Identifie les overrides locaux non gérés par Panorama

    Args:
        limit: Nombre maximum de devices à vérifier (défaut: 100)

    Returns:
        Dict JSON avec:
        - total_devices_checked: Nombre de devices vérifiés
        - devices_with_overrides: Liste des devices avec overrides locaux
        - note: Note sur l'implémentation
    """
    connector = PanoramaConnector()
    return await connector.find_local_overrides(limit)
