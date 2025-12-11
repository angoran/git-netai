#!/usr/bin/env python3
"""
Script de test complet pour le routeur MikroTik
Récupère les interfaces et les adresses IP
"""

import asyncio
import json
from connectors.mikrotik_c import get_interfaces, get_ip_address

async def main():
    """Récupère les interfaces et adresses IP du MikroTik"""

    router_ip = "10.140.3.251"

    print(f"🔍 Interrogation du routeur MikroTik: {router_ip}")
    print("=" * 80)

    # Récupération des interfaces et adresses IP en parallèle
    interfaces_result, ip_addresses_result = await asyncio.gather(
        get_interfaces(router_ip),
        get_ip_address(router_ip)
    )

    # Affichage des interfaces
    print("\n" + "=" * 80)
    print("📡 INTERFACES")
    print("=" * 80)

    if "error" in interfaces_result:
        print(f"❌ Erreur: {interfaces_result['error']}")
    else:
        print(f"Total interfaces: {interfaces_result.get('total_interfaces')}")
        print("\nDétail des interfaces:\n")
        for i, iface in enumerate(interfaces_result.get('interfaces', []), 1):
            status = "🟢 RUNNING" if iface.get('running') else "🔴 STOPPED"
            disabled = " (DISABLED)" if iface.get('disabled') else ""
            print(f"{i:2d}. {iface.get('name'):30s} {status}{disabled}")
            mtu = iface.get('mtu', '')
            print(f"    Type: {iface.get('type'):20s} MTU: {str(mtu):5s} MAC: {iface.get('mac_address')}")
            print()

    # Affichage des adresses IP
    print("=" * 80)
    print("🌐 ADRESSES IP")
    print("=" * 80)

    if "error" in ip_addresses_result:
        print(f"❌ Erreur: {ip_addresses_result['error']}")
    else:
        print(f"Total addresses: {ip_addresses_result.get('total_addresses')}")
        print("\nDétail des adresses IP:\n")
        for i, addr in enumerate(ip_addresses_result.get('addresses', []), 1):
            disabled = " (DISABLED)" if addr.get('disabled') != "false" and addr.get('disabled') != False else ""
            print(f"{i:2d}. {addr.get('address'):20s} → {addr.get('interface')}{disabled}")
            print(f"    Network: {addr.get('network')}")
            print()

    # Résumé JSON complet
    print("=" * 80)
    print("📄 RÉSUMÉ JSON COMPLET")
    print("=" * 80)

    full_result = {
        "router_ip": router_ip,
        "interfaces": interfaces_result,
        "ip_addresses": ip_addresses_result
    }

    print(json.dumps(full_result, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    asyncio.run(main())
