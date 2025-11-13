#!/usr/bin/env python3
"""
Smoke tests for the four new connectors.
Tests basic import and connectivity for each connector.
"""

import sys
from typing import Dict, Any
from dotenv import load_dotenv

# Force reload .env to get correct passwords with special characters
load_dotenv(override=True)


def test_librenms_connector() -> Dict[str, Any]:
    """Test LibreNMS connector import and basic functionality."""
    result = {
        "connector": "LibreNMS",
        "import_success": False,
        "connection_test": False,
        "error": None
    }

    try:
        from connectors.librenms_con import (
            _api_request,
            search_devices,
            get_statistics_by_field
        )
        result["import_success"] = True

        # Test basic API connectivity
        test_data = _api_request("devices")
        if "error" not in test_data:
            result["connection_test"] = True
            result["message"] = f"Successfully retrieved {len(test_data.get('devices', []))} devices"
        else:
            result["error"] = test_data["error"]

    except ImportError as e:
        result["error"] = f"Import error: {str(e)}"
    except Exception as e:
        result["error"] = f"Connection error: {str(e)}"

    return result


def test_graylog_connector() -> Dict[str, Any]:
    """Test Graylog connector import and basic functionality."""
    result = {
        "connector": "Graylog",
        "import_success": False,
        "connection_test": False,
        "error": None
    }

    try:
        from connectors.graylog_con import (
            get_system_overview,
            get_streams
        )
        result["import_success"] = True

        # Test basic API connectivity
        system_info = get_system_overview()
        if "error" not in system_info:
            result["connection_test"] = True
            result["message"] = f"Connected to Graylog: {system_info.get('hostname', 'unknown')}"
        else:
            result["error"] = system_info["error"]

    except ImportError as e:
        result["error"] = f"Import error: {str(e)}"
    except Exception as e:
        result["error"] = f"Connection error: {str(e)}"

    return result


def test_apic_connector() -> Dict[str, Any]:
    """Test Cisco APIC connector import and basic functionality."""
    result = {
        "connector": "Cisco APIC",
        "import_success": False,
        "connection_test": False,
        "error": None
    }

    try:
        from connectors.apic_con import (
            test_apic_connection,
            get_apic_fabric_health
        )
        result["import_success"] = True

        # Test basic API connectivity
        conn_test = test_apic_connection()
        if conn_test.get("status") == "success":
            result["connection_test"] = True
            result["message"] = f"Connected to APIC: {conn_test.get('host')}"
        else:
            result["error"] = conn_test.get("message", "Unknown error")

    except ImportError as e:
        result["error"] = f"Import error: {str(e)}"
    except Exception as e:
        result["error"] = f"Connection error: {str(e)}"

    return result


def test_aruba_connector() -> Dict[str, Any]:
    """Test Aruba WiFi Controller connector import and basic functionality."""
    result = {
        "connector": "Aruba WiFi",
        "import_success": False,
        "connection_test": False,
        "error": None
    }

    try:
        from connectors.aruba_con import ArubaConnector
        result["import_success"] = True

        # Test basic API connectivity
        connector = ArubaConnector()
        if connector.login():
            result["connection_test"] = True
            result["message"] = f"Connected to Aruba controller: {connector.base_url}"
            connector.logout()
        else:
            result["error"] = "Authentication failed"

    except ImportError as e:
        result["error"] = f"Import error: {str(e)}"
    except Exception as e:
        result["error"] = f"Connection error: {str(e)}"

    return result


def test_environment_variables() -> Dict[str, Any]:
    """Test that all required environment variables are loaded."""
    import os
    from dotenv import load_dotenv

    load_dotenv()

    required_vars = {
        "LibreNMS": ["LIBRENMS_API_URL", "LIBRENMS_TOKEN"],
        "Graylog": ["GRAYLOG_API_URL", "GRAYLOG_USERNAME", "GRAYLOG_PASSWORD"],
        "APIC": ["APIC_HOST", "APIC_USERNAME", "APIC_PASSWORD"],
        "Aruba": ["ARUBA_URL", "ARUBA_USERNAME", "ARUBA_PASSWORD"]
    }

    result = {
        "env_vars_loaded": True,
        "missing_vars": [],
        "configured_connectors": []
    }

    for connector, vars_list in required_vars.items():
        all_present = all(os.getenv(var) for var in vars_list)
        if all_present:
            result["configured_connectors"].append(connector)
        else:
            missing = [var for var in vars_list if not os.getenv(var)]
            result["missing_vars"].extend([(connector, var) for var in missing])
            result["env_vars_loaded"] = False

    return result


def run_all_tests():
    """Run all connector tests and display results."""
    print("=" * 70)
    print("CONNECTOR SMOKE TESTS - Phase 1")
    print("=" * 70)
    print()

    # Test environment variables first
    print("Testing environment variables...")
    env_result = test_environment_variables()
    print(f"✓ Environment variables configured: {', '.join(env_result['configured_connectors'])}")
    if env_result['missing_vars']:
        print(f"⚠ Missing variables:")
        for connector, var in env_result['missing_vars']:
            print(f"  - {connector}: {var}")
    print()

    # Test each connector
    connectors_tests = [
        ("LibreNMS", test_librenms_connector),
        ("Graylog", test_graylog_connector),
        ("Cisco APIC", test_apic_connector),
        ("Aruba WiFi", test_aruba_connector)
    ]

    results = []
    for name, test_func in connectors_tests:
        print(f"Testing {name} connector...")
        result = test_func()
        results.append(result)

        # Display result
        if result["import_success"]:
            print(f"  ✓ Import successful")
        else:
            print(f"  ✗ Import failed: {result['error']}")

        if result["connection_test"]:
            print(f"  ✓ Connection test passed")
            if result.get("message"):
                print(f"    {result['message']}")
        else:
            if result["error"]:
                print(f"  ✗ Connection test failed: {result['error']}")
        print()

    # Summary
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)

    total = len(results)
    import_success = sum(1 for r in results if r["import_success"])
    connection_success = sum(1 for r in results if r["connection_test"])

    print(f"Connectors tested: {total}")
    print(f"Import successful: {import_success}/{total}")
    print(f"Connection successful: {connection_success}/{total}")
    print()

    if import_success == total and connection_success == total:
        print("✓ All tests passed!")
        return 0
    else:
        print("⚠ Some tests failed. Check errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
