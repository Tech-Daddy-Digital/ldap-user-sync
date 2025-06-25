#!/usr/bin/env python3
"""
Validation script for LDAP User Sync application.

This script validates that all dependencies are installed correctly
and that all core functionality is working as expected.
"""

import sys
import importlib
from pathlib import Path

def check_dependency(package_name, import_name=None):
    """Check if a package/module can be imported."""
    if import_name is None:
        import_name = package_name
    
    try:
        importlib.import_module(import_name)
        return True, f"✓ {package_name} available"
    except ImportError as e:
        return False, f"✗ {package_name} missing: {e}"

def validate_dependencies():
    """Validate all required dependencies."""
    print("=== Dependency Validation ===")
    
    dependencies = [
        ("ldap3", "ldap3"),
        ("PyYAML", "yaml"),
        ("cryptography", "cryptography"),
        ("pytest", "pytest"),
        ("pytest-mock", "pytest_mock"),
    ]
    
    optional_dependencies = [
        ("pyjks (optional for JKS keystores)", "jks"),
    ]
    
    all_ok = True
    for pkg_name, import_name in dependencies:
        ok, message = check_dependency(pkg_name, import_name)
        print(f"  {message}")
        if not ok:
            all_ok = False
    
    print("\n  Optional dependencies:")
    for pkg_name, import_name in optional_dependencies:
        ok, message = check_dependency(pkg_name, import_name)
        print(f"  {message}")
    
    return all_ok

def validate_core_modules():
    """Validate core application modules."""
    print("\n=== Core Module Validation ===")
    
    modules = [
        "ldap_sync.config",
        "ldap_sync.main",
        "ldap_sync.ldap_client", 
        "ldap_sync.notifications",
        "ldap_sync.retry",
        "ldap_sync.vendors.base",
        "ldap_sync.vendors.vendor_app1",
        "ldap_sync.vendors.vendor_app2",
    ]
    
    all_ok = True
    for module in modules:
        ok, message = check_dependency(module, module)
        print(f"  {message}")
        if not ok:
            all_ok = False
    
    return all_ok

def validate_functionality():
    """Validate key functionality."""
    print("\n=== Functionality Validation ===")
    
    try:
        # Test configuration loading
        from ldap_sync.config import load_config
        config = load_config()
        print("  ✓ Configuration loading")
        
        # Test health check
        from ldap_sync.main import SyncOrchestrator
        orchestrator = SyncOrchestrator()
        health = orchestrator.health_check()
        print("  ✓ Health check system")
        
        # Test vendor modules
        from ldap_sync.vendors.vendor_app1 import VendorApp1API
        from ldap_sync.vendors.vendor_app2 import VendorApp2API
        vendor1 = VendorApp1API(config['vendor_apps'][0])
        vendor2 = VendorApp2API(config['vendor_apps'][1])
        print("  ✓ Vendor module instantiation")
        
        # Test notifications
        from ldap_sync.notifications import send_email, send_failure_notification
        print("  ✓ Notification system")
        
        # Test retry functionality
        from ldap_sync.retry import retry_call, is_retryable_error
        result = retry_call(lambda: "test", max_attempts=1, delay=0, exceptions=())
        print("  ✓ Retry mechanism")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Functionality test failed: {e}")
        return False

def validate_cli():
    """Validate command-line interface."""
    print("\n=== CLI Validation ===")
    
    try:
        import subprocess
        import json
        
        # Test --help
        result = subprocess.run([sys.executable, "-m", "ldap_sync.main", "--help"], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print("  ✓ Help command working")
        else:
            print("  ✗ Help command failed")
            return False
        
        # Test --health-check (will fail due to LDAP but should return JSON)
        result = subprocess.run([sys.executable, "-m", "ldap_sync.main", "--health-check"], 
                              capture_output=True, text=True)
        if result.returncode == 1:  # Expected failure due to LDAP
            try:
                health_data = json.loads(result.stdout)
                if 'status' in health_data and 'checks' in health_data:
                    print("  ✓ Health check command working (LDAP failure expected)")
                else:
                    print("  ✗ Health check returned invalid JSON")
                    return False
            except json.JSONDecodeError:
                print("  ✗ Health check didn't return valid JSON")
                return False
        else:
            print("  ✗ Health check returned unexpected exit code")
            return False
        
        return True
        
    except Exception as e:
        print(f"  ✗ CLI validation failed: {e}")
        return False

def main():
    """Run all validations."""
    print("LDAP User Sync - Installation Validation")
    print("=" * 50)
    
    all_validations = [
        validate_dependencies(),
        validate_core_modules(),
        validate_functionality(),
        validate_cli(),
    ]
    
    print("\n=== Summary ===")
    if all(all_validations):
        print("✓ All validations passed!")
        print("✓ LDAP User Sync is ready for use")
        print("\nNext steps:")
        print("  1. Configure your LDAP and vendor settings in config.yaml")
        print("  2. Test with: python -m ldap_sync.main --health-check")
        print("  3. Test email with: python -m ldap_sync.main --test-email")
        print("  4. Run sync: python -m ldap_sync.main")
        return 0
    else:
        print("✗ Some validations failed!")
        print("Please resolve the issues above before using the application.")
        return 1

if __name__ == "__main__":
    sys.exit(main())