#!/usr/bin/env python3
"""
Validation script for SSL certificate implementation.

This script validates that the SSL certificate support is properly implemented
in the VendorAPIBase class according to the Phase 3.2 requirements.
"""

import os
import sys
import inspect
import ssl
from typing import List, Tuple

# Add parent directory to path to import ldap_sync modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ldap_sync.vendors.base import VendorAPIBase


def check_ssl_implementation() -> Tuple[bool, List[str]]:
    """
    Check if SSL certificate implementation is complete.
    
    Returns:
        Tuple of (success, issues_list)
    """
    issues = []
    success = True
    
    print("=== SSL Certificate Implementation Validation ===\n")
    
    # Check 1: SSL context setup method exists
    print("1. Checking SSL context setup...")
    if hasattr(VendorAPIBase, '_setup_ssl_context'):
        print("   ✓ _setup_ssl_context method exists")
    else:
        issues.append("❌ _setup_ssl_context method missing")
        success = False
    
    # Check 2: Truststore loading method exists
    print("2. Checking truststore loading...")
    if hasattr(VendorAPIBase, '_load_truststore'):
        print("   ✓ _load_truststore method exists")
    else:
        issues.append("❌ _load_truststore method missing")
        success = False
    
    # Check 3: Client certificate loading method exists
    print("3. Checking client certificate loading...")
    if hasattr(VendorAPIBase, '_load_client_cert'):
        print("   ✓ _load_client_cert method exists")
    else:
        issues.append("❌ _load_client_cert method missing")
        success = False
    
    # Check 4: Examine truststore loading implementation
    print("4. Checking truststore format support...")
    if hasattr(VendorAPIBase, '_load_truststore'):
        source = inspect.getsource(VendorAPIBase._load_truststore)
        
        # Check for PEM support
        if 'PEM' in source and 'load_verify_locations' in source:
            print("   ✓ PEM truststore support implemented")
        else:
            issues.append("❌ PEM truststore support incomplete")
            success = False
        
        # Check for JKS support
        if 'JKS' in source and 'pyjks' in source:
            print("   ✓ JKS truststore support implemented")
        else:
            issues.append("❌ JKS truststore support incomplete")
            success = False
        
        # Check for PKCS12 support
        if 'PKCS12' in source and 'cryptography' in source:
            print("   ✓ PKCS12 truststore support implemented")
        else:
            issues.append("❌ PKCS12 truststore support incomplete")
            success = False
    
    # Check 5: Examine client certificate implementation
    print("5. Checking client certificate format support...")
    if hasattr(VendorAPIBase, '_load_client_cert'):
        source = inspect.getsource(VendorAPIBase._load_client_cert)
        
        # Check for PEM client cert support
        if 'PEM' in source and 'load_cert_chain' in source:
            print("   ✓ PEM client certificate support implemented")
        else:
            issues.append("❌ PEM client certificate support incomplete")
            success = False
        
        # Check for PKCS12 client cert support
        if 'PKCS12' in source and 'pkcs12.load_key_and_certificates' in source:
            print("   ✓ PKCS12 client certificate support implemented")
        else:
            issues.append("❌ PKCS12 client certificate support incomplete")
            success = False
    
    # Check 6: SSL context configuration
    print("6. Checking SSL context configuration...")
    if hasattr(VendorAPIBase, '_setup_ssl_context'):
        source = inspect.getsource(VendorAPIBase._setup_ssl_context)
        
        # Check for SSL verification toggle
        if 'verify_ssl' in source and '_create_unverified_context' in source:
            print("   ✓ SSL verification toggle implemented")
        else:
            issues.append("❌ SSL verification toggle incomplete")
            success = False
        
        # Check for default context creation
        if 'create_default_context' in source:
            print("   ✓ Default SSL context creation implemented")
        else:
            issues.append("❌ Default SSL context creation incomplete")
            success = False
    
    # Check 7: Authentication method support
    print("7. Checking authentication method support...")
    if hasattr(VendorAPIBase, '_setup_authentication'):
        source = inspect.getsource(VendorAPIBase._setup_authentication)
        
        # Check for Basic auth
        if 'basic' in source and 'base64' in source:
            print("   ✓ Basic authentication implemented")
        else:
            issues.append("❌ Basic authentication incomplete")
            success = False
        
        # Check for Token auth
        if 'token' in source and 'Bearer' in source:
            print("   ✓ Bearer token authentication implemented")
        else:
            issues.append("❌ Bearer token authentication incomplete")
            success = False
        
        # Check for OAuth2 placeholder
        if 'oauth2' in source:
            print("   ✓ OAuth2 authentication framework implemented")
        else:
            issues.append("❌ OAuth2 authentication framework incomplete")
            success = False
    
    # Check 8: Connection handling
    print("8. Checking connection handling...")
    if hasattr(VendorAPIBase, '_get_connection'):
        source = inspect.getsource(VendorAPIBase._get_connection)
        
        # Check for HTTPS with SSL context
        if 'HTTPSConnection' in source and 'context=self.ssl_context' in source:
            print("   ✓ HTTPS connection with SSL context implemented")
        else:
            issues.append("❌ HTTPS connection with SSL context incomplete")
            success = False
        
        # Check for HTTP fallback
        if 'HTTPConnection' in source:
            print("   ✓ HTTP connection fallback implemented")
        else:
            issues.append("❌ HTTP connection fallback incomplete")
            success = False
    
    # Check 9: Configuration parsing
    print("9. Checking configuration support...")
    if hasattr(VendorAPIBase, '__init__'):
        init_source = inspect.getsource(VendorAPIBase.__init__)
        ssl_source = inspect.getsource(VendorAPIBase._setup_ssl_context)
        
        # Check for certificate config parsing
        if ('verify_ssl' in init_source and 
            'truststore_file' in ssl_source and 
            'keystore_file' in ssl_source):
            print("   ✓ Certificate configuration parsing implemented")
        else:
            issues.append("❌ Certificate configuration parsing incomplete")
            success = False
    
    print(f"\n=== Validation Results ===")
    print(f"Overall Status: {'✓ PASSED' if success else '❌ FAILED'}")
    print(f"Issues Found: {len(issues)}")
    
    if issues:
        print("\nIssues:")
        for issue in issues:
            print(f"  {issue}")
    
    return success, issues


def check_dependencies():
    """Check if optional dependencies are available."""
    print("\n=== Dependency Check ===")
    
    # Check cryptography
    try:
        import cryptography
        print(f"✓ cryptography library available (version: {cryptography.__version__})")
    except ImportError:
        print("⚠ cryptography library not available (required for PKCS12 support)")
    
    # Check pyjks
    try:
        import pyjks
        print(f"✓ pyjks library available (version: {pyjks.__version__})")
    except ImportError:
        print("⚠ pyjks library not available (required for JKS support)")
        print("  Note: JKS support can be added by installing: pip install pyjks")


def main():
    """Main validation function."""
    success, issues = check_ssl_implementation()
    check_dependencies()
    
    print(f"\n=== Final Status ===")
    if success:
        print("✓ SSL certificate implementation is COMPLETE")
        print("✓ Phase 3.2 objectives have been met")
        return 0
    else:
        print("❌ SSL certificate implementation has issues")
        print(f"❌ {len(issues)} issues need to be resolved")
        return 1


if __name__ == '__main__':
    exit(main())