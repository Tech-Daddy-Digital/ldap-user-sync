#!/usr/bin/env python3
"""
Validation script for authentication implementation.

This script validates that all authentication methods are properly implemented
in the VendorAPIBase class according to the Phase 3.3 requirements.
"""

import os
import sys
import inspect
from typing import List, Tuple

# Add parent directory to path to import ldap_sync modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ldap_sync.vendors.base import VendorAPIBase


class MockVendorAPI(VendorAPIBase):
    """Simple mock implementation for testing."""
    
    def get_group_members(self, group_cfg):
        return []
    
    def add_user_to_group(self, group_cfg, user_info):
        return True
    
    def remove_user_from_group(self, group_cfg, user_identifier):
        return True
    
    def update_user(self, user_identifier, user_info):
        return True


def check_authentication_implementation() -> Tuple[bool, List[str]]:
    """
    Check if authentication implementation is complete.
    
    Returns:
        Tuple of (success, issues_list)
    """
    issues = []
    success = True
    
    print("=== Authentication Methods Implementation Validation ===\n")
    
    base_config = {
        'name': 'TestVendor',
        'base_url': 'https://api.example.com/v1',
        'format': 'json',
        'verify_ssl': True
    }
    
    # Test 1: Basic Authentication
    print("1. Testing HTTP Basic Authentication...")
    try:
        config = base_config.copy()
        config['auth'] = {
            'method': 'basic',
            'username': 'testuser',
            'password': 'testpass'
        }
        
        vendor = MockVendorAPI(config)
        
        if 'Authorization' in vendor.auth_headers:
            auth_header = vendor.auth_headers['Authorization']
            if auth_header.startswith('Basic '):
                print("   ✓ Basic authentication header correctly set")
            else:
                issues.append("❌ Basic authentication header format incorrect")
                success = False
        else:
            issues.append("❌ Basic authentication header not set")
            success = False
            
        # Test authenticate method
        if vendor.authenticate():
            print("   ✓ Basic authentication authenticate() method works")
        else:
            issues.append("❌ Basic authentication authenticate() method failed")
            success = False
            
    except Exception as e:
        issues.append(f"❌ Basic authentication setup failed: {e}")
        success = False
    
    # Test 2: Bearer Token Authentication
    print("2. Testing Bearer Token Authentication...")
    try:
        config = base_config.copy()
        config['auth'] = {
            'method': 'token',
            'token': 'abc123token'
        }
        
        vendor = MockVendorAPI(config)
        
        if 'Authorization' in vendor.auth_headers:
            auth_header = vendor.auth_headers['Authorization']
            if auth_header == 'Bearer abc123token':
                print("   ✓ Bearer token authentication header correctly set")
            else:
                issues.append("❌ Bearer token authentication header format incorrect")
                success = False
        else:
            issues.append("❌ Bearer token authentication header not set")
            success = False
            
        # Test authenticate method
        if vendor.authenticate():
            print("   ✓ Bearer token authentication authenticate() method works")
        else:
            issues.append("❌ Bearer token authentication authenticate() method failed")
            success = False
            
    except Exception as e:
        issues.append(f"❌ Bearer token authentication setup failed: {e}")
        success = False
    
    # Test 3: OAuth2 Configuration Validation
    print("3. Testing OAuth2 Configuration...")
    try:
        config = base_config.copy()
        config['auth'] = {
            'method': 'oauth2',
            'client_id': 'client123',
            'client_secret': 'secret456',
            'token_url': 'https://auth.example.com/token'
        }
        
        vendor = MockVendorAPI(config)
        
        # Check if OAuth2 methods exist
        if hasattr(vendor, '_oauth2_get_token'):
            print("   ✓ OAuth2 token retrieval method exists")
        else:
            issues.append("❌ OAuth2 token retrieval method missing")
            success = False
            
        if hasattr(vendor, '_is_oauth2_token_valid'):
            print("   ✓ OAuth2 token validation method exists")
        else:
            issues.append("❌ OAuth2 token validation method missing")
            success = False
            
        # OAuth2 should not set immediate auth headers (done in authenticate)
        if 'Authorization' not in vendor.auth_headers:
            print("   ✓ OAuth2 correctly defers token setup to authenticate()")
        else:
            print("   ⚠ OAuth2 unexpectedly set immediate auth headers")
            
    except Exception as e:
        issues.append(f"❌ OAuth2 configuration setup failed: {e}")
        success = False
    
    # Test 4: Mutual TLS Authentication
    print("4. Testing Mutual TLS Authentication...")
    try:
        config = base_config.copy()
        config['auth'] = {
            'method': 'mtls'
        }
        
        vendor = MockVendorAPI(config)
        
        # mTLS should not set auth headers (handled by SSL context)
        if 'Authorization' not in vendor.auth_headers:
            print("   ✓ Mutual TLS correctly uses SSL context for authentication")
        else:
            issues.append("❌ Mutual TLS incorrectly set auth headers")
            success = False
            
        # Test authenticate method
        if vendor.authenticate():
            print("   ✓ Mutual TLS authentication authenticate() method works")
        else:
            issues.append("❌ Mutual TLS authentication authenticate() method failed")
            success = False
            
    except Exception as e:
        issues.append(f"❌ Mutual TLS authentication setup failed: {e}")
        success = False
    
    # Test 5: Method Implementation Check
    print("5. Checking authentication method implementations...")
    
    # Check if authentication setup method exists
    if hasattr(VendorAPIBase, '_setup_authentication'):
        source = inspect.getsource(VendorAPIBase._setup_authentication)
        
        # Check for all supported methods
        supported_methods = ['basic', 'token', 'bearer', 'oauth2', 'mtls', 'mutual_tls']
        missing_methods = []
        
        for method in supported_methods:
            if method not in source:
                missing_methods.append(method)
        
        if not missing_methods:
            print("   ✓ All authentication methods implemented in _setup_authentication")
        else:
            issues.append(f"❌ Missing authentication methods: {missing_methods}")
            success = False
    else:
        issues.append("❌ _setup_authentication method missing")
        success = False
    
    # Check authenticate method
    if hasattr(VendorAPIBase, 'authenticate'):
        print("   ✓ authenticate() method exists")
        
        # Check if it's no longer abstract (has implementation)
        source = inspect.getsource(VendorAPIBase.authenticate)
        if 'pass' not in source and 'abstractmethod' not in source:
            print("   ✓ authenticate() method has default implementation")
        else:
            print("   ⚠ authenticate() method appears to be abstract or empty")
    else:
        issues.append("❌ authenticate() method missing")
        success = False
    
    # Test 6: Error Handling
    print("6. Testing authentication error handling...")
    try:
        # Test missing basic auth credentials
        config = base_config.copy()
        config['auth'] = {
            'method': 'basic',
            'username': 'testuser'
            # password missing
        }
        
        vendor = MockVendorAPI(config)
        
        # Should handle gracefully without setting auth headers
        if 'Authorization' not in vendor.auth_headers:
            print("   ✓ Missing credentials handled gracefully")
        else:
            issues.append("❌ Missing credentials not handled properly")
            success = False
            
    except Exception as e:
        issues.append(f"❌ Authentication error handling failed: {e}")
        success = False
    
    # Test 7: Unknown method handling
    print("7. Testing unknown authentication method handling...")
    try:
        config = base_config.copy()
        config['auth'] = {
            'method': 'unknown_method'
        }
        
        vendor = MockVendorAPI(config)
        
        # Should handle gracefully without setting auth headers
        if 'Authorization' not in vendor.auth_headers:
            print("   ✓ Unknown authentication method handled gracefully")
        else:
            issues.append("❌ Unknown authentication method not handled properly")
            success = False
            
        # authenticate() should return False for unknown methods
        if not vendor.authenticate():
            print("   ✓ authenticate() correctly returns False for unknown methods")
        else:
            issues.append("❌ authenticate() incorrectly returns True for unknown methods")
            success = False
            
    except Exception as e:
        issues.append(f"❌ Unknown method handling failed: {e}")
        success = False
    
    print(f"\n=== Validation Results ===")
    print(f"Overall Status: {'✓ PASSED' if success else '❌ FAILED'}")
    print(f"Issues Found: {len(issues)}")
    
    if issues:
        print("\nIssues:")
        for issue in issues:
            print(f"  {issue}")
    
    return success, issues


def check_oauth2_implementation():
    """Check OAuth2 specific implementation details."""
    print("\n=== OAuth2 Implementation Details ===")
    
    # Check OAuth2 method implementations
    oauth2_methods = ['_oauth2_get_token', '_is_oauth2_token_valid']
    
    for method_name in oauth2_methods:
        if hasattr(VendorAPIBase, method_name):
            print(f"✓ {method_name} method implemented")
            
            # Check method signature and basic implementation
            method = getattr(VendorAPIBase, method_name)
            source = inspect.getsource(method)
            
            if method_name == '_oauth2_get_token':
                required_elements = ['client_id', 'client_secret', 'token_url', 'grant_type', 'client_credentials']
                missing_elements = [elem for elem in required_elements if elem not in source]
                
                if not missing_elements:
                    print(f"  ✓ {method_name} contains required OAuth2 elements")
                else:
                    print(f"  ⚠ {method_name} missing elements: {missing_elements}")
            
            elif method_name == '_is_oauth2_token_valid':
                if '_token_expires_at' in source and 'time.time()' in source:
                    print(f"  ✓ {method_name} properly checks token expiry")
                else:
                    print(f"  ⚠ {method_name} may not properly check token expiry")
        else:
            print(f"❌ {method_name} method missing")


def main():
    """Main validation function."""
    success, issues = check_authentication_implementation()
    check_oauth2_implementation()
    
    print(f"\n=== Final Status ===")
    if success:
        print("✓ Authentication implementation is COMPLETE")
        print("✓ Phase 3.3 objectives have been met")
        return 0
    else:
        print("❌ Authentication implementation has issues")
        print(f"❌ {len(issues)} issues need to be resolved")
        return 1


if __name__ == '__main__':
    exit(main())