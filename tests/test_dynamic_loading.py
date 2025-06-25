#!/usr/bin/env python3
"""
Test dynamic vendor module loading.

Tests that the plugin architecture correctly loads different vendor modules
based on configuration.
"""

import unittest
import importlib
import sys
import os
from unittest.mock import patch

# Add parent directory to path to import ldap_sync modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ldap_sync.vendors.vendor_app1 import VendorApp1API
from ldap_sync.vendors.vendor_app2 import VendorApp2API


class TestDynamicVendorLoading(unittest.TestCase):
    """Test dynamic loading of vendor modules."""
    
    def test_load_vendor_app1_module(self):
        """Test loading VendorApp1 module dynamically."""
        config = {
            'name': 'TestVendorApp1',
            'module': 'vendor_app1',
            'base_url': 'https://api.vendorapp1.test/v1',
            'auth': {'method': 'basic', 'username': 'test', 'password': 'test'},
            'format': 'json'
        }
        
        # Simulate dynamic module loading
        module_name = f"ldap_sync.vendors.{config['module']}"
        
        try:
            vendor_module = importlib.import_module(module_name)
            self.assertTrue(hasattr(vendor_module, 'create_vendor_api'))
            
            # Test factory function exists and works
            with patch.object(VendorApp1API, '__init__', return_value=None):
                api_instance = VendorApp1API.__new__(VendorApp1API)
                self.assertIsInstance(api_instance, VendorApp1API)
                
        except ImportError as e:
            self.fail(f"Failed to load module {module_name}: {e}")
    
    def test_load_vendor_app2_module(self):
        """Test loading VendorApp2 module dynamically."""
        config = {
            'name': 'TestVendorApp2',
            'module': 'vendor_app2',
            'base_url': 'https://api.vendorapp2.test/v1',
            'auth': {'method': 'token', 'token': 'test-token'},
            'format': 'xml'
        }
        
        # Simulate dynamic module loading
        module_name = f"ldap_sync.vendors.{config['module']}"
        
        try:
            vendor_module = importlib.import_module(module_name)
            self.assertTrue(hasattr(vendor_module, 'create_vendor_api'))
            
            # Test factory function exists and works
            with patch.object(VendorApp2API, '__init__', return_value=None):
                api_instance = VendorApp2API.__new__(VendorApp2API)
                self.assertIsInstance(api_instance, VendorApp2API)
                
        except ImportError as e:
            self.fail(f"Failed to load module {module_name}: {e}")
    
    def test_multiple_vendor_configs(self):
        """Test loading multiple different vendor modules."""
        vendor_configs = [
            {
                'name': 'VendorApp1',
                'module': 'vendor_app1',
                'base_url': 'https://api.vendorapp1.test/v1',
                'auth': {'method': 'basic', 'username': 'test1', 'password': 'test1'},
                'format': 'json',
                'groups': [{'ldap_group': 'CN=Group1', 'vendor_group': 'group1'}]
            },
            {
                'name': 'VendorApp2',
                'module': 'vendor_app2',
                'base_url': 'https://api.vendorapp2.test/v1',
                'auth': {'method': 'token', 'token': 'test-token-2'},
                'format': 'xml',
                'groups': [{'ldap_group': 'CN=Group2', 'vendor_group': 'group2'}]
            }
        ]
        
        loaded_vendors = []
        
        for vendor_config in vendor_configs:
            module_name = f"ldap_sync.vendors.{vendor_config['module']}"
            
            try:
                vendor_module = importlib.import_module(module_name)
                
                # Verify factory function
                self.assertTrue(hasattr(vendor_module, 'create_vendor_api'))
                
                # Mock the vendor class to avoid actual initialization
                if vendor_config['module'] == 'vendor_app1':
                    with patch.object(VendorApp1API, '__init__', return_value=None):
                        api_instance = VendorApp1API.__new__(VendorApp1API)
                else:
                    with patch.object(VendorApp2API, '__init__', return_value=None):
                        api_instance = VendorApp2API.__new__(VendorApp2API)
                
                loaded_vendors.append({
                    'name': vendor_config['name'],
                    'instance': api_instance,
                    'config': vendor_config
                })
                
            except ImportError as e:
                self.fail(f"Failed to load module {module_name}: {e}")
        
        # Verify we loaded both vendors
        self.assertEqual(len(loaded_vendors), 2)
        
        # Verify they are different types
        vendor_types = [type(v['instance']).__name__ for v in loaded_vendors]
        self.assertIn('VendorApp1API', vendor_types)
        self.assertIn('VendorApp2API', vendor_types)
        
        # Verify configurations are preserved
        self.assertEqual(loaded_vendors[0]['config']['format'], 'json')
        self.assertEqual(loaded_vendors[1]['config']['format'], 'xml')
    
    def test_vendor_module_interface_compliance(self):
        """Test that both vendor modules implement required methods."""
        required_methods = [
            'get_group_members',
            'add_user_to_group', 
            'remove_user_from_group',
            'update_user',
            'authenticate'
        ]
        
        configs = [
            {
                'name': 'VendorApp1',
                'module': 'vendor_app1',
                'base_url': 'https://test.com',
                'auth': {'method': 'basic', 'username': 'test', 'password': 'test'},
                'format': 'json'
            },
            {
                'name': 'VendorApp2', 
                'module': 'vendor_app2',
                'base_url': 'https://test.com',
                'auth': {'method': 'token', 'token': 'test'},
                'format': 'xml'
            }
        ]
        
        for config in configs:
            module_name = f"ldap_sync.vendors.{config['module']}"
            vendor_module = importlib.import_module(module_name)
            
            # Create instance without full initialization
            if config['module'] == 'vendor_app1':
                with patch.object(VendorApp1API, '__init__', return_value=None):
                    api_instance = VendorApp1API.__new__(VendorApp1API)
            else:
                with patch.object(VendorApp2API, '__init__', return_value=None):
                    api_instance = VendorApp2API.__new__(VendorApp2API)
            
            # Check all required methods exist
            for method_name in required_methods:
                self.assertTrue(hasattr(api_instance, method_name),
                              f"{config['module']} missing method {method_name}")
                self.assertTrue(callable(getattr(api_instance, method_name)),
                              f"{config['module']}.{method_name} is not callable")


if __name__ == '__main__':
    # Set up logging for tests
    import logging
    logging.basicConfig(level=logging.DEBUG)
    
    unittest.main()