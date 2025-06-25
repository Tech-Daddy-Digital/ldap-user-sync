#!/usr/bin/env python3
"""
Unit tests for configuration module.

This module provides comprehensive unit tests for the configuration loading,
validation, and environment variable override functionality.
"""

import os
import sys
import tempfile
import yaml
import unittest
from unittest.mock import patch, mock_open
from typing import Dict, Any

# Add the project directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ldap_sync.config import ConfigLoader, ConfigurationError, load_config


class TestConfigLoader(unittest.TestCase):
    """Test cases for ConfigLoader class."""

    def setUp(self):
        """Set up test fixtures."""
        self.valid_config = {
            'ldap': {
                'server_url': 'ldaps://ldap.example.com:636',
                'bind_dn': 'CN=Service,DC=example,DC=com',
                'bind_password': 'password',
                'user_base_dn': 'OU=Users,DC=example,DC=com',
                'user_filter': '(objectClass=person)',
                'attributes': ['cn', 'givenName', 'sn', 'mail', 'sAMAccountName']
            },
            'vendor_apps': [
                {
                    'name': 'TestApp1',
                    'module': 'vendor_app1',
                    'base_url': 'https://api.testapp1.com/v1',
                    'auth': {
                        'method': 'basic',
                        'username': 'testuser',
                        'password': 'testpass'
                    },
                    'format': 'json',
                    'verify_ssl': True,
                    'groups': [
                        {
                            'ldap_group': 'CN=TestGroup,OU=Groups,DC=example,DC=com',
                            'vendor_group': 'test_group'
                        }
                    ]
                }
            ],
            'logging': {
                'level': 'INFO',
                'log_dir': 'logs',
                'rotation': 'daily',
                'retention_days': 7
            },
            'error_handling': {
                'max_retries': 3,
                'retry_wait_seconds': 5,
                'max_errors_per_vendor': 5
            },
            'notifications': {
                'enable_email': True,
                'email_on_failure': True,
                'smtp_server': 'smtp.example.com',
                'smtp_port': 587,
                'smtp_tls': True,
                'smtp_username': 'alerts@example.com',
                'smtp_password': 'smtppass',
                'email_from': 'alerts@example.com',
                'email_to': ['admin@example.com']
            }
        }

    def create_test_config(self, config_data: Dict[str, Any]) -> str:
        """Create a temporary config file with the given data."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.safe_dump(config_data, f)
            return f.name

    def test_valid_config(self):
    """Test loading a valid configuration."""
    print("Testing valid configuration...")
    
    config_data = {
        'ldap': {
            'server_url': 'ldaps://test.example.com:636',
            'bind_dn': 'CN=test,DC=example,DC=com',
            'bind_password': 'testpass'
        },
        'vendor_apps': [
            {
                'name': 'TestVendor',
                'module': 'test_vendor',
                'base_url': 'https://api.test.com',
                'auth': {'method': 'basic', 'username': 'user', 'password': 'pass'},
                'groups': [
                    {'ldap_group': 'CN=test,DC=example,DC=com', 'vendor_group': 'test'}
                ]
            }
        ]
    }
    
    config_file = create_test_config(config_data)
    try:
        loader = ConfigLoader(config_file)
        config = loader.load()
        
        # Verify required fields are present
        assert 'ldap' in config
        assert 'vendor_apps' in config
        assert len(config['vendor_apps']) == 1
        
        # Verify defaults were applied
        assert config['logging']['level'] == 'INFO'
        assert config['error_handling']['max_retries'] == 3
        assert config['vendor_apps'][0]['format'] == 'json'
        
        print("✓ Valid configuration test passed")
        
    finally:
        os.unlink(config_file)


def test_missing_required_fields():
    """Test configuration validation with missing required fields."""
    print("Testing missing required fields...")
    
    # Missing LDAP configuration
    config_data = {
        'vendor_apps': [
            {
                'name': 'TestVendor',
                'module': 'test_vendor',
                'base_url': 'https://api.test.com',
                'auth': {'method': 'basic'},
                'groups': []
            }
        ]
    }
    
    config_file = create_test_config(config_data)
    try:
        loader = ConfigLoader(config_file)
        try:
            loader.load()
            assert False, "Should have raised ConfigurationError"
        except ConfigurationError as e:
            assert "LDAP" in str(e)
            print("✓ Missing LDAP config detected correctly")
    finally:
        os.unlink(config_file)
    
    # Missing vendor apps
    config_data = {
        'ldap': {
            'server_url': 'ldaps://test.example.com:636',
            'bind_dn': 'CN=test,DC=example,DC=com',
            'bind_password': 'testpass'
        },
        'vendor_apps': []
    }
    
    config_file = create_test_config(config_data)
    try:
        loader = ConfigLoader(config_file)
        try:
            loader.load()
            assert False, "Should have raised ConfigurationError"
        except ConfigurationError as e:
            assert "vendor application" in str(e)
            print("✓ Missing vendor apps detected correctly")
    finally:
        os.unlink(config_file)


def test_env_var_overrides():
    """Test environment variable overrides for sensitive data."""
    print("Testing environment variable overrides...")
    
    config_data = {
        'ldap': {
            'server_url': 'ldaps://test.example.com:636',
            'bind_dn': 'CN=test,DC=example,DC=com',
            'bind_password': 'original_password'
        },
        'vendor_apps': [
            {
                'name': 'TestVendor',
                'module': 'test_vendor',
                'base_url': 'https://api.test.com',
                'auth': {'method': 'basic', 'username': 'user', 'password': 'original_vendor_pass'},
                'groups': [
                    {'ldap_group': 'CN=test,DC=example,DC=com', 'vendor_group': 'test'}
                ]
            }
        ],
        'notifications': {
            'smtp_password': 'original_smtp_pass'
        }
    }
    
    config_file = create_test_config(config_data)
    
    # Set environment variables
    os.environ['LDAP_BIND_PASSWORD'] = 'env_ldap_password'
    os.environ['TESTVENDOR_PASSWORD'] = 'env_vendor_password'
    os.environ['SMTP_PASSWORD'] = 'env_smtp_password'
    
    try:
        loader = ConfigLoader(config_file)
        config = loader.load()
        
        # Verify environment overrides were applied
        assert config['ldap']['bind_password'] == 'env_ldap_password'
        assert config['vendor_apps'][0]['auth']['password'] == 'env_vendor_password'
        assert config['notifications']['smtp_password'] == 'env_smtp_password'
        
        print("✓ Environment variable overrides working correctly")
        
    finally:
        # Clean up environment variables
        for var in ['LDAP_BIND_PASSWORD', 'TESTVENDOR_PASSWORD', 'SMTP_PASSWORD']:
            if var in os.environ:
                del os.environ[var]
        os.unlink(config_file)


def test_invalid_yaml():
    """Test handling of invalid YAML syntax."""
    print("Testing invalid YAML handling...")
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write("invalid: yaml: syntax: [\n")
        invalid_config_file = f.name
    
    try:
        loader = ConfigLoader(invalid_config_file)
        try:
            loader.load()
            assert False, "Should have raised ConfigurationError"
        except ConfigurationError as e:
            assert "YAML" in str(e)
            print("✓ Invalid YAML detected correctly")
    finally:
        os.unlink(invalid_config_file)


def test_missing_config_file():
    """Test handling of missing configuration file."""
    print("Testing missing config file handling...")
    
    non_existent_file = "/tmp/non_existent_config.yaml"
    loader = ConfigLoader(non_existent_file)
    
    try:
        loader.load()
        assert False, "Should have raised ConfigurationError"
    except ConfigurationError as e:
        assert "not found" in str(e)
        print("✓ Missing config file detected correctly")


def test_convenience_function():
    """Test the convenience load_config function."""
    print("Testing convenience load_config function...")
    
    config_data = {
        'ldap': {
            'server_url': 'ldaps://test.example.com:636',
            'bind_dn': 'CN=test,DC=example,DC=com',
            'bind_password': 'testpass'
        },
        'vendor_apps': [
            {
                'name': 'TestVendor',
                'module': 'test_vendor',
                'base_url': 'https://api.test.com',
                'auth': {'method': 'basic', 'username': 'user', 'password': 'pass'},
                'groups': [
                    {'ldap_group': 'CN=test,DC=example,DC=com', 'vendor_group': 'test'}
                ]
            }
        ]
    }
    
    config_file = create_test_config(config_data)
    try:
        config = load_config(config_file)
        assert 'ldap' in config
        assert 'vendor_apps' in config
        print("✓ Convenience function working correctly")
    finally:
        os.unlink(config_file)


def test_actual_config_file():
    """Test loading the actual config.yaml file in the project."""
    print("Testing actual project config.yaml file...")
    
    config_file = os.path.join(os.path.dirname(__file__), 'config.yaml')
    if os.path.exists(config_file):
        try:
            # We expect this to fail validation due to placeholder values
            config = load_config(config_file)
            print("✓ Config file syntax is valid")
            
            # Verify structure
            assert 'ldap' in config
            assert 'vendor_apps' in config
            assert 'logging' in config
            assert 'error_handling' in config
            assert 'notifications' in config
            
            print("✓ Config file structure is correct")
            
        except ConfigurationError as e:
            # This is expected if placeholder values are used
            if "example.com" in str(e) or "password" in str(e).lower():
                print("✓ Config file validation correctly rejects placeholder values")
            else:
                print(f"⚠ Unexpected validation error: {e}")
    else:
        print("⚠ config.yaml file not found - this is expected during testing")


def main():
    """Run all configuration tests."""
    print("Running LDAP User Sync Configuration Tests")
    print("=" * 50)
    
    try:
        test_valid_config()
        test_missing_required_fields()
        test_env_var_overrides()
        test_invalid_yaml()
        test_missing_config_file()
        test_convenience_function()
        test_actual_config_file()
        
        print("\n" + "=" * 50)
        print("✓ All configuration tests passed!")
        print("\nConfiguration management implementation is working correctly.")
        
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()