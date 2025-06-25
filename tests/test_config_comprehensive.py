#!/usr/bin/env python3
"""
Comprehensive unit tests for configuration module.
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

    def test_load_valid_config_file(self):
        """Test loading a valid configuration file."""
        config_path = self.create_test_config(self.valid_config)
        
        try:
            loader = ConfigLoader(config_path)
            config = loader.load()
            
            self.assertEqual(config['ldap']['server_url'], 'ldaps://ldap.example.com:636')
            self.assertEqual(len(config['vendor_apps']), 1)
            self.assertEqual(config['vendor_apps'][0]['name'], 'TestApp1')
        finally:
            os.unlink(config_path)

    def test_load_config_with_environment_overrides(self):
        """Test configuration loading with environment variable overrides."""
        config_path = self.create_test_config(self.valid_config)
        
        try:
            with patch.dict(os.environ, {
                'LDAP_BIND_PASSWORD': 'env_password',
                'TESTAPP1_PASSWORD': 'env_vendor_password',
                'SMTP_PASSWORD': 'env_smtp_password'
            }):
                loader = ConfigLoader(config_path)
                config = loader.load()
                
                self.assertEqual(config['ldap']['bind_password'], 'env_password')
                self.assertEqual(config['vendor_apps'][0]['auth']['password'], 'env_vendor_password')
                self.assertEqual(config['notifications']['smtp_password'], 'env_smtp_password')
        finally:
            os.unlink(config_path)

    def test_missing_config_file(self):
        """Test handling of missing configuration file."""
        with self.assertRaises(ConfigurationError) as context:
            loader = ConfigLoader('/nonexistent/config.yaml')
            loader.load()
        
        self.assertIn('not found', str(context.exception))

    def test_invalid_yaml_format(self):
        """Test handling of invalid YAML format."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("invalid: yaml: content: [unclosed")
            invalid_config_path = f.name
        
        try:
            with self.assertRaises(ConfigurationError) as context:
                loader = ConfigLoader(invalid_config_path)
                loader.load()
            
            self.assertIn('YAML', str(context.exception))
        finally:
            os.unlink(invalid_config_path)

    def test_missing_required_ldap_section(self):
        """Test validation of missing LDAP section."""
        invalid_config = {
            'vendor_apps': self.valid_config['vendor_apps'],
            'logging': self.valid_config['logging']
        }
        
        config_path = self.create_test_config(invalid_config)
        
        try:
            with self.assertRaises(ConfigurationError) as context:
                loader = ConfigLoader(config_path)
                loader.load()
            
            self.assertIn('LDAP', str(context.exception))
        finally:
            os.unlink(config_path)

    def test_missing_required_ldap_fields(self):
        """Test validation of missing required LDAP fields."""
        invalid_config = self.valid_config.copy()
        del invalid_config['ldap']['server_url']
        
        config_path = self.create_test_config(invalid_config)
        
        try:
            with self.assertRaises(ConfigurationError) as context:
                loader = ConfigLoader(config_path)
                loader.load()
            
            self.assertIn('server_url', str(context.exception))
        finally:
            os.unlink(config_path)

    def test_no_vendor_apps_configured(self):
        """Test validation when no vendor apps are configured."""
        invalid_config = self.valid_config.copy()
        invalid_config['vendor_apps'] = []
        
        config_path = self.create_test_config(invalid_config)
        
        try:
            with self.assertRaises(ConfigurationError) as context:
                loader = ConfigLoader(config_path)
                loader.load()
            
            self.assertIn('vendor application', str(context.exception))
        finally:
            os.unlink(config_path)

    def test_invalid_vendor_app_config(self):
        """Test validation of invalid vendor app configuration."""
        invalid_config = self.valid_config.copy()
        invalid_config['vendor_apps'][0]['auth'] = {'method': 'invalid'}
        
        config_path = self.create_test_config(invalid_config)
        
        try:
            with self.assertRaises(ConfigurationError) as context:
                loader = ConfigLoader(config_path)
                loader.load()
            
            self.assertIn('authentication', str(context.exception).lower())
        finally:
            os.unlink(config_path)

    def test_missing_vendor_groups(self):
        """Test validation when vendor has no groups configured."""
        invalid_config = self.valid_config.copy()
        invalid_config['vendor_apps'][0]['groups'] = []
        
        config_path = self.create_test_config(invalid_config)
        
        try:
            with self.assertRaises(ConfigurationError) as context:
                loader = ConfigLoader(config_path)
                loader.load()
            
            self.assertIn('groups', str(context.exception).lower())
        finally:
            os.unlink(config_path)

    def test_default_values_applied(self):
        """Test that default values are properly applied."""
        minimal_config = {
            'ldap': {
                'server_url': 'ldaps://ldap.example.com:636',
                'bind_dn': 'CN=Service,DC=example,DC=com',
                'bind_password': 'password',
                'user_base_dn': 'OU=Users,DC=example,DC=com'
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
                    'groups': [
                        {
                            'ldap_group': 'CN=TestGroup,OU=Groups,DC=example,DC=com',
                            'vendor_group': 'test_group'
                        }
                    ]
                }
            ]
        }
        
        config_path = self.create_test_config(minimal_config)
        
        try:
            loader = ConfigLoader(config_path)
            config = loader.load()
            
            # Check default values
            self.assertEqual(config['ldap']['user_filter'], '(objectClass=person)')
            self.assertEqual(config['vendor_apps'][0]['format'], 'json')
            self.assertTrue(config['vendor_apps'][0]['verify_ssl'])
            self.assertEqual(config['logging']['level'], 'INFO')
            self.assertEqual(config['error_handling']['max_retries'], 3)
            self.assertFalse(config['notifications']['enable_email'])
        finally:
            os.unlink(config_path)

    def test_oauth2_auth_validation(self):
        """Test validation of OAuth2 authentication configuration."""
        oauth_config = self.valid_config.copy()
        oauth_config['vendor_apps'][0]['auth'] = {
            'method': 'oauth2',
            'client_id': 'test_client',
            'client_secret': 'test_secret',
            'token_url': 'https://api.testapp1.com/oauth/token'
        }
        
        config_path = self.create_test_config(oauth_config)
        
        try:
            loader = ConfigLoader(config_path)
            config = loader.load()
            
            auth = config['vendor_apps'][0]['auth']
            self.assertEqual(auth['method'], 'oauth2')
            self.assertEqual(auth['client_id'], 'test_client')
            self.assertEqual(auth['token_url'], 'https://api.testapp1.com/oauth/token')
        finally:
            os.unlink(config_path)

    def test_token_auth_validation(self):
        """Test validation of token authentication configuration."""
        token_config = self.valid_config.copy()
        token_config['vendor_apps'][0]['auth'] = {
            'method': 'token',
            'token': 'abc123def456'
        }
        
        config_path = self.create_test_config(token_config)
        
        try:
            loader = ConfigLoader(config_path)
            config = loader.load()
            
            auth = config['vendor_apps'][0]['auth']
            self.assertEqual(auth['method'], 'token')
            self.assertEqual(auth['token'], 'abc123def456')
        finally:
            os.unlink(config_path)

    def test_ssl_certificate_config(self):
        """Test SSL certificate configuration validation."""
        ssl_config = self.valid_config.copy()
        ssl_config['vendor_apps'][0].update({
            'truststore_file': '/path/to/truststore.jks',
            'truststore_password': 'changeit',
            'truststore_type': 'JKS',
            'keystore_file': '/path/to/client.p12',
            'keystore_password': 'keypass',
            'keystore_type': 'PKCS12'
        })
        
        config_path = self.create_test_config(ssl_config)
        
        try:
            loader = ConfigLoader(config_path)
            config = loader.load()
            
            vendor = config['vendor_apps'][0]
            self.assertEqual(vendor['truststore_file'], '/path/to/truststore.jks')
            self.assertEqual(vendor['truststore_type'], 'JKS')
            self.assertEqual(vendor['keystore_type'], 'PKCS12')
        finally:
            os.unlink(config_path)

    def test_multiple_vendor_apps(self):
        """Test configuration with multiple vendor applications."""
        multi_vendor_config = self.valid_config.copy()
        multi_vendor_config['vendor_apps'].append({
            'name': 'TestApp2',
            'module': 'vendor_app2',
            'base_url': 'https://api.testapp2.com/rest',
            'auth': {
                'method': 'token',
                'token': 'xyz789'
            },
            'format': 'xml',
            'verify_ssl': True,
            'groups': [
                {
                    'ldap_group': 'CN=TestGroup2,OU=Groups,DC=example,DC=com',
                    'vendor_group': 'test_group_2'
                }
            ]
        })
        
        config_path = self.create_test_config(multi_vendor_config)
        
        try:
            loader = ConfigLoader(config_path)
            config = loader.load()
            
            self.assertEqual(len(config['vendor_apps']), 2)
            self.assertEqual(config['vendor_apps'][1]['name'], 'TestApp2')
            self.assertEqual(config['vendor_apps'][1]['format'], 'xml')
        finally:
            os.unlink(config_path)

    def test_config_from_environment_path(self):
        """Test loading configuration from environment-specified path."""
        config_path = self.create_test_config(self.valid_config)
        
        try:
            with patch.dict(os.environ, {'CONFIG_PATH': config_path}):
                loader = ConfigLoader()
                config = loader.load()
                
                self.assertEqual(config['ldap']['server_url'], 'ldaps://ldap.example.com:636')
        finally:
            os.unlink(config_path)

    def test_invalid_logging_level(self):
        """Test handling of invalid logging level."""
        invalid_config = self.valid_config.copy()
        invalid_config['logging']['level'] = 'INVALID'
        
        config_path = self.create_test_config(invalid_config)
        
        try:
            loader = ConfigLoader(config_path)
            config = loader.load()
            
            # Should default to INFO for invalid levels
            self.assertEqual(config['logging']['level'], 'INFO')
        finally:
            os.unlink(config_path)

    def test_convenience_load_config_function(self):
        """Test the convenience load_config function."""
        config_path = self.create_test_config(self.valid_config)
        
        try:
            config = load_config(config_path)
            self.assertEqual(config['ldap']['server_url'], 'ldaps://ldap.example.com:636')
            self.assertEqual(len(config['vendor_apps']), 1)
        finally:
            os.unlink(config_path)

    def test_nested_environment_overrides(self):
        """Test nested environment variable overrides."""
        config_path = self.create_test_config(self.valid_config)
        
        try:
            with patch.dict(os.environ, {
                'LDAP_SERVER_URL': 'ldaps://new-server.example.com:636',
                'LOGGING_LEVEL': 'DEBUG',
                'ERROR_HANDLING_MAX_RETRIES': '5'
            }):
                loader = ConfigLoader(config_path)
                config = loader.load()
                
                self.assertEqual(config['ldap']['server_url'], 'ldaps://new-server.example.com:636')
                self.assertEqual(config['logging']['level'], 'DEBUG')
                self.assertEqual(config['error_handling']['max_retries'], 5)
        finally:
            os.unlink(config_path)

    def test_boolean_environment_overrides(self):
        """Test boolean environment variable overrides."""
        config_path = self.create_test_config(self.valid_config)
        
        try:
            with patch.dict(os.environ, {
                'TESTAPP1_VERIFY_SSL': 'false',
                'NOTIFICATIONS_ENABLE_EMAIL': 'true',
                'NOTIFICATIONS_EMAIL_ON_FAILURE': 'false'
            }):
                loader = ConfigLoader(config_path)
                config = loader.load()
                
                self.assertFalse(config['vendor_apps'][0]['verify_ssl'])
                self.assertTrue(config['notifications']['enable_email'])
                self.assertFalse(config['notifications']['email_on_failure'])
        finally:
            os.unlink(config_path)

    def test_integer_environment_overrides(self):
        """Test integer environment variable overrides."""
        config_path = self.create_test_config(self.valid_config)
        
        try:
            with patch.dict(os.environ, {
                'NOTIFICATIONS_SMTP_PORT': '25',
                'LOGGING_RETENTION_DAYS': '14',
                'ERROR_HANDLING_RETRY_WAIT_SECONDS': '10'
            }):
                loader = ConfigLoader(config_path)
                config = loader.load()
                
                self.assertEqual(config['notifications']['smtp_port'], 25)
                self.assertEqual(config['logging']['retention_days'], 14)
                self.assertEqual(config['error_handling']['retry_wait_seconds'], 10)
        finally:
            os.unlink(config_path)

    def test_list_environment_overrides(self):
        """Test list environment variable overrides."""
        config_path = self.create_test_config(self.valid_config)
        
        try:
            with patch.dict(os.environ, {
                'NOTIFICATIONS_EMAIL_TO': 'admin1@example.com,admin2@example.com,admin3@example.com',
                'LDAP_ATTRIBUTES': 'cn,mail,sAMAccountName'
            }):
                loader = ConfigLoader(config_path)
                config = loader.load()
                
                self.assertEqual(len(config['notifications']['email_to']), 3)
                self.assertIn('admin3@example.com', config['notifications']['email_to'])
                self.assertEqual(len(config['ldap']['attributes']), 3)
                self.assertIn('mail', config['ldap']['attributes'])
        finally:
            os.unlink(config_path)


if __name__ == '__main__':
    unittest.main()