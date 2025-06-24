#!/usr/bin/env python3
"""
Integration test for SSL certificate handling functionality.

This test verifies the SSL certificate implementation using basic functionality
without complex mocking or real certificate files.
"""

import os
import ssl
import sys
import unittest
from unittest.mock import patch, MagicMock

# Add parent directory to path to import ldap_sync modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ldap_sync.vendors.base import VendorAPIBase, VendorAPIError


class MockVendorAPI(VendorAPIBase):
    """Mock implementation of VendorAPIBase for testing."""
    
    def authenticate(self) -> bool:
        return True
    
    def get_group_members(self, group_cfg):
        return []
    
    def add_user_to_group(self, group_cfg, user_info):
        return True
    
    def remove_user_from_group(self, group_cfg, user_identifier):
        return True
    
    def update_user(self, user_identifier, user_info):
        return True


class TestSSLIntegration(unittest.TestCase):
    """Test SSL certificate integration functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.base_config = {
            'name': 'TestVendor',
            'base_url': 'https://api.example.com/v1',
            'auth': {
                'method': 'basic',
                'username': 'testuser',
                'password': 'testpass'
            },
            'format': 'json',
            'verify_ssl': True
        }
    
    def test_ssl_context_creation(self):
        """Test that SSL context is properly created."""
        vendor = MockVendorAPI(self.base_config)
        
        # Verify SSL context was created
        self.assertIsNotNone(vendor.ssl_context)
        self.assertIsInstance(vendor.ssl_context, ssl.SSLContext)
        
        # Verify configuration
        self.assertTrue(vendor.verify_ssl)
        self.assertEqual(vendor.parsed_url.scheme, 'https')
    
    def test_ssl_disabled_context(self):
        """Test SSL verification disabled configuration."""
        config = self.base_config.copy()
        config['verify_ssl'] = False
        
        vendor = MockVendorAPI(config)
        
        # Should still have SSL context but unverified
        self.assertIsNotNone(vendor.ssl_context)
        self.assertFalse(vendor.verify_ssl)
    
    def test_http_no_ssl_context(self):
        """Test that HTTP URLs don't create SSL context."""
        config = self.base_config.copy()
        config['base_url'] = 'http://api.example.com/v1'
        
        vendor = MockVendorAPI(config)
        
        # Should not create SSL context for HTTP
        self.assertIsNone(vendor.ssl_context)
        self.assertEqual(vendor.parsed_url.scheme, 'http')
    
    def test_certificate_loading_methods_exist(self):
        """Test that certificate loading methods are implemented."""
        vendor = MockVendorAPI(self.base_config)
        
        # Verify methods exist
        self.assertTrue(hasattr(vendor, '_load_truststore'))
        self.assertTrue(hasattr(vendor, '_load_client_cert'))
        self.assertTrue(callable(vendor._load_truststore))
        self.assertTrue(callable(vendor._load_client_cert))
    
    def test_pem_truststore_method_with_mock(self):
        """Test PEM truststore loading method with mocked SSL context."""
        config = self.base_config.copy()
        config['truststore_file'] = '/tmp/test.pem'
        config['truststore_type'] = 'PEM'
        
        with patch.object(ssl.SSLContext, 'load_verify_locations') as mock_load:
            vendor = MockVendorAPI(config)
            mock_load.assert_called_once_with(cafile='/tmp/test.pem')
    
    def test_jks_truststore_import_handling(self):
        """Test that JKS support handles import errors gracefully."""
        config = self.base_config.copy()
        config['truststore_file'] = '/tmp/test.jks'
        config['truststore_type'] = 'JKS'
        
        # Mock the import to fail
        with patch('builtins.__import__', side_effect=ImportError("No module named 'pyjks'")):
            with self.assertRaises(VendorAPIError) as cm:
                MockVendorAPI(config)
            
            self.assertIn("pyjks library", str(cm.exception))
    
    def test_pkcs12_truststore_import_handling(self):
        """Test that PKCS12 support handles import errors gracefully."""
        config = self.base_config.copy()
        config['truststore_file'] = '/tmp/test.p12'
        config['truststore_type'] = 'PKCS12'
        
        # Mock the cryptography import to fail
        with patch('builtins.__import__', side_effect=ImportError("No module named 'cryptography'")):
            with self.assertRaises(VendorAPIError) as cm:
                MockVendorAPI(config)
            
            self.assertIn("cryptography library", str(cm.exception))
    
    def test_authentication_header_setup(self):
        """Test that authentication headers are properly set up."""
        # Test Basic auth
        vendor = MockVendorAPI(self.base_config)
        self.assertIn('Authorization', vendor.auth_headers)
        self.assertTrue(vendor.auth_headers['Authorization'].startswith('Basic '))
        
        # Test Token auth
        config = self.base_config.copy()
        config['auth'] = {'method': 'token', 'token': 'abc123'}
        vendor = MockVendorAPI(config)
        self.assertEqual(vendor.auth_headers['Authorization'], 'Bearer abc123')
        
        # Test OAuth2 (headers not set until authenticate() called)
        config['auth'] = {'method': 'oauth2', 'client_id': 'test', 'client_secret': 'secret'}
        vendor = MockVendorAPI(config)
        self.assertNotIn('Authorization', vendor.auth_headers)
    
    def test_connection_creation(self):
        """Test HTTP/HTTPS connection creation."""
        # Test HTTPS connection
        vendor = MockVendorAPI(self.base_config)
        with patch('http.client.HTTPSConnection') as mock_https:
            conn = vendor._get_connection()
            mock_https.assert_called_once_with(
                'api.example.com',
                context=vendor.ssl_context,
                timeout=30
            )
        
        # Test HTTP connection
        config = self.base_config.copy()
        config['base_url'] = 'http://api.example.com/v1'
        vendor = MockVendorAPI(config)
        with patch('http.client.HTTPConnection') as mock_http:
            conn = vendor._get_connection()
            mock_http.assert_called_once_with('api.example.com', timeout=30)
    
    def test_supported_truststore_types(self):
        """Test that all supported truststore types are handled."""
        base_config = self.base_config.copy()
        
        # Test each supported type with mocked loading
        supported_types = ['PEM', 'JKS', 'PKCS12']
        
        for truststore_type in supported_types:
            with self.subTest(truststore_type=truststore_type):
                config = base_config.copy()
                config['truststore_file'] = f'/tmp/test.{truststore_type.lower()}'
                config['truststore_type'] = truststore_type
                
                # Mock the appropriate loading mechanism
                if truststore_type == 'PEM':
                    with patch.object(ssl.SSLContext, 'load_verify_locations'):
                        vendor = MockVendorAPI(config)
                        self.assertIsNotNone(vendor.ssl_context)
                
                elif truststore_type == 'JKS':
                    mock_cert = MagicMock()
                    mock_cert.cert = b'mock-cert-data'
                    mock_keystore = MagicMock()
                    mock_keystore.certs = {'alias': mock_cert}
                    
                    with patch('pyjks.KeyStore.load', return_value=mock_keystore):
                        with patch.object(ssl.SSLContext, 'load_verify_locations'):
                            vendor = MockVendorAPI(config)
                            self.assertIsNotNone(vendor.ssl_context)
                
                elif truststore_type == 'PKCS12':
                    mock_cert = MagicMock()
                    mock_cert.public_bytes.return_value = b'mock-cert-pem'
                    
                    with patch('cryptography.hazmat.primitives.serialization.pkcs12.load_key_and_certificates',
                               return_value=(None, mock_cert, [])):
                        with patch.object(ssl.SSLContext, 'load_verify_locations'):
                            vendor = MockVendorAPI(config)
                            self.assertIsNotNone(vendor.ssl_context)


if __name__ == '__main__':
    unittest.main(verbosity=2)