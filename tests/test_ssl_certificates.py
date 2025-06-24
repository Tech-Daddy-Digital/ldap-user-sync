#!/usr/bin/env python3
"""
Test SSL certificate handling functionality in VendorAPIBase.

This test verifies that the SSL/certificate support works correctly for
different certificate types (PEM, JKS, PKCS12) and authentication methods.
"""

import os
import ssl
import tempfile
import unittest
from unittest.mock import patch, MagicMock
import sys
import logging

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


class TestSSLCertificates(unittest.TestCase):
    """Test SSL certificate handling functionality."""
    
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
    
    def test_ssl_context_creation_default(self):
        """Test default SSL context creation."""
        vendor = MockVendorAPI(self.base_config)
        
        # Should create default SSL context for HTTPS
        self.assertIsNotNone(vendor.ssl_context)
        self.assertIsInstance(vendor.ssl_context, ssl.SSLContext)
        self.assertTrue(vendor.verify_ssl)
    
    def test_ssl_verification_disabled(self):
        """Test SSL verification disabled."""
        config = self.base_config.copy()
        config['verify_ssl'] = False
        
        vendor = MockVendorAPI(config)
        
        # Should create unverified context
        self.assertIsNotNone(vendor.ssl_context)
        self.assertFalse(vendor.verify_ssl)
    
    def test_http_no_ssl_context(self):
        """Test HTTP (non-SSL) connection."""
        config = self.base_config.copy()
        config['base_url'] = 'http://api.example.com/v1'
        
        vendor = MockVendorAPI(config)
        
        # Should not create SSL context for HTTP
        self.assertIsNone(vendor.ssl_context)
    
    def test_pem_truststore_loading(self):
        """Test PEM truststore loading."""
        # Create a temporary PEM file
        pem_content = """-----BEGIN CERTIFICATE-----
MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65DANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH
MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI
2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx
1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQ
q2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5Wz
tCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQ
vIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAP
BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUTiJUIBiV
5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY
1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4
NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NG
Fdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ91
8rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTe
pLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LBfRccfcjt
zk=
-----END CERTIFICATE-----"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as f:
            f.write(pem_content)
            pem_file = f.name
        
        try:
            config = self.base_config.copy()
            config['truststore_file'] = pem_file
            config['truststore_type'] = 'PEM'
            
            # Should not raise exception
            vendor = MockVendorAPI(config)
            self.assertIsNotNone(vendor.ssl_context)
            
        finally:
            os.unlink(pem_file)
    
    @patch('pyjks.KeyStore.load')
    def test_jks_truststore_loading(self, mock_load):
        """Test JKS truststore loading (mocked)."""
        # Mock pyjks KeyStore
        mock_keystore = MagicMock()
        mock_cert = MagicMock()
        mock_cert.cert = b'mock-cert-data'
        mock_keystore.certs = {'test-alias': mock_cert}
        mock_load.return_value = mock_keystore
        
        config = self.base_config.copy()
        config['truststore_file'] = '/tmp/test.jks'
        config['truststore_type'] = 'JKS'
        config['truststore_password'] = 'changeit'
        
        with patch('builtins.open', create=True):
            vendor = MockVendorAPI(config)
            self.assertIsNotNone(vendor.ssl_context)
            mock_load.assert_called_once()
    
    def test_jks_truststore_no_pyjks(self):
        """Test JKS truststore when pyjks not available."""
        config = self.base_config.copy()
        config['truststore_file'] = '/tmp/test.jks'
        config['truststore_type'] = 'JKS'
        
        with patch('builtins.__import__', side_effect=ImportError("No module named 'pyjks'")):
            with self.assertRaises(VendorAPIError) as cm:
                MockVendorAPI(config)
            self.assertIn("pyjks library", str(cm.exception))
    
    @patch('cryptography.hazmat.primitives.serialization.pkcs12.load_key_and_certificates')
    def test_pkcs12_truststore_loading(self, mock_load):
        """Test PKCS12 truststore loading (mocked)."""
        # Mock cryptography PKCS12 loading
        from cryptography.hazmat.primitives import serialization
        
        mock_cert = MagicMock()
        mock_cert.public_bytes.return_value = b'mock-cert-pem'
        mock_load.return_value = (None, mock_cert, [])
        
        config = self.base_config.copy()
        config['truststore_file'] = '/tmp/test.p12'
        config['truststore_type'] = 'PKCS12'
        config['truststore_password'] = 'password'
        
        with patch('builtins.open', create=True):
            vendor = MockVendorAPI(config)
            self.assertIsNotNone(vendor.ssl_context)
            mock_load.assert_called_once()
    
    def test_client_cert_pem(self):
        """Test PEM client certificate loading."""
        # Create temporary cert and key files
        cert_content = """-----BEGIN CERTIFICATE-----
MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65DANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH
MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI
2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx
1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQ
q2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5Wz
tCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQ
vIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAP
BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUTiJUIBiV
5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY
1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4
NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NG
Fdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ91
8rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTe
pLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LBfRccfcjt
zk=
-----END CERTIFICATE-----"""
        
        key_content = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7N8003HtryZJo
kK1Kdf9GuiEKCI31GVTJ+4jb867yOomRPHrmqwYaa8+sLeheCSSBEummaftajoH7
gUXUgBaxQt5hjGkww3NoePGbHfHt7+PLlIM3ruwfQ07deyyz7S6lL+SraaU621Jm
ktibYdusaBIQgEw9Pw3kYSzONhCtgQacj+K66bTpkjJrtdCF6F0bzYweq5UElUnz
lS2W40lt3gfT+0lLvKy1B6mPmzO0I7tMbUXw9qmylTC09UxVjCdKWh9QgpONdJLT
FkoGDIxQ0Y8eCb4XoeYyhv2D5RC8g6UKyuGcp9kUFD1GdsOHFIkhNE2vD0UMpkmh
uruYccMzMoEFAgMBAAECggEAZ7I4nNpzKhjGDa6Db1J0yz7Pf5ktOr1LNzM1S3Ev
Vv8JgOELJRGJQLw6tVTlCg6D3XfCi8MLOq8VJzX2J6Gom9g4oWNrO7M4cQCGdQH
PHyC8zg5L7Qjs1hvEIvAw3I8dAaL+8GJ/gQnGJ2GYt6VZJKiI2eMsWmNyEOONsY3y
N0x0Lr6YGo+M+NVLtYOdOdOoMWaWsZwgr3+HOoKRTaP6EGfJP0bLwt5r3w1+QKo9
j6A2a9QAa5Pj2QTWCf9uyJZhCYk7QZy9OKwNQsP6U3/+0Y2q6j6JFxp5aWa9H4kD
A7s+7FiBSDX34QhRqHQKzP5HFnxvg9GqYmh9cD0tJGnCfwKBgQDk7qwz4n2cOnQt
R/2k5PzTdV7f7Y3YZOgQcYOa8K3FwT7QOLYPgdZEsJCG1OT9Jm1vYs6COI1q8A6q
4VkSQwNlXBgXLdnBfmhOGOc3oW7wGxJ1Nw=
-----END PRIVATE KEY-----"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as cert_file:
            cert_file.write(cert_content + key_content)  # Combined cert+key file
            cert_path = cert_file.name
        
        try:
            config = self.base_config.copy()
            config['keystore_file'] = cert_path
            config['keystore_type'] = 'PEM'
            
            # Mock load_cert_chain to avoid actual cert validation
            with patch.object(ssl.SSLContext, 'load_cert_chain') as mock_load:
                vendor = MockVendorAPI(config)
                mock_load.assert_called_once_with(cert_path, password=None)
                
        finally:
            os.unlink(cert_path)
    
    def test_authentication_basic(self):
        """Test Basic authentication setup."""
        vendor = MockVendorAPI(self.base_config)
        
        # Should have Basic auth header
        self.assertIn('Authorization', vendor.auth_headers)
        self.assertTrue(vendor.auth_headers['Authorization'].startswith('Basic '))
    
    def test_authentication_token(self):
        """Test Bearer token authentication setup."""
        config = self.base_config.copy()
        config['auth'] = {
            'method': 'token',
            'token': 'abc123token'
        }
        
        vendor = MockVendorAPI(config)
        
        # Should have Bearer token header
        self.assertIn('Authorization', vendor.auth_headers)
        self.assertEqual(vendor.auth_headers['Authorization'], 'Bearer abc123token')
    
    def test_authentication_oauth2(self):
        """Test OAuth2 authentication setup."""
        config = self.base_config.copy()
        config['auth'] = {
            'method': 'oauth2',
            'token_url': 'https://auth.example.com/token',
            'client_id': 'client123',
            'client_secret': 'secret456'
        }
        
        vendor = MockVendorAPI(config)
        
        # OAuth2 headers are set up in authenticate() method
        self.assertNotIn('Authorization', vendor.auth_headers)


if __name__ == '__main__':
    # Set up logging
    logging.basicConfig(level=logging.DEBUG)
    
    # Run tests
    unittest.main(verbosity=2)