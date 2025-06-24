#!/usr/bin/env python3
"""
Test authentication methods implementation in VendorAPIBase.

This test suite verifies that all authentication methods work correctly:
- HTTP Basic Authentication
- Bearer Token Authentication
- OAuth2 Client Credentials Flow
- Mutual TLS Authentication
"""

import os
import sys
import json
import base64
import unittest
from unittest.mock import patch, MagicMock, Mock
import tempfile

# Add parent directory to path to import ldap_sync modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ldap_sync.vendors.base import VendorAPIBase, VendorAPIError, VendorAuthenticationError


class MockVendorAPI(VendorAPIBase):
    """Mock implementation of VendorAPIBase for testing."""
    
    def get_group_members(self, group_cfg):
        return []
    
    def add_user_to_group(self, group_cfg, user_info):
        return True
    
    def remove_user_from_group(self, group_cfg, user_identifier):
        return True
    
    def update_user(self, user_identifier, user_info):
        return True


class TestAuthenticationMethods(unittest.TestCase):
    """Test authentication method implementations."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.base_config = {
            'name': 'TestVendor',
            'base_url': 'https://api.example.com/v1',
            'format': 'json',
            'verify_ssl': True
        }
    
    def test_basic_authentication_setup(self):
        """Test HTTP Basic Authentication setup."""
        config = self.base_config.copy()
        config['auth'] = {
            'method': 'basic',
            'username': 'testuser',
            'password': 'testpass'
        }
        
        vendor = MockVendorAPI(config)
        
        # Verify Basic auth header is set
        self.assertIn('Authorization', vendor.auth_headers)
        auth_header = vendor.auth_headers['Authorization']
        self.assertTrue(auth_header.startswith('Basic '))
        
        # Verify the encoded credentials are correct
        encoded_creds = auth_header.split(' ')[1]
        decoded_creds = base64.b64decode(encoded_creds).decode()
        self.assertEqual(decoded_creds, 'testuser:testpass')
    
    def test_basic_authentication_missing_credentials(self):
        """Test Basic Authentication with missing credentials."""
        config = self.base_config.copy()
        config['auth'] = {
            'method': 'basic',
            'username': 'testuser'
            # password missing
        }
        
        with patch('ldap_sync.vendors.base.logger') as mock_logger:
            vendor = MockVendorAPI(config)
            mock_logger.error.assert_called_once()
            self.assertNotIn('Authorization', vendor.auth_headers)
    
    def test_bearer_token_authentication_setup(self):
        """Test Bearer Token Authentication setup."""
        config = self.base_config.copy()
        config['auth'] = {
            'method': 'token',
            'token': 'abc123token'
        }
        
        vendor = MockVendorAPI(config)
        
        # Verify Bearer token header is set
        self.assertIn('Authorization', vendor.auth_headers)
        self.assertEqual(vendor.auth_headers['Authorization'], 'Bearer abc123token')
    
    def test_bearer_token_authentication_alias(self):
        """Test Bearer Token Authentication using 'bearer' method alias."""
        config = self.base_config.copy()
        config['auth'] = {
            'method': 'bearer',
            'token': 'xyz789token'
        }
        
        vendor = MockVendorAPI(config)
        
        # Verify Bearer token header is set
        self.assertIn('Authorization', vendor.auth_headers)
        self.assertEqual(vendor.auth_headers['Authorization'], 'Bearer xyz789token')
    
    def test_bearer_token_missing_token(self):
        """Test Bearer Token Authentication with missing token."""
        config = self.base_config.copy()
        config['auth'] = {
            'method': 'token'
            # token missing
        }
        
        with patch('ldap_sync.vendors.base.logger') as mock_logger:
            vendor = MockVendorAPI(config)
            mock_logger.error.assert_called_once()
            self.assertNotIn('Authorization', vendor.auth_headers)
    
    def test_oauth2_configuration_validation(self):
        """Test OAuth2 configuration validation."""
        # Complete OAuth2 config
        config = self.base_config.copy()
        config['auth'] = {
            'method': 'oauth2',
            'client_id': 'client123',
            'client_secret': 'secret456',
            'token_url': 'https://auth.example.com/token'
        }
        
        with patch('ldap_sync.vendors.base.logger') as mock_logger:
            vendor = MockVendorAPI(config)
            mock_logger.debug.assert_called()
            # Should not have called error
            mock_logger.error.assert_not_called()
    
    def test_oauth2_missing_configuration(self):
        """Test OAuth2 with missing configuration."""
        config = self.base_config.copy()
        config['auth'] = {
            'method': 'oauth2',
            'client_id': 'client123'
            # missing client_secret and token_url
        }
        
        with patch('ldap_sync.vendors.base.logger') as mock_logger:
            vendor = MockVendorAPI(config)
            mock_logger.error.assert_called_once()
    
    @patch('http.client.HTTPSConnection')
    def test_oauth2_token_retrieval_success(self, mock_https):
        """Test successful OAuth2 token retrieval."""
        config = self.base_config.copy()
        config['auth'] = {
            'method': 'oauth2',
            'client_id': 'client123',
            'client_secret': 'secret456',
            'token_url': 'https://auth.example.com/token',
            'scope': 'read write'
        }
        
        # Mock successful token response
        mock_response = Mock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps({
            'access_token': 'new_token_123',
            'token_type': 'Bearer',
            'expires_in': 3600
        }).encode()
        
        mock_conn = Mock()
        mock_conn.getresponse.return_value = mock_response
        mock_https.return_value = mock_conn
        
        vendor = MockVendorAPI(config)
        result = vendor._oauth2_get_token()
        
        # Verify success
        self.assertTrue(result)
        self.assertIn('Authorization', vendor.auth_headers)
        self.assertEqual(vendor.auth_headers['Authorization'], 'Bearer new_token_123')
        
        # Verify token expiry is set
        self.assertTrue(hasattr(vendor, '_token_expires_at'))
        
        # Verify request was made correctly
        mock_https.assert_called_once()
        mock_conn.request.assert_called_once()
        
        # Get the request arguments
        args = mock_conn.request.call_args
        method, path, body, headers = args[0]
        
        self.assertEqual(method, 'POST')
        self.assertIn('grant_type=client_credentials', body)
        self.assertIn('client_id=client123', body)
        self.assertIn('client_secret=secret456', body)
        self.assertIn('scope=read+write', body)
    
    @patch('http.client.HTTPSConnection')
    def test_oauth2_token_retrieval_failure(self, mock_https):
        """Test OAuth2 token retrieval failure."""
        config = self.base_config.copy()
        config['auth'] = {
            'method': 'oauth2',
            'client_id': 'client123',
            'client_secret': 'secret456',
            'token_url': 'https://auth.example.com/token'
        }
        
        # Mock failed token response
        mock_response = Mock()
        mock_response.status = 401
        mock_response.reason = 'Unauthorized'
        mock_response.read.return_value = b'{"error": "invalid_client"}'
        
        mock_conn = Mock()
        mock_conn.getresponse.return_value = mock_response
        mock_https.return_value = mock_conn
        
        vendor = MockVendorAPI(config)
        
        with patch('ldap_sync.vendors.base.logger') as mock_logger:
            result = vendor._oauth2_get_token()
            
            # Verify failure
            self.assertFalse(result)
            mock_logger.error.assert_called()
    
    def test_oauth2_token_validity_check(self):
        """Test OAuth2 token validity checking."""
        config = self.base_config.copy()
        config['auth'] = {
            'method': 'oauth2',
            'client_id': 'client123',
            'client_secret': 'secret456',
            'token_url': 'https://auth.example.com/token'
        }
        
        vendor = MockVendorAPI(config)
        
        # No token initially
        self.assertFalse(vendor._is_oauth2_token_valid())
        
        # Set token that expires in the future
        import time
        vendor._token_expires_at = time.time() + 1800  # 30 minutes from now
        self.assertTrue(vendor._is_oauth2_token_valid())
        
        # Set token that has expired
        vendor._token_expires_at = time.time() - 300  # 5 minutes ago
        self.assertFalse(vendor._is_oauth2_token_valid())
    
    def test_mutual_tls_authentication_setup(self):
        """Test Mutual TLS authentication setup."""
        config = self.base_config.copy()
        config['auth'] = {
            'method': 'mtls'
        }
        
        with patch('ldap_sync.vendors.base.logger') as mock_logger:
            vendor = MockVendorAPI(config)
            mock_logger.debug.assert_called()
            # mtls should not add any auth headers (handled by SSL context)
            self.assertEqual(len(vendor.auth_headers), 0)
    
    def test_mutual_tls_authentication_alias(self):
        """Test Mutual TLS authentication using 'mutual_tls' method alias."""
        config = self.base_config.copy()
        config['auth'] = {
            'method': 'mutual_tls'
        }
        
        with patch('ldap_sync.vendors.base.logger') as mock_logger:
            vendor = MockVendorAPI(config)
            mock_logger.debug.assert_called()
    
    def test_no_authentication_method(self):
        """Test when no authentication method is specified."""
        config = self.base_config.copy()
        config['auth'] = {}
        
        with patch('ldap_sync.vendors.base.logger') as mock_logger:
            vendor = MockVendorAPI(config)
            mock_logger.debug.assert_called()
            self.assertEqual(len(vendor.auth_headers), 0)
    
    def test_unknown_authentication_method(self):
        """Test unknown authentication method."""
        config = self.base_config.copy()
        config['auth'] = {
            'method': 'unknown_method'
        }
        
        with patch('ldap_sync.vendors.base.logger') as mock_logger:
            vendor = MockVendorAPI(config)
            mock_logger.warning.assert_called()
    
    def test_authenticate_method_basic(self):
        """Test authenticate() method with Basic auth."""
        config = self.base_config.copy()
        config['auth'] = {
            'method': 'basic',
            'username': 'testuser',
            'password': 'testpass'
        }
        
        vendor = MockVendorAPI(config)
        result = vendor.authenticate()
        self.assertTrue(result)
    
    def test_authenticate_method_token(self):
        """Test authenticate() method with token auth."""
        config = self.base_config.copy()
        config['auth'] = {
            'method': 'token',
            'token': 'abc123'
        }
        
        vendor = MockVendorAPI(config)
        result = vendor.authenticate()
        self.assertTrue(result)
    
    @patch('http.client.HTTPSConnection')
    def test_authenticate_method_oauth2(self, mock_https):
        """Test authenticate() method with OAuth2."""
        config = self.base_config.copy()
        config['auth'] = {
            'method': 'oauth2',
            'client_id': 'client123',
            'client_secret': 'secret456',
            'token_url': 'https://auth.example.com/token'
        }
        
        # Mock successful token response
        mock_response = Mock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps({
            'access_token': 'oauth2_token',
            'expires_in': 3600
        }).encode()
        
        mock_conn = Mock()
        mock_conn.getresponse.return_value = mock_response
        mock_https.return_value = mock_conn
        
        vendor = MockVendorAPI(config)
        result = vendor.authenticate()
        
        self.assertTrue(result)
        self.assertIn('Authorization', vendor.auth_headers)
    
    def test_authenticate_method_unknown(self):
        """Test authenticate() method with unknown auth method."""
        config = self.base_config.copy()
        config['auth'] = {
            'method': 'unknown'
        }
        
        vendor = MockVendorAPI(config)
        result = vendor.authenticate()
        self.assertFalse(result)
    
    @patch('http.client.HTTPSConnection')
    def test_oauth2_automatic_token_refresh_on_401(self, mock_https):
        """Test automatic OAuth2 token refresh on 401 response."""
        config = self.base_config.copy()
        config['auth'] = {
            'method': 'oauth2',
            'client_id': 'client123',
            'client_secret': 'secret456',
            'token_url': 'https://auth.example.com/token'
        }
        
        vendor = MockVendorAPI(config)
        
        # Set up initial token
        vendor.auth_headers['Authorization'] = 'Bearer old_token'
        
        # Mock responses: first 401 (expired token), then success after refresh
        mock_api_response_401 = Mock()
        mock_api_response_401.status = 401
        mock_api_response_401.reason = 'Unauthorized'
        mock_api_response_401.read.return_value = b'{"error": "token_expired"}'
        
        mock_api_response_200 = Mock()
        mock_api_response_200.status = 200
        mock_api_response_200.read.return_value = b'{"result": "success"}'
        
        # Mock token refresh response
        mock_token_response = Mock()
        mock_token_response.status = 200
        mock_token_response.read.return_value = json.dumps({
            'access_token': 'new_refreshed_token',
            'expires_in': 3600
        }).encode()
        
        # Create separate mock connections for different calls
        mock_api_conn = Mock()
        mock_token_conn = Mock()
        
        # Set up the sequence: 401 response, then success response
        mock_api_conn.getresponse.side_effect = [mock_api_response_401, mock_api_response_200]
        mock_token_conn.getresponse.return_value = mock_token_response
        
        # Mock HTTPSConnection to return different connections for different hosts
        def mock_https_factory(host, **kwargs):
            if 'auth.example.com' in host:
                return mock_token_conn
            else:
                return mock_api_conn
        
        mock_https.side_effect = mock_https_factory
        
        # Make request that should trigger token refresh
        result = vendor.request('GET', '/test')
        
        # Verify we got the success response
        self.assertEqual(result, {'result': 'success'})
        
        # Verify the token was refreshed
        self.assertEqual(vendor.auth_headers['Authorization'], 'Bearer new_refreshed_token')
        
        # Verify API was called twice (initial + retry)
        self.assertEqual(mock_api_conn.request.call_count, 2)
        
        # Verify token endpoint was called once
        mock_token_conn.request.assert_called_once()


if __name__ == '__main__':
    unittest.main(verbosity=2)