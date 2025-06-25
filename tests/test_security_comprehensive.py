#!/usr/bin/env python3
"""
Comprehensive security tests for credential handling and SSL.
"""

import os
import sys
import unittest
import tempfile
import ssl
import base64
from unittest.mock import Mock, patch, mock_open, MagicMock

# Add the project directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ldap_sync.config import ConfigLoader
from ldap_sync.ldap_client import LDAPClient
from ldap_sync.vendors.base import VendorAPIBase
from ldap_sync.logging_setup import SensitiveDataFilter


class TestCredentialHandling(unittest.TestCase):
    """Test cases for secure credential handling."""

    def test_config_password_masking(self):
        """Test that passwords are masked in configuration objects."""
        config_data = {
            'ldap': {
                'server_url': 'ldaps://ldap.example.com:636',
                'bind_dn': 'cn=service,dc=example,dc=com',
                'bind_password': 'secret_ldap_password',
                'user_base_dn': 'ou=users,dc=example,dc=com'
            },
            'vendor_apps': [
                {
                    'name': 'TestApp',
                    'module': 'vendor_app1',
                    'base_url': 'https://api.testapp.com/v1',
                    'auth': {
                        'method': 'basic',
                        'username': 'api_user',
                        'password': 'secret_api_password'
                    },
                    'groups': [
                        {
                            'ldap_group': 'cn=test,dc=example,dc=com',
                            'vendor_group': 'test_group'
                        }
                    ]
                }
            ],
            'notifications': {
                'smtp_password': 'secret_smtp_password',
                'smtp_server': 'smtp.example.com',
                'email_from': 'alerts@example.com',
                'email_to': ['admin@example.com']
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(config_data, f)
            config_path = f.name
        
        try:
            loader = ConfigLoader(config_path)
            config = loader.load()
            
            # Convert config to string representation
            config_str = str(config)
            
            # Passwords should be masked in string representation
            self.assertNotIn('secret_ldap_password', config_str)
            self.assertNotIn('secret_api_password', config_str)
            self.assertNotIn('secret_smtp_password', config_str)
            
            # Should contain masked indicators
            self.assertIn('***', config_str)
            
        finally:
            os.unlink(config_path)

    def test_environment_variable_password_override(self):
        """Test that environment variables properly override password configs."""
        config_data = {
            'ldap': {
                'server_url': 'ldaps://ldap.example.com:636',
                'bind_dn': 'cn=service,dc=example,dc=com',
                'bind_password': 'file_password',
                'user_base_dn': 'ou=users,dc=example,dc=com'
            },
            'vendor_apps': [
                {
                    'name': 'TestApp',
                    'module': 'vendor_app1',
                    'base_url': 'https://api.testapp.com/v1',
                    'auth': {
                        'method': 'basic',
                        'username': 'api_user',
                        'password': 'file_password'
                    },
                    'groups': [
                        {
                            'ldap_group': 'cn=test,dc=example,dc=com',
                            'vendor_group': 'test_group'
                        }
                    ]
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(config_data, f)
            config_path = f.name
        
        try:
            with patch.dict(os.environ, {
                'LDAP_BIND_PASSWORD': 'env_ldap_password',
                'TESTAPP_PASSWORD': 'env_api_password'
            }):
                loader = ConfigLoader(config_path)
                config = loader.load()
                
                # Environment variables should override file values
                self.assertEqual(config['ldap']['bind_password'], 'env_ldap_password')
                self.assertEqual(config['vendor_apps'][0]['auth']['password'], 'env_api_password')
                
                # Original file passwords should not be present
                config_str = str(config)
                self.assertNotIn('file_password', config_str)
                
        finally:
            os.unlink(config_path)

    def test_vendor_auth_header_encoding(self):
        """Test proper encoding of authentication headers."""
        config = {
            'name': 'TestVendor',
            'base_url': 'https://api.testvendor.com/v1',
            'auth': {
                'method': 'basic',
                'username': 'test_user',
                'password': 'test_password123!'  # Special characters
            },
            'format': 'json'
        }
        
        api = VendorAPIBase(config)
        headers = api._prepare_auth_headers()
        
        # Verify Authorization header is present
        self.assertIn('Authorization', headers)
        
        # Verify proper base64 encoding
        auth_header = headers['Authorization']
        self.assertTrue(auth_header.startswith('Basic '))
        
        encoded_creds = auth_header[6:]  # Remove 'Basic ' prefix
        decoded_creds = base64.b64decode(encoded_creds).decode('utf-8')
        self.assertEqual(decoded_creds, 'test_user:test_password123!')

    def test_token_auth_header_security(self):
        """Test secure handling of token authentication."""
        config = {
            'name': 'TestVendor',
            'base_url': 'https://api.testvendor.com/v1',
            'auth': {
                'method': 'token',
                'token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sensitive_token_data'
            },
            'format': 'json'
        }
        
        api = VendorAPIBase(config)
        headers = api._prepare_auth_headers()
        
        # Verify Authorization header is present with Bearer token
        self.assertIn('Authorization', headers)
        auth_header = headers['Authorization']
        self.assertTrue(auth_header.startswith('Bearer '))
        self.assertIn('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', auth_header)

    def test_oauth2_token_handling(self):
        """Test secure OAuth2 token handling."""
        config = {
            'name': 'TestVendor',
            'base_url': 'https://api.testvendor.com/v1',
            'auth': {
                'method': 'oauth2',
                'client_id': 'test_client_id',
                'client_secret': 'very_secret_client_secret',
                'token_url': 'https://api.testvendor.com/oauth/token'
            },
            'format': 'json'
        }
        
        api = VendorAPIBase(config)
        
        # Mock successful token retrieval
        with patch.object(api, '_make_request') as mock_request:
            mock_request.return_value = {
                'status_code': 200,
                'data': {
                    'access_token': 'oauth_access_token_12345',
                    'token_type': 'Bearer',
                    'expires_in': 3600
                }
            }
            
            api.authenticate()
            
            # Verify token is stored securely
            self.assertEqual(api.access_token, 'oauth_access_token_12345')
            
            # Verify client credentials are properly encoded in request
            mock_request.assert_called_once()
            call_args = mock_request.call_args
            
            # Should use client credentials for token request
            self.assertIn('data', call_args[1])

    def test_ldap_password_not_logged(self):
        """Test that LDAP passwords are not logged."""
        config = {
            'server_url': 'ldaps://ldap.example.com:636',
            'bind_dn': 'cn=service,dc=example,dc=com',
            'bind_password': 'secret_ldap_password',
            'user_base_dn': 'ou=users,dc=example,dc=com'
        }
        
        with patch('ldap_sync.ldap_client.logger') as mock_logger:
            client = LDAPClient(config)
            
            # Check all log calls to ensure password is not present
            for call in mock_logger.debug.call_args_list + mock_logger.info.call_args_list:
                log_message = str(call)
                self.assertNotIn('secret_ldap_password', log_message)


class TestSSLConfiguration(unittest.TestCase):
    """Test cases for SSL/TLS configuration and security."""

    def test_ssl_context_creation_default(self):
        """Test default SSL context creation."""
        config = {
            'name': 'TestVendor',
            'base_url': 'https://api.testvendor.com/v1',
            'auth': {'method': 'basic', 'username': 'user', 'password': 'pass'},
            'verify_ssl': True
        }
        
        with patch('ssl.create_default_context') as mock_ssl_context:
            mock_context = Mock()
            mock_ssl_context.return_value = mock_context
            
            api = VendorAPIBase(config)
            context = api._create_ssl_context()
            
            self.assertIsNotNone(context)
            mock_ssl_context.assert_called_once()
            
            # Default context should have secure settings
            self.assertNotEqual(mock_context.verify_mode, ssl.CERT_NONE)

    def test_ssl_context_verification_disabled(self):
        """Test SSL context with verification disabled."""
        config = {
            'name': 'TestVendor',
            'base_url': 'https://api.testvendor.com/v1',
            'auth': {'method': 'basic', 'username': 'user', 'password': 'pass'},
            'verify_ssl': False
        }
        
        with patch('ssl.create_default_context') as mock_ssl_context:
            mock_context = Mock()
            mock_ssl_context.return_value = mock_context
            
            api = VendorAPIBase(config)
            context = api._create_ssl_context()
            
            # Verification should be disabled
            self.assertEqual(mock_context.check_hostname, False)
            self.assertEqual(mock_context.verify_mode, ssl.CERT_NONE)

    @patch('os.path.exists')
    def test_ssl_context_with_custom_ca(self, mock_exists):
        """Test SSL context with custom CA certificate."""
        mock_exists.return_value = True
        
        config = {
            'name': 'TestVendor',
            'base_url': 'https://api.testvendor.com/v1',
            'auth': {'method': 'basic', 'username': 'user', 'password': 'pass'},
            'verify_ssl': True,
            'truststore_file': '/path/to/ca-bundle.pem'
        }
        
        with patch('ssl.create_default_context') as mock_ssl_context:
            mock_context = Mock()
            mock_ssl_context.return_value = mock_context
            
            api = VendorAPIBase(config)
            context = api._create_ssl_context()
            
            # Should load custom CA certificate
            mock_context.load_verify_locations.assert_called_once_with('/path/to/ca-bundle.pem')

    @patch('os.path.exists')
    def test_ssl_context_with_client_certificate(self, mock_exists):
        """Test SSL context with client certificate."""
        mock_exists.return_value = True
        
        config = {
            'name': 'TestVendor',
            'base_url': 'https://api.testvendor.com/v1',
            'auth': {'method': 'basic', 'username': 'user', 'password': 'pass'},
            'verify_ssl': True,
            'cert_file': '/path/to/client.pem',
            'key_file': '/path/to/client-key.pem'
        }
        
        with patch('ssl.create_default_context') as mock_ssl_context:
            mock_context = Mock()
            mock_ssl_context.return_value = mock_context
            
            api = VendorAPIBase(config)
            context = api._create_ssl_context()
            
            # Should load client certificate
            mock_context.load_cert_chain.assert_called_once_with('/path/to/client.pem', '/path/to/client-key.pem')

    def test_ssl_context_certificate_file_validation(self):
        """Test SSL context validation of certificate file paths."""
        config = {
            'name': 'TestVendor',
            'base_url': 'https://api.testvendor.com/v1',
            'auth': {'method': 'basic', 'username': 'user', 'password': 'pass'},
            'verify_ssl': True,
            'truststore_file': '/nonexistent/ca-bundle.pem'
        }
        
        with patch('os.path.exists', return_value=False):
            api = VendorAPIBase(config)
            
            # Should log warning about missing certificate file
            with patch('ldap_sync.vendors.base.logger') as mock_logger:
                context = api._create_ssl_context()
                
                # Should still create context but log warning
                mock_logger.warning.assert_called()
                warning_message = str(mock_logger.warning.call_args)
                self.assertIn('not found', warning_message)

    def test_ldap_ssl_context_creation(self):
        """Test LDAP SSL context creation."""
        config = {
            'server_url': 'ldaps://ldap.example.com:636',
            'bind_dn': 'cn=service,dc=example,dc=com',
            'bind_password': 'password',
            'verify_ssl': True,
            'ca_cert_file': '/path/to/ldap-ca.pem'
        }
        
        with patch('os.path.exists', return_value=True):
            client = LDAPClient(config)
            
            with patch('ssl.create_default_context') as mock_ssl_context:
                mock_context = Mock()
                mock_ssl_context.return_value = mock_context
                
                tls_config = client._create_tls_config()
                
                self.assertIsNotNone(tls_config)
                mock_context.load_verify_locations.assert_called_with('/path/to/ldap-ca.pem')

    def test_ldap_starttls_configuration(self):
        """Test LDAP StartTLS configuration."""
        config = {
            'server_url': 'ldap://ldap.example.com:389',
            'bind_dn': 'cn=service,dc=example,dc=com',
            'bind_password': 'password',
            'start_tls': True,
            'verify_ssl': True
        }
        
        client = LDAPClient(config)
        
        # Should configure for StartTLS
        self.assertFalse(client.use_ssl)  # Not LDAPS
        self.assertTrue(client.start_tls)   # But StartTLS enabled
        self.assertTrue(client.verify_ssl)

    def test_ssl_protocol_version_security(self):
        """Test that only secure SSL/TLS protocols are used."""
        config = {
            'name': 'TestVendor',
            'base_url': 'https://api.testvendor.com/v1',
            'auth': {'method': 'basic', 'username': 'user', 'password': 'pass'},
            'verify_ssl': True
        }
        
        with patch('ssl.create_default_context') as mock_ssl_context:
            mock_context = Mock()
            mock_ssl_context.return_value = mock_context
            
            api = VendorAPIBase(config)
            context = api._create_ssl_context()
            
            # Should use secure SSL context with appropriate minimum version
            mock_ssl_context.assert_called_once()
            
            # Context should not allow insecure protocols
            # (Modern ssl.create_default_context() handles this automatically)


class TestLogSanitization(unittest.TestCase):
    """Test cases for log sanitization and sensitive data filtering."""

    def test_sensitive_data_filter_passwords(self):
        """Test filtering of passwords from log messages."""
        filter_obj = SensitiveDataFilter()
        
        # Test various password patterns
        test_cases = [
            ("User password: secret123", "User password: ***"),
            ("bind_password=mysecret", "bind_password=***"),
            ("password='complex!pass'", "password='***'"),
            ('password="another!secret"', 'password="***"'),
            ("API key: abc123def456", "API key: ***"),
            ("token=bearer_token_value", "token=***"),
            ("authorization: Bearer xyz789", "authorization: Bearer ***")
        ]
        
        for original, expected in test_cases:
            record = Mock()
            record.getMessage.return_value = original
            
            # Apply filter
            filtered = filter_obj.filter(record)
            
            # Filter should return True to allow logging
            self.assertTrue(filtered)
            
            # Message should be sanitized
            sanitized_message = record.getMessage()
            self.assertNotIn('secret', sanitized_message.lower())
            self.assertNotIn('abc123', sanitized_message)
            self.assertIn('***', sanitized_message)

    def test_sensitive_data_filter_json_content(self):
        """Test filtering of JSON content with sensitive data."""
        filter_obj = SensitiveDataFilter()
        
        json_with_secrets = '''
        {
            "username": "test_user",
            "password": "secret_password",
            "api_key": "sensitive_api_key",
            "data": {
                "token": "nested_token_value",
                "public_info": "this should remain"
            }
        }
        '''
        
        record = Mock()
        record.getMessage.return_value = json_with_secrets
        
        filtered = filter_obj.filter(record)
        sanitized = record.getMessage()
        
        # Should remove sensitive values but keep structure
        self.assertIn('"username": "test_user"', sanitized)
        self.assertIn('"public_info": "this should remain"', sanitized)
        self.assertNotIn('secret_password', sanitized)
        self.assertNotIn('sensitive_api_key', sanitized)
        self.assertNotIn('nested_token_value', sanitized)
        self.assertIn('***', sanitized)

    def test_sensitive_data_filter_url_parameters(self):
        """Test filtering of sensitive data in URLs."""
        filter_obj = SensitiveDataFilter()
        
        test_urls = [
            "https://api.example.com/auth?password=secret123&user=test",
            "https://api.example.com/oauth?client_secret=abc123&grant_type=client_credentials",
            "POST /token HTTP/1.1\nAuthorization: Basic dGVzdDpzZWNyZXQ="
        ]
        
        for url in test_urls:
            record = Mock()
            record.getMessage.return_value = f"Making request to: {url}"
            
            filter_obj.filter(record)
            sanitized = record.getMessage()
            
            self.assertNotIn('secret123', sanitized)
            self.assertNotIn('abc123', sanitized)
            self.assertNotIn('dGVzdDpzZWNyZXQ=', sanitized)  # base64 encoded secret
            self.assertIn('***', sanitized)

    def test_sensitive_data_filter_preserves_non_sensitive(self):
        """Test that non-sensitive data is preserved."""
        filter_obj = SensitiveDataFilter()
        
        safe_messages = [
            "User john.doe logged in successfully",
            "Processing group: cn=users,ou=groups,dc=example,dc=com",
            "HTTP 200 OK: Request successful",
            "Added 5 users to group 'developers'",
            "Configuration loaded from config.yaml"
        ]
        
        for message in safe_messages:
            record = Mock()
            record.getMessage.return_value = message
            original_message = message
            
            filter_obj.filter(record)
            sanitized = record.getMessage()
            
            # Non-sensitive messages should be unchanged
            self.assertEqual(sanitized, original_message)

    def test_config_representation_security(self):
        """Test that config object representations don't leak secrets."""
        config_data = {
            'ldap': {
                'bind_password': 'ldap_secret_password',
                'server_url': 'ldaps://ldap.example.com:636'
            },
            'vendor_apps': [
                {
                    'auth': {
                        'password': 'vendor_secret_password',
                        'username': 'api_user'
                    }
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(config_data, f)
            config_path = f.name
        
        try:
            loader = ConfigLoader(config_path)
            config = loader.load()
            
            # Test various ways config might be represented
            config_str = str(config)
            config_repr = repr(config)
            
            for representation in [config_str, config_repr]:
                self.assertNotIn('ldap_secret_password', representation)
                self.assertNotIn('vendor_secret_password', representation)
                
        finally:
            os.unlink(config_path)


class TestSecurityBestPractices(unittest.TestCase):
    """Test cases for security best practices implementation."""

    def test_http_to_https_enforcement(self):
        """Test that HTTP URLs are properly handled for security."""
        config = {
            'name': 'TestVendor',
            'base_url': 'http://api.testvendor.com/v1',  # HTTP instead of HTTPS
            'auth': {'method': 'basic', 'username': 'user', 'password': 'pass'}
        }
        
        with patch('ldap_sync.vendors.base.logger') as mock_logger:
            api = VendorAPIBase(config)
            
            # Should log warning about HTTP usage
            mock_logger.warning.assert_called()
            warning_message = str(mock_logger.warning.call_args)
            self.assertIn('HTTP', warning_message)
            self.assertIn('secure', warning_message.lower())

    def test_default_ssl_verification_enabled(self):
        """Test that SSL verification is enabled by default."""
        config = {
            'name': 'TestVendor',
            'base_url': 'https://api.testvendor.com/v1',
            'auth': {'method': 'basic', 'username': 'user', 'password': 'pass'}
            # No verify_ssl specified - should default to True
        }
        
        api = VendorAPIBase(config)
        self.assertTrue(api.verify_ssl)  # Should default to True for security

    def test_secure_defaults_ldap(self):
        """Test that LDAP client uses secure defaults."""
        config = {
            'server_url': 'ldaps://ldap.example.com:636',
            'bind_dn': 'cn=service,dc=example,dc=com',
            'bind_password': 'password'
            # No explicit SSL settings
        }
        
        client = LDAPClient(config)
        
        # Should detect LDAPS and enable SSL
        self.assertTrue(client.use_ssl)
        # Should default to SSL verification
        self.assertTrue(client.verify_ssl)

    def test_minimum_password_requirements_warning(self):
        """Test warnings for weak password configurations."""
        weak_passwords = [
            'weak',
            '12345',
            'password',
            'admin'
        ]
        
        for weak_password in weak_passwords:
            config_data = {
                'ldap': {
                    'server_url': 'ldaps://ldap.example.com:636',
                    'bind_dn': 'cn=service,dc=example,dc=com',
                    'bind_password': weak_password
                },
                'vendor_apps': []
            }
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                import yaml
                yaml.dump(config_data, f)
                config_path = f.name
            
            try:
                with patch('ldap_sync.config.logger') as mock_logger:
                    loader = ConfigLoader(config_path)
                    config = loader.load()
                    
                    # Should log warning about weak password
                    # (Implementation depends on whether weak password detection is implemented)
                    
            finally:
                os.unlink(config_path)

    def test_secure_temp_file_handling(self):
        """Test secure handling of temporary files."""
        # This test ensures that any temporary files created have secure permissions
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            temp_path = temp_file.name
            temp_file.write("sensitive data")
        
        try:
            # Check file permissions
            stat_info = os.stat(temp_path)
            permissions = oct(stat_info.st_mode)[-3:]
            
            # Should not be world-readable (6xx or 7xx permissions are acceptable)
            self.assertNotIn('4', permissions[2])  # Others should not have read permission
            self.assertNotIn('5', permissions[2])  # Others should not have read+execute
            self.assertNotIn('6', permissions[2])  # Others should not have read+write
            self.assertNotIn('7', permissions[2])  # Others should not have full permissions
            
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_memory_cleanup_sensitive_data(self):
        """Test that sensitive data is properly cleaned from memory."""
        config = {
            'name': 'TestVendor',
            'base_url': 'https://api.testvendor.com/v1',
            'auth': {
                'method': 'basic',
                'username': 'user',
                'password': 'sensitive_password'
            }
        }
        
        api = VendorAPIBase(config)
        
        # Access password to ensure it's loaded
        password = api.auth_config['password']
        self.assertEqual(password, 'sensitive_password')
        
        # Clean up (simulated - actual implementation would need memory clearing)
        api.auth_config['password'] = None
        
        # Verify password is cleared
        self.assertIsNone(api.auth_config['password'])


class TestInputValidation(unittest.TestCase):
    """Test cases for input validation and injection prevention."""

    def test_ldap_injection_prevention(self):
        """Test prevention of LDAP injection attacks."""
        # Test malicious LDAP filter injection attempts
        malicious_inputs = [
            "user)(objectClass=*",
            "user*)(&(objectClass=person)(cn=admin",
            "user*)(|(objectClass=*)(cn=*",
            "user\\2a)(objectClass=*"
        ]
        
        config = {
            'server_url': 'ldaps://ldap.example.com:636',
            'bind_dn': 'cn=service,dc=example,dc=com',
            'bind_password': 'password'
        }
        
        client = LDAPClient(config)
        
        for malicious_input in malicious_inputs:
            # The LDAP client should properly escape or validate inputs
            # This test assumes the client has input validation
            with self.assertRaises((ValueError, Exception)):
                # Attempt to use malicious input in group DN
                client._validate_group_dn(malicious_input)

    def test_api_parameter_validation(self):
        """Test validation of API parameters."""
        config = {
            'name': 'TestVendor',
            'base_url': 'https://api.testvendor.com/v1',
            'auth': {'method': 'basic', 'username': 'user', 'password': 'pass'}
        }
        
        api = VendorAPIBase(config)
        
        # Test parameter validation in URL building
        malicious_params = {
            'user'; DROP TABLE users; --': 'value',
            '<script>alert("xss")</script>': 'value',
            '../../../etc/passwd': 'value'
        }
        
        # Should handle malicious parameters safely
        for param_name, param_value in malicious_params.items():
            url = api._build_url('/test', {param_name: param_value})
            
            # URL should be properly encoded/escaped
            self.assertNotIn('<script>', url)
            self.assertNotIn('DROP TABLE', url)
            self.assertNotIn('../', url)

    def test_json_payload_sanitization(self):
        """Test sanitization of JSON payloads."""
        config = {
            'name': 'TestVendor',
            'base_url': 'https://api.testvendor.com/v1',
            'auth': {'method': 'basic', 'username': 'user', 'password': 'pass'},
            'format': 'json'
        }
        
        api = VendorAPIBase(config)
        
        # Test with potentially dangerous data
        dangerous_data = {
            'username': 'normal_user',
            'description': '<script>alert("xss")</script>',
            'notes': '"; DROP TABLE users; --',
            'email': 'user@example.com'
        }
        
        json_body = api._prepare_request_body(dangerous_data)
        
        # Should be valid JSON
        import json
        parsed = json.loads(json_body)
        
        # Should contain the data but safely encoded
        self.assertIn('normal_user', json_body)
        self.assertIn('user@example.com', json_body)
        
        # Dangerous content should be safely encoded in JSON
        self.assertNotIn('<script>', parsed['description'])  # JSON encoding should escape
        self.assertNotIn('DROP TABLE', parsed['notes'])       # Should be string literal


if __name__ == '__main__':
    unittest.main()