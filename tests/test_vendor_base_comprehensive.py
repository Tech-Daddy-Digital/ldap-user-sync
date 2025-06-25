#!/usr/bin/env python3
"""
Comprehensive unit tests for vendor base class.
"""

import os
import sys
import unittest
import json
import ssl
from unittest.mock import Mock, patch, MagicMock, mock_open
from http.client import HTTPResponse
from io import BytesIO

# Add the project directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ldap_sync.vendors.base import VendorAPIBase, VendorAPIError, AuthenticationError


class TestVendorAPIBase(unittest.TestCase):
    """Test cases for VendorAPIBase class."""

    def setUp(self):
        """Set up test fixtures."""
        self.basic_config = {
            'name': 'TestVendor',
            'base_url': 'https://api.testvendor.com/v1',
            'auth': {
                'method': 'basic',
                'username': 'testuser',
                'password': 'testpass'
            },
            'format': 'json',
            'verify_ssl': True,
            'timeout': 30
        }

    def test_initialization_basic_config(self):
        """Test basic vendor API initialization."""
        api = VendorAPIBase(self.basic_config)
        
        self.assertEqual(api.name, 'TestVendor')
        self.assertEqual(api.base_url, 'https://api.testvendor.com/v1')
        self.assertEqual(api.host, 'api.testvendor.com')
        self.assertEqual(api.port, 443)
        self.assertEqual(api.auth_method, 'basic')
        self.assertEqual(api.format, 'json')
        self.assertTrue(api.verify_ssl)
        self.assertEqual(api.timeout, 30)

    def test_initialization_advanced_config(self):
        """Test vendor API initialization with advanced configuration."""
        advanced_config = self.basic_config.copy()
        advanced_config.update({
            'base_url': 'http://api.testvendor.com:8080/api',
            'auth': {
                'method': 'token',
                'token': 'abc123def456'
            },
            'format': 'xml',
            'verify_ssl': False,
            'timeout': 60,
            'headers': {
                'X-API-Version': '2.0',
                'X-Client-ID': 'ldap-sync'
            },
            'truststore_file': '/path/to/truststore.pem',
            'cert_file': '/path/to/client.pem',
            'key_file': '/path/to/client-key.pem'
        })
        
        api = VendorAPIBase(advanced_config)
        
        self.assertEqual(api.host, 'api.testvendor.com')
        self.assertEqual(api.port, 8080)
        self.assertEqual(api.auth_method, 'token')
        self.assertEqual(api.format, 'xml')
        self.assertFalse(api.verify_ssl)
        self.assertEqual(api.timeout, 60)
        self.assertIn('X-API-Version', api.headers)

    def test_url_parsing(self):
        """Test URL parsing for different formats."""
        test_cases = [
            ('https://api.example.com', 'api.example.com', 443),
            ('https://api.example.com:8443', 'api.example.com', 8443),
            ('http://api.example.com', 'api.example.com', 80),
            ('http://api.example.com:8080/api/v1', 'api.example.com', 8080),
        ]
        
        for url, expected_host, expected_port in test_cases:
            config = self.basic_config.copy()
            config['base_url'] = url
            api = VendorAPIBase(config)
            
            self.assertEqual(api.host, expected_host)
            self.assertEqual(api.port, expected_port)

    @patch('ssl.create_default_context')
    def test_ssl_context_creation_default(self, mock_ssl_context):
        """Test SSL context creation with default settings."""
        mock_context = Mock()
        mock_ssl_context.return_value = mock_context
        
        api = VendorAPIBase(self.basic_config)
        context = api._create_ssl_context()
        
        self.assertIsNotNone(context)
        mock_ssl_context.assert_called_once()

    @patch('ssl.create_default_context')
    def test_ssl_context_creation_no_verification(self, mock_ssl_context):
        """Test SSL context creation without verification."""
        mock_context = Mock()
        mock_ssl_context.return_value = mock_context
        
        config = self.basic_config.copy()
        config['verify_ssl'] = False
        
        api = VendorAPIBase(config)
        context = api._create_ssl_context()
        
        self.assertEqual(mock_context.check_hostname, False)
        self.assertEqual(mock_context.verify_mode, ssl.CERT_NONE)

    @patch('ssl.create_default_context')
    @patch('os.path.exists')
    def test_ssl_context_with_certificates(self, mock_exists, mock_ssl_context):
        """Test SSL context creation with custom certificates."""
        mock_exists.return_value = True
        mock_context = Mock()
        mock_ssl_context.return_value = mock_context
        
        config = self.basic_config.copy()
        config.update({
            'truststore_file': '/path/to/ca.pem',
            'cert_file': '/path/to/client.pem',
            'key_file': '/path/to/client-key.pem'
        })
        
        api = VendorAPIBase(config)
        context = api._create_ssl_context()
        
        mock_context.load_verify_locations.assert_called_once_with('/path/to/ca.pem')
        mock_context.load_cert_chain.assert_called_once_with('/path/to/client.pem', '/path/to/client-key.pem')

    def test_basic_auth_header_preparation(self):
        """Test basic authentication header preparation."""
        api = VendorAPIBase(self.basic_config)
        headers = api._prepare_auth_headers()
        
        self.assertIn('Authorization', headers)
        # Should be base64 encoded "testuser:testpass"
        import base64
        expected = base64.b64encode(b'testuser:testpass').decode('ascii')
        self.assertEqual(headers['Authorization'], f'Basic {expected}')

    def test_token_auth_header_preparation(self):
        """Test token authentication header preparation."""
        config = self.basic_config.copy()
        config['auth'] = {
            'method': 'token',
            'token': 'abc123def456'
        }
        
        api = VendorAPIBase(config)
        headers = api._prepare_auth_headers()
        
        self.assertIn('Authorization', headers)
        self.assertEqual(headers['Authorization'], 'Bearer abc123def456')

    def test_oauth2_auth_header_preparation(self):
        """Test OAuth2 authentication header preparation."""
        config = self.basic_config.copy()
        config['auth'] = {
            'method': 'oauth2',
            'client_id': 'test_client',
            'client_secret': 'test_secret',
            'token_url': 'https://api.testvendor.com/oauth/token'
        }
        
        api = VendorAPIBase(config)
        api.access_token = 'oauth_access_token'
        headers = api._prepare_auth_headers()
        
        self.assertIn('Authorization', headers)
        self.assertEqual(headers['Authorization'], 'Bearer oauth_access_token')

    def test_prepare_request_headers_json(self):
        """Test request headers preparation for JSON format."""
        api = VendorAPIBase(self.basic_config)
        headers = api._prepare_request_headers({'Custom': 'Value'})
        
        self.assertIn('Content-Type', headers)
        self.assertEqual(headers['Content-Type'], 'application/json')
        self.assertIn('Accept', headers)
        self.assertEqual(headers['Accept'], 'application/json')
        self.assertIn('Custom', headers)
        self.assertEqual(headers['Custom'], 'Value')

    def test_prepare_request_headers_xml(self):
        """Test request headers preparation for XML format."""
        config = self.basic_config.copy()
        config['format'] = 'xml'
        
        api = VendorAPIBase(config)
        headers = api._prepare_request_headers()
        
        self.assertEqual(headers['Content-Type'], 'application/xml')
        self.assertEqual(headers['Accept'], 'application/xml')

    def test_prepare_request_body_json(self):
        """Test request body preparation for JSON format."""
        api = VendorAPIBase(self.basic_config)
        data = {'name': 'Test User', 'email': 'test@example.com'}
        
        body = api._prepare_request_body(data)
        
        self.assertIsInstance(body, str)
        parsed = json.loads(body)
        self.assertEqual(parsed['name'], 'Test User')
        self.assertEqual(parsed['email'], 'test@example.com')

    def test_prepare_request_body_xml(self):
        """Test request body preparation for XML format."""
        config = self.basic_config.copy()
        config['format'] = 'xml'
        
        api = VendorAPIBase(config)
        data = {'name': 'Test User', 'email': 'test@example.com'}
        
        body = api._prepare_request_body(data)
        
        self.assertIsInstance(body, str)
        self.assertIn('<name>Test User</name>', body)
        self.assertIn('<email>test@example.com</email>', body)

    def test_prepare_request_body_none(self):
        """Test request body preparation with None data."""
        api = VendorAPIBase(self.basic_config)
        body = api._prepare_request_body(None)
        self.assertIsNone(body)

    def test_prepare_request_body_string(self):
        """Test request body preparation with string data."""
        api = VendorAPIBase(self.basic_config)
        data = '{"already": "json"}'
        body = api._prepare_request_body(data)
        self.assertEqual(body, data)

    @patch('http.client.HTTPSConnection')
    def test_make_request_success(self, mock_https):
        """Test successful HTTP request."""
        # Mock HTTP response
        mock_response = Mock(spec=HTTPResponse)
        mock_response.status = 200
        mock_response.reason = 'OK'
        mock_response.read.return_value = b'{"status": "success"}'
        mock_response.getheader.return_value = 'application/json'
        
        mock_connection = Mock()
        mock_connection.getresponse.return_value = mock_response
        mock_https.return_value = mock_connection
        
        api = VendorAPIBase(self.basic_config)
        response = api._make_request('GET', '/test')
        
        self.assertEqual(response['status_code'], 200)
        self.assertEqual(response['data']['status'], 'success')
        mock_connection.request.assert_called_once()

    @patch('http.client.HTTPSConnection')
    def test_make_request_with_body(self, mock_https):
        """Test HTTP request with request body."""
        mock_response = Mock(spec=HTTPResponse)
        mock_response.status = 201
        mock_response.reason = 'Created'
        mock_response.read.return_value = b'{"id": 123}'
        mock_response.getheader.return_value = 'application/json'
        
        mock_connection = Mock()
        mock_connection.getresponse.return_value = mock_response
        mock_https.return_value = mock_connection
        
        api = VendorAPIBase(self.basic_config)
        data = {'name': 'Test User'}
        response = api._make_request('POST', '/users', data=data)
        
        self.assertEqual(response['status_code'], 201)
        # Verify request was called with JSON body
        args, kwargs = mock_connection.request.call_args
        self.assertEqual(args[0], 'POST')
        self.assertIn('{"name": "Test User"}', args[2])

    @patch('http.client.HTTPSConnection')
    def test_make_request_http_error(self, mock_https):
        """Test HTTP request with error status."""
        mock_response = Mock(spec=HTTPResponse)
        mock_response.status = 404
        mock_response.reason = 'Not Found'
        mock_response.read.return_value = b'{"error": "Resource not found"}'
        mock_response.getheader.return_value = 'application/json'
        
        mock_connection = Mock()
        mock_connection.getresponse.return_value = mock_response
        mock_https.return_value = mock_connection
        
        api = VendorAPIBase(self.basic_config)
        
        with self.assertRaises(VendorAPIError) as context:
            api._make_request('GET', '/nonexistent')
        
        self.assertIn('404', str(context.exception))
        self.assertIn('Not Found', str(context.exception))

    @patch('http.client.HTTPSConnection')
    def test_make_request_connection_error(self, mock_https):
        """Test HTTP request with connection error."""
        mock_https.side_effect = ConnectionError("Connection failed")
        
        api = VendorAPIBase(self.basic_config)
        
        with self.assertRaises(VendorAPIError) as context:
            api._make_request('GET', '/test')
        
        self.assertIn('Connection failed', str(context.exception))

    def test_parse_response_json(self):
        """Test JSON response parsing."""
        api = VendorAPIBase(self.basic_config)
        
        response_data = b'{"users": [{"id": 1, "name": "Test"}]}'
        content_type = 'application/json'
        
        parsed = api._parse_response(response_data, content_type)
        
        self.assertIsInstance(parsed, dict)
        self.assertIn('users', parsed)
        self.assertEqual(len(parsed['users']), 1)
        self.assertEqual(parsed['users'][0]['name'], 'Test')

    def test_parse_response_xml(self):
        """Test XML response parsing."""
        config = self.basic_config.copy()
        config['format'] = 'xml'
        
        api = VendorAPIBase(config)
        
        response_data = b'<root><user><id>1</id><name>Test</name></user></root>'
        content_type = 'application/xml'
        
        parsed = api._parse_response(response_data, content_type)
        
        self.assertIsInstance(parsed, dict)
        self.assertIn('user', parsed)
        self.assertEqual(parsed['user']['name'], 'Test')

    def test_parse_response_invalid_json(self):
        """Test parsing of invalid JSON response."""
        api = VendorAPIBase(self.basic_config)
        
        response_data = b'invalid json content'
        content_type = 'application/json'
        
        with self.assertRaises(VendorAPIError):
            api._parse_response(response_data, content_type)

    def test_parse_response_empty(self):
        """Test parsing of empty response."""
        api = VendorAPIBase(self.basic_config)
        
        response_data = b''
        content_type = 'application/json'
        
        parsed = api._parse_response(response_data, content_type)
        self.assertIsNone(parsed)

    def test_build_url_with_path(self):
        """Test URL building with path."""
        api = VendorAPIBase(self.basic_config)
        
        url = api._build_url('/users/123')
        self.assertEqual(url, 'https://api.testvendor.com/v1/users/123')

    def test_build_url_with_query_params(self):
        """Test URL building with query parameters."""
        api = VendorAPIBase(self.basic_config)
        
        params = {'page': 1, 'limit': 50, 'filter': 'active'}
        url = api._build_url('/users', params)
        
        self.assertIn('page=1', url)
        self.assertIn('limit=50', url)
        self.assertIn('filter=active', url)

    def test_abstract_methods_not_implemented(self):
        """Test that abstract methods raise NotImplementedError."""
        api = VendorAPIBase(self.basic_config)
        
        with self.assertRaises(NotImplementedError):
            api.get_group_members({'vendor_group': 'test'})
        
        with self.assertRaises(NotImplementedError):
            api.add_user_to_group({'vendor_group': 'test'}, {'username': 'test'})
        
        with self.assertRaises(NotImplementedError):
            api.remove_user_from_group({'vendor_group': 'test'}, 'test')
        
        with self.assertRaises(NotImplementedError):
            api.update_user('test', {'email': 'new@example.com'})

    @patch('http.client.HTTPSConnection')
    def test_oauth2_token_retrieval(self, mock_https):
        """Test OAuth2 token retrieval."""
        config = self.basic_config.copy()
        config['auth'] = {
            'method': 'oauth2',
            'client_id': 'test_client',
            'client_secret': 'test_secret',
            'token_url': 'https://api.testvendor.com/oauth/token'
        }
        
        # Mock token response
        mock_response = Mock(spec=HTTPResponse)
        mock_response.status = 200
        mock_response.reason = 'OK'
        mock_response.read.return_value = b'{"access_token": "oauth_token_123", "token_type": "Bearer"}'
        mock_response.getheader.return_value = 'application/json'
        
        mock_connection = Mock()
        mock_connection.getresponse.return_value = mock_response
        mock_https.return_value = mock_connection
        
        api = VendorAPIBase(config)
        api.authenticate()
        
        self.assertEqual(api.access_token, 'oauth_token_123')
        mock_connection.request.assert_called_once()

    @patch('http.client.HTTPSConnection')
    def test_oauth2_token_retrieval_failure(self, mock_https):
        """Test OAuth2 token retrieval failure."""
        config = self.basic_config.copy()
        config['auth'] = {
            'method': 'oauth2',
            'client_id': 'test_client',
            'client_secret': 'test_secret',
            'token_url': 'https://api.testvendor.com/oauth/token'
        }
        
        # Mock error response
        mock_response = Mock(spec=HTTPResponse)
        mock_response.status = 401
        mock_response.reason = 'Unauthorized'
        mock_response.read.return_value = b'{"error": "invalid_client"}'
        mock_response.getheader.return_value = 'application/json'
        
        mock_connection = Mock()
        mock_connection.getresponse.return_value = mock_response
        mock_https.return_value = mock_connection
        
        api = VendorAPIBase(config)
        
        with self.assertRaises(AuthenticationError):
            api.authenticate()

    def test_get_connection_stats(self):
        """Test connection statistics retrieval."""
        api = VendorAPIBase(self.basic_config)
        stats = api.get_connection_stats()
        
        expected_keys = [
            'name', 'base_url', 'host', 'port', 'auth_method',
            'format', 'verify_ssl', 'timeout'
        ]
        
        for key in expected_keys:
            self.assertIn(key, stats)
        
        self.assertEqual(stats['name'], 'TestVendor')
        self.assertEqual(stats['auth_method'], 'basic')
        self.assertEqual(stats['format'], 'json')

    def test_headers_merge(self):
        """Test header merging functionality."""
        config = self.basic_config.copy()
        config['headers'] = {
            'X-API-Version': '2.0',
            'X-Client-ID': 'ldap-sync'
        }
        
        api = VendorAPIBase(config)
        headers = api._prepare_request_headers({'Custom': 'Value'})
        
        self.assertIn('X-API-Version', headers)
        self.assertIn('X-Client-ID', headers)
        self.assertIn('Custom', headers)
        self.assertIn('Authorization', headers)  # Auth header
        self.assertIn('Content-Type', headers)   # Format header

    def test_error_handling_configuration(self):
        """Test error handling configuration."""
        config = self.basic_config.copy()
        config['error_handling'] = {
            'max_retries': 5,
            'retry_wait_seconds': 10,
            'retry_on_status': [502, 503, 504]
        }
        
        api = VendorAPIBase(config)
        
        self.assertEqual(api.max_retries, 5)
        self.assertEqual(api.retry_wait, 10)
        self.assertEqual(api.retry_on_status, [502, 503, 504])

    def test_timeout_configuration(self):
        """Test timeout configuration."""
        config = self.basic_config.copy()
        config['timeout'] = 60
        
        api = VendorAPIBase(config)
        self.assertEqual(api.timeout, 60)

    def test_custom_user_agent(self):
        """Test custom user agent header."""
        api = VendorAPIBase(self.basic_config)
        headers = api._prepare_request_headers()
        
        self.assertIn('User-Agent', headers)
        self.assertIn('LDAP-User-Sync', headers['User-Agent'])

    def test_ssl_context_http_url(self):
        """Test SSL context creation for HTTP URLs."""
        config = self.basic_config.copy()
        config['base_url'] = 'http://api.testvendor.com/v1'
        
        api = VendorAPIBase(config)
        context = api._create_ssl_context()
        
        self.assertIsNone(context)  # No SSL context needed for HTTP


if __name__ == '__main__':
    unittest.main()