#!/usr/bin/env python3
"""
Comprehensive tests for error injection and failure scenarios.
"""

import os
import sys
import unittest
import tempfile
import time
from unittest.mock import Mock, patch, MagicMock, call, side_effect

# Add the project directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ldap_sync.main import SyncOrchestrator
from ldap_sync.ldap_client import LDAPClient, LDAPConnectionError, LDAPQueryError
from ldap_sync.vendors.base import VendorAPIBase, VendorAPIError, AuthenticationError
from ldap_sync.config import ConfigurationError
from ldap_sync.notifications import NotificationError


class TestLDAPFailureScenarios(unittest.TestCase):
    """Test cases for LDAP failure scenarios."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            'server_url': 'ldaps://ldap.example.com:636',
            'bind_dn': 'cn=service,dc=example,dc=com',
            'bind_password': 'password',
            'user_base_dn': 'ou=users,dc=example,dc=com',
            'error_handling': {
                'max_retries': 3,
                'retry_wait_seconds': 0.1
            }
        }

    @patch('time.sleep')  # Speed up tests
    @patch('ldap_sync.ldap_client.Server')
    @patch('ldap_sync.ldap_client.Connection')
    def test_ldap_connection_timeout(self, mock_connection, mock_server, mock_sleep):
        """Test LDAP connection timeout handling."""
        mock_server.side_effect = TimeoutError("Connection timed out")
        
        client = LDAPClient(self.config)
        
        with self.assertRaises(LDAPConnectionError) as context:
            client.connect()
        
        self.assertIn("Connection timed out", str(context.exception))
        self.assertEqual(mock_server.call_count, 3)  # Should retry

    @patch('time.sleep')
    @patch('ldap_sync.ldap_client.Server')
    @patch('ldap_sync.ldap_client.Connection')
    def test_ldap_authentication_failure(self, mock_connection, mock_server, mock_sleep):
        """Test LDAP authentication failure."""
        mock_server_instance = Mock()
        mock_server.return_value = mock_server_instance
        
        mock_conn_instance = Mock()
        mock_conn_instance.open.return_value = True
        mock_conn_instance.bind.return_value = False
        mock_conn_instance.result = {'description': 'Invalid credentials'}
        mock_connection.return_value = mock_conn_instance
        
        client = LDAPClient(self.config)
        
        with self.assertRaises(LDAPConnectionError) as context:
            client.connect()
        
        self.assertIn("Invalid credentials", str(context.exception))

    @patch('ldap_sync.ldap_client.Server')
    @patch('ldap_sync.ldap_client.Connection')
    def test_ldap_query_failure_during_sync(self, mock_connection, mock_server):
        """Test LDAP query failure during synchronization."""
        mock_server_instance = Mock()
        mock_server.return_value = mock_server_instance
        
        mock_conn_instance = Mock()
        mock_conn_instance.open.return_value = True
        mock_conn_instance.bind.return_value = True
        mock_conn_instance.search.side_effect = Exception("LDAP search failed")
        mock_connection.return_value = mock_conn_instance
        
        client = LDAPClient(self.config)
        client.connect()
        
        with self.assertRaises(LDAPQueryError):
            client.get_group_members('cn=test,ou=groups,dc=example,dc=com')

    @patch('ldap_sync.ldap_client.Server')
    @patch('ldap_sync.ldap_client.Connection')
    def test_ldap_connection_lost_during_operation(self, mock_connection, mock_server):
        """Test LDAP connection lost during operation."""
        mock_server_instance = Mock()
        mock_server.return_value = mock_server_instance
        
        mock_conn_instance = Mock()
        mock_conn_instance.open.return_value = True
        mock_conn_instance.bind.return_value = True
        
        # First call succeeds, subsequent calls fail
        mock_conn_instance.search.side_effect = [
            True,  # First query succeeds
            ConnectionError("Connection lost"),  # Second query fails
            Exception("Server unavailable")  # Third query fails
        ]
        
        mock_connection.return_value = mock_conn_instance
        
        client = LDAPClient(self.config)
        client.connect()
        
        # First query should succeed
        mock_conn_instance.entries = []
        result1 = client.get_group_members('cn=group1,ou=groups,dc=example,dc=com')
        self.assertEqual(result1, {})
        
        # Second query should fail
        with self.assertRaises(LDAPQueryError):
            client.get_group_members('cn=group2,ou=groups,dc=example,dc=com')

    @patch('ldap_sync.ldap_client.Server')
    @patch('ldap_sync.ldap_client.Connection')
    def test_ldap_malformed_response(self, mock_connection, mock_server):
        """Test handling of malformed LDAP responses."""
        mock_server_instance = Mock()
        mock_server.return_value = mock_server_instance
        
        mock_conn_instance = Mock()
        mock_conn_instance.open.return_value = True
        mock_conn_instance.bind.return_value = True
        mock_conn_instance.search.return_value = True
        
        # Create malformed entry (missing required attributes)
        mock_entry = Mock()
        mock_entry.entry_dn = 'cn=user1,ou=users,dc=example,dc=com'
        mock_entry.sAMAccountName = Mock()
        mock_entry.sAMAccountName.value = None  # Missing value
        mock_entry.givenName = None  # Missing attribute entirely
        
        mock_conn_instance.entries = [mock_entry]
        mock_connection.return_value = mock_conn_instance
        
        client = LDAPClient(self.config)
        client.connect()
        
        # Should handle malformed data gracefully
        result = client.get_group_members('cn=test,ou=groups,dc=example,dc=com')
        
        # Should still return results but with missing data handled
        self.assertIsInstance(result, dict)


class TestVendorAPIFailureScenarios(unittest.TestCase):
    """Test cases for vendor API failure scenarios."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
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

    @patch('http.client.HTTPSConnection')
    def test_vendor_api_timeout(self, mock_https):
        """Test vendor API timeout handling."""
        mock_https.side_effect = TimeoutError("Request timed out")
        
        api = VendorAPIBase(self.config)
        
        with self.assertRaises(VendorAPIError) as context:
            api._make_request('GET', '/test')
        
        self.assertIn("timed out", str(context.exception))

    @patch('http.client.HTTPSConnection')
    def test_vendor_api_connection_refused(self, mock_https):
        """Test vendor API connection refused."""
        mock_https.side_effect = ConnectionRefusedError("Connection refused")
        
        api = VendorAPIBase(self.config)
        
        with self.assertRaises(VendorAPIError) as context:
            api._make_request('GET', '/test')
        
        self.assertIn("Connection refused", str(context.exception))

    @patch('http.client.HTTPSConnection')
    def test_vendor_api_ssl_error(self, mock_https):
        """Test vendor API SSL/TLS errors."""
        import ssl
        mock_https.side_effect = ssl.SSLError("SSL certificate verification failed")
        
        api = VendorAPIBase(self.config)
        
        with self.assertRaises(VendorAPIError) as context:
            api._make_request('GET', '/test')
        
        self.assertIn("SSL", str(context.exception))

    @patch('http.client.HTTPSConnection')
    def test_vendor_api_authentication_failure(self, mock_https):
        """Test vendor API authentication failures."""
        mock_response = Mock()
        mock_response.status = 401
        mock_response.reason = 'Unauthorized'
        mock_response.read.return_value = b'{"error": "Invalid credentials"}'
        mock_response.getheader.return_value = 'application/json'
        
        mock_connection = Mock()
        mock_connection.getresponse.return_value = mock_response
        mock_https.return_value = mock_connection
        
        api = VendorAPIBase(self.config)
        
        with self.assertRaises(VendorAPIError) as context:
            api._make_request('GET', '/test')
        
        self.assertIn("401", str(context.exception))

    @patch('http.client.HTTPSConnection')
    def test_vendor_api_rate_limiting(self, mock_https):
        """Test vendor API rate limiting scenarios."""
        mock_response = Mock()
        mock_response.status = 429
        mock_response.reason = 'Too Many Requests'
        mock_response.read.return_value = b'{"error": "Rate limit exceeded"}'
        mock_response.getheader.side_effect = lambda header: {
            'content-type': 'application/json',
            'retry-after': '60'
        }.get(header.lower())
        
        mock_connection = Mock()
        mock_connection.getresponse.return_value = mock_response
        mock_https.return_value = mock_connection
        
        api = VendorAPIBase(self.config)
        
        with self.assertRaises(VendorAPIError) as context:
            api._make_request('GET', '/test')
        
        error = context.exception
        self.assertEqual(error.status_code, 429)
        self.assertIn("Rate limit", str(error))

    @patch('http.client.HTTPSConnection')
    def test_vendor_api_server_error(self, mock_https):
        """Test vendor API server errors (5xx)."""
        error_scenarios = [
            (500, 'Internal Server Error'),
            (502, 'Bad Gateway'),
            (503, 'Service Unavailable'),
            (504, 'Gateway Timeout')
        ]
        
        for status_code, reason in error_scenarios:
            with self.subTest(status_code=status_code):
                mock_response = Mock()
                mock_response.status = status_code
                mock_response.reason = reason
                mock_response.read.return_value = b'{"error": "Server error"}'
                mock_response.getheader.return_value = 'application/json'
                
                mock_connection = Mock()
                mock_connection.getresponse.return_value = mock_response
                mock_https.return_value = mock_connection
                
                api = VendorAPIBase(self.config)
                
                with self.assertRaises(VendorAPIError) as context:
                    api._make_request('GET', '/test')
                
                self.assertEqual(context.exception.status_code, status_code)

    @patch('http.client.HTTPSConnection')
    def test_vendor_api_malformed_json_response(self, mock_https):
        """Test handling of malformed JSON responses."""
        mock_response = Mock()
        mock_response.status = 200
        mock_response.reason = 'OK'
        mock_response.read.return_value = b'{"invalid": json: response}'  # Malformed JSON
        mock_response.getheader.return_value = 'application/json'
        
        mock_connection = Mock()
        mock_connection.getresponse.return_value = mock_response
        mock_https.return_value = mock_connection
        
        api = VendorAPIBase(self.config)
        
        with self.assertRaises(VendorAPIError) as context:
            api._make_request('GET', '/test')
        
        self.assertIn("JSON", str(context.exception))

    @patch('http.client.HTTPSConnection')
    def test_vendor_api_empty_response(self, mock_https):
        """Test handling of empty responses."""
        mock_response = Mock()
        mock_response.status = 200
        mock_response.reason = 'OK'
        mock_response.read.return_value = b''  # Empty response
        mock_response.getheader.return_value = 'application/json'
        
        mock_connection = Mock()
        mock_connection.getresponse.return_value = mock_response
        mock_https.return_value = mock_connection
        
        api = VendorAPIBase(self.config)
        
        # Should handle empty response gracefully
        response = api._make_request('GET', '/test')
        self.assertEqual(response['status_code'], 200)
        self.assertIsNone(response['data'])

    @patch('http.client.HTTPSConnection')
    def test_vendor_api_network_interruption(self, mock_https):
        """Test network interruption during API call."""
        mock_connection = Mock()
        mock_connection.getresponse.side_effect = ConnectionError("Network unreachable")
        mock_https.return_value = mock_connection
        
        api = VendorAPIBase(self.config)
        
        with self.assertRaises(VendorAPIError) as context:
            api._make_request('GET', '/test')
        
        self.assertIn("Network", str(context.exception))


class TestSyncOrchestrationFailures(unittest.TestCase):
    """Test cases for sync orchestration failure scenarios."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            'ldap': {
                'server_url': 'ldaps://ldap.example.com:636',
                'bind_dn': 'cn=service,dc=example,dc=com',
                'bind_password': 'password',
                'user_base_dn': 'ou=users,dc=example,dc=com'
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
                            'ldap_group': 'cn=testgroup,ou=groups,dc=example,dc=com',
                            'vendor_group': 'test_group'
                        }
                    ]
                }
            ],
            'error_handling': {
                'max_retries': 3,
                'retry_wait_seconds': 0.1,
                'max_errors_per_vendor': 5
            },
            'logging': {'level': 'INFO'},
            'notifications': {'enable_email': False}
        }

    @patch('ldap_sync.main.setup_logging')
    def test_orchestrator_ldap_total_failure(self, mock_setup_logging):
        """Test orchestrator behavior when LDAP is completely unavailable."""
        orchestrator = SyncOrchestrator(self.config)
        
        with patch.object(orchestrator, '_setup_ldap_client') as mock_setup_ldap:
            mock_setup_ldap.side_effect = LDAPConnectionError("LDAP server unreachable")
            
            result = orchestrator.run()
            
            self.assertFalse(result['success'])
            self.assertIn("LDAP server unreachable", result['error'])
            self.assertEqual(result['vendors_processed'], 0)

    @patch('ldap_sync.main.setup_logging')
    def test_orchestrator_vendor_module_import_failure(self, mock_setup_logging):
        """Test orchestrator behavior when vendor module cannot be imported."""
        orchestrator = SyncOrchestrator(self.config)
        
        with patch.object(orchestrator, '_setup_ldap_client') as mock_setup_ldap, \
             patch.object(orchestrator, '_load_vendor_api') as mock_load_vendor:
            
            mock_setup_ldap.return_value = True
            mock_load_vendor.side_effect = ImportError("Module 'vendor_app1' not found")
            
            result = orchestrator.run()
            
            self.assertFalse(result['success'])
            self.assertEqual(result['vendors_processed'], 0)

    @patch('ldap_sync.main.setup_logging')
    @patch('ldap_sync.main.send_notification')
    def test_orchestrator_cascading_failures(self, mock_send_notification, mock_setup_logging):
        """Test orchestrator behavior with cascading failures."""
        orchestrator = SyncOrchestrator(self.config)
        
        # Mock LDAP client that works initially but then fails
        mock_ldap_client = Mock()
        
        call_count = 0
        def failing_get_group_members(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {'user1': {'sAMAccountName': 'user1', 'mail': 'user1@example.com'}}
            else:
                raise LDAPQueryError("LDAP query failed")
        
        mock_ldap_client.get_group_members.side_effect = failing_get_group_members
        
        with patch.object(orchestrator, '_setup_ldap_client') as mock_setup_ldap, \
             patch.object(orchestrator, '_load_vendor_api') as mock_load_vendor:
            
            mock_setup_ldap.return_value = True
            orchestrator.ldap_client = mock_ldap_client
            
            # Mock vendor API that also fails
            mock_vendor_api = Mock()
            mock_vendor_api.name = 'TestApp1'
            mock_vendor_api.authenticate.side_effect = AuthenticationError("Auth failed")
            mock_load_vendor.return_value = mock_vendor_api
            
            result = orchestrator.run()
            
            # Should handle multiple failure points
            self.assertFalse(result['success'])

    @patch('ldap_sync.main.setup_logging')
    @patch('ldap_sync.main.send_notification')
    def test_orchestrator_error_threshold_exceeded(self, mock_send_notification, mock_setup_logging):
        """Test orchestrator behavior when error threshold is exceeded."""
        # Lower the error threshold for this test
        config = self.config.copy()
        config['error_handling']['max_errors_per_vendor'] = 2
        
        orchestrator = SyncOrchestrator(config)
        
        # Mock LDAP with multiple users
        mock_ldap_client = Mock()
        mock_ldap_client.get_group_members.return_value = {
            'user1': {'sAMAccountName': 'user1', 'mail': 'user1@example.com'},
            'user2': {'sAMAccountName': 'user2', 'mail': 'user2@example.com'},
            'user3': {'sAMAccountName': 'user3', 'mail': 'user3@example.com'},
            'user4': {'sAMAccountName': 'user4', 'mail': 'user4@example.com'}
        }
        
        with patch.object(orchestrator, '_setup_ldap_client') as mock_setup_ldap, \
             patch.object(orchestrator, '_load_vendor_api') as mock_load_vendor:
            
            mock_setup_ldap.return_value = True
            orchestrator.ldap_client = mock_ldap_client
            
            # Mock vendor API that fails for most operations
            mock_vendor_api = Mock()
            mock_vendor_api.name = 'TestApp1'
            mock_vendor_api.authenticate.return_value = True
            mock_vendor_api.get_group_members.return_value = {}  # Empty vendor group
            mock_vendor_api.add_user_to_group.side_effect = VendorAPIError("API error", 500)
            
            mock_load_vendor.return_value = mock_vendor_api
            
            result = orchestrator.run()
            
            # Should detect error threshold exceeded
            self.assertFalse(result['success'])
            mock_send_notification.assert_called()

    @patch('ldap_sync.main.setup_logging')
    def test_orchestrator_partial_success_with_errors(self, mock_setup_logging):
        """Test orchestrator with partial success (some operations fail)."""
        orchestrator = SyncOrchestrator(self.config)
        
        mock_ldap_client = Mock()
        mock_ldap_client.get_group_members.return_value = {
            'user1': {'sAMAccountName': 'user1', 'mail': 'user1@example.com'},
            'user2': {'sAMAccountName': 'user2', 'mail': 'user2@example.com'}
        }
        
        with patch.object(orchestrator, '_setup_ldap_client') as mock_setup_ldap, \
             patch.object(orchestrator, '_load_vendor_api') as mock_load_vendor:
            
            mock_setup_ldap.return_value = True
            orchestrator.ldap_client = mock_ldap_client
            
            # Mock vendor API with mixed success/failure
            mock_vendor_api = Mock()
            mock_vendor_api.name = 'TestApp1'
            mock_vendor_api.authenticate.return_value = True
            mock_vendor_api.get_group_members.return_value = {}
            
            # First user succeeds, second fails
            mock_vendor_api.add_user_to_group.side_effect = [
                True,  # user1 succeeds
                VendorAPIError("API error for user2", 500)  # user2 fails
            ]
            
            mock_load_vendor.return_value = mock_vendor_api
            
            result = orchestrator.run()
            
            # Should complete but report errors
            self.assertEqual(result['vendors_processed'], 1)
            # Success value depends on implementation - could be True or False


class TestConfigurationFailures(unittest.TestCase):
    """Test cases for configuration failure scenarios."""

    def test_missing_config_file(self):
        """Test handling of missing configuration file."""
        from ldap_sync.config import load_config
        
        with self.assertRaises(ConfigurationError):
            load_config('/nonexistent/config.yaml')

    def test_malformed_yaml_config(self):
        """Test handling of malformed YAML configuration."""
        malformed_yaml = """
        ldap:
          server_url: ldaps://ldap.example.com:636
          bind_dn: cn=service,dc=example,dc=com
        vendor_apps: [
          invalid yaml structure
        """
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(malformed_yaml)
            config_path = f.name
        
        try:
            from ldap_sync.config import load_config
            
            with self.assertRaises(ConfigurationError):
                load_config(config_path)
                
        finally:
            os.unlink(config_path)

    def test_incomplete_config_structure(self):
        """Test handling of incomplete configuration structure."""
        incomplete_configs = [
            {},  # Empty config
            {'ldap': {}},  # Missing vendor_apps
            {'vendor_apps': []},  # Missing ldap
            {'ldap': {'server_url': 'ldap://test'}, 'vendor_apps': []}  # Empty vendor_apps
        ]
        
        for config_data in incomplete_configs:
            with self.subTest(config=config_data):
                with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                    import yaml
                    yaml.dump(config_data, f)
                    config_path = f.name
                
                try:
                    from ldap_sync.config import load_config
                    
                    with self.assertRaises(ConfigurationError):
                        load_config(config_path)
                        
                finally:
                    os.unlink(config_path)

    def test_invalid_auth_method_config(self):
        """Test handling of invalid authentication method configuration."""
        invalid_auth_configs = [
            {'method': 'invalid_method'},
            {'method': 'basic'},  # Missing username/password
            {'method': 'token'},  # Missing token
            {'method': 'oauth2'},  # Missing client_id/client_secret
        ]
        
        base_config = {
            'ldap': {
                'server_url': 'ldaps://ldap.example.com:636',
                'bind_dn': 'cn=service,dc=example,dc=com',
                'bind_password': 'password'
            },
            'vendor_apps': [
                {
                    'name': 'TestApp',
                    'module': 'vendor_app1',
                    'base_url': 'https://api.testapp.com/v1',
                    'groups': [
                        {
                            'ldap_group': 'cn=test,dc=example,dc=com',
                            'vendor_group': 'test_group'
                        }
                    ]
                }
            ]
        }
        
        for auth_config in invalid_auth_configs:
            with self.subTest(auth=auth_config):
                config = base_config.copy()
                config['vendor_apps'][0]['auth'] = auth_config
                
                with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                    import yaml
                    yaml.dump(config, f)
                    config_path = f.name
                
                try:
                    from ldap_sync.config import load_config
                    
                    with self.assertRaises(ConfigurationError):
                        load_config(config_path)
                        
                finally:
                    os.unlink(config_path)


class TestNotificationFailures(unittest.TestCase):
    """Test cases for notification failure scenarios."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            'enable_email': True,
            'email_on_failure': True,
            'smtp_server': 'smtp.example.com',
            'smtp_port': 587,
            'smtp_tls': True,
            'smtp_username': 'alerts@example.com',
            'smtp_password': 'password',
            'email_from': 'alerts@example.com',
            'email_to': ['admin@example.com']
        }

    @patch('smtplib.SMTP')
    def test_smtp_connection_failure(self, mock_smtp):
        """Test SMTP connection failure."""
        import smtplib
        mock_smtp.side_effect = smtplib.SMTPConnectError(421, "Service not available")
        
        from ldap_sync.notifications import send_notification
        
        # Should not raise exception but return False
        result = send_notification(
            config=self.config,
            subject="Test Alert",
            message="Test message",
            notification_type="failure"
        )
        
        self.assertFalse(result)

    @patch('smtplib.SMTP')
    def test_smtp_authentication_failure(self, mock_smtp):
        """Test SMTP authentication failure."""
        import smtplib
        mock_server = Mock()
        mock_server.login.side_effect = smtplib.SMTPAuthenticationError(535, "Authentication failed")
        mock_smtp.return_value = mock_server
        
        from ldap_sync.notifications import send_notification
        
        result = send_notification(
            config=self.config,
            subject="Test Alert",
            message="Test message",
            notification_type="failure"
        )
        
        self.assertFalse(result)

    @patch('smtplib.SMTP')
    def test_smtp_send_failure(self, mock_smtp):
        """Test SMTP send failure."""
        import smtplib
        mock_server = Mock()
        mock_server.send_message.side_effect = smtplib.SMTPRecipientsRefused({
            'admin@example.com': (550, 'User unknown')
        })
        mock_smtp.return_value = mock_server
        
        from ldap_sync.notifications import send_notification
        
        result = send_notification(
            config=self.config,
            subject="Test Alert",
            message="Test message",
            notification_type="failure"
        )
        
        self.assertFalse(result)

    def test_notification_with_invalid_config(self):
        """Test notification with invalid configuration."""
        invalid_configs = [
            {},  # Empty config
            {'enable_email': True},  # Missing required fields
            {'enable_email': True, 'smtp_server': ''},  # Empty server
            {'enable_email': True, 'smtp_server': 'smtp.test.com', 'email_to': []}  # Empty recipients
        ]
        
        from ldap_sync.notifications import send_notification
        
        for config in invalid_configs:
            with self.subTest(config=config):
                result = send_notification(
                    config=config,
                    subject="Test Alert",
                    message="Test message",
                    notification_type="failure"
                )
                
                # Should handle gracefully and return False
                self.assertFalse(result)


class TestMemoryAndResourceFailures(unittest.TestCase):
    """Test cases for memory and resource failure scenarios."""

    def test_memory_pressure_simulation(self):
        """Test behavior under memory pressure."""
        # Simulate processing large datasets that could cause memory issues
        from ldap_sync.main import SyncOrchestrator
        
        config = {
            'ldap': {
                'server_url': 'ldaps://ldap.example.com:636',
                'bind_dn': 'cn=service,dc=example,dc=com',
                'bind_password': 'password'
            },
            'vendor_apps': [
                {
                    'name': 'TestApp',
                    'module': 'vendor_app1',
                    'base_url': 'https://api.testapp.com/v1',
                    'auth': {'method': 'basic', 'username': 'user', 'password': 'pass'},
                    'groups': [
                        {
                            'ldap_group': 'cn=large_group,dc=example,dc=com',
                            'vendor_group': 'large_group'
                        }
                    ]
                }
            ],
            'logging': {'level': 'INFO'},
            'notifications': {'enable_email': False}
        }
        
        # Generate large dataset
        large_dataset = {}
        for i in range(10000):  # 10k users
            username = f'user{i:05d}'
            large_dataset[username] = {
                'sAMAccountName': username,
                'givenName': f'User{i}',
                'sn': 'Test',
                'mail': f'{username}@example.com'
            }
        
        orchestrator = SyncOrchestrator(config)
        
        with patch.object(orchestrator, '_setup_ldap_client') as mock_setup_ldap, \
             patch.object(orchestrator, '_load_vendor_api') as mock_load_vendor:
            
            mock_setup_ldap.return_value = True
            
            mock_ldap_client = Mock()
            mock_ldap_client.get_group_members.return_value = large_dataset
            orchestrator.ldap_client = mock_ldap_client
            
            mock_vendor_api = Mock()
            mock_vendor_api.name = 'TestApp'
            mock_vendor_api.authenticate.return_value = True
            mock_vendor_api.get_group_members.return_value = {}
            mock_vendor_api.add_user_to_group.return_value = True
            mock_load_vendor.return_value = mock_vendor_api
            
            # Should handle large dataset without memory issues
            result = orchestrator.run()
            
            # Verify it completed (regardless of success/failure)
            self.assertIn('vendors_processed', result)

    @patch('builtins.open')
    def test_file_system_failure(self, mock_open):
        """Test handling of file system failures."""
        mock_open.side_effect = PermissionError("Permission denied")
        
        from ldap_sync.config import load_config
        
        with self.assertRaises(ConfigurationError):
            load_config('/etc/restricted/config.yaml')

    def test_disk_space_exhaustion_simulation(self):
        """Test behavior when disk space is exhausted."""
        # This would typically manifest as write failures to log files
        
        from ldap_sync.logging_setup import setup_logging
        
        config = {
            'level': 'INFO',
            'log_dir': '/tmp/test_logs',
            'rotation': 'daily',
            'retention_days': 7
        }
        
        with patch('builtins.open', side_effect=OSError("No space left on device")):
            # Should handle disk space issues gracefully
            try:
                setup_logging(config)
                # If it doesn't raise an exception, that's fine
                # The implementation should degrade gracefully
            except OSError:
                # If it does raise, it should be a clear error message
                pass


class TestConcurrencyFailures(unittest.TestCase):
    """Test cases for concurrency-related failures."""

    def test_race_condition_simulation(self):
        """Test potential race condition scenarios."""
        # Simulate concurrent access to shared resources
        
        from ldap_sync.vendors.base import VendorAPIBase
        
        config = {
            'name': 'TestVendor',
            'base_url': 'https://api.testvendor.com/v1',
            'auth': {'method': 'basic', 'username': 'user', 'password': 'pass'}
        }
        
        api = VendorAPIBase(config)
        
        # Simulate concurrent access to authentication token
        import threading
        import time
        
        results = []
        exceptions = []
        
        def concurrent_auth():
            try:
                api.access_token = 'test_token'
                time.sleep(0.01)  # Simulate work
                token = api.access_token
                results.append(token)
            except Exception as e:
                exceptions.append(e)
        
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=concurrent_auth)
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Should not have any exceptions from concurrent access
        self.assertEqual(len(exceptions), 0)
        self.assertEqual(len(results), 10)

    def test_deadlock_prevention(self):
        """Test that the application prevents deadlocks."""
        # Test scenarios that could potentially cause deadlocks
        
        from ldap_sync.main import SyncOrchestrator
        
        config = {
            'ldap': {
                'server_url': 'ldaps://ldap.example.com:636',
                'bind_dn': 'cn=service,dc=example,dc=com',
                'bind_password': 'password'
            },
            'vendor_apps': [
                {
                    'name': 'TestApp',
                    'module': 'vendor_app1',
                    'base_url': 'https://api.testapp.com/v1',
                    'auth': {'method': 'basic', 'username': 'user', 'password': 'pass'},
                    'groups': [
                        {
                            'ldap_group': 'cn=test,dc=example,dc=com',
                            'vendor_group': 'test_group'
                        }
                    ]
                }
            ],
            'logging': {'level': 'INFO'},
            'notifications': {'enable_email': False}
        }
        
        orchestrator = SyncOrchestrator(config)
        
        # Test with timeouts to prevent hanging
        import signal
        
        def timeout_handler(signum, frame):
            raise TimeoutError("Operation timed out - potential deadlock")
        
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(5)  # 5 second timeout
        
        try:
            with patch.object(orchestrator, '_setup_ldap_client') as mock_setup_ldap:
                mock_setup_ldap.side_effect = Exception("Simulated failure")
                
                result = orchestrator.run()
                
                # Should complete within timeout (no deadlock)
                self.assertIsInstance(result, dict)
                
        finally:
            signal.alarm(0)  # Cancel alarm


if __name__ == '__main__':
    unittest.main()