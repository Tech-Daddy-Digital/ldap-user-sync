#!/usr/bin/env python3
"""
Comprehensive unit tests for LDAP client module.
"""

import os
import sys
import unittest
from unittest.mock import Mock, patch, MagicMock, call
import ssl
import tempfile

# Add the project directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ldap_sync.ldap_client import LDAPClient, LDAPConnectionError, LDAPQueryError


class TestLDAPClient(unittest.TestCase):
    """Test cases for LDAPClient class."""

    def setUp(self):
        """Set up test fixtures."""
        self.basic_config = {
            'server_url': 'ldaps://ldap.example.com:636',
            'bind_dn': 'cn=service,dc=example,dc=com',
            'bind_password': 'password123',
            'user_base_dn': 'ou=users,dc=example,dc=com',
            'user_filter': '(objectClass=person)',
            'attributes': ['cn', 'givenName', 'sn', 'mail', 'sAMAccountName']
        }

    def test_initialization_basic_config(self):
        """Test basic LDAP client initialization."""
        client = LDAPClient(self.basic_config)
        
        self.assertEqual(client.server_url, 'ldaps://ldap.example.com:636')
        self.assertEqual(client.bind_dn, 'cn=service,dc=example,dc=com')
        self.assertEqual(client.bind_password, 'password123')
        self.assertTrue(client.use_ssl)  # Auto-detected from ldaps://
        self.assertFalse(client.start_tls)
        self.assertTrue(client.verify_ssl)  # Default
        self.assertEqual(client.page_size, 1000)  # Default

    def test_initialization_advanced_config(self):
        """Test LDAP client initialization with advanced configuration."""
        advanced_config = self.basic_config.copy()
        advanced_config.update({
            'server_url': 'ldap://ldap.example.com:389',
            'start_tls': True,
            'verify_ssl': False,
            'connection_timeout': 30,
            'receive_timeout': 60,
            'page_size': 500,
            'ca_cert_file': '/path/to/ca.pem',
            'cert_file': '/path/to/client.pem',
            'key_file': '/path/to/client-key.pem',
            'error_handling': {
                'max_retries': 5,
                'retry_wait_seconds': 10
            }
        })
        
        client = LDAPClient(advanced_config)
        
        self.assertFalse(client.use_ssl)
        self.assertTrue(client.start_tls)
        self.assertFalse(client.verify_ssl)
        self.assertEqual(client.connection_timeout, 30)
        self.assertEqual(client.receive_timeout, 60)
        self.assertEqual(client.page_size, 500)
        self.assertEqual(client.max_retries, 5)
        self.assertEqual(client.retry_wait, 10)

    def test_ssl_detection_from_url(self):
        """Test SSL detection from server URL."""
        # LDAPS URL
        config = self.basic_config.copy()
        config['server_url'] = 'ldaps://ldap.example.com:636'
        client = LDAPClient(config)
        self.assertTrue(client.use_ssl)

        # LDAP URL
        config['server_url'] = 'ldap://ldap.example.com:389'
        client = LDAPClient(config)
        self.assertFalse(client.use_ssl)

        # Explicit SSL override
        config['use_ssl'] = True
        client = LDAPClient(config)
        self.assertTrue(client.use_ssl)

    @patch('ldap_sync.ldap_client.ssl.create_default_context')
    def test_tls_config_creation_no_ssl(self, mock_ssl_context):
        """Test TLS configuration when SSL is not used."""
        config = self.basic_config.copy()
        config.update({
            'server_url': 'ldap://ldap.example.com:389',
            'use_ssl': False,
            'start_tls': False
        })
        
        client = LDAPClient(config)
        tls_config = client._create_tls_config()
        
        self.assertIsNone(tls_config)
        mock_ssl_context.assert_not_called()

    @patch('ldap_sync.ldap_client.ssl.create_default_context')
    def test_tls_config_creation_with_ssl(self, mock_ssl_context):
        """Test TLS configuration creation with SSL enabled."""
        mock_context = Mock()
        mock_ssl_context.return_value = mock_context
        
        config = self.basic_config.copy()
        config.update({
            'use_ssl': True,
            'verify_ssl': True
        })
        
        client = LDAPClient(config)
        tls_config = client._create_tls_config()
        
        self.assertIsNotNone(tls_config)
        mock_ssl_context.assert_called_once()

    @patch('ldap_sync.ldap_client.ssl.create_default_context')
    def test_tls_config_no_verification(self, mock_ssl_context):
        """Test TLS configuration without certificate verification."""
        mock_context = Mock()
        mock_ssl_context.return_value = mock_context
        
        config = self.basic_config.copy()
        config.update({
            'use_ssl': True,
            'verify_ssl': False
        })
        
        client = LDAPClient(config)
        tls_config = client._create_tls_config()
        
        self.assertIsNotNone(tls_config)
        self.assertEqual(mock_context.check_hostname, False)
        self.assertEqual(mock_context.verify_mode, ssl.CERT_NONE)

    @patch('ldap_sync.ldap_client.ssl.create_default_context')
    @patch('os.path.exists')
    def test_tls_config_with_certificates(self, mock_exists, mock_ssl_context):
        """Test TLS configuration with custom certificates."""
        mock_exists.return_value = True
        mock_context = Mock()
        mock_ssl_context.return_value = mock_context
        
        config = self.basic_config.copy()
        config.update({
            'use_ssl': True,
            'verify_ssl': True,
            'ca_cert_file': '/path/to/ca.pem',
            'cert_file': '/path/to/client.pem',
            'key_file': '/path/to/client-key.pem'
        })
        
        client = LDAPClient(config)
        tls_config = client._create_tls_config()
        
        self.assertIsNotNone(tls_config)
        mock_context.load_verify_locations.assert_called_once_with('/path/to/ca.pem')
        mock_context.load_cert_chain.assert_called_once_with('/path/to/client.pem', '/path/to/client-key.pem')

    @patch('ldap_sync.ldap_client.Server')
    @patch('ldap_sync.ldap_client.Connection')
    def test_successful_connection(self, mock_connection, mock_server):
        """Test successful LDAP connection."""
        # Setup mocks
        mock_server_instance = Mock()
        mock_server.return_value = mock_server_instance
        
        mock_conn_instance = Mock()
        mock_conn_instance.open.return_value = True
        mock_conn_instance.bind.return_value = True
        mock_connection.return_value = mock_conn_instance
        
        client = LDAPClient(self.basic_config)
        result = client.connect()
        
        self.assertTrue(result)
        self.assertTrue(client._connected)
        self.assertEqual(client.connection, mock_conn_instance)
        
        mock_server.assert_called_once()
        mock_connection.assert_called_once()
        mock_conn_instance.open.assert_called_once()
        mock_conn_instance.bind.assert_called_once()

    @patch('ldap_sync.ldap_client.Server')
    @patch('ldap_sync.ldap_client.Connection')
    def test_connection_bind_failure(self, mock_connection, mock_server):
        """Test LDAP connection with bind failure."""
        mock_server_instance = Mock()
        mock_server.return_value = mock_server_instance
        
        mock_conn_instance = Mock()
        mock_conn_instance.open.return_value = True
        mock_conn_instance.bind.return_value = False
        mock_conn_instance.result = {'description': 'Invalid credentials'}
        mock_connection.return_value = mock_conn_instance
        
        client = LDAPClient(self.basic_config)
        
        with self.assertRaises(LDAPConnectionError) as context:
            client.connect()
        
        self.assertIn('bind failed', str(context.exception).lower())

    @patch('ldap_sync.ldap_client.Server')
    @patch('ldap_sync.ldap_client.Connection')
    @patch('time.sleep')
    def test_connection_retry_logic(self, mock_sleep, mock_connection, mock_server):
        """Test connection retry logic on failures."""
        config = self.basic_config.copy()
        config['error_handling'] = {
            'max_retries': 2,
            'retry_wait_seconds': 1
        }
        
        mock_server.side_effect = Exception("Connection failed")
        
        client = LDAPClient(config)
        
        with self.assertRaises(LDAPConnectionError) as context:
            client.connect()
        
        self.assertIn('Failed to connect to LDAP after 2 attempts', str(context.exception))
        self.assertEqual(mock_server.call_count, 2)
        mock_sleep.assert_called_with(1)

    @patch('ldap_sync.ldap_client.Server')
    @patch('ldap_sync.ldap_client.Connection')
    def test_get_group_members_memberof_method(self, mock_connection, mock_server):
        """Test getting group members using memberOf method."""
        # Setup successful connection
        mock_server_instance = Mock()
        mock_server.return_value = mock_server_instance
        
        mock_conn_instance = Mock()
        mock_conn_instance.open.return_value = True
        mock_conn_instance.bind.return_value = True
        
        # Mock search results
        mock_entry1 = Mock()
        mock_entry1.entry_dn = 'cn=user1,ou=users,dc=example,dc=com'
        mock_entry1.cn.value = 'User One'
        mock_entry1.givenName.value = 'User'
        mock_entry1.sn.value = 'One'
        mock_entry1.mail.value = 'user1@example.com'
        mock_entry1.sAMAccountName.value = 'user1'
        
        mock_entry2 = Mock()
        mock_entry2.entry_dn = 'cn=user2,ou=users,dc=example,dc=com'
        mock_entry2.cn.value = 'User Two'
        mock_entry2.givenName.value = 'User'
        mock_entry2.sn.value = 'Two'
        mock_entry2.mail.value = 'user2@example.com'
        mock_entry2.sAMAccountName.value = 'user2'
        
        mock_conn_instance.entries = [mock_entry1, mock_entry2]
        mock_conn_instance.search.return_value = True
        mock_connection.return_value = mock_conn_instance
        
        client = LDAPClient(self.basic_config)
        client.connect()
        
        group_dn = 'cn=testgroup,ou=groups,dc=example,dc=com'
        members = client.get_group_members(group_dn, method='memberof')
        
        self.assertEqual(len(members), 2)
        self.assertIn('user1', members)
        self.assertIn('user2', members)
        self.assertEqual(members['user1']['givenName'], 'User')
        self.assertEqual(members['user1']['mail'], 'user1@example.com')

    @patch('ldap_sync.ldap_client.Server')
    @patch('ldap_sync.ldap_client.Connection')
    def test_get_group_members_group_method(self, mock_connection, mock_server):
        """Test getting group members using group member attribute method."""
        # Setup successful connection
        mock_server_instance = Mock()
        mock_server.return_value = mock_server_instance
        
        mock_conn_instance = Mock()
        mock_conn_instance.open.return_value = True
        mock_conn_instance.bind.return_value = True
        
        # Mock group search result
        mock_group_entry = Mock()
        mock_group_entry.member = [
            'cn=user1,ou=users,dc=example,dc=com',
            'cn=user2,ou=users,dc=example,dc=com'
        ]
        
        # Mock user search results
        mock_user1 = Mock()
        mock_user1.entry_dn = 'cn=user1,ou=users,dc=example,dc=com'
        mock_user1.sAMAccountName.value = 'user1'
        mock_user1.givenName.value = 'User'
        mock_user1.sn.value = 'One'
        mock_user1.mail.value = 'user1@example.com'
        
        mock_user2 = Mock()
        mock_user2.entry_dn = 'cn=user2,ou=users,dc=example,dc=com'
        mock_user2.sAMAccountName.value = 'user2'
        mock_user2.givenName.value = 'User'
        mock_user2.sn.value = 'Two'
        mock_user2.mail.value = 'user2@example.com'
        
        # Configure search calls
        def search_side_effect(search_base, search_filter, **kwargs):
            if 'objectClass=group' in search_filter or 'objectClass=groupOfNames' in search_filter:
                mock_conn_instance.entries = [mock_group_entry]
            else:
                # User search
                user_dn = search_base
                if 'user1' in user_dn:
                    mock_conn_instance.entries = [mock_user1]
                elif 'user2' in user_dn:
                    mock_conn_instance.entries = [mock_user2]
                else:
                    mock_conn_instance.entries = []
            return True
        
        mock_conn_instance.search.side_effect = search_side_effect
        mock_connection.return_value = mock_conn_instance
        
        client = LDAPClient(self.basic_config)
        client.connect()
        
        group_dn = 'cn=testgroup,ou=groups,dc=example,dc=com'
        members = client.get_group_members(group_dn, method='group')
        
        self.assertEqual(len(members), 2)
        self.assertIn('user1', members)
        self.assertIn('user2', members)

    @patch('ldap_sync.ldap_client.Server')
    @patch('ldap_sync.ldap_client.Connection')
    def test_get_group_members_with_pagination(self, mock_connection, mock_server):
        """Test getting group members with pagination support."""
        # Setup successful connection
        mock_server_instance = Mock()
        mock_server.return_value = mock_server_instance
        
        mock_conn_instance = Mock()
        mock_conn_instance.open.return_value = True
        mock_conn_instance.bind.return_value = True
        
        # Mock paginated search results
        call_count = 0
        def search_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            
            if call_count == 1:
                # First page
                mock_entry1 = Mock()
                mock_entry1.sAMAccountName.value = 'user1'
                mock_entry1.givenName.value = 'User'
                mock_entry1.sn.value = 'One'
                mock_entry1.mail.value = 'user1@example.com'
                mock_conn_instance.entries = [mock_entry1]
                # Simulate more results available
                mock_conn_instance.result = {'controls': {'1.2.840.113556.1.4.319': {'value': {'cookie': b'page2'}}}}
            else:
                # Second page (last page)
                mock_entry2 = Mock()
                mock_entry2.sAMAccountName.value = 'user2'
                mock_entry2.givenName.value = 'User'
                mock_entry2.sn.value = 'Two'
                mock_entry2.mail.value = 'user2@example.com'
                mock_conn_instance.entries = [mock_entry2]
                # No more results
                mock_conn_instance.result = {'controls': {}}
            
            return True
        
        mock_conn_instance.search.side_effect = search_side_effect
        mock_connection.return_value = mock_conn_instance
        
        # Use small page size to trigger pagination
        config = self.basic_config.copy()
        config['page_size'] = 1
        
        client = LDAPClient(config)
        client.connect()
        
        group_dn = 'cn=testgroup,ou=groups,dc=example,dc=com'
        members = client.get_group_members(group_dn, method='memberof')
        
        self.assertEqual(len(members), 2)
        self.assertIn('user1', members)
        self.assertIn('user2', members)
        self.assertEqual(mock_conn_instance.search.call_count, 2)

    @patch('ldap_sync.ldap_client.Server')
    @patch('ldap_sync.ldap_client.Connection')
    def test_get_group_members_search_failure(self, mock_connection, mock_server):
        """Test group member search failure handling."""
        mock_server_instance = Mock()
        mock_server.return_value = mock_server_instance
        
        mock_conn_instance = Mock()
        mock_conn_instance.open.return_value = True
        mock_conn_instance.bind.return_value = True
        mock_conn_instance.search.return_value = False
        mock_conn_instance.result = {'description': 'Search failed'}
        mock_connection.return_value = mock_conn_instance
        
        client = LDAPClient(self.basic_config)
        client.connect()
        
        group_dn = 'cn=testgroup,ou=groups,dc=example,dc=com'
        
        with self.assertRaises(LDAPQueryError):
            client.get_group_members(group_dn)

    def test_disconnect(self):
        """Test LDAP connection disconnection."""
        client = LDAPClient(self.basic_config)
        
        # Mock connected state
        mock_connection = Mock()
        client.connection = mock_connection
        client._connected = True
        
        client.disconnect()
        
        mock_connection.unbind.assert_called_once()
        self.assertFalse(client._connected)
        self.assertIsNone(client.connection)

    def test_connection_stats(self):
        """Test connection statistics retrieval."""
        client = LDAPClient(self.basic_config)
        stats = client.get_connection_stats()
        
        expected_keys = [
            'connected', 'server_url', 'bind_dn', 'use_ssl', 'start_tls',
            'verify_ssl', 'connection_timeout', 'receive_timeout', 'page_size'
        ]
        
        for key in expected_keys:
            self.assertIn(key, stats)
        
        self.assertFalse(stats['connected'])
        self.assertEqual(stats['server_url'], 'ldaps://ldap.example.com:636')
        self.assertTrue(stats['use_ssl'])

    @patch('ldap_sync.ldap_client.Server')
    @patch('ldap_sync.ldap_client.Connection')
    def test_context_manager(self, mock_connection, mock_server):
        """Test LDAP client as context manager."""
        mock_server_instance = Mock()
        mock_server.return_value = mock_server_instance
        
        mock_conn_instance = Mock()
        mock_conn_instance.open.return_value = True
        mock_conn_instance.bind.return_value = True
        mock_connection.return_value = mock_conn_instance
        
        with LDAPClient(self.basic_config) as client:
            self.assertIsNotNone(client)
            self.assertTrue(client._connected)
        
        # Should automatically disconnect on exit
        mock_conn_instance.unbind.assert_called_once()

    def test_validate_connection_not_connected(self):
        """Test connection validation when not connected."""
        client = LDAPClient(self.basic_config)
        
        with self.assertRaises(LDAPConnectionError):
            client.validate_connection()

    @patch('ldap_sync.ldap_client.Server')
    @patch('ldap_sync.ldap_client.Connection')
    def test_validate_connection_success(self, mock_connection, mock_server):
        """Test successful connection validation."""
        mock_server_instance = Mock()
        mock_server.return_value = mock_server_instance
        
        mock_conn_instance = Mock()
        mock_conn_instance.open.return_value = True
        mock_conn_instance.bind.return_value = True
        mock_conn_instance.search.return_value = True
        mock_connection.return_value = mock_conn_instance
        
        client = LDAPClient(self.basic_config)
        client.connect()
        
        # Should not raise exception
        client.validate_connection()
        
        # Should have performed a test search
        mock_conn_instance.search.assert_called()

    def test_get_group_members_invalid_method(self):
        """Test get_group_members with invalid method."""
        client = LDAPClient(self.basic_config)
        
        with self.assertRaises(ValueError):
            client.get_group_members('cn=test,dc=example,dc=com', method='invalid')

    def test_attribute_extraction_with_missing_attributes(self):
        """Test attribute extraction when some attributes are missing."""
        client = LDAPClient(self.basic_config)
        
        # Mock entry with missing attributes
        mock_entry = Mock()
        mock_entry.entry_dn = 'cn=user1,ou=users,dc=example,dc=com'
        
        # Only some attributes present
        mock_entry.sAMAccountName.value = 'user1'
        mock_entry.givenName.value = 'User'
        # sn and mail are missing
        mock_entry.sn = Mock()
        mock_entry.sn.value = None
        mock_entry.mail = Mock()
        mock_entry.mail.value = None
        
        attributes = client._extract_user_attributes(mock_entry)
        
        self.assertEqual(attributes['sAMAccountName'], 'user1')
        self.assertEqual(attributes['givenName'], 'User')
        self.assertIsNone(attributes['sn'])
        self.assertIsNone(attributes['mail'])

    def test_handle_search_controls_no_pagination(self):
        """Test search controls handling without pagination."""
        client = LDAPClient(self.basic_config)
        
        # Mock result without pagination controls
        result = {'controls': {}}
        cookie = client._handle_search_controls(result)
        
        self.assertIsNone(cookie)

    def test_handle_search_controls_with_pagination(self):
        """Test search controls handling with pagination."""
        client = LDAPClient(self.basic_config)
        
        # Mock result with pagination controls
        result = {
            'controls': {
                '1.2.840.113556.1.4.319': {
                    'value': {'cookie': b'next_page_token'}
                }
            }
        }
        cookie = client._handle_search_controls(result)
        
        self.assertEqual(cookie, b'next_page_token')


if __name__ == '__main__':
    unittest.main()