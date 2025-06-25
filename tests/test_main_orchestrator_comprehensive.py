#!/usr/bin/env python3
"""
Comprehensive unit tests for main orchestrator logic.
"""

import os
import sys
import unittest
import tempfile
import json
from unittest.mock import Mock, patch, MagicMock, call

# Add the project directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ldap_sync.main import SyncOrchestrator, main_sync
from ldap_sync.ldap_client import LDAPConnectionError, LDAPQueryError
from ldap_sync.vendors.base import VendorAPIError
from ldap_sync.config import ConfigurationError


class TestSyncOrchestrator(unittest.TestCase):
    """Test cases for SyncOrchestrator class."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            'ldap': {
                'server_url': 'ldaps://ldap.example.com:636',
                'bind_dn': 'cn=service,dc=example,dc=com',
                'bind_password': 'password',
                'user_base_dn': 'ou=users,dc=example,dc=com',
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
                    'groups': [
                        {
                            'ldap_group': 'cn=testgroup1,ou=groups,dc=example,dc=com',
                            'vendor_group': 'test_group_1'
                        },
                        {
                            'ldap_group': 'cn=testgroup2,ou=groups,dc=example,dc=com',
                            'vendor_group': 'test_group_2'
                        }
                    ]
                }
            ],
            'logging': {
                'level': 'INFO',
                'log_dir': 'logs'
            },
            'error_handling': {
                'max_retries': 3,
                'retry_wait_seconds': 1,
                'max_errors_per_vendor': 5
            },
            'notifications': {
                'enable_email': True,
                'email_on_failure': True
            }
        }

    def test_initialization(self):
        """Test SyncOrchestrator initialization."""
        orchestrator = SyncOrchestrator(self.config)
        
        self.assertEqual(orchestrator.config, self.config)
        self.assertEqual(orchestrator.max_errors_per_vendor, 5)
        self.assertIsNone(orchestrator.ldap_client)
        self.assertEqual(len(orchestrator.vendor_apis), 0)

    @patch('ldap_sync.main.LDAPClient')
    def test_setup_ldap_client_success(self, mock_ldap_client):
        """Test successful LDAP client setup."""
        mock_client = Mock()
        mock_client.connect.return_value = True
        mock_ldap_client.return_value = mock_client
        
        orchestrator = SyncOrchestrator(self.config)
        result = orchestrator._setup_ldap_client()
        
        self.assertTrue(result)
        self.assertEqual(orchestrator.ldap_client, mock_client)
        mock_client.connect.assert_called_once()

    @patch('ldap_sync.main.LDAPClient')
    def test_setup_ldap_client_failure(self, mock_ldap_client):
        """Test LDAP client setup failure."""
        mock_client = Mock()
        mock_client.connect.side_effect = LDAPConnectionError("Connection failed")
        mock_ldap_client.return_value = mock_client
        
        orchestrator = SyncOrchestrator(self.config)
        
        with self.assertRaises(LDAPConnectionError):
            orchestrator._setup_ldap_client()

    @patch('ldap_sync.main.importlib.import_module')
    def test_load_vendor_api_success(self, mock_import):
        """Test successful vendor API loading."""
        mock_module = Mock()
        mock_api_class = Mock()
        mock_api_instance = Mock()
        
        # Setup the mock module to return a VendorAPI class
        mock_module.VendorApp1API = mock_api_class
        mock_api_class.return_value = mock_api_instance
        mock_import.return_value = mock_module
        
        orchestrator = SyncOrchestrator(self.config)
        vendor_config = self.config['vendor_apps'][0]
        
        api = orchestrator._load_vendor_api(vendor_config)
        
        self.assertEqual(api, mock_api_instance)
        mock_import.assert_called_once_with('ldap_sync.vendors.vendor_app1')
        mock_api_class.assert_called_once_with(vendor_config)

    @patch('ldap_sync.main.importlib.import_module')
    def test_load_vendor_api_module_not_found(self, mock_import):
        """Test vendor API loading with missing module."""
        mock_import.side_effect = ImportError("Module not found")
        
        orchestrator = SyncOrchestrator(self.config)
        vendor_config = self.config['vendor_apps'][0]
        
        with self.assertRaises(ImportError):
            orchestrator._load_vendor_api(vendor_config)

    @patch('ldap_sync.main.importlib.import_module')
    def test_load_vendor_api_class_not_found(self, mock_import):
        """Test vendor API loading with missing class."""
        mock_module = Mock()
        # Module exists but doesn't have the expected class
        del mock_module.VendorApp1API
        mock_import.return_value = mock_module
        
        orchestrator = SyncOrchestrator(self.config)
        vendor_config = self.config['vendor_apps'][0]
        
        with self.assertRaises(AttributeError):
            orchestrator._load_vendor_api(vendor_config)

    def test_compare_user_sets_additions(self):
        """Test user set comparison for additions."""
        ldap_users = {
            'user1': {'givenName': 'User', 'sn': 'One', 'mail': 'user1@example.com'},
            'user2': {'givenName': 'User', 'sn': 'Two', 'mail': 'user2@example.com'}
        }
        
        vendor_users = {
            'user1': {'givenName': 'User', 'sn': 'One', 'mail': 'user1@example.com'}
        }
        
        orchestrator = SyncOrchestrator(self.config)
        comparison = orchestrator._compare_user_sets(ldap_users, vendor_users)
        
        self.assertEqual(len(comparison['to_add']), 1)
        self.assertIn('user2', comparison['to_add'])
        self.assertEqual(len(comparison['to_remove']), 0)
        self.assertEqual(len(comparison['to_update']), 0)

    def test_compare_user_sets_removals(self):
        """Test user set comparison for removals."""
        ldap_users = {
            'user1': {'givenName': 'User', 'sn': 'One', 'mail': 'user1@example.com'}
        }
        
        vendor_users = {
            'user1': {'givenName': 'User', 'sn': 'One', 'mail': 'user1@example.com'},
            'user2': {'givenName': 'User', 'sn': 'Two', 'mail': 'user2@example.com'}
        }
        
        orchestrator = SyncOrchestrator(self.config)
        comparison = orchestrator._compare_user_sets(ldap_users, vendor_users)
        
        self.assertEqual(len(comparison['to_add']), 0)
        self.assertEqual(len(comparison['to_remove']), 1)
        self.assertIn('user2', comparison['to_remove'])
        self.assertEqual(len(comparison['to_update']), 0)

    def test_compare_user_sets_updates(self):
        """Test user set comparison for updates."""
        ldap_users = {
            'user1': {'givenName': 'User', 'sn': 'One', 'mail': 'user1@example.com'},
            'user2': {'givenName': 'Updated', 'sn': 'Two', 'mail': 'updated2@example.com'}
        }
        
        vendor_users = {
            'user1': {'givenName': 'User', 'sn': 'One', 'mail': 'user1@example.com'},
            'user2': {'givenName': 'User', 'sn': 'Two', 'mail': 'user2@example.com'}
        }
        
        orchestrator = SyncOrchestrator(self.config)
        comparison = orchestrator._compare_user_sets(ldap_users, vendor_users)
        
        self.assertEqual(len(comparison['to_add']), 0)
        self.assertEqual(len(comparison['to_remove']), 0)
        self.assertEqual(len(comparison['to_update']), 1)
        self.assertIn('user2', comparison['to_update'])
        
        # Check that changed fields are identified
        update_info = comparison['to_update']['user2']
        self.assertIn('givenName', update_info['changed_fields'])
        self.assertIn('mail', update_info['changed_fields'])
        self.assertNotIn('sn', update_info['changed_fields'])

    def test_compare_user_sets_no_changes(self):
        """Test user set comparison with no changes."""
        user_data = {
            'user1': {'givenName': 'User', 'sn': 'One', 'mail': 'user1@example.com'},
            'user2': {'givenName': 'User', 'sn': 'Two', 'mail': 'user2@example.com'}
        }
        
        orchestrator = SyncOrchestrator(self.config)
        comparison = orchestrator._compare_user_sets(user_data, user_data)
        
        self.assertEqual(len(comparison['to_add']), 0)
        self.assertEqual(len(comparison['to_remove']), 0)
        self.assertEqual(len(comparison['to_update']), 0)

    @patch('ldap_sync.main.send_notification')
    def test_sync_group_success(self, mock_send_notification):
        """Test successful group synchronization."""
        orchestrator = SyncOrchestrator(self.config)
        
        # Mock LDAP client
        mock_ldap_client = Mock()
        mock_ldap_client.get_group_members.return_value = {
            'user1': {'givenName': 'User', 'sn': 'One', 'mail': 'user1@example.com'},
            'user2': {'givenName': 'User', 'sn': 'Two', 'mail': 'user2@example.com'}
        }
        orchestrator.ldap_client = mock_ldap_client
        
        # Mock vendor API
        mock_vendor_api = Mock()
        mock_vendor_api.get_group_members.return_value = {
            'user1': {'givenName': 'User', 'sn': 'One', 'mail': 'user1@example.com'}
        }
        mock_vendor_api.add_user_to_group.return_value = True
        
        group_config = {
            'ldap_group': 'cn=testgroup,ou=groups,dc=example,dc=com',
            'vendor_group': 'test_group'
        }
        
        result = orchestrator._sync_group(mock_vendor_api, group_config)
        
        self.assertTrue(result['success'])
        self.assertEqual(result['stats']['added'], 1)
        self.assertEqual(result['stats']['removed'], 0)
        self.assertEqual(result['stats']['updated'], 0)
        self.assertEqual(result['stats']['errors'], 0)
        
        mock_vendor_api.add_user_to_group.assert_called_once()

    @patch('ldap_sync.main.send_notification')
    def test_sync_group_with_errors(self, mock_send_notification):
        """Test group synchronization with errors."""
        orchestrator = SyncOrchestrator(self.config)
        
        # Mock LDAP client
        mock_ldap_client = Mock()
        mock_ldap_client.get_group_members.return_value = {
            'user1': {'givenName': 'User', 'sn': 'One', 'mail': 'user1@example.com'},
            'user2': {'givenName': 'User', 'sn': 'Two', 'mail': 'user2@example.com'}
        }
        orchestrator.ldap_client = mock_ldap_client
        
        # Mock vendor API with errors
        mock_vendor_api = Mock()
        mock_vendor_api.get_group_members.return_value = {}
        mock_vendor_api.add_user_to_group.side_effect = [
            True,  # First call succeeds
            VendorAPIError("API error", 500)  # Second call fails
        ]
        
        group_config = {
            'ldap_group': 'cn=testgroup,ou=groups,dc=example,dc=com',
            'vendor_group': 'test_group'
        }
        
        result = orchestrator._sync_group(mock_vendor_api, group_config)
        
        self.assertTrue(result['success'])  # Should still be successful overall
        self.assertEqual(result['stats']['added'], 1)  # One successful addition
        self.assertEqual(result['stats']['errors'], 1)  # One error
        
        self.assertEqual(mock_vendor_api.add_user_to_group.call_count, 2)

    @patch('ldap_sync.main.send_notification')
    def test_sync_group_ldap_error(self, mock_send_notification):
        """Test group synchronization with LDAP error."""
        orchestrator = SyncOrchestrator(self.config)
        
        # Mock LDAP client with error
        mock_ldap_client = Mock()
        mock_ldap_client.get_group_members.side_effect = LDAPQueryError("LDAP query failed")
        orchestrator.ldap_client = mock_ldap_client
        
        mock_vendor_api = Mock()
        
        group_config = {
            'ldap_group': 'cn=testgroup,ou=groups,dc=example,dc=com',
            'vendor_group': 'test_group'
        }
        
        result = orchestrator._sync_group(mock_vendor_api, group_config)
        
        self.assertFalse(result['success'])
        self.assertIn('LDAP query failed', result['error'])

    @patch('ldap_sync.main.send_notification')
    def test_sync_vendor_success(self, mock_send_notification):
        """Test successful vendor synchronization."""
        orchestrator = SyncOrchestrator(self.config)
        
        # Mock LDAP client
        mock_ldap_client = Mock()
        orchestrator.ldap_client = mock_ldap_client
        
        # Mock vendor API
        mock_vendor_api = Mock()
        mock_vendor_api.name = 'TestApp1'
        mock_vendor_api.authenticate.return_value = True
        
        with patch.object(orchestrator, '_sync_group') as mock_sync_group:
            mock_sync_group.return_value = {
                'success': True,
                'stats': {'added': 1, 'removed': 0, 'updated': 0, 'errors': 0}
            }
            
            vendor_config = self.config['vendor_apps'][0]
            result = orchestrator._sync_vendor(mock_vendor_api, vendor_config)
            
            self.assertTrue(result['success'])
            self.assertEqual(result['total_errors'], 0)
            self.assertEqual(mock_sync_group.call_count, 2)  # Two groups configured

    @patch('ldap_sync.main.send_notification')
    def test_sync_vendor_auth_failure(self, mock_send_notification):
        """Test vendor synchronization with authentication failure."""
        orchestrator = SyncOrchestrator(self.config)
        
        mock_vendor_api = Mock()
        mock_vendor_api.name = 'TestApp1'
        mock_vendor_api.authenticate.side_effect = VendorAPIError("Authentication failed", 401)
        
        vendor_config = self.config['vendor_apps'][0]
        result = orchestrator._sync_vendor(mock_vendor_api, vendor_config)
        
        self.assertFalse(result['success'])
        self.assertIn('Authentication failed', result['error'])

    @patch('ldap_sync.main.send_notification')
    def test_sync_vendor_max_errors_exceeded(self, mock_send_notification):
        """Test vendor synchronization with max errors exceeded."""
        orchestrator = SyncOrchestrator(self.config)
        
        # Mock LDAP client
        mock_ldap_client = Mock()
        orchestrator.ldap_client = mock_ldap_client
        
        mock_vendor_api = Mock()
        mock_vendor_api.name = 'TestApp1'
        mock_vendor_api.authenticate.return_value = True
        
        with patch.object(orchestrator, '_sync_group') as mock_sync_group:
            # Return many errors to exceed threshold
            mock_sync_group.return_value = {
                'success': True,
                'stats': {'added': 0, 'removed': 0, 'updated': 0, 'errors': 6}  # Exceeds max of 5
            }
            
            vendor_config = self.config['vendor_apps'][0]
            result = orchestrator._sync_vendor(mock_vendor_api, vendor_config)
            
            self.assertFalse(result['success'])
            self.assertIn('error threshold', result['error'])
            mock_send_notification.assert_called()

    @patch('ldap_sync.main.setup_logging')
    @patch('ldap_sync.main.load_config')
    def test_run_sync_success(self, mock_load_config, mock_setup_logging):
        """Test successful sync run."""
        mock_load_config.return_value = self.config
        
        orchestrator = SyncOrchestrator(self.config)
        
        with patch.object(orchestrator, '_setup_ldap_client') as mock_setup_ldap, \
             patch.object(orchestrator, '_load_vendor_api') as mock_load_vendor, \
             patch.object(orchestrator, '_sync_vendor') as mock_sync_vendor:
            
            mock_setup_ldap.return_value = True
            mock_load_vendor.return_value = Mock()
            mock_sync_vendor.return_value = {
                'success': True,
                'total_errors': 0,
                'groups_synced': 2
            }
            
            result = orchestrator.run()
            
            self.assertTrue(result['success'])
            self.assertEqual(result['vendors_processed'], 1)
            mock_setup_ldap.assert_called_once()
            mock_load_vendor.assert_called_once()
            mock_sync_vendor.assert_called_once()

    @patch('ldap_sync.main.setup_logging')
    @patch('ldap_sync.main.load_config')
    def test_run_sync_ldap_failure(self, mock_load_config, mock_setup_logging):
        """Test sync run with LDAP connection failure."""
        mock_load_config.return_value = self.config
        
        orchestrator = SyncOrchestrator(self.config)
        
        with patch.object(orchestrator, '_setup_ldap_client') as mock_setup_ldap:
            mock_setup_ldap.side_effect = LDAPConnectionError("LDAP connection failed")
            
            result = orchestrator.run()
            
            self.assertFalse(result['success'])
            self.assertIn('LDAP connection failed', result['error'])

    @patch('ldap_sync.main.setup_logging')
    @patch('ldap_sync.main.load_config')
    def test_run_sync_vendor_load_failure(self, mock_load_config, mock_setup_logging):
        """Test sync run with vendor loading failure."""
        mock_load_config.return_value = self.config
        
        orchestrator = SyncOrchestrator(self.config)
        
        with patch.object(orchestrator, '_setup_ldap_client') as mock_setup_ldap, \
             patch.object(orchestrator, '_load_vendor_api') as mock_load_vendor:
            
            mock_setup_ldap.return_value = True
            mock_load_vendor.side_effect = ImportError("Vendor module not found")
            
            result = orchestrator.run()
            
            self.assertFalse(result['success'])
            self.assertEqual(result['vendors_processed'], 0)

    def test_cleanup(self):
        """Test cleanup functionality."""
        orchestrator = SyncOrchestrator(self.config)
        
        # Mock LDAP client
        mock_ldap_client = Mock()
        orchestrator.ldap_client = mock_ldap_client
        
        # Mock vendor APIs
        mock_vendor_api = Mock()
        orchestrator.vendor_apis = [mock_vendor_api]
        
        orchestrator._cleanup()
        
        mock_ldap_client.disconnect.assert_called_once()
        # Vendor APIs don't have explicit cleanup in the base implementation

    def test_get_sync_stats(self):
        """Test sync statistics collection."""
        orchestrator = SyncOrchestrator(self.config)
        
        stats = orchestrator.get_sync_stats()
        
        expected_keys = [
            'vendors_configured', 'vendors_processed', 'total_groups',
            'start_time', 'end_time', 'duration_seconds'
        ]
        
        for key in expected_keys:
            self.assertIn(key, stats)
        
        self.assertEqual(stats['vendors_configured'], 1)


class TestMainSyncFunction(unittest.TestCase):
    """Test cases for main_sync function."""

    @patch('ldap_sync.main.load_config')
    @patch('ldap_sync.main.setup_logging')
    def test_main_sync_success(self, mock_setup_logging, mock_load_config):
        """Test successful main sync execution."""
        config = {
            'ldap': {
                'server_url': 'ldaps://ldap.example.com:636',
                'bind_dn': 'cn=service,dc=example,dc=com',
                'bind_password': 'password'
            },
            'vendor_apps': [
                {
                    'name': 'TestApp1',
                    'module': 'vendor_app1',
                    'base_url': 'https://api.testapp1.com/v1',
                    'auth': {'method': 'basic', 'username': 'user', 'password': 'pass'},
                    'groups': [
                        {'ldap_group': 'cn=test,dc=example,dc=com', 'vendor_group': 'test'}
                    ]
                }
            ],
            'logging': {'level': 'INFO'},
            'error_handling': {'max_retries': 3},
            'notifications': {'enable_email': False}
        }
        
        mock_load_config.return_value = config
        
        with patch('ldap_sync.main.SyncOrchestrator') as mock_orchestrator_class:
            mock_orchestrator = Mock()
            mock_orchestrator.run.return_value = {
                'success': True,
                'vendors_processed': 1,
                'total_errors': 0
            }
            mock_orchestrator_class.return_value = mock_orchestrator
            
            result = main_sync()
            
            self.assertEqual(result, 0)  # Success exit code
            mock_orchestrator.run.assert_called_once()

    @patch('ldap_sync.main.load_config')
    @patch('ldap_sync.main.setup_logging')
    def test_main_sync_config_error(self, mock_setup_logging, mock_load_config):
        """Test main sync with configuration error."""
        mock_load_config.side_effect = ConfigurationError("Invalid config")
        
        result = main_sync()
        
        self.assertEqual(result, 1)  # Error exit code

    @patch('ldap_sync.main.load_config')
    @patch('ldap_sync.main.setup_logging')
    def test_main_sync_unexpected_error(self, mock_setup_logging, mock_load_config):
        """Test main sync with unexpected error."""
        mock_load_config.side_effect = Exception("Unexpected error")
        
        result = main_sync()
        
        self.assertEqual(result, 1)  # Error exit code

    @patch('ldap_sync.main.load_config')
    @patch('ldap_sync.main.setup_logging')
    def test_main_sync_orchestrator_failure(self, mock_setup_logging, mock_load_config):
        """Test main sync with orchestrator failure."""
        config = {
            'ldap': {'server_url': 'ldaps://ldap.example.com:636'},
            'vendor_apps': [],
            'logging': {'level': 'INFO'},
            'error_handling': {'max_retries': 3},
            'notifications': {'enable_email': False}
        }
        
        mock_load_config.return_value = config
        
        with patch('ldap_sync.main.SyncOrchestrator') as mock_orchestrator_class:
            mock_orchestrator = Mock()
            mock_orchestrator.run.return_value = {
                'success': False,
                'error': 'Sync failed',
                'vendors_processed': 0
            }
            mock_orchestrator_class.return_value = mock_orchestrator
            
            result = main_sync()
            
            self.assertEqual(result, 1)  # Error exit code


class TestUtilityFunctions(unittest.TestCase):
    """Test cases for utility functions in main module."""

    def test_format_duration(self):
        """Test duration formatting."""
        from ldap_sync.main import format_duration
        
        # Test various durations
        self.assertEqual(format_duration(30), "30.0 seconds")
        self.assertEqual(format_duration(90), "1 minute 30 seconds")
        self.assertEqual(format_duration(3661), "1 hour 1 minute 1 second")

    def test_summarize_changes(self):
        """Test change summarization."""
        from ldap_sync.main import summarize_changes
        
        changes = {
            'to_add': {'user1': {}, 'user2': {}},
            'to_remove': {'user3': {}},
            'to_update': {'user4': {'changed_fields': ['email']}}
        }
        
        summary = summarize_changes(changes)
        
        self.assertIn('2 additions', summary)
        self.assertIn('1 removal', summary)
        self.assertIn('1 update', summary)


if __name__ == '__main__':
    unittest.main()