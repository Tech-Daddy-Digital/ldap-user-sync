#!/usr/bin/env python3
"""
Unit tests for the main sync orchestrator.

Tests the core synchronization logic with mock LDAP and vendor systems.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add parent directory to path to import ldap_sync modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ldap_sync.main import SyncOrchestrator, SyncError
from ldap_sync.config import ConfigurationError
from ldap_sync.ldap_client import LDAPConnectionError


class TestSyncOrchestrator(unittest.TestCase):
    """Test cases for SyncOrchestrator class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_config = {
            'ldap': {
                'server_url': 'ldaps://test.example.com',
                'bind_dn': 'CN=service,DC=test,DC=com',
                'bind_password': 'test_password',
                'user_base_dn': 'OU=Users,DC=test,DC=com'
            },
            'vendor_apps': [
                {
                    'name': 'TestVendor',
                    'module': 'vendor_app1',
                    'base_url': 'https://api.test.com',
                    'auth': {'method': 'basic', 'username': 'test', 'password': 'test'},
                    'groups': [
                        {
                            'ldap_group': 'CN=TestGroup,OU=Groups,DC=test,DC=com',
                            'vendor_group': 'test_group'
                        }
                    ]
                }
            ],
            'logging': {
                'level': 'INFO',
                'log_dir': 'test_logs',
                'retention_days': 7
            },
            'error_handling': {
                'max_retries': 2,
                'retry_wait_seconds': 1,
                'max_errors_per_vendor': 3
            },
            'notifications': {
                'enable_email': False
            }
        }
    
    @patch('ldap_sync.main.load_config')
    @patch('ldap_sync.main.LDAPClient')
    @patch('ldap_sync.main.os.makedirs')
    @patch('ldap_sync.main.logging')
    def test_successful_sync(self, mock_logging, mock_makedirs, mock_ldap_client, mock_load_config):
        """Test successful synchronization run."""
        # Mock configuration
        mock_load_config.return_value = self.test_config
        
        # Mock LDAP client
        mock_ldap = Mock()
        mock_ldap.get_group_members.return_value = {
            'user1@test.com': {
                'email': 'user1@test.com',
                'first_name': 'User',
                'last_name': 'One',
                'username': 'user1'
            }
        }
        mock_ldap_client.return_value = mock_ldap
        
        # Mock vendor API
        with patch('ldap_sync.main.importlib.import_module') as mock_import:
            mock_vendor_module = Mock()
            mock_vendor_class = Mock()
            mock_vendor_api = Mock()
            
            # Configure vendor API mock
            mock_vendor_api.authenticate.return_value = True
            mock_vendor_api.get_group_members.return_value = []
            mock_vendor_api.add_user_to_group.return_value = True
            mock_vendor_api.close_connection.return_value = None
            
            mock_vendor_class.return_value = mock_vendor_api
            mock_vendor_module.return_value = mock_vendor_module
            
            # Set up module attributes
            setattr(mock_vendor_module, 'VendorApp1API', mock_vendor_class)
            mock_import.return_value = mock_vendor_module
            
            # Run orchestrator
            orchestrator = SyncOrchestrator()
            with patch.object(orchestrator, '_load_vendor_module', return_value=mock_vendor_api):
                exit_code = orchestrator.run()
            
            # Verify success
            self.assertEqual(exit_code, 0)
            self.assertEqual(orchestrator.sync_stats['vendors_processed'], 1)
            self.assertEqual(orchestrator.sync_stats['vendors_failed'], 0)
            self.assertEqual(orchestrator.sync_stats['total_users_added'], 1)
    
    @patch('ldap_sync.main.load_config')
    def test_configuration_error(self, mock_load_config):
        """Test handling of configuration errors."""
        mock_load_config.side_effect = Exception("Invalid config")
        
        orchestrator = SyncOrchestrator()
        exit_code = orchestrator.run()
        
        self.assertEqual(exit_code, 2)
    
    @patch('ldap_sync.main.load_config')
    @patch('ldap_sync.main.LDAPClient')
    @patch('ldap_sync.main.os.makedirs')
    @patch('ldap_sync.main.logging')
    def test_ldap_connection_error(self, mock_logging, mock_makedirs, mock_ldap_client, mock_load_config):
        """Test handling of LDAP connection errors."""
        mock_load_config.return_value = self.test_config
        
        # Mock LDAP connection failure
        mock_ldap = Mock()
        mock_ldap.connect.side_effect = LDAPConnectionError("LDAP server unreachable")
        mock_ldap_client.return_value = mock_ldap
        
        orchestrator = SyncOrchestrator()
        exit_code = orchestrator.run()
        
        self.assertEqual(exit_code, 3)
    
    @patch('ldap_sync.main.load_config')
    @patch('ldap_sync.main.LDAPClient')
    @patch('ldap_sync.main.os.makedirs')
    @patch('ldap_sync.main.logging')
    def test_vendor_authentication_failure(self, mock_logging, mock_makedirs, mock_ldap_client, mock_load_config):
        """Test handling of vendor authentication failures."""
        mock_load_config.return_value = self.test_config
        
        # Mock LDAP client
        mock_ldap = Mock()
        mock_ldap_client.return_value = mock_ldap
        
        # Mock vendor API with auth failure
        mock_vendor_api = Mock()
        mock_vendor_api.authenticate.return_value = False
        
        orchestrator = SyncOrchestrator()
        with patch.object(orchestrator, '_load_vendor_module', return_value=mock_vendor_api):
            exit_code = orchestrator.run()
        
        # Should complete with vendor failure
        self.assertEqual(exit_code, 1)
        self.assertEqual(orchestrator.sync_stats['vendors_failed'], 1)
    
    def test_user_comparison_logic(self):
        """Test user comparison logic for updates."""
        orchestrator = SyncOrchestrator()
        
        # Users that need updates
        ldap_user = {
            'email': 'test@example.com',
            'first_name': 'John',
            'last_name': 'Doe'
        }
        
        vendor_user = {
            'email': 'test@example.com',
            'first_name': 'John',
            'last_name': 'Smith'  # Different last name
        }
        
        self.assertTrue(orchestrator._user_needs_update(ldap_user, vendor_user))
        
        # Users that don't need updates
        vendor_user_same = {
            'email': 'test@example.com',
            'first_name': 'John',
            'last_name': 'Doe'
        }
        
        self.assertFalse(orchestrator._user_needs_update(ldap_user, vendor_user_same))
    
    def test_user_identifier_extraction(self):
        """Test user identifier extraction logic."""
        orchestrator = SyncOrchestrator()
        
        # Test with email
        user_with_email = {'email': 'test@example.com', 'username': 'test'}
        self.assertEqual(orchestrator._get_user_identifier(user_with_email), 'test@example.com')
        
        # Test with username fallback
        user_with_username = {'username': 'test_user'}
        self.assertEqual(orchestrator._get_user_identifier(user_with_username), 'test_user')
        
        # Test with ID fallback
        user_with_id = {'id': '12345'}
        self.assertEqual(orchestrator._get_user_identifier(user_with_id), '12345')
        
        # Test with unknown fallback
        user_unknown = {}
        self.assertEqual(orchestrator._get_user_identifier(user_unknown), 'unknown')
    
    @patch('ldap_sync.main.load_config')
    @patch('ldap_sync.main.LDAPClient')
    @patch('ldap_sync.main.os.makedirs')
    @patch('ldap_sync.main.logging')
    def test_error_threshold_handling(self, mock_logging, mock_makedirs, mock_ldap_client, mock_load_config):
        """Test vendor error threshold handling."""
        # Lower error threshold for testing
        test_config = self.test_config.copy()
        test_config['error_handling']['max_errors_per_vendor'] = 2
        mock_load_config.return_value = test_config
        
        # Mock LDAP client
        mock_ldap = Mock()
        mock_ldap.get_group_members.side_effect = Exception("LDAP query failed")
        mock_ldap_client.return_value = mock_ldap
        
        # Mock vendor API
        mock_vendor_api = Mock()
        mock_vendor_api.authenticate.return_value = True
        mock_vendor_api.close_connection.return_value = None
        
        orchestrator = SyncOrchestrator()
        with patch.object(orchestrator, '_load_vendor_module', return_value=mock_vendor_api):
            exit_code = orchestrator.run()
        
        # Should complete with vendor failure due to error threshold
        self.assertEqual(exit_code, 1)
        self.assertEqual(orchestrator.sync_stats['vendors_failed'], 1)
    
    @patch('ldap_sync.main.retry_call')
    def test_retry_operation(self, mock_retry_call):
        """Test retry operation logic."""
        orchestrator = SyncOrchestrator()
        orchestrator.config = self.test_config
        
        # Test successful retry
        mock_operation = Mock(return_value=True)
        mock_retry_call.return_value = True
        
        result = orchestrator._retry_operation(mock_operation, self.test_config['error_handling'])
        
        self.assertTrue(result)
        mock_retry_call.assert_called_once()


if __name__ == '__main__':
    # Set up logging for tests
    import logging
    logging.basicConfig(level=logging.DEBUG)
    
    unittest.main()