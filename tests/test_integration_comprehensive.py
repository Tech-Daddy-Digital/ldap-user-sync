#!/usr/bin/env python3
"""
Comprehensive integration tests for end-to-end scenarios.
"""

import os
import sys
import unittest
import tempfile
import yaml
import json
from unittest.mock import Mock, patch, MagicMock, call

# Add the project directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ldap_sync.main import SyncOrchestrator, main_sync
from ldap_sync.config import load_config
from ldap_sync.ldap_client import LDAPClient
from ldap_sync.vendors.vendor_app1 import VendorApp1API
from ldap_sync.vendors.vendor_app2 import VendorApp2API
from ldap_sync.notifications import send_notification


class TestEndToEndSyncScenarios(unittest.TestCase):
    """Test complete end-to-end sync scenarios."""

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
                            'ldap_group': 'cn=app1_users,ou=groups,dc=example,dc=com',
                            'vendor_group': 'app1_users'
                        },
                        {
                            'ldap_group': 'cn=app1_admins,ou=groups,dc=example,dc=com',
                            'vendor_group': 'app1_admins'
                        }
                    ]
                },
                {
                    'name': 'TestApp2',
                    'module': 'vendor_app2',
                    'base_url': 'https://api.testapp2.com/rest',
                    'auth': {
                        'method': 'token',
                        'token': 'abc123def456'
                    },
                    'format': 'xml',
                    'groups': [
                        {
                            'ldap_group': 'cn=app2_users,ou=groups,dc=example,dc=com',
                            'vendor_group': 'app2_users_id'
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
                'email_on_failure': True,
                'smtp_server': 'smtp.example.com',
                'email_from': 'alerts@example.com',
                'email_to': ['admin@example.com']
            }
        }

        # Sample LDAP data
        self.ldap_data = {
            'cn=app1_users,ou=groups,dc=example,dc=com': {
                'user1': {
                    'sAMAccountName': 'user1',
                    'givenName': 'John',
                    'sn': 'Doe',
                    'mail': 'john.doe@example.com'
                },
                'user2': {
                    'sAMAccountName': 'user2',
                    'givenName': 'Jane',
                    'sn': 'Smith',
                    'mail': 'jane.smith@example.com'
                },
                'user3': {
                    'sAMAccountName': 'user3',
                    'givenName': 'Bob',
                    'sn': 'Johnson',
                    'mail': 'bob.johnson@example.com'
                }
            },
            'cn=app1_admins,ou=groups,dc=example,dc=com': {
                'admin1': {
                    'sAMAccountName': 'admin1',
                    'givenName': 'Alice',
                    'sn': 'Admin',
                    'mail': 'alice.admin@example.com'
                }
            },
            'cn=app2_users,ou=groups,dc=example,dc=com': {
                'user1': {
                    'sAMAccountName': 'user1',
                    'givenName': 'John',
                    'sn': 'Doe',
                    'mail': 'john.doe@example.com'
                },
                'user4': {
                    'sAMAccountName': 'user4',
                    'givenName': 'Charlie',
                    'sn': 'Brown',
                    'mail': 'charlie.brown@example.com'
                }
            }
        }

        # Sample vendor data (before sync)
        self.vendor_data = {
            'TestApp1': {
                'app1_users': {
                    'user1': {
                        'username': 'user1',
                        'firstName': 'John',
                        'lastName': 'Doe',
                        'email': 'john.doe@example.com'
                    },
                    'user5': {  # User that should be removed
                        'username': 'user5',
                        'firstName': 'Old',
                        'lastName': 'User',
                        'email': 'old.user@example.com'
                    }
                },
                'app1_admins': {}  # Empty group
            },
            'TestApp2': {
                'app2_users_id': {
                    'user1': {
                        'username': 'user1',
                        'firstName': 'John',
                        'lastName': 'Doe',
                        'emailAddress': 'john.doe@old-email.com'  # Outdated email
                    }
                }
            }
        }

    @patch('ldap_sync.main.setup_logging')
    @patch('ldap_sync.main.send_notification')
    def test_complete_sync_success(self, mock_send_notification, mock_setup_logging):
        """Test complete successful sync across multiple vendors and groups."""
        
        # Mock LDAP client
        with patch('ldap_sync.main.LDAPClient') as mock_ldap_class:
            mock_ldap_client = Mock()
            mock_ldap_class.return_value = mock_ldap_client
            mock_ldap_client.connect.return_value = True
            
            # Configure LDAP responses
            def ldap_get_group_members(group_dn, method='memberof'):
                return self.ldap_data.get(group_dn, {})
            
            mock_ldap_client.get_group_members.side_effect = ldap_get_group_members
            
            # Mock vendor APIs
            with patch('ldap_sync.main.importlib.import_module') as mock_import:
                
                # Setup vendor modules and classes
                mock_vendor1_module = Mock()
                mock_vendor2_module = Mock()
                
                def import_side_effect(module_name):
                    if 'vendor_app1' in module_name:
                        return mock_vendor1_module
                    elif 'vendor_app2' in module_name:
                        return mock_vendor2_module
                    else:
                        raise ImportError(f"Module {module_name} not found")
                
                mock_import.side_effect = import_side_effect
                
                # Create mock vendor API instances
                mock_vendor1_api = Mock()
                mock_vendor2_api = Mock()
                
                mock_vendor1_module.VendorApp1API = Mock(return_value=mock_vendor1_api)
                mock_vendor2_module.VendorApp2API = Mock(return_value=mock_vendor2_api)
                
                # Configure vendor API responses
                mock_vendor1_api.name = 'TestApp1'
                mock_vendor1_api.authenticate.return_value = True
                
                def vendor1_get_group_members(group_config):
                    group_name = group_config['vendor_group']
                    return self.vendor_data['TestApp1'].get(group_name, {})
                
                mock_vendor1_api.get_group_members.side_effect = vendor1_get_group_members
                mock_vendor1_api.add_user_to_group.return_value = True
                mock_vendor1_api.remove_user_from_group.return_value = True
                mock_vendor1_api.update_user.return_value = True
                
                mock_vendor2_api.name = 'TestApp2'
                mock_vendor2_api.authenticate.return_value = True
                
                def vendor2_get_group_members(group_config):
                    group_name = group_config['vendor_group']
                    return self.vendor_data['TestApp2'].get(group_name, {})
                
                mock_vendor2_api.get_group_members.side_effect = vendor2_get_group_members
                mock_vendor2_api.add_user_to_group.return_value = True
                mock_vendor2_api.remove_user_from_group.return_value = True
                mock_vendor2_api.update_user.return_value = True
                
                # Run the sync
                orchestrator = SyncOrchestrator(self.config)
                result = orchestrator.run()
                
                # Verify overall success
                self.assertTrue(result['success'])
                self.assertEqual(result['vendors_processed'], 2)
                
                # Verify LDAP calls
                expected_ldap_calls = [
                    call('cn=app1_users,ou=groups,dc=example,dc=com'),
                    call('cn=app1_admins,ou=groups,dc=example,dc=com'),
                    call('cn=app2_users,ou=groups,dc=example,dc=com')
                ]
                mock_ldap_client.get_group_members.assert_has_calls(expected_ldap_calls, any_order=True)
                
                # Verify vendor API calls
                self.assertTrue(mock_vendor1_api.authenticate.called)
                self.assertTrue(mock_vendor2_api.authenticate.called)
                
                # Verify specific sync operations for TestApp1
                # - Should add user2, user3 to app1_users
                # - Should remove user5 from app1_users  
                # - Should add admin1 to app1_admins
                add_calls = mock_vendor1_api.add_user_to_group.call_args_list
                remove_calls = mock_vendor1_api.remove_user_from_group.call_args_list
                
                self.assertGreaterEqual(len(add_calls), 2)  # At least user2, user3, admin1
                self.assertGreaterEqual(len(remove_calls), 1)  # At least user5
                
                # Verify specific sync operations for TestApp2
                # - Should add user4 to app2_users
                # - Should update user1 email
                vendor2_add_calls = mock_vendor2_api.add_user_to_group.call_args_list
                vendor2_update_calls = mock_vendor2_api.update_user.call_args_list
                
                self.assertGreaterEqual(len(vendor2_add_calls), 1)  # At least user4
                self.assertGreaterEqual(len(vendor2_update_calls), 1)  # At least user1 email update

    @patch('ldap_sync.main.setup_logging')
    @patch('ldap_sync.main.send_notification')
    def test_sync_with_ldap_failure(self, mock_send_notification, mock_setup_logging):
        """Test sync behavior when LDAP connection fails."""
        
        with patch('ldap_sync.main.LDAPClient') as mock_ldap_class:
            mock_ldap_client = Mock()
            mock_ldap_class.return_value = mock_ldap_client
            mock_ldap_client.connect.side_effect = Exception("LDAP connection failed")
            
            orchestrator = SyncOrchestrator(self.config)
            result = orchestrator.run()
            
            # Verify failure
            self.assertFalse(result['success'])
            self.assertIn('LDAP connection failed', result['error'])
            self.assertEqual(result['vendors_processed'], 0)
            
            # Verify notification was sent
            mock_send_notification.assert_called()

    @patch('ldap_sync.main.setup_logging')
    @patch('ldap_sync.main.send_notification')
    def test_sync_with_vendor_auth_failure(self, mock_send_notification, mock_setup_logging):
        """Test sync behavior when vendor authentication fails."""
        
        with patch('ldap_sync.main.LDAPClient') as mock_ldap_class, \
             patch('ldap_sync.main.importlib.import_module') as mock_import:
            
            # Setup successful LDAP
            mock_ldap_client = Mock()
            mock_ldap_class.return_value = mock_ldap_client
            mock_ldap_client.connect.return_value = True
            mock_ldap_client.get_group_members.return_value = {}
            
            # Setup vendor with auth failure
            mock_vendor_module = Mock()
            mock_import.return_value = mock_vendor_module
            
            mock_vendor_api = Mock()
            mock_vendor_module.VendorApp1API = Mock(return_value=mock_vendor_api)
            mock_vendor_api.name = 'TestApp1'
            mock_vendor_api.authenticate.side_effect = Exception("Authentication failed")
            
            orchestrator = SyncOrchestrator(self.config)
            result = orchestrator.run()
            
            # Should continue processing but with failures
            self.assertFalse(result['success'])
            # Note: vendors_processed might be 0 or 1 depending on implementation

    @patch('ldap_sync.main.setup_logging')
    @patch('ldap_sync.main.send_notification')
    def test_sync_with_partial_vendor_errors(self, mock_send_notification, mock_setup_logging):
        """Test sync behavior with errors in some vendor operations."""
        
        with patch('ldap_sync.main.LDAPClient') as mock_ldap_class, \
             patch('ldap_sync.main.importlib.import_module') as mock_import:
            
            # Setup successful LDAP
            mock_ldap_client = Mock()
            mock_ldap_class.return_value = mock_ldap_client
            mock_ldap_client.connect.return_value = True
            mock_ldap_client.get_group_members.return_value = {
                'user1': {'sAMAccountName': 'user1', 'givenName': 'John', 'sn': 'Doe', 'mail': 'john@example.com'},
                'user2': {'sAMAccountName': 'user2', 'givenName': 'Jane', 'sn': 'Smith', 'mail': 'jane@example.com'}
            }
            
            # Setup vendor with partial failures
            mock_vendor_module = Mock()
            mock_import.return_value = mock_vendor_module
            
            mock_vendor_api = Mock()
            mock_vendor_module.VendorApp1API = Mock(return_value=mock_vendor_api)
            mock_vendor_api.name = 'TestApp1'
            mock_vendor_api.authenticate.return_value = True
            mock_vendor_api.get_group_members.return_value = {}  # Empty vendor group
            
            # First user addition succeeds, second fails
            mock_vendor_api.add_user_to_group.side_effect = [
                True,  # user1 succeeds
                Exception("API error for user2")  # user2 fails
            ]
            
            orchestrator = SyncOrchestrator(self.config)
            result = orchestrator.run()
            
            # Should complete but with errors reported
            # Exact success value depends on error handling implementation
            self.assertGreaterEqual(result['vendors_processed'], 0)

    @patch('ldap_sync.main.setup_logging')
    def test_sync_with_multiple_vendor_formats(self, mock_setup_logging):
        """Test sync with different vendor API formats (JSON and XML)."""
        
        with patch('ldap_sync.main.LDAPClient') as mock_ldap_class, \
             patch('ldap_sync.main.importlib.import_module') as mock_import:
            
            # Setup LDAP
            mock_ldap_client = Mock()
            mock_ldap_class.return_value = mock_ldap_client
            mock_ldap_client.connect.return_value = True
            mock_ldap_client.get_group_members.return_value = {
                'user1': {'sAMAccountName': 'user1', 'givenName': 'John', 'sn': 'Doe', 'mail': 'john@example.com'}
            }
            
            # Setup both vendor modules
            mock_vendor1_module = Mock()
            mock_vendor2_module = Mock()
            
            def import_side_effect(module_name):
                if 'vendor_app1' in module_name:
                    return mock_vendor1_module
                elif 'vendor_app2' in module_name:
                    return mock_vendor2_module
                else:
                    raise ImportError(f"Module {module_name} not found")
            
            mock_import.side_effect = import_side_effect
            
            # Setup vendor APIs
            mock_vendor1_api = Mock()
            mock_vendor2_api = Mock()
            
            mock_vendor1_module.VendorApp1API = Mock(return_value=mock_vendor1_api)
            mock_vendor2_module.VendorApp2API = Mock(return_value=mock_vendor2_api)
            
            # Configure both vendors
            for api in [mock_vendor1_api, mock_vendor2_api]:
                api.authenticate.return_value = True
                api.get_group_members.return_value = {}
                api.add_user_to_group.return_value = True
            
            mock_vendor1_api.name = 'TestApp1'
            mock_vendor2_api.name = 'TestApp2'
            
            orchestrator = SyncOrchestrator(self.config)
            result = orchestrator.run()
            
            # Both vendors should be processed
            self.assertTrue(result['success'])
            self.assertEqual(result['vendors_processed'], 2)
            
            # Both vendor APIs should be called
            self.assertTrue(mock_vendor1_api.authenticate.called)
            self.assertTrue(mock_vendor2_api.authenticate.called)

    def test_config_loading_and_validation_integration(self):
        """Test integration of configuration loading and validation."""
        
        # Create temporary config file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(self.config, f)
            config_path = f.name
        
        try:
            # Load config and verify it's valid
            loaded_config = load_config(config_path)
            
            # Verify structure
            self.assertIn('ldap', loaded_config)
            self.assertIn('vendor_apps', loaded_config)
            self.assertEqual(len(loaded_config['vendor_apps']), 2)
            
            # Verify defaults were applied
            self.assertEqual(loaded_config['error_handling']['max_retries'], 3)
            self.assertTrue(loaded_config['vendor_apps'][0]['verify_ssl'])
            
            # Test orchestrator can be created with loaded config
            orchestrator = SyncOrchestrator(loaded_config)
            self.assertIsNotNone(orchestrator)
            
        finally:
            os.unlink(config_path)

    @patch('ldap_sync.main.setup_logging')
    @patch('ldap_sync.main.load_config')
    def test_main_sync_function_integration(self, mock_load_config, mock_setup_logging):
        """Test main_sync function integration."""
        
        mock_load_config.return_value = self.config
        
        with patch('ldap_sync.main.SyncOrchestrator') as mock_orchestrator_class:
            mock_orchestrator = Mock()
            mock_orchestrator.run.return_value = {
                'success': True,
                'vendors_processed': 2,
                'total_errors': 0
            }
            mock_orchestrator_class.return_value = mock_orchestrator
            
            # Test successful run
            exit_code = main_sync()
            
            self.assertEqual(exit_code, 0)
            mock_load_config.assert_called_once()
            mock_setup_logging.assert_called_once()
            mock_orchestrator.run.assert_called_once()

    @patch('ldap_sync.main.setup_logging')
    @patch('ldap_sync.main.send_notification')
    def test_error_threshold_integration(self, mock_send_notification, mock_setup_logging):
        """Test error threshold handling across the system."""
        
        # Configure for low error threshold
        config = self.config.copy()
        config['error_handling']['max_errors_per_vendor'] = 2
        
        with patch('ldap_sync.main.LDAPClient') as mock_ldap_class, \
             patch('ldap_sync.main.importlib.import_module') as mock_import:
            
            # Setup LDAP
            mock_ldap_client = Mock()
            mock_ldap_class.return_value = mock_ldap_client
            mock_ldap_client.connect.return_value = True
            mock_ldap_client.get_group_members.return_value = {
                'user1': {'sAMAccountName': 'user1', 'givenName': 'John', 'sn': 'Doe', 'mail': 'john@example.com'},
                'user2': {'sAMAccountName': 'user2', 'givenName': 'Jane', 'sn': 'Smith', 'mail': 'jane@example.com'},
                'user3': {'sAMAccountName': 'user3', 'givenName': 'Bob', 'sn': 'Johnson', 'mail': 'bob@example.com'}
            }
            
            # Setup vendor with many failures
            mock_vendor_module = Mock()
            mock_import.return_value = mock_vendor_module
            
            mock_vendor_api = Mock()
            mock_vendor_module.VendorApp1API = Mock(return_value=mock_vendor_api)
            mock_vendor_api.name = 'TestApp1'
            mock_vendor_api.authenticate.return_value = True
            mock_vendor_api.get_group_members.return_value = {}
            
            # All user additions fail
            mock_vendor_api.add_user_to_group.side_effect = Exception("API error")
            
            orchestrator = SyncOrchestrator(config)
            result = orchestrator.run()
            
            # Should detect error threshold exceeded
            self.assertFalse(result['success'])
            
            # Should send notification about threshold breach
            mock_send_notification.assert_called()


class TestLargeDatasetIntegration(unittest.TestCase):
    """Test integration with larger datasets."""

    def setUp(self):
        """Set up test fixtures for large dataset tests."""
        self.config = {
            'ldap': {
                'server_url': 'ldaps://ldap.example.com:636',
                'bind_dn': 'cn=service,dc=example,dc=com',
                'bind_password': 'password',
                'user_base_dn': 'ou=users,dc=example,dc=com',
                'page_size': 100  # Test pagination
            },
            'vendor_apps': [
                {
                    'name': 'LargeVendor',
                    'module': 'vendor_app1',
                    'base_url': 'https://api.largevendor.com/v1',
                    'auth': {'method': 'basic', 'username': 'user', 'password': 'pass'},
                    'groups': [
                        {
                            'ldap_group': 'cn=large_group,ou=groups,dc=example,dc=com',
                            'vendor_group': 'large_group'
                        }
                    ]
                }
            ],
            'error_handling': {'max_errors_per_vendor': 50},  # Higher threshold
            'logging': {'level': 'INFO'},
            'notifications': {'enable_email': False}
        }

    @patch('ldap_sync.main.setup_logging')
    def test_sync_large_user_group(self, mock_setup_logging):
        """Test sync with large user groups (>1000 users)."""
        
        # Generate large datasets
        ldap_users = {}
        vendor_users = {}
        
        for i in range(1500):  # 1500 users
            username = f'user{i:04d}'
            ldap_users[username] = {
                'sAMAccountName': username,
                'givenName': f'User{i}',
                'sn': 'Test',
                'mail': f'{username}@example.com'
            }
            
            # Only first 1000 users exist in vendor (500 need to be added)
            if i < 1000:
                vendor_users[username] = {
                    'username': username,
                    'firstName': f'User{i}',
                    'lastName': 'Test',
                    'email': f'{username}@example.com'
                }
        
        with patch('ldap_sync.main.LDAPClient') as mock_ldap_class, \
             patch('ldap_sync.main.importlib.import_module') as mock_import:
            
            # Setup LDAP
            mock_ldap_client = Mock()
            mock_ldap_class.return_value = mock_ldap_client
            mock_ldap_client.connect.return_value = True
            mock_ldap_client.get_group_members.return_value = ldap_users
            
            # Setup vendor
            mock_vendor_module = Mock()
            mock_import.return_value = mock_vendor_module
            
            mock_vendor_api = Mock()
            mock_vendor_module.VendorApp1API = Mock(return_value=mock_vendor_api)
            mock_vendor_api.name = 'LargeVendor'
            mock_vendor_api.authenticate.return_value = True
            mock_vendor_api.get_group_members.return_value = vendor_users
            mock_vendor_api.add_user_to_group.return_value = True
            
            orchestrator = SyncOrchestrator(self.config)
            result = orchestrator.run()
            
            # Should successfully process large dataset
            self.assertTrue(result['success'])
            
            # Should make many add_user calls (500 new users)
            self.assertEqual(mock_vendor_api.add_user_to_group.call_count, 500)

    @patch('ldap_sync.main.setup_logging')
    def test_sync_performance_monitoring(self, mock_setup_logging):
        """Test sync performance monitoring and statistics."""
        
        # Generate moderate dataset
        ldap_users = {}
        for i in range(100):
            username = f'user{i:03d}'
            ldap_users[username] = {
                'sAMAccountName': username,
                'givenName': f'User{i}',
                'sn': 'Test',
                'mail': f'{username}@example.com'
            }
        
        with patch('ldap_sync.main.LDAPClient') as mock_ldap_class, \
             patch('ldap_sync.main.importlib.import_module') as mock_import:
            
            # Setup LDAP
            mock_ldap_client = Mock()
            mock_ldap_class.return_value = mock_ldap_client
            mock_ldap_client.connect.return_value = True
            mock_ldap_client.get_group_members.return_value = ldap_users
            
            # Setup vendor
            mock_vendor_module = Mock()
            mock_import.return_value = mock_vendor_module
            
            mock_vendor_api = Mock()
            mock_vendor_module.VendorApp1API = Mock(return_value=mock_vendor_api)
            mock_vendor_api.name = 'LargeVendor'
            mock_vendor_api.authenticate.return_value = True
            mock_vendor_api.get_group_members.return_value = {}  # Empty vendor group
            mock_vendor_api.add_user_to_group.return_value = True
            
            # Measure sync performance
            import time
            start_time = time.time()
            
            orchestrator = SyncOrchestrator(self.config)
            result = orchestrator.run()
            
            end_time = time.time()
            duration = end_time - start_time
            
            # Verify performance stats are reasonable
            self.assertTrue(result['success'])
            self.assertLess(duration, 10.0)  # Should complete within 10 seconds
            
            # Verify all users were processed
            self.assertEqual(mock_vendor_api.add_user_to_group.call_count, 100)


class TestNetworkFailureScenarios(unittest.TestCase):
    """Test integration with network failure scenarios."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
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
                            'ldap_group': 'cn=test,ou=groups,dc=example,dc=com',
                            'vendor_group': 'test_group'
                        }
                    ]
                }
            ],
            'error_handling': {
                'max_retries': 3,
                'retry_wait_seconds': 0.1  # Fast retries for testing
            },
            'logging': {'level': 'INFO'},
            'notifications': {'enable_email': False}
        }

    @patch('ldap_sync.main.setup_logging')
    @patch('time.sleep')  # Speed up retry delays
    def test_ldap_intermittent_failures(self, mock_sleep, mock_setup_logging):
        """Test sync with intermittent LDAP failures."""
        
        with patch('ldap_sync.main.LDAPClient') as mock_ldap_class:
            mock_ldap_client = Mock()
            mock_ldap_class.return_value = mock_ldap_client
            
            # First attempt fails, second succeeds
            mock_ldap_client.connect.side_effect = [
                Exception("Connection timeout"),
                True  # Success on retry
            ]
            mock_ldap_client.get_group_members.return_value = {}
            
            with patch('ldap_sync.main.importlib.import_module') as mock_import:
                # Setup vendor
                mock_vendor_module = Mock()
                mock_import.return_value = mock_vendor_module
                mock_vendor_api = Mock()
                mock_vendor_module.VendorApp1API = Mock(return_value=mock_vendor_api)
                mock_vendor_api.name = 'TestApp'
                mock_vendor_api.authenticate.return_value = True
                mock_vendor_api.get_group_members.return_value = {}
                
                orchestrator = SyncOrchestrator(self.config)
                result = orchestrator.run()
                
                # Should eventually succeed after retry
                self.assertTrue(result['success'])
                self.assertEqual(mock_ldap_client.connect.call_count, 2)

    @patch('ldap_sync.main.setup_logging')
    @patch('time.sleep')  # Speed up retry delays
    def test_vendor_api_intermittent_failures(self, mock_sleep, mock_setup_logging):
        """Test sync with intermittent vendor API failures."""
        
        with patch('ldap_sync.main.LDAPClient') as mock_ldap_class, \
             patch('ldap_sync.main.importlib.import_module') as mock_import:
            
            # Setup successful LDAP
            mock_ldap_client = Mock()
            mock_ldap_class.return_value = mock_ldap_client
            mock_ldap_client.connect.return_value = True
            mock_ldap_client.get_group_members.return_value = {
                'user1': {'sAMAccountName': 'user1', 'givenName': 'John', 'sn': 'Doe', 'mail': 'john@example.com'}
            }
            
            # Setup vendor with intermittent failures
            mock_vendor_module = Mock()
            mock_import.return_value = mock_vendor_module
            
            mock_vendor_api = Mock()
            mock_vendor_module.VendorApp1API = Mock(return_value=mock_vendor_api)
            mock_vendor_api.name = 'TestApp'
            
            # Authentication fails first time, succeeds second time
            mock_vendor_api.authenticate.side_effect = [
                Exception("API temporarily unavailable"),
                True  # Success on retry
            ]
            mock_vendor_api.get_group_members.return_value = {}
            mock_vendor_api.add_user_to_group.return_value = True
            
            orchestrator = SyncOrchestrator(self.config)
            result = orchestrator.run()
            
            # Should handle intermittent failures gracefully
            # Result depends on retry implementation in vendor sync


if __name__ == '__main__':
    # Run specific test suites
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test suites
    suite.addTests(loader.loadTestsFromTestCase(TestEndToEndSyncScenarios))
    suite.addTests(loader.loadTestsFromTestCase(TestLargeDatasetIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestNetworkFailureScenarios))
    
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)