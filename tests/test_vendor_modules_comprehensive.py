#!/usr/bin/env python3
"""
Comprehensive unit tests for individual vendor modules.
"""

import os
import sys
import unittest
import json
from unittest.mock import Mock, patch, MagicMock
from http.client import HTTPResponse

# Add the project directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ldap_sync.vendors.vendor_app1 import VendorApp1API
from ldap_sync.vendors.vendor_app2 import VendorApp2API
from ldap_sync.vendors.base import VendorAPIError


class TestVendorApp1API(unittest.TestCase):
    """Test cases for VendorApp1API class."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            'name': 'VendorApp1',
            'base_url': 'https://api.vendorapp1.com/v1',
            'auth': {
                'method': 'basic',
                'username': 'testuser',
                'password': 'testpass'
            },
            'format': 'json',
            'verify_ssl': True,
            'timeout': 30
        }

    def test_initialization(self):
        """Test VendorApp1API initialization."""
        api = VendorApp1API(self.config)
        
        self.assertEqual(api.name, 'VendorApp1')
        self.assertEqual(api.base_url, 'https://api.vendorapp1.com/v1')
        self.assertEqual(api.auth_method, 'basic')
        self.assertEqual(api.format, 'json')

    @patch.object(VendorApp1API, '_make_request')
    def test_get_group_members_success(self, mock_request):
        """Test successful group member retrieval."""
        mock_response = {
            'status_code': 200,
            'data': {
                'members': [
                    {
                        'id': 'user1',
                        'username': 'user1',
                        'firstName': 'User',
                        'lastName': 'One',
                        'email': 'user1@example.com'
                    },
                    {
                        'id': 'user2',
                        'username': 'user2',
                        'firstName': 'User',
                        'lastName': 'Two',
                        'email': 'user2@example.com'
                    }
                ]
            }
        }
        mock_request.return_value = mock_response
        
        api = VendorApp1API(self.config)
        group_config = {'vendor_group': 'test_group'}
        
        members = api.get_group_members(group_config)
        
        self.assertEqual(len(members), 2)
        self.assertIn('user1', members)
        self.assertIn('user2', members)
        
        user1 = members['user1']
        self.assertEqual(user1['firstName'], 'User')
        self.assertEqual(user1['lastName'], 'One')
        self.assertEqual(user1['email'], 'user1@example.com')
        
        mock_request.assert_called_once_with('GET', '/groups/test_group/members')

    @patch.object(VendorApp1API, '_make_request')
    def test_get_group_members_empty_group(self, mock_request):
        """Test group member retrieval for empty group."""
        mock_response = {
            'status_code': 200,
            'data': {'members': []}
        }
        mock_request.return_value = mock_response
        
        api = VendorApp1API(self.config)
        group_config = {'vendor_group': 'empty_group'}
        
        members = api.get_group_members(group_config)
        
        self.assertEqual(len(members), 0)
        self.assertIsInstance(members, dict)

    @patch.object(VendorApp1API, '_make_request')
    def test_get_group_members_group_not_found(self, mock_request):
        """Test group member retrieval for non-existent group."""
        mock_request.side_effect = VendorAPIError("Group not found", 404)
        
        api = VendorApp1API(self.config)
        group_config = {'vendor_group': 'nonexistent_group'}
        
        with self.assertRaises(VendorAPIError):
            api.get_group_members(group_config)

    @patch.object(VendorApp1API, '_make_request')
    def test_add_user_to_group_new_user(self, mock_request):
        """Test adding a new user to a group."""
        # Mock responses for user creation and group assignment
        mock_responses = [
            # First call: create user
            {
                'status_code': 201,
                'data': {
                    'id': 'user123',
                    'username': 'newuser',
                    'firstName': 'New',
                    'lastName': 'User',
                    'email': 'newuser@example.com'
                }
            },
            # Second call: add to group
            {
                'status_code': 200,
                'data': {'success': True}
            }
        ]
        mock_request.side_effect = mock_responses
        
        api = VendorApp1API(self.config)
        group_config = {'vendor_group': 'test_group'}
        user_info = {
            'sAMAccountName': 'newuser',
            'givenName': 'New',
            'sn': 'User',
            'mail': 'newuser@example.com'
        }
        
        result = api.add_user_to_group(group_config, user_info)
        
        self.assertTrue(result)
        self.assertEqual(mock_request.call_count, 2)
        
        # Verify user creation call
        create_call = mock_request.call_args_list[0]
        self.assertEqual(create_call[0][0], 'POST')
        self.assertEqual(create_call[0][1], '/users')
        
        # Verify group assignment call
        assign_call = mock_request.call_args_list[1]
        self.assertEqual(assign_call[0][0], 'POST')
        self.assertEqual(assign_call[0][1], '/groups/test_group/members')

    @patch.object(VendorApp1API, '_make_request')
    def test_add_user_to_group_existing_user(self, mock_request):
        """Test adding an existing user to a group."""
        # Mock user creation conflict and successful group assignment
        mock_responses = [
            # First call: user already exists
            VendorAPIError("User already exists", 409),
            # Second call: get existing user
            {
                'status_code': 200,
                'data': {
                    'id': 'user123',
                    'username': 'existinguser',
                    'firstName': 'Existing',
                    'lastName': 'User',
                    'email': 'existinguser@example.com'
                }
            },
            # Third call: add to group
            {
                'status_code': 200,
                'data': {'success': True}
            }
        ]
        
        def side_effect(*args, **kwargs):
            if len(mock_request.call_args_list) == 0:
                raise mock_responses[0]
            else:
                return mock_responses[len(mock_request.call_args_list)]
        
        mock_request.side_effect = side_effect
        
        api = VendorApp1API(self.config)
        group_config = {'vendor_group': 'test_group'}
        user_info = {
            'sAMAccountName': 'existinguser',
            'givenName': 'Existing',
            'sn': 'User',
            'mail': 'existinguser@example.com'
        }
        
        result = api.add_user_to_group(group_config, user_info)
        
        self.assertTrue(result)
        self.assertEqual(mock_request.call_count, 3)

    @patch.object(VendorApp1API, '_make_request')
    def test_remove_user_from_group_success(self, mock_request):
        """Test successful user removal from group."""
        mock_response = {
            'status_code': 200,
            'data': {'success': True}
        }
        mock_request.return_value = mock_response
        
        api = VendorApp1API(self.config)
        group_config = {'vendor_group': 'test_group'}
        user_identifier = 'user123'
        
        result = api.remove_user_from_group(group_config, user_identifier)
        
        self.assertTrue(result)
        mock_request.assert_called_once_with('DELETE', '/groups/test_group/members/user123')

    @patch.object(VendorApp1API, '_make_request')
    def test_remove_user_from_group_user_not_found(self, mock_request):
        """Test user removal when user is not in group."""
        mock_request.side_effect = VendorAPIError("User not found in group", 404)
        
        api = VendorApp1API(self.config)
        group_config = {'vendor_group': 'test_group'}
        user_identifier = 'nonexistent_user'
        
        # Should not raise exception for 404 (user already not in group)
        result = api.remove_user_from_group(group_config, user_identifier)
        self.assertTrue(result)

    @patch.object(VendorApp1API, '_make_request')
    def test_update_user_success(self, mock_request):
        """Test successful user update."""
        mock_response = {
            'status_code': 200,
            'data': {
                'id': 'user123',
                'username': 'user123',
                'firstName': 'Updated',
                'lastName': 'Name',
                'email': 'updated@example.com'
            }
        }
        mock_request.return_value = mock_response
        
        api = VendorApp1API(self.config)
        user_identifier = 'user123'
        user_info = {
            'givenName': 'Updated',
            'sn': 'Name',
            'mail': 'updated@example.com'
        }
        
        result = api.update_user(user_identifier, user_info)
        
        self.assertTrue(result)
        mock_request.assert_called_once_with('PUT', '/users/user123', data={
            'firstName': 'Updated',
            'lastName': 'Name',
            'email': 'updated@example.com'
        })

    @patch.object(VendorApp1API, '_make_request')
    def test_update_user_not_found(self, mock_request):
        """Test user update when user doesn't exist."""
        mock_request.side_effect = VendorAPIError("User not found", 404)
        
        api = VendorApp1API(self.config)
        user_identifier = 'nonexistent_user'
        user_info = {'givenName': 'Test'}
        
        with self.assertRaises(VendorAPIError):
            api.update_user(user_identifier, user_info)

    def test_map_ldap_to_vendor_attributes(self):
        """Test LDAP to vendor attribute mapping."""
        api = VendorApp1API(self.config)
        
        ldap_data = {
            'sAMAccountName': 'testuser',
            'givenName': 'Test',
            'sn': 'User',
            'mail': 'test@example.com'
        }
        
        vendor_data = api._map_ldap_to_vendor(ldap_data)
        
        self.assertEqual(vendor_data['username'], 'testuser')
        self.assertEqual(vendor_data['firstName'], 'Test')
        self.assertEqual(vendor_data['lastName'], 'User')
        self.assertEqual(vendor_data['email'], 'test@example.com')

    def test_map_vendor_to_standard_attributes(self):
        """Test vendor to standard attribute mapping."""
        api = VendorApp1API(self.config)
        
        vendor_data = {
            'id': 'user123',
            'username': 'testuser',
            'firstName': 'Test',
            'lastName': 'User',
            'email': 'test@example.com'
        }
        
        standard_data = api._map_vendor_to_standard(vendor_data)
        
        self.assertEqual(standard_data['sAMAccountName'], 'testuser')
        self.assertEqual(standard_data['givenName'], 'Test')
        self.assertEqual(standard_data['sn'], 'User')
        self.assertEqual(standard_data['mail'], 'test@example.com')


class TestVendorApp2API(unittest.TestCase):
    """Test cases for VendorApp2API class."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            'name': 'VendorApp2',
            'base_url': 'https://api.vendorapp2.com/rest',
            'auth': {
                'method': 'token',
                'token': 'abc123def456'
            },
            'format': 'xml',
            'verify_ssl': True,
            'timeout': 30
        }

    def test_initialization(self):
        """Test VendorApp2API initialization."""
        api = VendorApp2API(self.config)
        
        self.assertEqual(api.name, 'VendorApp2')
        self.assertEqual(api.base_url, 'https://api.vendorapp2.com/rest')
        self.assertEqual(api.auth_method, 'token')
        self.assertEqual(api.format, 'xml')

    @patch.object(VendorApp2API, '_make_request')
    def test_get_group_members_success(self, mock_request):
        """Test successful group member retrieval with XML response."""
        mock_response = {
            'status_code': 200,
            'data': {
                'group': {
                    'member': [
                        {
                            'userId': 'user1',
                            'username': 'user1',
                            'firstName': 'User',
                            'lastName': 'One',
                            'emailAddress': 'user1@example.com'
                        },
                        {
                            'userId': 'user2', 
                            'username': 'user2',
                            'firstName': 'User',
                            'lastName': 'Two',
                            'emailAddress': 'user2@example.com'
                        }
                    ]
                }
            }
        }
        mock_request.return_value = mock_response
        
        api = VendorApp2API(self.config)
        group_config = {'vendor_group': 'test_group_id'}
        
        members = api.get_group_members(group_config)
        
        self.assertEqual(len(members), 2)
        self.assertIn('user1', members)
        self.assertIn('user2', members)
        
        user1 = members['user1']
        self.assertEqual(user1['givenName'], 'User')
        self.assertEqual(user1['sn'], 'One')
        self.assertEqual(user1['mail'], 'user1@example.com')

    @patch.object(VendorApp2API, '_make_request')
    def test_get_group_members_single_member(self, mock_request):
        """Test group member retrieval with single member (not a list)."""
        mock_response = {
            'status_code': 200,
            'data': {
                'group': {
                    'member': {
                        'userId': 'user1',
                        'username': 'user1',
                        'firstName': 'Only',
                        'lastName': 'User',
                        'emailAddress': 'only@example.com'
                    }
                }
            }
        }
        mock_request.return_value = mock_response
        
        api = VendorApp2API(self.config)
        group_config = {'vendor_group': 'test_group_id'}
        
        members = api.get_group_members(group_config)
        
        self.assertEqual(len(members), 1)
        self.assertIn('user1', members)

    @patch.object(VendorApp2API, '_make_request')
    def test_add_user_to_group_success(self, mock_request):
        """Test successful user addition to group."""
        mock_responses = [
            # User creation
            {
                'status_code': 201,
                'data': {
                    'user': {
                        'userId': 'user123',
                        'username': 'newuser',
                        'firstName': 'New',
                        'lastName': 'User',
                        'emailAddress': 'newuser@example.com'
                    }
                }
            },
            # Group assignment
            {
                'status_code': 200,
                'data': {'result': 'success'}
            }
        ]
        mock_request.side_effect = mock_responses
        
        api = VendorApp2API(self.config)
        group_config = {'vendor_group': 'test_group_id'}
        user_info = {
            'sAMAccountName': 'newuser',
            'givenName': 'New',
            'sn': 'User',
            'mail': 'newuser@example.com'
        }
        
        result = api.add_user_to_group(group_config, user_info)
        
        self.assertTrue(result)
        self.assertEqual(mock_request.call_count, 2)

    @patch.object(VendorApp2API, '_make_request')
    def test_remove_user_from_group_success(self, mock_request):
        """Test successful user removal from group."""
        mock_response = {
            'status_code': 200,
            'data': {'result': 'success'}
        }
        mock_request.return_value = mock_response
        
        api = VendorApp2API(self.config)
        group_config = {'vendor_group': 'test_group_id'}
        user_identifier = 'user123'
        
        result = api.remove_user_from_group(group_config, user_identifier)
        
        self.assertTrue(result)
        mock_request.assert_called_once_with('DELETE', '/group/test_group_id/member/user123')

    @patch.object(VendorApp2API, '_make_request')
    def test_update_user_success(self, mock_request):
        """Test successful user update."""
        mock_response = {
            'status_code': 200,
            'data': {
                'user': {
                    'userId': 'user123',
                    'username': 'user123',
                    'firstName': 'Updated',
                    'lastName': 'Name',
                    'emailAddress': 'updated@example.com'
                }
            }
        }
        mock_request.return_value = mock_response
        
        api = VendorApp2API(self.config)
        user_identifier = 'user123'
        user_info = {
            'givenName': 'Updated',
            'sn': 'Name',
            'mail': 'updated@example.com'
        }
        
        result = api.update_user(user_identifier, user_info)
        
        self.assertTrue(result)

    def test_map_ldap_to_vendor_attributes(self):
        """Test LDAP to vendor attribute mapping for VendorApp2."""
        api = VendorApp2API(self.config)
        
        ldap_data = {
            'sAMAccountName': 'testuser',
            'givenName': 'Test',
            'sn': 'User', 
            'mail': 'test@example.com'
        }
        
        vendor_data = api._map_ldap_to_vendor(ldap_data)
        
        self.assertEqual(vendor_data['username'], 'testuser')
        self.assertEqual(vendor_data['firstName'], 'Test')
        self.assertEqual(vendor_data['lastName'], 'User')
        self.assertEqual(vendor_data['emailAddress'], 'test@example.com')

    def test_map_vendor_to_standard_attributes(self):
        """Test vendor to standard attribute mapping for VendorApp2."""
        api = VendorApp2API(self.config)
        
        vendor_data = {
            'userId': 'user123',
            'username': 'testuser',
            'firstName': 'Test',
            'lastName': 'User',
            'emailAddress': 'test@example.com'
        }
        
        standard_data = api._map_vendor_to_standard(vendor_data)
        
        self.assertEqual(standard_data['sAMAccountName'], 'testuser')
        self.assertEqual(standard_data['givenName'], 'Test')
        self.assertEqual(standard_data['sn'], 'User')
        self.assertEqual(standard_data['mail'], 'test@example.com')

    @patch.object(VendorApp2API, '_make_request')
    def test_error_handling_with_xml_error_response(self, mock_request):
        """Test error handling with XML error response."""
        mock_request.side_effect = VendorAPIError("XML error response", 400)
        
        api = VendorApp2API(self.config)
        group_config = {'vendor_group': 'test_group'}
        
        with self.assertRaises(VendorAPIError):
            api.get_group_members(group_config)

    def test_xml_response_handling_edge_cases(self):
        """Test XML response handling edge cases."""
        api = VendorApp2API(self.config)
        
        # Test with None data
        result = api._handle_xml_response_format(None)
        self.assertEqual(result, {})
        
        # Test with empty dict
        result = api._handle_xml_response_format({})
        self.assertEqual(result, {})


class TestVendorModuleIntegration(unittest.TestCase):
    """Integration tests for vendor modules."""

    def test_vendor_module_compatibility(self):
        """Test that both vendor modules implement the same interface."""
        config1 = {
            'name': 'VendorApp1',
            'base_url': 'https://api.vendorapp1.com/v1',
            'auth': {'method': 'basic', 'username': 'user', 'password': 'pass'},
            'format': 'json'
        }
        
        config2 = {
            'name': 'VendorApp2',
            'base_url': 'https://api.vendorapp2.com/rest',
            'auth': {'method': 'token', 'token': 'token123'},
            'format': 'xml'
        }
        
        api1 = VendorApp1API(config1)
        api2 = VendorApp2API(config2)
        
        # Both should have the same interface methods
        required_methods = [
            'get_group_members',
            'add_user_to_group', 
            'remove_user_from_group',
            'update_user',
            'authenticate'
        ]
        
        for method in required_methods:
            self.assertTrue(hasattr(api1, method))
            self.assertTrue(hasattr(api2, method))
            self.assertTrue(callable(getattr(api1, method)))
            self.assertTrue(callable(getattr(api2, method)))

    def test_vendor_stats_compatibility(self):
        """Test that both vendor modules provide connection stats."""
        config1 = {
            'name': 'VendorApp1',
            'base_url': 'https://api.vendorapp1.com/v1',
            'auth': {'method': 'basic', 'username': 'user', 'password': 'pass'},
            'format': 'json'
        }
        
        config2 = {
            'name': 'VendorApp2',
            'base_url': 'https://api.vendorapp2.com/rest',
            'auth': {'method': 'token', 'token': 'token123'},
            'format': 'xml'
        }
        
        api1 = VendorApp1API(config1)
        api2 = VendorApp2API(config2)
        
        stats1 = api1.get_connection_stats()
        stats2 = api2.get_connection_stats()
        
        # Both should have basic stats
        required_keys = ['name', 'base_url', 'auth_method', 'format']
        
        for key in required_keys:
            self.assertIn(key, stats1)
            self.assertIn(key, stats2)
        
        # Verify specific values
        self.assertEqual(stats1['name'], 'VendorApp1')
        self.assertEqual(stats1['format'], 'json')
        self.assertEqual(stats2['name'], 'VendorApp2')
        self.assertEqual(stats2['format'], 'xml')


if __name__ == '__main__':
    unittest.main()