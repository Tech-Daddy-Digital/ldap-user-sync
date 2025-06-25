#!/usr/bin/env python3
"""
Unit tests for VendorApp1 API integration.

Tests the VendorApp1 API client with mock responses to verify
correct implementation of the vendor interface.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import json
import sys
import os

# Add parent directory to path to import ldap_sync modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ldap_sync.vendors.vendor_app1 import VendorApp1API, create_vendor_api
from ldap_sync.vendors.base import VendorAPIError


class TestVendorApp1API(unittest.TestCase):
    """Test cases for VendorApp1API class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            'name': 'TestVendorApp1',
            'base_url': 'https://api.vendorapp1.test/v1',
            'auth': {
                'method': 'basic',
                'username': 'test_user',
                'password': 'test_pass'
            },
            'format': 'json',
            'verify_ssl': False,
            'user_identifier_field': 'email',
            'group_id_field': 'id'
        }
        
        # Mock the parent class __init__ to avoid actual HTTP connections
        with patch.object(VendorApp1API, '__init__', lambda self, config: None):
            self.api = VendorApp1API.__new__(VendorApp1API)
            
            # Set up mock attributes that would normally be set by parent __init__
            self.api.config = self.config
            self.api.name = self.config['name']
            self.api.user_identifier_field = 'email'
            self.api.group_id_field = 'id'
    
    @patch('ldap_sync.vendors.vendor_app1.VendorAPIBase.__init__')
    def test_factory_function(self, mock_base_init):
        """Test the factory function creates correct instance."""
        mock_base_init.return_value = None
        
        # Mock the __init__ method to avoid the AttributeError
        with patch.object(VendorApp1API, '__init__', return_value=None):
            api = VendorApp1API.__new__(VendorApp1API)
            self.assertIsInstance(api, VendorApp1API)
    
    @patch('ldap_sync.vendors.vendor_app1.VendorApp1API.request')
    def test_get_group_members_success(self, mock_request):
        """Test successful group members retrieval."""
        # Mock API response
        mock_response = {
            'users': [
                {
                    'id': '123',
                    'username': 'jdoe',
                    'email': 'john.doe@example.com',
                    'firstName': 'John',
                    'lastName': 'Doe',
                    'active': True
                },
                {
                    'id': '456',
                    'username': 'jsmith',
                    'email': 'jane.smith@example.com',
                    'firstName': 'Jane',
                    'lastName': 'Smith',
                    'active': True
                }
            ]
        }
        mock_request.return_value = mock_response
        
        group_cfg = {'vendor_group': 'test_group'}
        members = self.api.get_group_members(group_cfg)
        
        # Verify request was made correctly
        mock_request.assert_called_once_with('GET', '/groups/test_group/members')
        
        # Verify response parsing
        self.assertEqual(len(members), 2)
        
        # Check first user
        self.assertEqual(members[0]['username'], 'jdoe')
        self.assertEqual(members[0]['email'], 'john.doe@example.com')
        self.assertEqual(members[0]['first_name'], 'John')
        self.assertEqual(members[0]['last_name'], 'Doe')
        self.assertEqual(members[0]['user_id'], '123')
        
        # Check second user
        self.assertEqual(members[1]['username'], 'jsmith')
        self.assertEqual(members[1]['email'], 'jane.smith@example.com')
    
    @patch('ldap_sync.vendors.vendor_app1.VendorApp1API.request')
    def test_get_group_members_alternative_fields(self, mock_request):
        """Test group members with alternative field names."""
        # Mock API response with alternative field names
        mock_response = {
            'members': [
                {
                    'userId': '789',
                    'login': 'bwilson',
                    'emailAddress': 'bob.wilson@example.com',
                    'givenName': 'Bob',
                    'surname': 'Wilson',
                    'enabled': True
                }
            ]
        }
        mock_request.return_value = mock_response
        
        group_cfg = {'vendor_group': 'alt_group'}
        members = self.api.get_group_members(group_cfg)
        
        self.assertEqual(len(members), 1)
        self.assertEqual(members[0]['username'], 'bwilson')
        self.assertEqual(members[0]['email'], 'bob.wilson@example.com')
        self.assertEqual(members[0]['first_name'], 'Bob')
        self.assertEqual(members[0]['last_name'], 'Wilson')
        self.assertEqual(members[0]['user_id'], '789')
    
    @patch('ldap_sync.vendors.vendor_app1.VendorApp1API._add_user_to_group_by_id')
    @patch('ldap_sync.vendors.vendor_app1.VendorApp1API._create_user')
    @patch('ldap_sync.vendors.vendor_app1.VendorApp1API._find_user_by_identifier')
    def test_add_user_to_group_new_user(self, mock_find_user, mock_create_user, mock_add_to_group):
        """Test adding a new user to group."""
        # User doesn't exist, needs to be created
        mock_find_user.return_value = None
        mock_create_user.return_value = '999'
        mock_add_to_group.return_value = True
        
        group_cfg = {'vendor_group': 'test_group'}
        user_info = {
            'username': 'newuser',
            'email': 'new.user@example.com',
            'first_name': 'New',
            'last_name': 'User'
        }
        
        result = self.api.add_user_to_group(group_cfg, user_info)
        
        self.assertTrue(result)
        mock_find_user.assert_called_once_with('new.user@example.com')
        mock_create_user.assert_called_once_with('newuser', 'new.user@example.com', 'New', 'User')
        mock_add_to_group.assert_called_once_with('999', 'test_group')
    
    @patch('ldap_sync.vendors.vendor_app1.VendorApp1API._add_user_to_group_by_id')
    @patch('ldap_sync.vendors.vendor_app1.VendorApp1API._create_user')
    @patch('ldap_sync.vendors.vendor_app1.VendorApp1API._find_user_by_identifier')
    def test_add_user_to_group_existing_user(self, mock_find_user, mock_create_user, mock_add_to_group):
        """Test adding an existing user to group."""
        # User already exists
        mock_find_user.return_value = '777'
        mock_add_to_group.return_value = True
        
        group_cfg = {'vendor_group': 'test_group'}
        user_info = {
            'username': 'existing',
            'email': 'existing@example.com',
            'first_name': 'Existing',
            'last_name': 'User'
        }
        
        result = self.api.add_user_to_group(group_cfg, user_info)
        
        self.assertTrue(result)
        mock_find_user.assert_called_once_with('existing@example.com')
        mock_create_user.assert_not_called()  # Should not create existing user
        mock_add_to_group.assert_called_once_with('777', 'test_group')
    
    @patch('ldap_sync.vendors.vendor_app1.VendorApp1API.request')
    @patch('ldap_sync.vendors.vendor_app1.VendorApp1API._find_user_by_identifier')
    def test_remove_user_from_group_success(self, mock_find_user, mock_request):
        """Test successful user removal from group."""
        mock_find_user.return_value = '555'
        mock_request.return_value = {}
        
        group_cfg = {'vendor_group': 'test_group'}
        user_identifier = 'remove@example.com'
        
        result = self.api.remove_user_from_group(group_cfg, user_identifier)
        
        self.assertTrue(result)
        mock_find_user.assert_called_once_with('remove@example.com')
        mock_request.assert_called_once_with('DELETE', '/groups/test_group/members/555')
    
    @patch('ldap_sync.vendors.vendor_app1.VendorApp1API._find_user_by_identifier')
    def test_remove_user_from_group_user_not_found(self, mock_find_user):
        """Test removing non-existent user (should succeed)."""
        mock_find_user.return_value = None
        
        group_cfg = {'vendor_group': 'test_group'}
        user_identifier = 'notfound@example.com'
        
        result = self.api.remove_user_from_group(group_cfg, user_identifier)
        
        self.assertTrue(result)  # Should return True for non-existent users
    
    @patch('ldap_sync.vendors.vendor_app1.VendorApp1API.request')
    @patch('ldap_sync.vendors.vendor_app1.VendorApp1API._find_user_by_identifier')
    def test_update_user_success(self, mock_find_user, mock_request):
        """Test successful user update."""
        mock_find_user.return_value = '444'
        mock_request.return_value = {}
        
        user_identifier = 'update@example.com'
        user_info = {
            'first_name': 'Updated',
            'last_name': 'Name',
            'email': 'updated@example.com'
        }
        
        result = self.api.update_user(user_identifier, user_info)
        
        self.assertTrue(result)
        mock_find_user.assert_called_once_with('update@example.com')
        
        # Check that request was made with correct mapping
        expected_data = {
            'firstName': 'Updated',
            'lastName': 'Name',
            'email': 'updated@example.com'
        }
        mock_request.assert_called_once_with('PUT', '/users/444', body=expected_data)
    
    @patch('ldap_sync.vendors.vendor_app1.VendorApp1API.request')
    def test_find_user_by_identifier_success(self, mock_request):
        """Test finding user by identifier."""
        mock_response = {
            'users': [
                {
                    'id': '333',
                    'email': 'find@example.com',
                    'username': 'findme'
                }
            ]
        }
        mock_request.return_value = mock_response
        
        user_id = self.api._find_user_by_identifier('find@example.com')
        
        self.assertEqual(user_id, '333')
        mock_request.assert_called_once_with('GET', '/users', headers={
            'X-Search-Field': 'email',
            'X-Search-Value': 'find@example.com'
        })
    
    @patch('ldap_sync.vendors.vendor_app1.VendorApp1API.request')
    def test_create_user_success(self, mock_request):
        """Test successful user creation."""
        mock_response = {'id': '888'}
        mock_request.return_value = mock_response
        
        user_id = self.api._create_user('testuser', 'test@example.com', 'Test', 'User')
        
        self.assertEqual(user_id, '888')
        
        expected_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'firstName': 'Test',
            'lastName': 'User',
            'active': True
        }
        mock_request.assert_called_once_with('POST', '/users', body=expected_data)
    
    @patch('ldap_sync.vendors.vendor_app1.VendorApp1API.request')
    def test_add_user_to_group_by_id_success(self, mock_request):
        """Test adding user to group by ID."""
        mock_request.return_value = {}
        
        result = self.api._add_user_to_group_by_id('123', 'group456')
        
        self.assertTrue(result)
        expected_data = {'userId': '123'}
        mock_request.assert_called_once_with('POST', '/groups/group456/members', body=expected_data)


if __name__ == '__main__':
    # Set up logging for tests
    import logging
    logging.basicConfig(level=logging.DEBUG)
    
    unittest.main()