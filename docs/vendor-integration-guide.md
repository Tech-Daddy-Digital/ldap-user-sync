# Vendor Integration Developer Guide

This guide provides comprehensive instructions for developers who need to integrate new vendor applications with the LDAP User Sync system.

## Overview

The LDAP User Sync application uses a plugin-based architecture that allows easy integration of new vendor applications without modifying the core synchronization logic. Each vendor integration is implemented as a Python module that extends the base `VendorAPIBase` class.

## Architecture Overview

### Plugin System
- Vendor integrations are dynamically loaded based on configuration
- Each vendor module implements a standardized interface
- The core sync engine calls vendor methods generically
- No changes to core code are required for new vendors

### Base Class Hierarchy
```
VendorAPIBase (Abstract)
├── VendorApp1API (Concrete Implementation)
├── VendorApp2API (Concrete Implementation)
└── YourVendorAPI (Your Implementation)
```

## Getting Started

### 1. Create Vendor Module

Create a new Python module in the `ldap_sync/vendors/` directory:

```bash
touch ldap_sync/vendors/your_vendor.py
```

### 2. Basic Module Structure

```python
"""
Your Vendor API Integration Module

This module provides integration with Your Vendor's REST API
for user and group management synchronization.
"""

import json
import logging
from typing import Dict, List, Optional, Any

from .base import VendorAPIBase

logger = logging.getLogger(__name__)


class YourVendorAPI(VendorAPIBase):
    """
    API client for Your Vendor Application
    
    Implements the required methods for LDAP user synchronization
    with Your Vendor's REST API endpoints.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the Your Vendor API client."""
        super().__init__(config)
        self.api_version = config.get('api_version', 'v1')
        
    def authenticate(self) -> bool:
        """Perform authentication if required."""
        # Implement vendor-specific authentication logic
        pass
        
    def get_group_members(self, group_cfg: Dict[str, str]) -> List[Dict[str, Any]]:
        """Get all members of a vendor group."""
        # Implement group member retrieval
        pass
        
    def add_user_to_group(self, group_cfg: Dict[str, str], user_info: Dict[str, Any]) -> bool:
        """Add a user to a vendor group."""
        # Implement user addition logic
        pass
        
    def remove_user_from_group(self, group_cfg: Dict[str, str], user_identifier: str) -> bool:
        """Remove a user from a vendor group."""
        # Implement user removal logic
        pass
        
    def update_user(self, user_identifier: str, user_info: Dict[str, Any]) -> bool:
        """Update user attributes in the vendor system."""
        # Implement user update logic
        pass
```

## VendorAPIBase Class Reference

### Inherited Properties and Methods

The base class provides common functionality that your implementation can use:

#### HTTP Client Methods
```python
# Make HTTP requests with automatic authentication
response = self.request('GET', '/api/users')
response = self.request('POST', '/api/users', data={'name': 'John'})
response = self.request('PUT', '/api/users/123', data={'email': 'new@email.com'})
response = self.request('DELETE', '/api/users/123')
```

#### Authentication Headers
```python
# Access prepared authentication headers
headers = self.get_auth_headers()
```

#### SSL Context
```python
# Pre-configured SSL context for HTTPS requests
ssl_context = self.ssl_context
```

#### Configuration Access
```python
# Access vendor configuration
base_url = self.config['base_url']
auth_method = self.config['auth']['method']
data_format = self.config.get('format', 'json')
```

## Required Method Implementations

### 1. authenticate()

Perform any required authentication setup:

```python
def authenticate(self) -> bool:
    """
    Perform authentication with the vendor API.
    
    Returns:
        bool: True if authentication successful, False otherwise
    """
    if self.config['auth']['method'] == 'oauth2':
        # OAuth2 token retrieval
        token_url = self.config['auth']['token_url']
        client_id = self.config['auth']['client_id']
        client_secret = self.config['auth']['client_secret']
        
        data = {
            'grant_type': 'client_credentials',
            'client_id': client_id,
            'client_secret': client_secret
        }
        
        try:
            response = self.request('POST', token_url, data=data, skip_auth=True)
            if response.get('access_token'):
                self.auth_token = response['access_token']
                logger.info("OAuth2 authentication successful")
                return True
            else:
                logger.error("OAuth2 authentication failed: No access token")
                return False
        except Exception as e:
            logger.error(f"OAuth2 authentication error: {e}")
            return False
    
    # For basic auth or token auth, no additional setup needed
    return True
```

### 2. get_group_members()

Retrieve all members of a vendor group:

```python
def get_group_members(self, group_cfg: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Get all members of a vendor group.
    
    Args:
        group_cfg: Group configuration containing vendor_group identifier
        
    Returns:
        List of user dictionaries with standardized keys:
        - username: User's unique identifier
        - email: User's email address
        - first_name: User's first name
        - last_name: User's last name
        - user_id: Vendor-specific user ID (if different from username)
    """
    vendor_group = group_cfg['vendor_group']
    
    try:
        # Example: GET /api/groups/{group_id}/members
        response = self.request('GET', f'/api/groups/{vendor_group}/members')
        
        # Handle pagination if needed
        all_members = []
        members = response.get('members', [])
        
        while members:
            for member in members:
                # Map vendor fields to standard format
                user_data = {
                    'username': member.get('username') or member.get('login'),
                    'email': member.get('email'),
                    'first_name': member.get('firstName') or member.get('first_name'),
                    'last_name': member.get('lastName') or member.get('last_name'),
                    'user_id': member.get('id', member.get('username'))
                }
                all_members.append(user_data)
            
            # Handle pagination
            if response.get('next_page'):
                response = self.request('GET', response['next_page'])
                members = response.get('members', [])
            else:
                break
        
        logger.info(f"Retrieved {len(all_members)} members from group {vendor_group}")
        return all_members
        
    except Exception as e:
        logger.error(f"Failed to get group members for {vendor_group}: {e}")
        raise
```

### 3. add_user_to_group()

Add a user to a vendor group:

```python
def add_user_to_group(self, group_cfg: Dict[str, str], user_info: Dict[str, Any]) -> bool:
    """
    Add a user to a vendor group.
    
    Args:
        group_cfg: Group configuration
        user_info: User information from LDAP
        
    Returns:
        bool: True if successful, False otherwise
    """
    vendor_group = group_cfg['vendor_group']
    
    try:
        # First, ensure user exists in vendor system
        user_id = self._ensure_user_exists(user_info)
        if not user_id:
            return False
        
        # Add user to group
        data = {
            'user_id': user_id,
            'group_id': vendor_group
        }
        
        response = self.request('POST', f'/api/groups/{vendor_group}/members', data=data)
        
        if response.get('success', True):  # Adjust based on API response format
            logger.info(f"Added user {user_info['username']} to group {vendor_group}")
            return True
        else:
            logger.error(f"API returned failure for adding user to group: {response}")
            return False
            
    except Exception as e:
        logger.error(f"Failed to add user {user_info.get('username')} to group {vendor_group}: {e}")
        return False

def _ensure_user_exists(self, user_info: Dict[str, Any]) -> Optional[str]:
    """
    Ensure user exists in vendor system, create if necessary.
    
    Returns:
        str: User ID if successful, None if failed
    """
    username = user_info['username']
    
    # Check if user exists
    try:
        response = self.request('GET', f'/api/users/{username}')
        if response.get('id'):
            return response['id']
    except Exception:
        pass  # User doesn't exist, create them
    
    # Create user
    user_data = {
        'username': username,
        'email': user_info['email'],
        'firstName': user_info['first_name'],
        'lastName': user_info['last_name'],
        'active': True
    }
    
    try:
        response = self.request('POST', '/api/users', data=user_data)
        user_id = response.get('id')
        if user_id:
            logger.info(f"Created user {username} with ID {user_id}")
            return user_id
        else:
            logger.error(f"Failed to create user {username}: {response}")
            return None
    except Exception as e:
        logger.error(f"Error creating user {username}: {e}")
        return None
```

### 4. remove_user_from_group()

Remove a user from a vendor group:

```python
def remove_user_from_group(self, group_cfg: Dict[str, str], user_identifier: str) -> bool:
    """
    Remove a user from a vendor group.
    
    Args:
        group_cfg: Group configuration
        user_identifier: User's identifier (username, email, or ID)
        
    Returns:
        bool: True if successful, False otherwise
    """
    vendor_group = group_cfg['vendor_group']
    
    try:
        # Get user ID if needed
        user_id = self._get_user_id(user_identifier)
        if not user_id:
            logger.warning(f"User {user_identifier} not found in vendor system")
            return True  # User already doesn't exist
        
        # Remove from group
        response = self.request('DELETE', f'/api/groups/{vendor_group}/members/{user_id}')
        
        # Check if removal was successful
        if response.get('success', True):
            logger.info(f"Removed user {user_identifier} from group {vendor_group}")
            return True
        else:
            logger.error(f"Failed to remove user from group: {response}")
            return False
            
    except Exception as e:
        logger.error(f"Error removing user {user_identifier} from group: {e}")
        return False

def _get_user_id(self, user_identifier: str) -> Optional[str]:
    """Get vendor user ID from username/email."""
    try:
        # Try by username first
        response = self.request('GET', f'/api/users/{user_identifier}')
        if response.get('id'):
            return response['id']
        
        # Try by email if username lookup failed
        response = self.request('GET', f'/api/users?email={user_identifier}')
        users = response.get('users', [])
        if users:
            return users[0].get('id')
        
        return None
    except Exception:
        return None
```

### 5. update_user()

Update user attributes in the vendor system:

```python
def update_user(self, user_identifier: str, user_info: Dict[str, Any]) -> bool:
    """
    Update user attributes in the vendor system.
    
    Args:
        user_identifier: User's identifier
        user_info: Updated user information from LDAP
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        user_id = self._get_user_id(user_identifier)
        if not user_id:
            logger.error(f"User {user_identifier} not found for update")
            return False
        
        # Prepare update data
        update_data = {
            'firstName': user_info.get('first_name'),
            'lastName': user_info.get('last_name'),
            'email': user_info.get('email')
        }
        
        # Remove None values
        update_data = {k: v for k, v in update_data.items() if v is not None}
        
        if not update_data:
            logger.info(f"No updates needed for user {user_identifier}")
            return True
        
        response = self.request('PUT', f'/api/users/{user_id}', data=update_data)
        
        if response.get('success', True):
            logger.info(f"Updated user {user_identifier}: {list(update_data.keys())}")
            return True
        else:
            logger.error(f"Failed to update user: {response}")
            return False
            
    except Exception as e:
        logger.error(f"Error updating user {user_identifier}: {e}")
        return False
```

## Advanced Features

### Handling Different Data Formats

#### JSON APIs
```python
def get_group_members(self, group_cfg: Dict[str, str]) -> List[Dict[str, Any]]:
    response = self.request('GET', f'/api/groups/{group_cfg["vendor_group"]}/members')
    return self._parse_json_members(response)

def _parse_json_members(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
    members = []
    for item in response.get('data', []):
        members.append({
            'username': item['username'],
            'email': item['email'],
            'first_name': item['profile']['firstName'],
            'last_name': item['profile']['lastName']
        })
    return members
```

#### XML APIs
```python
import xml.etree.ElementTree as ET

def get_group_members(self, group_cfg: Dict[str, str]) -> List[Dict[str, Any]]:
    response = self.request('GET', f'/api/groups/{group_cfg["vendor_group"]}/members')
    return self._parse_xml_members(response)

def _parse_xml_members(self, xml_response: str) -> List[Dict[str, Any]]:
    root = ET.fromstring(xml_response)
    members = []
    
    for user_elem in root.findall('.//user'):
        members.append({
            'username': user_elem.find('username').text,
            'email': user_elem.find('email').text,
            'first_name': user_elem.find('firstName').text,
            'last_name': user_elem.find('lastName').text
        })
    
    return members
```

### Error Handling Best Practices

```python
from ldap_sync.exceptions import VendorAPIError, AuthenticationError

def get_group_members(self, group_cfg: Dict[str, str]) -> List[Dict[str, Any]]:
    vendor_group = group_cfg['vendor_group']
    
    try:
        response = self.request('GET', f'/api/groups/{vendor_group}/members')
        return self._parse_members(response)
        
    except AuthenticationError:
        logger.error("Authentication failed - credentials may be expired")
        raise
        
    except VendorAPIError as e:
        if e.status_code == 404:
            logger.warning(f"Group {vendor_group} not found in vendor system")
            return []  # Return empty list for missing groups
        elif e.status_code == 403:
            logger.error(f"Access denied to group {vendor_group}")
            raise
        else:
            logger.error(f"API error getting group members: {e}")
            raise
            
    except Exception as e:
        logger.error(f"Unexpected error getting group members: {e}")
        raise VendorAPIError(f"Failed to get group members: {e}")
```

### Pagination Support

```python
def get_group_members(self, group_cfg: Dict[str, str]) -> List[Dict[str, Any]]:
    vendor_group = group_cfg['vendor_group']
    all_members = []
    page = 1
    page_size = 100
    
    while True:
        try:
            response = self.request('GET', f'/api/groups/{vendor_group}/members', 
                                  params={'page': page, 'per_page': page_size})
            
            members = response.get('members', [])
            if not members:
                break
                
            all_members.extend(self._parse_members(members))
            
            # Check if there are more pages
            if len(members) < page_size or not response.get('has_more', True):
                break
                
            page += 1
            
        except Exception as e:
            logger.error(f"Error retrieving page {page}: {e}")
            break
    
    return all_members
```

### Rate Limiting

```python
import time
from datetime import datetime, timedelta

class YourVendorAPI(VendorAPIBase):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.rate_limit_calls = 0
        self.rate_limit_window_start = datetime.now()
        self.max_calls_per_minute = config.get('rate_limit', 60)
    
    def request(self, method: str, path: str, **kwargs) -> Any:
        # Check rate limiting
        self._check_rate_limit()
        
        # Make the request
        response = super().request(method, path, **kwargs)
        
        # Track API calls
        self.rate_limit_calls += 1
        
        return response
    
    def _check_rate_limit(self):
        now = datetime.now()
        if now - self.rate_limit_window_start > timedelta(minutes=1):
            # Reset window
            self.rate_limit_calls = 0
            self.rate_limit_window_start = now
        elif self.rate_limit_calls >= self.max_calls_per_minute:
            # Wait until next window
            sleep_time = 60 - (now - self.rate_limit_window_start).seconds
            logger.info(f"Rate limit reached, sleeping for {sleep_time} seconds")
            time.sleep(sleep_time)
            self.rate_limit_calls = 0
            self.rate_limit_window_start = datetime.now()
```

## Configuration Integration

### 1. Add Configuration Section

Update your `config.yaml` to include the new vendor:

```yaml
vendor_apps:
  - name: "Your Vendor System"
    module: "your_vendor"  # Matches your module filename
    base_url: "https://api.yourvendor.com/v1"
    auth:
      method: "oauth2"
      token_url: "https://api.yourvendor.com/oauth/token"
      client_id: "${YOUR_VENDOR_CLIENT_ID}"
      client_secret: "${YOUR_VENDOR_CLIENT_SECRET}"
      scope: "users:read users:write groups:manage"
    format: "json"
    verify_ssl: true
    request_timeout: 30
    rate_limit: 100  # Custom vendor-specific setting
    groups:
      - ldap_group: "CN=YourVendor_Users,OU=Apps,DC=company,DC=com"
        vendor_group: "users"
      - ldap_group: "CN=YourVendor_Admins,OU=Apps,DC=company,DC=com"
        vendor_group: "administrators"
```

### 2. Environment Variables

Set up environment variables for sensitive data:

```bash
export YOUR_VENDOR_CLIENT_ID="your_client_id"
export YOUR_VENDOR_CLIENT_SECRET="your_client_secret"
```

## Testing Your Integration

### 1. Unit Tests

Create tests for your vendor module:

```python
# tests/test_your_vendor.py
import unittest
from unittest.mock import Mock, patch
from ldap_sync.vendors.your_vendor import YourVendorAPI

class TestYourVendorAPI(unittest.TestCase):
    def setUp(self):
        self.config = {
            'base_url': 'https://api.test.com',
            'auth': {'method': 'token', 'token': 'test_token'},
            'format': 'json'
        }
        self.api = YourVendorAPI(self.config)
    
    @patch('ldap_sync.vendors.your_vendor.YourVendorAPI.request')
    def test_get_group_members(self, mock_request):
        # Mock API response
        mock_request.return_value = {
            'members': [
                {'username': 'user1', 'email': 'user1@test.com', 
                 'firstName': 'User', 'lastName': 'One'}
            ]
        }
        
        result = self.api.get_group_members({'vendor_group': 'test_group'})
        
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['username'], 'user1')
```

### 2. Integration Testing

Test with the actual vendor API:

```python
# test_integration.py
from ldap_sync.vendors.your_vendor import YourVendorAPI

def test_vendor_integration():
    config = {
        'base_url': 'https://api-staging.yourvendor.com/v1',
        'auth': {
            'method': 'token',
            'token': 'your_test_token'
        },
        'format': 'json'
    }
    
    api = YourVendorAPI(config)
    
    # Test authentication
    assert api.authenticate() == True
    
    # Test getting group members
    group_cfg = {'vendor_group': 'test_group'}
    members = api.get_group_members(group_cfg)
    print(f"Found {len(members)} members")
    
    # Test other operations...
```

### 3. Manual Testing

Use the module directly for testing:

```bash
python -m ldap_sync.vendors.your_vendor
```

Add this to your module for direct testing:

```python
if __name__ == '__main__':
    import sys
    import yaml
    
    # Load test configuration
    with open('test_config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
    # Initialize API
    api = YourVendorAPI(config['vendor_apps'][0])
    
    # Test operations
    if api.authenticate():
        print("Authentication successful")
        
        # Test getting group members
        for group_cfg in config['vendor_apps'][0]['groups']:
            members = api.get_group_members(group_cfg)
            print(f"Group {group_cfg['vendor_group']}: {len(members)} members")
    else:
        print("Authentication failed")
        sys.exit(1)
```

## Common Patterns and Examples

### RESTful API Pattern

Most modern APIs follow REST conventions:

```python
# GET /api/users/{id} - Get user
# POST /api/users - Create user
# PUT /api/users/{id} - Update user
# DELETE /api/users/{id} - Delete user
# GET /api/groups/{id}/members - Get group members
# POST /api/groups/{id}/members - Add member to group
# DELETE /api/groups/{id}/members/{user_id} - Remove member from group
```

### GraphQL API Pattern

For GraphQL APIs:

```python
def get_group_members(self, group_cfg: Dict[str, str]) -> List[Dict[str, Any]]:
    query = """
    query GetGroupMembers($groupId: String!) {
        group(id: $groupId) {
            members {
                id
                username
                email
                profile {
                    firstName
                    lastName
                }
            }
        }
    }
    """
    
    variables = {'groupId': group_cfg['vendor_group']}
    
    response = self.request('POST', '/graphql', data={
        'query': query,
        'variables': variables
    })
    
    members = response['data']['group']['members']
    return self._parse_graphql_members(members)
```

### SOAP API Pattern

For SOAP/XML APIs:

```python
def get_group_members(self, group_cfg: Dict[str, str]) -> List[Dict[str, Any]]:
    soap_body = f"""
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
            <GetGroupMembers xmlns="http://api.vendor.com/v1">
                <GroupId>{group_cfg['vendor_group']}</GroupId>
            </GetGroupMembers>
        </soap:Body>
    </soap:Envelope>
    """
    
    headers = {
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': 'GetGroupMembers'
    }
    
    response = self.request('POST', '/soap', data=soap_body, headers=headers)
    return self._parse_soap_response(response)
```

## Troubleshooting

### Common Issues

1. **Authentication Failures**
   - Check credentials and API endpoints
   - Verify token expiration and refresh logic
   - Review API rate limits

2. **Data Mapping Issues**
   - Ensure field names match between LDAP and vendor
   - Handle missing or optional fields gracefully
   - Validate data types and formats

3. **Network Issues**
   - Implement proper timeout handling
   - Add retry logic for transient failures
   - Check SSL certificate validation

4. **API Changes**
   - Monitor vendor API documentation for changes
   - Implement version detection where possible
   - Add graceful degradation for deprecated endpoints

### Debugging Tips

1. **Enable Debug Logging**
   ```python
   import logging
   logging.getLogger('ldap_sync.vendors.your_vendor').setLevel(logging.DEBUG)
   ```

2. **Log API Requests/Responses**
   ```python
   logger.debug(f"API Request: {method} {url}")
   logger.debug(f"API Response: {response}")
   ```

3. **Use API Testing Tools**
   - Test endpoints with curl or Postman
   - Validate request/response formats
   - Check authentication flows

## Best Practices

1. **Error Handling**: Always implement comprehensive error handling
2. **Logging**: Log all important operations and errors
3. **Configuration**: Make the integration configurable
4. **Testing**: Write both unit and integration tests
5. **Documentation**: Document API quirks and limitations
6. **Performance**: Implement pagination and rate limiting
7. **Security**: Never log sensitive data like tokens or passwords

## Complete Example

See the [reference implementation](../ldap_sync/vendors/vendor_app1.py) for a complete example of a vendor integration.

## Getting Help

- Review existing vendor implementations in `ldap_sync/vendors/`
- Check the [API Reference](api-reference.md) for detailed method signatures
- See [Troubleshooting Guide](troubleshooting-guide.md) for common issues
- Contact the development team for assistance with complex integrations