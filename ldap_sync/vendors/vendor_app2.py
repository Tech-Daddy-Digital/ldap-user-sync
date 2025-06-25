"""
VendorApp2 API integration module.

This module implements the VendorAPIBase interface for VendorApp2's REST API.
It demonstrates different authentication (token) and data format (XML) compared to VendorApp1.
"""

import logging
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional
from .base import VendorAPIBase, VendorAPIError

logger = logging.getLogger(__name__)


class VendorApp2API(VendorAPIBase):
    """
    VendorApp2 API client implementation.
    
    This class implements the vendor API interface for VendorApp2's REST API.
    It uses token authentication and XML data format to demonstrate modularity.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize VendorApp2 API client.
        
        Args:
            config: Vendor configuration dictionary
        """
        super().__init__(config)
        
        # VendorApp2-specific configuration
        self.user_identifier_field = config.get('user_identifier_field', 'username')
        self.group_id_field = config.get('group_id_field', 'name')
        
        # VendorApp2 uses different API structure
        self.users_endpoint = config.get('users_endpoint', '/api/users')
        self.groups_endpoint = config.get('groups_endpoint', '/api/groups')
        
        logger.info(f"Initialized VendorApp2 API client for {self.name}")
    
    def get_group_members(self, group_cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Get list of users in the specified VendorApp2 group.
        
        Args:
            group_cfg: Group configuration containing vendor_group identifier
            
        Returns:
            List of user dictionaries with standardized fields
            
        Raises:
            VendorAPIError: If API call fails
        """
        vendor_group = group_cfg['vendor_group']
        
        try:
            logger.debug(f"Fetching members for group '{vendor_group}' in {self.name}")
            
            # VendorApp2 API: GET /api/groups/{group_name}/users
            response = self.request('GET', f'{self.groups_endpoint}/{vendor_group}/users')
            
            # Parse XML response (VendorApp2 uses XML)
            members = []
            users_list = response.get('users', [])
            
            # Handle both single user and list of users
            if not isinstance(users_list, list):
                users_list = [users_list] if users_list else []
            
            for user in users_list:
                # Map VendorApp2 XML fields to standardized format
                normalized_user = {
                    'username': user.get('login_name', user.get('username', '')),
                    'email': user.get('email_addr', user.get('email', '')),
                    'first_name': user.get('first_name', user.get('fname', '')),
                    'last_name': user.get('last_name', user.get('lname', '')),
                    'user_id': user.get('user_id', user.get('id', '')),
                    'active': self._parse_boolean(user.get('is_active', user.get('enabled', 'true')))
                }
                
                # Ensure we have a valid identifier
                if not normalized_user[self.user_identifier_field]:
                    logger.warning(f"User missing {self.user_identifier_field} field, skipping: {user}")
                    continue
                
                members.append(normalized_user)
            
            logger.info(f"Retrieved {len(members)} members from group '{vendor_group}' in {self.name}")
            return members
            
        except Exception as e:
            logger.error(f"Failed to get group members for '{vendor_group}' in {self.name}: {e}")
            raise VendorAPIError(f"Failed to get group members: {e}")
    
    def add_user_to_group(self, group_cfg: Dict[str, Any], user_info: Dict[str, Any]) -> bool:
        """
        Add user to VendorApp2 group (create user if needed).
        
        Args:
            group_cfg: Group configuration
            user_info: User data from LDAP
            
        Returns:
            True if successful
            
        Raises:
            VendorAPIError: If operation fails
        """
        vendor_group = group_cfg['vendor_group']
        
        # Extract user data with fallback field names
        username = user_info.get('username', user_info.get('sAMAccountName', ''))
        email = user_info.get('email', user_info.get('mail', ''))
        first_name = user_info.get('first_name', user_info.get('givenName', ''))
        last_name = user_info.get('last_name', user_info.get('sn', ''))
        
        user_identifier = user_info.get(self.user_identifier_field, 
                                      username if self.user_identifier_field == 'username' else email)
        
        if not user_identifier:
            raise VendorAPIError(f"User missing required identifier field '{self.user_identifier_field}'")
        
        try:
            logger.debug(f"Adding user '{user_identifier}' to group '{vendor_group}' in {self.name}")
            
            # Step 1: Check if user already exists
            user_id = self._find_user_by_identifier(user_identifier)
            
            if not user_id:
                # Step 2: Create user if they don't exist
                user_id = self._create_user(username, email, first_name, last_name)
                if not user_id:
                    raise VendorAPIError(f"Failed to create user '{user_identifier}'")
                logger.info(f"Created new user '{user_identifier}' with ID {user_id} in {self.name}")
            else:
                logger.debug(f"User '{user_identifier}' already exists with ID {user_id} in {self.name}")
            
            # Step 3: Add user to group
            if self._add_user_to_group_by_id(user_id, vendor_group):
                logger.info(f"Successfully added user '{user_identifier}' to group '{vendor_group}' in {self.name}")
                return True
            else:
                raise VendorAPIError(f"Failed to add user '{user_identifier}' to group '{vendor_group}'")
                
        except Exception as e:
            logger.error(f"Failed to add user '{user_identifier}' to group '{vendor_group}' in {self.name}: {e}")
            if isinstance(e, VendorAPIError):
                raise
            raise VendorAPIError(f"Failed to add user to group: {e}")
    
    def remove_user_from_group(self, group_cfg: Dict[str, Any], user_identifier: str) -> bool:
        """
        Remove user from VendorApp2 group.
        
        Args:
            group_cfg: Group configuration
            user_identifier: User identifier (username, etc.)
            
        Returns:
            True if successful
            
        Raises:
            VendorAPIError: If operation fails
        """
        vendor_group = group_cfg['vendor_group']
        
        try:
            logger.debug(f"Removing user '{user_identifier}' from group '{vendor_group}' in {self.name}")
            
            # Find user by identifier
            user_id = self._find_user_by_identifier(user_identifier)
            
            if not user_id:
                logger.warning(f"User '{user_identifier}' not found in {self.name}, considering removal successful")
                return True
            
            # Remove user from group - VendorApp2 API: DELETE /api/groups/{group_name}/users/{user_id}
            self.request('DELETE', f'{self.groups_endpoint}/{vendor_group}/users/{user_id}')
            
            logger.info(f"Successfully removed user '{user_identifier}' from group '{vendor_group}' in {self.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove user '{user_identifier}' from group '{vendor_group}' in {self.name}: {e}")
            if isinstance(e, VendorAPIError):
                raise
            raise VendorAPIError(f"Failed to remove user from group: {e}")
    
    def update_user(self, user_identifier: str, user_info: Dict[str, Any]) -> bool:
        """
        Update user attributes in VendorApp2.
        
        Args:
            user_identifier: User identifier
            user_info: Updated user data from LDAP
            
        Returns:
            True if successful
            
        Raises:
            VendorAPIError: If operation fails
        """
        try:
            logger.debug(f"Updating user '{user_identifier}' in {self.name}")
            
            # Find user by identifier
            user_id = self._find_user_by_identifier(user_identifier)
            
            if not user_id:
                raise VendorAPIError(f"User '{user_identifier}' not found in {self.name}")
            
            # Prepare update payload with only changed fields
            update_data = {}
            
            # Map LDAP fields to VendorApp2 XML fields
            field_mapping = {
                'first_name': 'first_name',
                'givenName': 'first_name',
                'last_name': 'last_name',
                'sn': 'last_name',
                'email': 'email_addr',
                'mail': 'email_addr',
                'username': 'login_name',
                'sAMAccountName': 'login_name'
            }
            
            for ldap_field, vendor_field in field_mapping.items():
                if ldap_field in user_info:
                    update_data[vendor_field] = user_info[ldap_field]
            
            if not update_data:
                logger.debug(f"No fields to update for user '{user_identifier}' in {self.name}")
                return True
            
            # Update user - VendorApp2 API: PUT /api/users/{user_id}
            self.request('PUT', f'{self.users_endpoint}/{user_id}', body=update_data)
            
            updated_fields = ', '.join(update_data.keys())
            logger.info(f"Successfully updated user '{user_identifier}' in {self.name}: {updated_fields}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update user '{user_identifier}' in {self.name}: {e}")
            if isinstance(e, VendorAPIError):
                raise
            raise VendorAPIError(f"Failed to update user: {e}")
    
    def _find_user_by_identifier(self, user_identifier: str) -> Optional[str]:
        """
        Find user by identifier and return their internal ID.
        
        Args:
            user_identifier: User identifier (username or email)
            
        Returns:
            User ID if found, None otherwise
        """
        try:
            # Search for user - VendorApp2 API: GET /api/users/search?field=value
            response = self.request('GET', f'{self.users_endpoint}/search', headers={
                'X-Filter-Field': self.user_identifier_field,
                'X-Filter-Value': user_identifier
            })
            
            # Handle XML response structure
            users = response.get('user_list', response.get('users', []))
            if not isinstance(users, list):
                users = [users] if users else []
            
            # Look for exact match
            for user in users:
                if user.get(self.user_identifier_field) == user_identifier:
                    return user.get('user_id', user.get('id'))
            
            return None
            
        except Exception as e:
            logger.debug(f"Error searching for user '{user_identifier}' in {self.name}: {e}")
            return None
    
    def _create_user(self, username: str, email: str, first_name: str, last_name: str) -> Optional[str]:
        """
        Create a new user in VendorApp2.
        
        Args:
            username: User's username
            email: User's email address
            first_name: User's first name
            last_name: User's last name
            
        Returns:
            Created user ID if successful, None otherwise
        """
        try:
            # Prepare user creation payload (VendorApp2 uses different field names)
            user_data = {
                'login_name': username,
                'email_addr': email,
                'first_name': first_name,
                'last_name': last_name,
                'is_active': 'true'
            }
            
            # Create user - VendorApp2 API: POST /api/users
            response = self.request('POST', self.users_endpoint, body=user_data)
            
            user_id = response.get('user_id', response.get('id'))
            if user_id:
                return str(user_id)
            else:
                logger.error(f"User creation response missing ID: {response}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to create user '{username}' in {self.name}: {e}")
            return None
    
    def _add_user_to_group_by_id(self, user_id: str, group_name: str) -> bool:
        """
        Add user to group by their IDs.
        
        Args:
            user_id: User's internal ID
            group_name: Group name/identifier
            
        Returns:
            True if successful
        """
        try:
            # Add user to group - VendorApp2 API: POST /api/groups/{group_name}/users
            payload = {'user_id': user_id, 'action': 'add'}
            self.request('POST', f'{self.groups_endpoint}/{group_name}/users', body=payload)
            return True
            
        except Exception as e:
            logger.error(f"Failed to add user ID {user_id} to group {group_name} in {self.name}: {e}")
            return False
    
    def _parse_boolean(self, value: Any) -> bool:
        """
        Parse boolean value from XML string.
        
        Args:
            value: Value to parse
            
        Returns:
            Boolean value
        """
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ('true', '1', 'yes', 'on', 'enabled')
        return bool(value)
    
    def _dict_to_xml(self, data: Dict) -> str:
        """
        Convert dictionary to VendorApp2-specific XML format.
        
        Args:
            data: Dictionary to convert
            
        Returns:
            XML string
        """
        # VendorApp2 uses a specific XML structure
        root = ET.Element('request')
        user_elem = ET.SubElement(root, 'user')
        
        for key, value in data.items():
            elem = ET.SubElement(user_elem, key)
            elem.text = str(value)
        
        return ET.tostring(root, encoding='unicode')
    
    def _xml_to_dict(self, xml_data: str) -> Dict:
        """
        Convert VendorApp2 XML response to dictionary.
        
        Args:
            xml_data: XML response string
            
        Returns:
            Parsed dictionary
        """
        try:
            root = ET.fromstring(xml_data)
            result = {}
            
            # Handle VendorApp2's XML structure
            if root.tag == 'response':
                # Single user response
                user_elem = root.find('user')
                if user_elem is not None:
                    for child in user_elem:
                        result[child.tag] = child.text
                else:
                    # Multiple users response
                    users_elem = root.find('users')
                    if users_elem is not None:
                        users = []
                        for user_elem in users_elem.findall('user'):
                            user_data = {}
                            for child in user_elem:
                                user_data[child.tag] = child.text
                            users.append(user_data)
                        result['users'] = users
            else:
                # Simple flat structure
                for child in root:
                    if len(child) > 0:
                        # Nested elements
                        child_dict = {}
                        for subchild in child:
                            child_dict[subchild.tag] = subchild.text
                        result[child.tag] = child_dict
                    else:
                        result[child.tag] = child.text
            
            return result
            
        except ET.ParseError as e:
            raise VendorAPIError(f"Invalid XML response: {e}")


# Factory function for dynamic module loading
def create_vendor_api(config: Dict[str, Any]) -> VendorApp2API:
    """
    Factory function to create VendorApp2API instance.
    
    Args:
        config: Vendor configuration dictionary
        
    Returns:
        VendorApp2API instance
    """
    return VendorApp2API(config)