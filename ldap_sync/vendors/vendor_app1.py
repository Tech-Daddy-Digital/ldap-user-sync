"""
VendorApp1 API integration module.

This module implements the VendorAPIBase interface for VendorApp1's REST API.
It provides methods to manage users and group memberships in VendorApp1.
"""

import logging
from typing import Dict, List, Any, Optional
from .base import VendorAPIBase, VendorAPIError

logger = logging.getLogger(__name__)


class VendorApp1API(VendorAPIBase):
    """
    VendorApp1 API client implementation.
    
    This class implements the vendor API interface for VendorApp1's REST API.
    It handles user management and group membership operations.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize VendorApp1 API client.
        
        Args:
            config: Vendor configuration dictionary
        """
        super().__init__(config)
        
        # VendorApp1-specific configuration
        self.user_identifier_field = config.get('user_identifier_field', 'email')
        self.group_id_field = config.get('group_id_field', 'id')
        
        logger.info(f"Initialized VendorApp1 API client for {self.name}")
    
    def get_group_members(self, group_cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Get list of users in the specified VendorApp1 group.
        
        Args:
            group_cfg: Group configuration containing vendor_group identifier
            
        Returns:
            List of user dictionaries with standardized fields:
            - username: User's username/login
            - email: User's email address
            - first_name: User's first name
            - last_name: User's last name
            - user_id: Internal user ID (for API operations)
            
        Raises:
            VendorAPIError: If API call fails
        """
        vendor_group = group_cfg['vendor_group']
        
        try:
            logger.debug(f"Fetching members for group '{vendor_group}' in {self.name}")
            
            # Get group members - VendorApp1 API: GET /groups/{group_id}/members
            response = self.request('GET', f'/groups/{vendor_group}/members')
            
            # Parse response and normalize user data
            members = []
            users_data = response.get('users', response.get('members', []))
            
            for user in users_data:
                # Map VendorApp1 fields to standardized format
                normalized_user = {
                    'username': user.get('username', user.get('login', '')),
                    'email': user.get('email', user.get('emailAddress', '')),
                    'first_name': user.get('firstName', user.get('givenName', '')),
                    'last_name': user.get('lastName', user.get('surname', user.get('sn', ''))),
                    'user_id': user.get('id', user.get('userId', '')),
                    'active': user.get('active', user.get('enabled', True))
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
        Add user to VendorApp1 group (create user if needed).
        
        Args:
            group_cfg: Group configuration
            user_info: User data from LDAP with fields:
                - username/sAMAccountName: User's login name
                - email/mail: User's email address
                - first_name/givenName: User's first name
                - last_name/sn: User's last name
                
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
        
        user_identifier = user_info.get(self.user_identifier_field, email if self.user_identifier_field == 'email' else username)
        
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
        Remove user from VendorApp1 group.
        
        Args:
            group_cfg: Group configuration
            user_identifier: User identifier (email, username, etc.)
            
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
            
            # Remove user from group - VendorApp1 API: DELETE /groups/{group_id}/members/{user_id}
            self.request('DELETE', f'/groups/{vendor_group}/members/{user_id}')
            
            logger.info(f"Successfully removed user '{user_identifier}' from group '{vendor_group}' in {self.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove user '{user_identifier}' from group '{vendor_group}' in {self.name}: {e}")
            if isinstance(e, VendorAPIError):
                raise
            raise VendorAPIError(f"Failed to remove user from group: {e}")
    
    def update_user(self, user_identifier: str, user_info: Dict[str, Any]) -> bool:
        """
        Update user attributes in VendorApp1.
        
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
            
            # Map LDAP fields to VendorApp1 fields
            field_mapping = {
                'first_name': 'firstName',
                'givenName': 'firstName',
                'last_name': 'lastName',
                'sn': 'lastName',
                'email': 'email',
                'mail': 'email',
                'username': 'username',
                'sAMAccountName': 'username'
            }
            
            for ldap_field, vendor_field in field_mapping.items():
                if ldap_field in user_info:
                    update_data[vendor_field] = user_info[ldap_field]
            
            if not update_data:
                logger.debug(f"No fields to update for user '{user_identifier}' in {self.name}")
                return True
            
            # Update user - VendorApp1 API: PUT /users/{user_id}
            self.request('PUT', f'/users/{user_id}', body=update_data)
            
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
            user_identifier: User identifier (email or username)
            
        Returns:
            User ID if found, None otherwise
        """
        try:
            # Search for user - VendorApp1 API: GET /users?search={identifier}
            response = self.request('GET', f'/users', headers={
                'X-Search-Field': self.user_identifier_field,
                'X-Search-Value': user_identifier
            })
            
            users = response.get('users', [])
            
            # Look for exact match
            for user in users:
                if user.get(self.user_identifier_field) == user_identifier:
                    return user.get('id', user.get('userId'))
            
            return None
            
        except Exception as e:
            logger.debug(f"Error searching for user '{user_identifier}' in {self.name}: {e}")
            return None
    
    def _create_user(self, username: str, email: str, first_name: str, last_name: str) -> Optional[str]:
        """
        Create a new user in VendorApp1.
        
        Args:
            username: User's username
            email: User's email address
            first_name: User's first name
            last_name: User's last name
            
        Returns:
            Created user ID if successful, None otherwise
        """
        try:
            # Prepare user creation payload
            user_data = {
                'username': username,
                'email': email,
                'firstName': first_name,
                'lastName': last_name,
                'active': True
            }
            
            # Create user - VendorApp1 API: POST /users
            response = self.request('POST', '/users', body=user_data)
            
            user_id = response.get('id', response.get('userId'))
            if user_id:
                return str(user_id)
            else:
                logger.error(f"User creation response missing ID: {response}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to create user '{username}' in {self.name}: {e}")
            return None
    
    def _add_user_to_group_by_id(self, user_id: str, group_id: str) -> bool:
        """
        Add user to group by their IDs.
        
        Args:
            user_id: User's internal ID
            group_id: Group identifier
            
        Returns:
            True if successful
        """
        try:
            # Add user to group - VendorApp1 API: POST /groups/{group_id}/members
            payload = {'userId': user_id}
            self.request('POST', f'/groups/{group_id}/members', body=payload)
            return True
            
        except Exception as e:
            logger.error(f"Failed to add user ID {user_id} to group {group_id} in {self.name}: {e}")
            return False


# Factory function for dynamic module loading
def create_vendor_api(config: Dict[str, Any]) -> VendorApp1API:
    """
    Factory function to create VendorApp1API instance.
    
    Args:
        config: Vendor configuration dictionary
        
    Returns:
        VendorApp1API instance
    """
    return VendorApp1API(config)