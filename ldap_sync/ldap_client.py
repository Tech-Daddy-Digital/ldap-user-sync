"""
LDAP client for connecting to and querying LDAP directories.

This module provides functionality to connect to LDAP servers and retrieve
user group memberships and attributes.
"""

import logging
import ssl
import time
from typing import Dict, List, Any, Optional
from ldap3 import Server, Connection, SUBTREE, ALL, Tls
from ldap3.core.exceptions import LDAPException, LDAPSocketOpenError, LDAPBindError

logger = logging.getLogger(__name__)


class LDAPConnectionError(Exception):
    """Raised when LDAP connection fails."""
    pass


class LDAPQueryError(Exception):
    """Raised when LDAP query fails."""
    pass


class LDAPClient:
    """
    LDAP client for connecting to and querying LDAP directories.
    
    Supports both direct group member lookup and memberOf reverse lookup.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize LDAP client with configuration.
        
        Args:
            config: LDAP configuration dictionary
        """
        self.config = config
        self.server_url = config['server_url']
        self.bind_dn = config['bind_dn']
        self.bind_password = config['bind_password']
        self.user_base_dn = config.get('user_base_dn', '')
        self.user_filter = config.get('user_filter', '(objectClass=person)')
        self.attributes = config.get('attributes', ['cn', 'givenName', 'sn', 'mail', 'sAMAccountName'])
        
        # SSL/TLS configuration
        self.use_ssl = config.get('use_ssl', self.server_url.lower().startswith('ldaps://'))
        self.start_tls = config.get('start_tls', False)
        self.verify_ssl = config.get('verify_ssl', True)
        self.ca_cert_file = config.get('ca_cert_file')
        self.cert_file = config.get('cert_file')
        self.key_file = config.get('key_file')
        
        # Connection settings
        self.connection_timeout = config.get('connection_timeout', 10)
        self.receive_timeout = config.get('receive_timeout', 10)
        self.page_size = config.get('page_size', 1000)
        
        # Retry settings from error_handling config
        error_config = config.get('error_handling', {})
        self.max_retries = error_config.get('max_retries', 3)
        self.retry_wait = error_config.get('retry_wait_seconds', 5)
        
        self.server = None
        self.connection = None
        self._connected = False
    
    def connect(self, max_retries: Optional[int] = None, retry_wait: Optional[int] = None) -> bool:
        """
        Establish connection to LDAP server with retry logic.
        
        Args:
            max_retries: Maximum number of connection attempts (uses config default if None)
            retry_wait: Seconds to wait between retries (uses config default if None)
            
        Returns:
            True if connection successful
            
        Raises:
            LDAPConnectionError: If connection fails after all retries
        """
        max_retries = max_retries or self.max_retries
        retry_wait = retry_wait or self.retry_wait
        
        try:
            # Create TLS configuration if needed
            tls_config = self._create_tls_config()
            
            # Create server with appropriate SSL/TLS settings
            self.server = Server(
                self.server_url,
                use_ssl=self.use_ssl,
                tls=tls_config,
                get_info=ALL,
                connect_timeout=self.connection_timeout
            )
            logger.debug(f"Created LDAP server object for {self.server_url} (SSL: {self.use_ssl}, StartTLS: {self.start_tls})")
        except Exception as e:
            raise LDAPConnectionError(f"Failed to create LDAP server: {e}")
        
        # Attempt connection with retries
        last_exception = None
        for attempt in range(max_retries):
            try:
                self.connection = Connection(
                    self.server,
                    user=self.bind_dn,
                    password=self.bind_password,
                    auto_bind=False,  # Manual bind for better error handling
                    receive_timeout=self.receive_timeout
                )
                
                # Open connection
                if not self.connection.open():
                    raise LDAPConnectionError(f"Failed to open connection: {self.connection.result}")
                
                # Start TLS if configured
                if self.start_tls and not self.use_ssl:
                    if not self.connection.start_tls():
                        raise LDAPConnectionError(f"Failed to start TLS: {self.connection.result}")
                    logger.debug("StartTLS negotiation successful")
                
                # Bind with credentials
                if not self.connection.bind():
                    raise LDAPBindError(f"Bind failed: {self.connection.result}")
                
                self._connected = True
                logger.info(f"Successfully connected and bound to LDAP server {self.server_url}")
                return True
                
            except (LDAPSocketOpenError, LDAPBindError) as e:
                last_exception = e
                logger.warning(f"LDAP connection attempt {attempt + 1}/{max_retries} failed: {e}")
                if self.connection:
                    try:
                        self.connection.unbind()
                    except:
                        pass
                    self.connection = None
                if attempt < max_retries - 1:
                    time.sleep(retry_wait)
            except LDAPException as e:
                last_exception = e
                logger.warning(f"LDAP connection attempt {attempt + 1}/{max_retries} failed: {e}")
                if self.connection:
                    try:
                        self.connection.unbind()
                    except:
                        pass
                    self.connection = None
                if attempt < max_retries - 1:
                    time.sleep(retry_wait)
            except Exception as e:
                last_exception = e
                logger.error(f"Unexpected error during LDAP connection: {e}")
                if self.connection:
                    try:
                        self.connection.unbind()
                    except:
                        pass
                    self.connection = None
                break
        
        # All retries failed
        error_msg = f"Failed to connect to LDAP after {max_retries} attempts"
        if last_exception:
            error_msg += f": {last_exception}"
        raise LDAPConnectionError(error_msg)
    
    def _create_tls_config(self) -> Optional[Tls]:
        """
        Create TLS configuration for LDAP connection.
        
        Returns:
            Tls configuration object or None if not needed
        """
        if not (self.use_ssl or self.start_tls):
            return None
        
        tls_config = {}
        
        # Certificate verification
        if not self.verify_ssl:
            tls_config['validate'] = ssl.CERT_NONE
            logger.warning("SSL certificate verification disabled")
        else:
            tls_config['validate'] = ssl.CERT_REQUIRED
        
        # CA certificate file
        if self.ca_cert_file:
            tls_config['ca_certs_file'] = self.ca_cert_file
            logger.debug(f"Using CA certificate file: {self.ca_cert_file}")
        
        # Client certificate for mutual TLS
        if self.cert_file and self.key_file:
            tls_config['local_certificate_file'] = self.cert_file
            tls_config['local_private_key_file'] = self.key_file
            logger.debug("Client certificate configured for mutual TLS")
        
        try:
            return Tls(**tls_config)
        except Exception as e:
            raise LDAPConnectionError(f"Failed to create TLS configuration: {e}")
    
    def disconnect(self):
        """Close LDAP connection."""
        if self.connection and self._connected:
            try:
                self.connection.unbind()
                logger.debug("LDAP connection closed")
            except Exception as e:
                logger.warning(f"Error closing LDAP connection: {e}")
            finally:
                self._connected = False
                self.connection = None
    
    def get_group_members(self, group_dn: str, use_memberof: bool = True) -> Dict[str, Dict[str, Any]]:
        """
        Retrieve members of an LDAP group with their attributes.
        
        Args:
            group_dn: Distinguished name of the group
            use_memberof: If True, use memberOf reverse lookup (faster for AD)
            
        Returns:
            Dictionary mapping user identifiers to user attributes
            
        Raises:
            LDAPQueryError: If query fails
        """
        if not self._connected:
            raise LDAPQueryError("Not connected to LDAP server")
        
        logger.info(f"Retrieving members of group: {group_dn}")
        
        try:
            if use_memberof:
                return self._get_members_by_memberof(group_dn)
            else:
                return self._get_members_by_group_attribute(group_dn)
        except LDAPException as e:
            raise LDAPQueryError(f"LDAP query failed: {e}")
        except Exception as e:
            raise LDAPQueryError(f"Unexpected error during LDAP query: {e}")
    
    def _get_members_by_memberof(self, group_dn: str) -> Dict[str, Dict[str, Any]]:
        """Get group members using memberOf reverse lookup (Active Directory style)."""
        search_filter = f"(&{self.user_filter}(memberOf={group_dn}))"
        search_base = self.user_base_dn or self._get_domain_base()
        
        logger.debug(f"Searching with filter: {search_filter} in base: {search_base}")
        
        members = {}
        page_count = 0
        
        # Handle pagination for large groups
        try:
            success = self.connection.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=self.attributes,
                paged_size=self.page_size
            )
            
            if not success:
                raise LDAPQueryError(f"Search failed: {self.connection.result}")
            
            page_count += 1
            page_members = self._process_search_results()
            members.update(page_members)
            logger.debug(f"Page {page_count}: Retrieved {len(page_members)} members")
            
            # Continue with additional pages if available
            while (self.connection.result.get('controls') and 
                   '1.2.840.113556.1.4.319' in [control.controlType for control in self.connection.result['controls']]):
                cookie = None
                for control in self.connection.result['controls']:
                    if control.controlType == '1.2.840.113556.1.4.319':
                        cookie = control.controlValue.get('cookie')
                        break
                
                if not cookie:
                    break
                
                # Search next page
                success = self.connection.search(
                    search_base=search_base,
                    search_filter=search_filter,
                    search_scope=SUBTREE,
                    attributes=self.attributes,
                    paged_size=self.page_size,
                    paged_cookie=cookie
                )
                
                if not success:
                    logger.warning(f"Failed to retrieve page {page_count + 1}: {self.connection.result}")
                    break
                
                page_count += 1
                page_members = self._process_search_results()
                members.update(page_members)
                logger.debug(f"Page {page_count}: Retrieved {len(page_members)} members")
                
                # Stop if no more results
                if not page_members:
                    break
            
            logger.info(f"Retrieved {len(members)} total members across {page_count} pages")
            return members
            
        except LDAPException as e:
            raise LDAPQueryError(f"Paginated search failed: {e}")
        except Exception as e:
            raise LDAPQueryError(f"Unexpected error during paginated search: {e}")
    
    def _get_members_by_group_attribute(self, group_dn: str) -> Dict[str, Dict[str, Any]]:
        """Get group members by reading group's member attribute."""
        # First, get the group's member attribute
        success = self.connection.search(
            search_base=group_dn,
            search_filter="(objectClass=*)",
            search_scope='BASE',
            attributes=['member']
        )
        
        if not success or not self.connection.entries:
            raise LDAPQueryError(f"Group not found or no members: {group_dn}")
        
        group_entry = self.connection.entries[0]
        member_dns = group_entry.member.values if hasattr(group_entry, 'member') else []
        
        if not member_dns:
            logger.info(f"No members found in group {group_dn}")
            return {}
        
        logger.debug(f"Found {len(member_dns)} members in group")
        
        # Now get attributes for each member
        members = {}
        for member_dn in member_dns:
            try:
                success = self.connection.search(
                    search_base=member_dn,
                    search_filter="(objectClass=*)",
                    search_scope='BASE',
                    attributes=self.attributes
                )
                
                if success and self.connection.entries:
                    entry = self.connection.entries[0]
                    user_data = self._extract_user_attributes(entry)
                    if user_data:
                        identifier = self._get_user_identifier(user_data)
                        members[identifier] = user_data
                        
            except Exception as e:
                logger.warning(f"Failed to get attributes for user {member_dn}: {e}")
                continue
        
        return members
    
    def _process_search_results(self) -> Dict[str, Dict[str, Any]]:
        """Process LDAP search results into user dictionary."""
        members = {}
        
        for entry in self.connection.entries:
            user_data = self._extract_user_attributes(entry)
            if user_data:
                identifier = self._get_user_identifier(user_data)
                members[identifier] = user_data
        
        logger.info(f"Retrieved {len(members)} group members")
        return members
    
    def _extract_user_attributes(self, entry) -> Optional[Dict[str, Any]]:
        """Extract user attributes from LDAP entry."""
        try:
            user_data = {
                'dn': str(entry.entry_dn)
            }
            
            # Map LDAP attributes to standard names
            attribute_mapping = {
                'cn': 'common_name',
                'givenName': 'first_name',
                'sn': 'last_name',
                'mail': 'email',
                'sAMAccountName': 'username',
                'uid': 'username'  # For non-AD LDAP
            }
            
            for ldap_attr, std_attr in attribute_mapping.items():
                if hasattr(entry, ldap_attr):
                    value = getattr(entry, ldap_attr).value
                    if value:
                        user_data[std_attr] = value
            
            # Ensure we have at least an identifier
            if not any(key in user_data for key in ['username', 'email']):
                logger.warning(f"User entry has no identifier: {entry.entry_dn}")
                return None
            
            return user_data
            
        except Exception as e:
            logger.warning(f"Failed to extract attributes from entry {entry.entry_dn}: {e}")
            return None
    
    def _get_user_identifier(self, user_data: Dict[str, Any]) -> str:
        """Get primary identifier for user (prefer email, fallback to username)."""
        return user_data.get('email') or user_data.get('username') or user_data.get('common_name', 'unknown')
    
    def _get_domain_base(self) -> str:
        """Extract domain base DN from bind DN or server info."""
        if self.user_base_dn:
            return self.user_base_dn
        
        # Try to extract from bind DN
        if 'DC=' in self.bind_dn.upper():
            parts = self.bind_dn.split(',')
            dc_parts = [part.strip() for part in parts if part.strip().upper().startswith('DC=')]
            if dc_parts:
                return ','.join(dc_parts)
        
        # Fallback to server info if available
        if self.server and self.server.info and self.server.info.naming_contexts:
            return self.server.info.naming_contexts[0]
        
        raise LDAPQueryError("Cannot determine domain base DN")
    
    def test_connection(self) -> bool:
        """
        Test LDAP connection without throwing exceptions.
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            if not self._connected:
                self.connect()
            
            # Simple search to test connectivity
            success = self.connection.search(
                search_base='',
                search_filter='(objectClass=*)',
                search_scope='BASE',
                attributes=['namingContexts'],
                size_limit=1
            )
            return success
        except Exception as e:
            logger.debug(f"Connection test failed: {e}")
            return False
    
    def get_server_info(self) -> Dict[str, Any]:
        """
        Get LDAP server information.
        
        Returns:
            Dictionary with server information
        """
        if not self.server or not self.server.info:
            return {}
        
        info = self.server.info
        return {
            'server_name': getattr(info, 'server_name', 'Unknown'),
            'naming_contexts': getattr(info, 'naming_contexts', []),
            'supported_controls': getattr(info, 'supported_controls', []),
            'supported_extensions': getattr(info, 'supported_extensions', []),
            'vendor_name': getattr(info, 'vendor_name', 'Unknown'),
            'vendor_version': getattr(info, 'vendor_version', 'Unknown')
        }
    
    def validate_group_dn(self, group_dn: str) -> bool:
        """
        Validate that a group DN exists and is accessible.
        
        Args:
            group_dn: Distinguished name of the group to validate
            
        Returns:
            True if group exists and is accessible
        """
        try:
            if not self._connected:
                raise LDAPQueryError("Not connected to LDAP server")
            
            success = self.connection.search(
                search_base=group_dn,
                search_filter="(objectClass=*)",
                search_scope='BASE',
                attributes=['objectClass'],
                size_limit=1
            )
            
            if success and self.connection.entries:
                logger.debug(f"Group DN validated: {group_dn}")
                return True
            else:
                logger.warning(f"Group DN not found or inaccessible: {group_dn}")
                return False
                
        except LDAPException as e:
            logger.error(f"Failed to validate group DN {group_dn}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error validating group DN {group_dn}: {e}")
            return False
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """
        Get connection statistics and status.
        
        Returns:
            Dictionary with connection information
        """
        stats = {
            'connected': self._connected,
            'server_url': self.server_url,
            'use_ssl': self.use_ssl,
            'start_tls': self.start_tls,
            'verify_ssl': self.verify_ssl,
            'bind_dn': self.bind_dn,
            'user_base_dn': self.user_base_dn,
            'page_size': self.page_size
        }
        
        if self.connection:
            stats.update({
                'server_host': getattr(self.connection.server, 'host', None),
                'server_port': getattr(self.connection.server, 'port', None),
                'bound': getattr(self.connection, 'bound', False),
                'tls_started': getattr(self.connection, 'tls_started', False)
            })
        
        return stats
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()