"""
Main orchestrator for LDAP User Sync application.

This module contains the core synchronization logic that coordinates between
LDAP and vendor systems to keep user accounts and group memberships in sync.
"""

import sys
import logging
import importlib
from typing import Dict, Any, List, Optional
from ldap_sync.config import load_config, ConfigurationError
from ldap_sync.ldap_client import LDAPClient, LDAPConnectionError, LDAPQueryError

logger = logging.getLogger(__name__)


class SyncError(Exception):
    """Base exception for sync errors."""
    pass


class SyncOrchestrator:
    """
    Main orchestrator for LDAP to vendor synchronization.
    
    Coordinates the sync process across multiple vendors and handles errors gracefully.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize sync orchestrator.
        
        Args:
            config_path: Path to configuration file
        """
        self.config = None
        self.ldap_client = None
        self.config_path = config_path
        
        # Sync statistics
        self.sync_stats = {
            'vendors_processed': 0,
            'vendors_failed': 0,
            'total_users_added': 0,
            'total_users_removed': 0,
            'total_users_updated': 0,
            'total_errors': 0
        }
    
    def run(self) -> int:
        """
        Run the complete synchronization process.
        
        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        try:
            # Load configuration
            self._load_configuration()
            
            # Setup logging
            self._setup_logging()
            
            logger.info("Starting LDAP User Sync")
            
            # Connect to LDAP
            self._connect_ldap()
            
            # Process each vendor
            self._process_vendors()
            
            # Log final statistics
            self._log_sync_summary()
            
            # Determine exit code
            if self.sync_stats['vendors_failed'] > 0:
                logger.warning(f"Sync completed with {self.sync_stats['vendors_failed']} vendor failures")
                return 1
            else:
                logger.info("Sync completed successfully")
                return 0
        
        except ConfigurationError as e:
            logger.error(f"Configuration error: {e}")
            return 2
        except LDAPConnectionError as e:
            logger.error(f"LDAP connection error: {e}")
            self._send_failure_notification("LDAP Connection Failed", str(e))
            return 3
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            self._send_failure_notification("Sync Failed", f"Unexpected error: {e}")
            return 4
        finally:
            self._cleanup()
    
    def _load_configuration(self):
        """Load and validate configuration."""
        try:
            self.config = load_config(self.config_path)
            logger.debug("Configuration loaded successfully")
        except Exception as e:
            raise ConfigurationError(f"Failed to load configuration: {e}")
    
    def _setup_logging(self):
        """Configure logging based on configuration."""
        logging_config = self.config.get('logging', {})
        
        # Create log directory
        import os
        log_dir = logging_config.get('log_dir', 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        # Configure logging
        log_level = getattr(logging, logging_config.get('level', 'INFO').upper())
        log_format = '%(asctime)s [%(levelname)s] %(name)s - %(message)s'
        
        # File handler with rotation
        from logging.handlers import TimedRotatingFileHandler
        file_handler = TimedRotatingFileHandler(
            filename=os.path.join(log_dir, 'app.log'),
            when='midnight',
            interval=1,
            backupCount=logging_config.get('retention_days', 7)
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(logging.Formatter(log_format))
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        console_handler.setFormatter(logging.Formatter(log_format))
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        root_logger.addHandler(file_handler)
        root_logger.addHandler(console_handler)
        
        logger.info("Logging configured successfully")
    
    def _connect_ldap(self):
        """Establish LDAP connection."""
        ldap_config = self.config['ldap']
        error_config = self.config.get('error_handling', {})
        
        self.ldap_client = LDAPClient(ldap_config)
        
        try:
            self.ldap_client.connect(
                max_retries=error_config.get('max_retries', 3),
                retry_wait=error_config.get('retry_wait_seconds', 5)
            )
        except LDAPConnectionError:
            self.ldap_client = None
            raise
    
    def _process_vendors(self):
        """Process synchronization for each configured vendor."""
        vendor_apps = self.config.get('vendor_apps', [])
        
        for vendor_config in vendor_apps:
            try:
                self._process_vendor(vendor_config)
                self.sync_stats['vendors_processed'] += 1
                
            except Exception as e:
                logger.error(f"Failed to process vendor {vendor_config.get('name', 'unknown')}: {e}")
                self.sync_stats['vendors_failed'] += 1
                
                # Send notification for vendor failure
                self._send_failure_notification(
                    f"Vendor Sync Failed: {vendor_config.get('name', 'unknown')}",
                    str(e)
                )
    
    def _process_vendor(self, vendor_config: Dict[str, Any]):
        """Process synchronization for a single vendor."""
        vendor_name = vendor_config['name']
        logger.info(f"Processing vendor: {vendor_name}")
        
        # Load vendor module
        vendor_api = self._load_vendor_module(vendor_config)
        
        # Authenticate with vendor
        if not vendor_api.authenticate():
            raise SyncError(f"Authentication failed for vendor {vendor_name}")
        
        # Track errors for this vendor
        vendor_errors = 0
        max_errors = self.config.get('error_handling', {}).get('max_errors_per_vendor', 5)
        
        # Process each group mapping
        groups = vendor_config.get('groups', [])
        for group_config in groups:
            try:
                added, removed, updated = self._sync_group(vendor_api, group_config)
                
                # Update statistics
                self.sync_stats['total_users_added'] += added
                self.sync_stats['total_users_removed'] += removed
                self.sync_stats['total_users_updated'] += updated
                
                logger.info(f"Group {group_config['ldap_group']}: "
                          f"{added} added, {removed} removed, {updated} updated")
                
            except Exception as e:
                vendor_errors += 1
                self.sync_stats['total_errors'] += 1
                logger.error(f"Error syncing group {group_config.get('ldap_group', 'unknown')}: {e}")
                
                # Check if we should abort this vendor
                if vendor_errors >= max_errors:
                    logger.error(f"Aborting vendor {vendor_name} due to too many errors ({vendor_errors})")
                    raise SyncError(f"Too many errors for vendor {vendor_name}")
        
        vendor_api.close_connection()
        logger.info(f"Completed vendor: {vendor_name}")
    
    def _load_vendor_module(self, vendor_config: Dict[str, Any]):
        """Dynamically load vendor module and create API instance."""
        module_name = vendor_config['module']
        vendor_name = vendor_config['name']
        
        try:
            # Import vendor module
            full_module_name = f"ldap_sync.vendors.{module_name}"
            vendor_module = importlib.import_module(full_module_name)
            
            # Find vendor API class (look for subclass of VendorAPIBase)
            from ldap_sync.vendors.base import VendorAPIBase
            
            vendor_class = None
            for attr_name in dir(vendor_module):
                attr = getattr(vendor_module, attr_name)
                if (isinstance(attr, type) and 
                    issubclass(attr, VendorAPIBase) and 
                    attr != VendorAPIBase):
                    vendor_class = attr
                    break
            
            if not vendor_class:
                raise SyncError(f"No VendorAPIBase subclass found in module {module_name}")
            
            # Create vendor API instance
            return vendor_class(vendor_config)
        
        except ImportError as e:
            raise SyncError(f"Failed to import vendor module {module_name}: {e}")
        except Exception as e:
            raise SyncError(f"Failed to initialize vendor {vendor_name}: {e}")
    
    def _sync_group(self, vendor_api, group_config: Dict[str, Any]) -> tuple:
        """
        Synchronize a single group between LDAP and vendor.
        
        Returns:
            Tuple of (users_added, users_removed, users_updated)
        """
        ldap_group = group_config['ldap_group']
        vendor_group = group_config['vendor_group']
        
        logger.info(f"Syncing group: {ldap_group} -> {vendor_group}")
        
        # Get LDAP group members
        ldap_members = self.ldap_client.get_group_members(ldap_group)
        logger.debug(f"LDAP group has {len(ldap_members)} members")
        
        # Get vendor group members
        vendor_members = vendor_api.get_group_members(group_config)
        logger.debug(f"Vendor group has {len(vendor_members)} members")
        
        # Convert to sets for comparison (using email as primary identifier)
        ldap_identifiers = set(ldap_members.keys())
        vendor_identifiers = {self._get_user_identifier(user) for user in vendor_members}
        
        # Determine changes needed
        to_add = ldap_identifiers - vendor_identifiers
        to_remove = vendor_identifiers - ldap_identifiers
        to_check_update = ldap_identifiers & vendor_identifiers
        
        logger.debug(f"Changes needed: {len(to_add)} to add, {len(to_remove)} to remove, "
                    f"{len(to_check_update)} to check for updates")
        
        # Execute changes
        users_added = self._add_users(vendor_api, group_config, to_add, ldap_members)
        users_removed = self._remove_users(vendor_api, group_config, to_remove)
        users_updated = self._update_users(vendor_api, group_config, to_check_update, 
                                         ldap_members, vendor_members)
        
        return users_added, users_removed, users_updated
    
    def _get_user_identifier(self, user_data: Dict[str, Any]) -> str:
        """Get primary identifier for user (prefer email, fallback to username)."""
        return user_data.get('email') or user_data.get('username') or user_data.get('id', 'unknown')
    
    def _add_users(self, vendor_api, group_config: Dict[str, Any], 
                   user_identifiers: set, ldap_members: Dict[str, Any]) -> int:
        """Add users to vendor group."""
        added_count = 0
        error_config = self.config.get('error_handling', {})
        
        for identifier in user_identifiers:
            user_info = ldap_members[identifier]
            
            try:
                if self._retry_operation(
                    lambda: vendor_api.add_user_to_group(group_config, user_info),
                    error_config
                ):
                    added_count += 1
                    logger.info(f"Added user {identifier} to vendor group")
            except Exception as e:
                logger.error(f"Failed to add user {identifier}: {e}")
        
        return added_count
    
    def _remove_users(self, vendor_api, group_config: Dict[str, Any], 
                      user_identifiers: set) -> int:
        """Remove users from vendor group."""
        removed_count = 0
        error_config = self.config.get('error_handling', {})
        
        for identifier in user_identifiers:
            try:
                if self._retry_operation(
                    lambda: vendor_api.remove_user_from_group(group_config, identifier),
                    error_config
                ):
                    removed_count += 1
                    logger.info(f"Removed user {identifier} from vendor group")
            except Exception as e:
                logger.error(f"Failed to remove user {identifier}: {e}")
        
        return removed_count
    
    def _update_users(self, vendor_api, group_config: Dict[str, Any], 
                      user_identifiers: set, ldap_members: Dict[str, Any],
                      vendor_members: List[Dict[str, Any]]) -> int:
        """Update users that exist in both systems."""
        updated_count = 0
        error_config = self.config.get('error_handling', {})
        
        # Create vendor members lookup
        vendor_lookup = {self._get_user_identifier(user): user for user in vendor_members}
        
        for identifier in user_identifiers:
            ldap_user = ldap_members[identifier]
            vendor_user = vendor_lookup.get(identifier)
            
            if not vendor_user:
                continue
            
            # Check if update is needed
            if self._user_needs_update(ldap_user, vendor_user):
                try:
                    if self._retry_operation(
                        lambda: vendor_api.update_user(identifier, ldap_user),
                        error_config
                    ):
                        updated_count += 1
                        logger.info(f"Updated user {identifier}")
                except Exception as e:
                    logger.error(f"Failed to update user {identifier}: {e}")
        
        return updated_count
    
    def _user_needs_update(self, ldap_user: Dict[str, Any], vendor_user: Dict[str, Any]) -> bool:
        """Check if user attributes need updating."""
        # Compare key attributes
        fields_to_compare = ['first_name', 'last_name', 'email']
        
        for field in fields_to_compare:
            ldap_value = ldap_user.get(field, '').strip()
            vendor_value = vendor_user.get(field, '').strip()
            
            if ldap_value and ldap_value != vendor_value:
                logger.debug(f"User {ldap_user.get('email', 'unknown')} needs update: "
                           f"{field} '{vendor_value}' -> '{ldap_value}'")
                return True
        
        return False
    
    def _retry_operation(self, operation, error_config: Dict[str, Any]) -> bool:
        """Retry an operation with configured retry logic."""
        import time
        
        max_retries = error_config.get('max_retries', 3)
        retry_wait = error_config.get('retry_wait_seconds', 5)
        
        last_exception = None
        for attempt in range(max_retries):
            try:
                return operation()
            except Exception as e:
                last_exception = e
                if attempt < max_retries - 1:
                    logger.debug(f"Operation failed (attempt {attempt + 1}/{max_retries}), retrying in {retry_wait}s: {e}")
                    time.sleep(retry_wait)
        
        # All retries failed
        raise last_exception
    
    def _send_failure_notification(self, subject: str, body: str):
        """Send email notification for failures."""
        try:
            notifications_config = self.config.get('notifications', {})
            if not notifications_config.get('enable_email', True):
                return
            
            if not notifications_config.get('email_on_failure', True):
                return
            
            # Import notification module (will be implemented later)
            # from ldap_sync.notifications import send_email
            # send_email(subject, body, notifications_config)
            
            logger.info(f"Would send notification: {subject}")
            
        except Exception as e:
            logger.error(f"Failed to send notification: {e}")
    
    def _log_sync_summary(self):
        """Log final synchronization statistics."""
        stats = self.sync_stats
        logger.info("=== Sync Summary ===")
        logger.info(f"Vendors processed: {stats['vendors_processed']}")
        logger.info(f"Vendors failed: {stats['vendors_failed']}")
        logger.info(f"Total users added: {stats['total_users_added']}")
        logger.info(f"Total users removed: {stats['total_users_removed']}")
        logger.info(f"Total users updated: {stats['total_users_updated']}")
        logger.info(f"Total errors: {stats['total_errors']}")
    
    def _cleanup(self):
        """Clean up resources."""
        if self.ldap_client:
            self.ldap_client.disconnect()


def main():
    """Main entry point for the application."""
    orchestrator = SyncOrchestrator()
    exit_code = orchestrator.run()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()