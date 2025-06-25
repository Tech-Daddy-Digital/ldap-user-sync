"""
Main orchestrator for LDAP User Sync application.

This module contains the core synchronization logic that coordinates between
LDAP and vendor systems to keep user accounts and group memberships in sync.
"""

import sys
import os
import time
import logging
import importlib
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from ldap_sync.config import load_config, ConfigurationError
from ldap_sync.ldap_client import LDAPClient, LDAPConnectionError, LDAPQueryError
from ldap_sync.retry import retry_call, is_retryable_error, create_retry_callback
from ldap_sync.notifications import (
    send_failure_notification, 
    send_vendor_error_notification,
    send_ldap_connection_failure,
    send_success_summary
)

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
        
        # Sync statistics and timing
        self.sync_stats = {
            'vendors_processed': 0,
            'vendors_failed': 0,
            'total_users_added': 0,
            'total_users_removed': 0,
            'total_users_updated': 0,
            'total_errors': 0,
            'start_time': None,
            'end_time': None,
            'runtime_seconds': 0,
            'vendor_details': {}
        }
        
        # Track errors per vendor for notifications
        self.vendor_errors = {}
    
    def run(self) -> int:
        """
        Run the complete synchronization process.
        
        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        try:
            # Record start time
            self.sync_stats['start_time'] = datetime.now()
            
            # Load configuration
            self._load_configuration()
            
            # Setup logging
            self._setup_logging()
            
            logger.info("Starting LDAP User Sync")
            
            # Connect to LDAP
            self._connect_ldap()
            
            # Process each vendor
            self._process_vendors()
            
            # Calculate runtime
            self.sync_stats['end_time'] = datetime.now()
            self.sync_stats['runtime_seconds'] = (
                self.sync_stats['end_time'] - self.sync_stats['start_time']
            ).total_seconds()
            
            # Log final statistics
            self._log_sync_summary()
            
            # Send success notification if configured
            self._send_success_notification()
            
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
            self._send_ldap_connection_failure(str(e))
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
        vendor_start_time = datetime.now()
        logger.info(f"Processing vendor: {vendor_name}")
        
        # Initialize vendor statistics
        vendor_stats = {
            'start_time': vendor_start_time,
            'groups_processed': 0,
            'groups_failed': 0,
            'users_added': 0,
            'users_removed': 0,
            'users_updated': 0,
            'errors': 0,
            'runtime_seconds': 0
        }
        
        try:
            # Load vendor module
            vendor_api = self._load_vendor_module(vendor_config)
            
            # Authenticate with vendor
            if not vendor_api.authenticate():
                raise SyncError(f"Authentication failed for vendor {vendor_name}")
            
            # Track errors for this vendor
            vendor_errors = 0
            vendor_error_messages = []
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
                    
                    vendor_stats['users_added'] += added
                    vendor_stats['users_removed'] += removed
                    vendor_stats['users_updated'] += updated
                    vendor_stats['groups_processed'] += 1
                    
                    logger.info(f"Group {group_config['ldap_group']}: "
                              f"{added} added, {removed} removed, {updated} updated")
                    
                except Exception as e:
                    vendor_errors += 1
                    vendor_stats['errors'] += 1
                    vendor_stats['groups_failed'] += 1
                    self.sync_stats['total_errors'] += 1
                    error_msg = f"Error syncing group {group_config.get('ldap_group', 'unknown')}: {e}"
                    vendor_error_messages.append(error_msg)
                    logger.error(error_msg)
                    
                    # Check if we should abort this vendor
                    if vendor_errors >= max_errors:
                        logger.error(f"Aborting vendor {vendor_name} due to too many errors ({vendor_errors})")
                        # Send vendor-specific error notification
                        self._send_vendor_error_notification(vendor_name, vendor_errors, vendor_error_messages)
                        raise SyncError(f"Too many errors for vendor {vendor_name}")
            
            vendor_api.close_connection()
            
        finally:
            # Calculate vendor runtime
            vendor_end_time = datetime.now()
            vendor_stats['end_time'] = vendor_end_time
            vendor_stats['runtime_seconds'] = (vendor_end_time - vendor_start_time).total_seconds()
            
            # Store vendor statistics
            self.sync_stats['vendor_details'][vendor_name] = vendor_stats
            
            logger.info(f"Completed vendor: {vendor_name} in {vendor_stats['runtime_seconds']:.2f} seconds")
    
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
        max_retries = error_config.get('max_retries', 3)
        retry_wait = error_config.get('retry_wait_seconds', 5)
        
        # Use retry utility with callback for logging
        callback = create_retry_callback("Vendor API operation")
        
        try:
            return retry_call(
                operation,
                max_attempts=max_retries + 1,  # +1 for initial attempt
                delay=retry_wait,
                backoff=1.0,  # No exponential backoff for API calls
                exceptions=(Exception,),  # Retry all exceptions
                on_retry=callback
            )
        except Exception as e:
            # Check if this was a retryable error
            if is_retryable_error(e):
                logger.warning(f"Retryable error after {max_retries} attempts: {e}")
            else:
                logger.debug(f"Non-retryable error: {e}")
            raise
    
    def _send_failure_notification(self, title: str, error_message: str):
        """Send email notification for failures."""
        try:
            notifications_config = self.config.get('notifications', {})
            send_failure_notification(title, error_message, notifications_config)
        except Exception as e:
            logger.error(f"Failed to send failure notification: {e}")
    
    def _send_vendor_error_notification(self, vendor_name: str, error_count: int, errors: List[str]):
        """Send email notification for vendor errors."""
        try:
            notifications_config = self.config.get('notifications', {})
            send_vendor_error_notification(vendor_name, error_count, errors, notifications_config)
        except Exception as e:
            logger.error(f"Failed to send vendor error notification: {e}")
    
    def _send_ldap_connection_failure(self, error_message: str):
        """Send email notification for LDAP connection failure."""
        try:
            notifications_config = self.config.get('notifications', {})
            retry_count = self.config.get('error_handling', {}).get('max_retries', 3)
            send_ldap_connection_failure(error_message, notifications_config, retry_count)
        except Exception as e:
            logger.error(f"Failed to send LDAP failure notification: {e}")
    
    def _send_success_notification(self):
        """Send email notification for successful sync."""
        try:
            notifications_config = self.config.get('notifications', {})
            send_success_summary(self.sync_stats, notifications_config)
        except Exception as e:
            logger.error(f"Failed to send success notification: {e}")
    
    def _log_sync_summary(self):
        """Log final synchronization statistics."""
        stats = self.sync_stats
        
        # Format runtime
        runtime_str = f"{stats['runtime_seconds']:.2f} seconds"
        if stats['runtime_seconds'] > 60:
            minutes = int(stats['runtime_seconds'] // 60)
            seconds = stats['runtime_seconds'] % 60
            runtime_str = f"{minutes}m {seconds:.1f}s"
        
        logger.info("=== Sync Summary ===")
        logger.info(f"Total runtime: {runtime_str}")
        logger.info(f"Vendors processed: {stats['vendors_processed']}")
        logger.info(f"Vendors failed: {stats['vendors_failed']}")
        logger.info(f"Total users added: {stats['total_users_added']}")
        logger.info(f"Total users removed: {stats['total_users_removed']}")
        logger.info(f"Total users updated: {stats['total_users_updated']}")
        logger.info(f"Total errors: {stats['total_errors']}")
        
        # Log detailed vendor statistics
        for vendor_name, vendor_stats in stats.get('vendor_details', {}).items():
            logger.info(f"--- {vendor_name} Details ---")
            logger.info(f"  Runtime: {vendor_stats['runtime_seconds']:.2f}s")
            logger.info(f"  Groups processed: {vendor_stats['groups_processed']}")
            logger.info(f"  Groups failed: {vendor_stats['groups_failed']}")
            logger.info(f"  Users added: {vendor_stats['users_added']}")
            logger.info(f"  Users removed: {vendor_stats['users_removed']}")
            logger.info(f"  Users updated: {vendor_stats['users_updated']}")
            logger.info(f"  Errors: {vendor_stats['errors']}")
    
    def health_check(self) -> Dict[str, Any]:
        """
        Perform a health check of the sync system.
        
        Returns:
            Dictionary containing health status and details
        """
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'checks': {}
        }
        
        try:
            # Load configuration
            self._load_configuration()
            health_status['checks']['configuration'] = {
                'status': 'pass',
                'message': 'Configuration loaded successfully'
            }
        except Exception as e:
            health_status['checks']['configuration'] = {
                'status': 'fail',
                'message': f'Configuration error: {e}'
            }
            health_status['status'] = 'unhealthy'
        
        # Test LDAP connectivity if config is available
        if self.config:
            try:
                ldap_config = self.config['ldap']
                test_client = LDAPClient(ldap_config)
                test_client.connect(max_retries=1, retry_wait=1)
                test_client.disconnect()
                
                health_status['checks']['ldap'] = {
                    'status': 'pass',
                    'message': 'LDAP connection successful'
                }
            except Exception as e:
                health_status['checks']['ldap'] = {
                    'status': 'fail',
                    'message': f'LDAP connection failed: {e}'
                }
                health_status['status'] = 'unhealthy'
            
            # Test vendor module loading
            vendor_checks = {}
            for vendor_config in self.config.get('vendor_apps', []):
                vendor_name = vendor_config['name']
                try:
                    self._load_vendor_module(vendor_config)
                    vendor_checks[vendor_name] = {
                        'status': 'pass',
                        'message': 'Module loaded successfully'
                    }
                except Exception as e:
                    vendor_checks[vendor_name] = {
                        'status': 'fail',
                        'message': f'Module loading failed: {e}'
                    }
                    health_status['status'] = 'unhealthy'
            
            health_status['checks']['vendors'] = vendor_checks
            
            # Test email notifications if configured
            notifications_config = self.config.get('notifications', {})
            if notifications_config.get('enable_email', False):
                try:
                    # Just validate configuration, don't actually send test email
                    required_fields = ['smtp_server', 'email_from', 'email_to']
                    missing_fields = [f for f in required_fields if not notifications_config.get(f)]
                    
                    if missing_fields:
                        raise ValueError(f"Missing notification config: {missing_fields}")
                    
                    health_status['checks']['notifications'] = {
                        'status': 'pass',
                        'message': 'Email notification configuration valid'
                    }
                except Exception as e:
                    health_status['checks']['notifications'] = {
                        'status': 'fail',
                        'message': f'Notification configuration invalid: {e}'
                    }
                    health_status['status'] = 'unhealthy'
            else:
                health_status['checks']['notifications'] = {
                    'status': 'skip',
                    'message': 'Email notifications disabled'
                }
        
        return health_status
    
    def _cleanup(self):
        """Clean up resources."""
        if self.ldap_client:
            self.ldap_client.disconnect()


def main():
    """Main entry point for the application."""
    import argparse
    import json
    
    parser = argparse.ArgumentParser(description='LDAP User Sync Application')
    parser.add_argument('--config', '-c', help='Path to configuration file')
    parser.add_argument('--health-check', action='store_true', 
                       help='Perform health check instead of sync')
    parser.add_argument('--test-email', action='store_true',
                       help='Send test email notification')
    
    args = parser.parse_args()
    
    orchestrator = SyncOrchestrator(config_path=args.config)
    
    if args.health_check:
        # Perform health check
        health_status = orchestrator.health_check()
        print(json.dumps(health_status, indent=2))
        
        # Exit with non-zero code if unhealthy
        if health_status['status'] != 'healthy':
            sys.exit(1)
        else:
            sys.exit(0)
    
    elif args.test_email:
        # Test email notification
        try:
            orchestrator._load_configuration()
            notifications_config = orchestrator.config.get('notifications', {})
            
            from ldap_sync.notifications import test_notification_config
            if test_notification_config(notifications_config):
                print("Test email sent successfully")
                sys.exit(0)
            else:
                print("Failed to send test email")
                sys.exit(1)
        except Exception as e:
            print(f"Error testing email: {e}")
            sys.exit(1)
    
    else:
        # Normal sync operation
        exit_code = orchestrator.run()
        sys.exit(exit_code)


if __name__ == "__main__":
    main()