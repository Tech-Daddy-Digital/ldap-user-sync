"""
Configuration loading and management for LDAP User Sync.

This module handles loading configuration from YAML files and environment variables,
with validation and defaults.
"""

import os
import yaml
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class ConfigurationError(Exception):
    """Raised when configuration is invalid or missing required fields."""
    pass


class ConfigLoader:
    """Handles loading and validation of application configuration."""
    
    # Environment variable mappings for sensitive fields
    ENV_OVERRIDES = {
        'ldap.bind_password': 'LDAP_BIND_PASSWORD',
        'notifications.smtp_password': 'SMTP_PASSWORD',
    }
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize config loader.
        
        Args:
            config_path: Path to config file. If None, uses CONFIG_PATH env var or 'config.yaml'
        """
        self.config_path = config_path or os.getenv('CONFIG_PATH', 'config.yaml')
        self.config = {}
    
    def load(self) -> Dict[str, Any]:
        """
        Load configuration from file and apply environment overrides.
        
        Returns:
            Parsed and validated configuration dictionary
            
        Raises:
            ConfigurationError: If config file not found or validation fails
        """
        try:
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        except FileNotFoundError:
            raise ConfigurationError(f"Configuration file not found: {self.config_path}")
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML in config file: {e}")
        
        # Apply environment variable overrides
        self._apply_env_overrides()
        
        # Validate configuration
        self._validate()
        
        # Apply defaults
        self._apply_defaults()
        
        logger.info(f"Configuration loaded successfully from {self.config_path}")
        return self.config
    
    def _apply_env_overrides(self):
        """Apply environment variable overrides for sensitive fields."""
        for config_key, env_var in self.ENV_OVERRIDES.items():
            env_value = os.getenv(env_var)
            if env_value:
                self._set_nested_value(self.config, config_key, env_value)
                logger.debug(f"Applied environment override for {config_key}")
        
        # Apply vendor-specific password overrides
        vendor_apps = self.config.get('vendor_apps', [])
        for i, vendor in enumerate(vendor_apps):
            vendor_name = vendor.get('name', f'vendor_{i}')
            env_var = f"{vendor_name.upper()}_PASSWORD"
            env_value = os.getenv(env_var)
            if env_value and 'auth' in vendor:
                vendor['auth']['password'] = env_value
                logger.debug(f"Applied environment override for {vendor_name} password")
    
    def _set_nested_value(self, config: Dict, key_path: str, value: Any):
        """Set a nested configuration value using dot notation."""
        keys = key_path.split('.')
        current = config
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        current[keys[-1]] = value
    
    def _validate(self):
        """Validate required configuration fields."""
        errors = []
        
        # Validate LDAP configuration
        ldap_config = self.config.get('ldap', {})
        required_ldap_fields = ['server_url', 'bind_dn', 'bind_password']
        for field in required_ldap_fields:
            if not ldap_config.get(field):
                errors.append(f"Missing required LDAP field: {field}")
        
        # Validate vendor applications
        vendor_apps = self.config.get('vendor_apps', [])
        if not vendor_apps:
            errors.append("At least one vendor application must be configured")
        
        for i, vendor in enumerate(vendor_apps):
            vendor_prefix = f"vendor_apps[{i}]"
            required_vendor_fields = ['name', 'module', 'base_url', 'auth', 'groups']
            for field in required_vendor_fields:
                if not vendor.get(field):
                    errors.append(f"Missing required field {vendor_prefix}.{field}")
            
            # Validate auth configuration
            auth = vendor.get('auth', {})
            if auth and not auth.get('method'):
                errors.append(f"Missing auth method for {vendor_prefix}")
            
            # Validate groups configuration
            groups = vendor.get('groups', [])
            if not groups:
                errors.append(f"No groups configured for {vendor_prefix}")
            
            for j, group in enumerate(groups):
                group_prefix = f"{vendor_prefix}.groups[{j}]"
                if not group.get('ldap_group'):
                    errors.append(f"Missing ldap_group for {group_prefix}")
                if not group.get('vendor_group'):
                    errors.append(f"Missing vendor_group for {group_prefix}")
        
        if errors:
            raise ConfigurationError("Configuration validation failed:\n" + "\n".join(f"  - {error}" for error in errors))
    
    def _apply_defaults(self):
        """Apply default values for optional configuration fields."""
        # LDAP defaults
        ldap_defaults = {
            'user_base_dn': '',
            'user_filter': '(objectClass=person)',
            'attributes': ['cn', 'givenName', 'sn', 'mail', 'sAMAccountName']
        }
        ldap_config = self.config.setdefault('ldap', {})
        for key, value in ldap_defaults.items():
            ldap_config.setdefault(key, value)
        
        # Logging defaults
        logging_defaults = {
            'level': 'INFO',
            'log_dir': 'logs',
            'rotation': 'daily',
            'retention_days': 7
        }
        logging_config = self.config.setdefault('logging', {})
        for key, value in logging_defaults.items():
            logging_config.setdefault(key, value)
        
        # Error handling defaults
        error_defaults = {
            'max_retries': 3,
            'retry_wait_seconds': 5,
            'max_errors_per_vendor': 5
        }
        error_config = self.config.setdefault('error_handling', {})
        for key, value in error_defaults.items():
            error_config.setdefault(key, value)
        
        # Notification defaults
        notification_defaults = {
            'enable_email': True,
            'email_on_failure': True,
            'email_on_success': False,
            'smtp_port': 587,
            'smtp_tls': True
        }
        notification_config = self.config.setdefault('notifications', {})
        for key, value in notification_defaults.items():
            notification_config.setdefault(key, value)
        
        # Vendor defaults
        for vendor in self.config.get('vendor_apps', []):
            vendor.setdefault('format', 'json')
            vendor.setdefault('verify_ssl', True)


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Convenience function to load configuration.
    
    Args:
        config_path: Path to config file
        
    Returns:
        Loaded configuration dictionary
    """
    loader = ConfigLoader(config_path)
    return loader.load()