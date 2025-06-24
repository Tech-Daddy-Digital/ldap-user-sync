"""
Logging setup and configuration for LDAP User Sync.

This module provides centralized logging configuration with features required
by the LDAP User Sync application including file rotation, retention policies,
and container-friendly output.
"""

import os
import logging
import logging.handlers
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import glob


class SensitiveDataFilter(logging.Filter):
    """Filter to scrub sensitive data from log messages."""
    
    SENSITIVE_KEYWORDS = [
        'password', 'bind_password', 'smtp_password', 'token', 'secret', 'key', 
        'auth', 'credential', 'pass', 'pwd', 'authorization', 'bearer',
        'api_key', 'client_secret', 'access_token', 'refresh_token'
    ]
    
    def filter(self, record):
        """Filter out sensitive data from log records."""
        if hasattr(record, 'msg'):
            # Convert message to string if it's not already
            msg = str(record.msg)
            
            # Check if message contains sensitive keywords and filter them
            import re
            
            # Pattern for key=value (simple assignment)
            for keyword in self.SENSITIVE_KEYWORDS:
                pattern1 = rf'({keyword}\s*=\s*)[^\s,}}\]]+(\s|,|$)'
                msg = re.sub(pattern1, r'\1****\2', msg, flags=re.IGNORECASE)
            
            # Pattern for "key": "value" in JSON (handles quoted values)
            for keyword in self.SENSITIVE_KEYWORDS:
                pattern2 = rf'("{keyword}"\s*:\s*")[^"]*(")'
                msg = re.sub(pattern2, r'\1****\2', msg, flags=re.IGNORECASE)
                
                # Also handle unquoted JSON values
                pattern3 = rf'("{keyword}"\s*:\s*)([^",}}\s]+)(\s*[,}}\]])'
                msg = re.sub(pattern3, r'\1****\3', msg, flags=re.IGNORECASE)
            
            # Pattern for Authorization: Bearer token
            msg = re.sub(r'(Authorization:\s*Bearer\s+)[^\s,}}\]]+(\s|,|$)', r'\1****\2', msg, flags=re.IGNORECASE)
            
            # Pattern for Authorization: Basic token  
            msg = re.sub(r'(Authorization:\s*Basic\s+)[^\s,}}\]]+(\s|,|$)', r'\1****\2', msg, flags=re.IGNORECASE)
            
            record.msg = msg
        
        return True


class LoggingManager:
    """
    Manages logging configuration for the LDAP User Sync application.
    
    Provides file-based logging with rotation, retention policies, and
    container-friendly console output.
    """
    
    def __init__(self):
        self.configured = False
        self.log_dir = None
        self.retention_days = 7
        
    def setup_logging(self, config: Dict[str, Any]) -> None:
        """
        Set up logging based on configuration.
        
        Args:
            config: Logging configuration dictionary
        """
        if self.configured:
            return
            
        logging_config = config if config else {}
        
        # Extract configuration values
        log_level = logging_config.get('level', 'INFO').upper()
        self.log_dir = logging_config.get('log_dir', 'logs')
        rotation = logging_config.get('rotation', 'daily')
        self.retention_days = logging_config.get('retention_days', 7)
        console_enabled = logging_config.get('console_output', True)
        console_level = logging_config.get('console_level', 'WARNING').upper()
        
        # Create log directory
        self._ensure_log_directory()
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, log_level, logging.INFO))
        
        # Clear any existing handlers
        root_logger.handlers.clear()
        
        # Create formatters
        detailed_formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        console_formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%H:%M:%S'
        )
        
        # Add sensitive data filter
        sensitive_filter = SensitiveDataFilter()
        
        # Set up file handler with rotation
        file_handler = self._create_file_handler(rotation)
        file_handler.setLevel(getattr(logging, log_level, logging.INFO))
        file_handler.setFormatter(detailed_formatter)
        file_handler.addFilter(sensitive_filter)
        root_logger.addHandler(file_handler)
        
        # Set up console handler if enabled
        if console_enabled:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(getattr(logging, console_level, logging.WARNING))
            console_handler.setFormatter(console_formatter)
            console_handler.addFilter(sensitive_filter)
            root_logger.addHandler(console_handler)
        
        # Clean up old log files
        self._cleanup_old_logs()
        
        self.configured = True
        
        # Log successful configuration
        logger = logging.getLogger(__name__)
        logger.info(f"Logging configured: level={log_level}, dir={self.log_dir}, "
                   f"retention={self.retention_days} days, console={console_enabled}")
    
    def _ensure_log_directory(self) -> None:
        """Ensure the log directory exists."""
        if self.log_dir and not os.path.exists(self.log_dir):
            try:
                os.makedirs(self.log_dir, exist_ok=True)
            except OSError as e:
                # Fallback to current directory if log directory creation fails
                print(f"Warning: Could not create log directory {self.log_dir}: {e}")
                print("Falling back to current directory for logs")
                self.log_dir = '.'
    
    def _create_file_handler(self, rotation: str) -> logging.Handler:
        """
        Create appropriate file handler based on rotation setting.
        
        Args:
            rotation: Rotation setting ('daily', 'midnight', or 'none')
            
        Returns:
            Configured logging handler
        """
        log_file = os.path.join(self.log_dir, 'app.log')
        
        if rotation.lower() in ['daily', 'midnight']:
            # Use TimedRotatingFileHandler for daily rotation
            handler = logging.handlers.TimedRotatingFileHandler(
                filename=log_file,
                when='midnight',
                interval=1,
                backupCount=self.retention_days,
                encoding='utf-8'
            )
            # Set suffix for rotated files
            handler.suffix = '%Y-%m-%d'
        else:
            # Use regular FileHandler without rotation
            handler = logging.FileHandler(log_file, encoding='utf-8')
        
        return handler
    
    def _cleanup_old_logs(self) -> None:
        """Clean up log files older than retention period."""
        if not self.log_dir or self.retention_days <= 0:
            return
        
        try:
            # Calculate cutoff date
            cutoff_date = datetime.now() - timedelta(days=self.retention_days)
            
            # Find all log files
            log_pattern = os.path.join(self.log_dir, 'app.log*')
            log_files = glob.glob(log_pattern)
            
            for log_file in log_files:
                try:
                    # Skip the current log file
                    if log_file.endswith('app.log'):
                        continue
                    
                    # Check file modification time
                    file_time = datetime.fromtimestamp(os.path.getmtime(log_file))
                    if file_time < cutoff_date:
                        os.remove(log_file)
                        print(f"Removed old log file: {log_file}")
                        
                except (OSError, ValueError) as e:
                    print(f"Warning: Could not remove old log file {log_file}: {e}")
                    
        except Exception as e:
            print(f"Warning: Error during log cleanup: {e}")
    
    def get_log_files(self) -> list:
        """
        Get list of current log files.
        
        Returns:
            List of log file paths
        """
        if not self.log_dir:
            return []
        
        log_pattern = os.path.join(self.log_dir, 'app.log*')
        return sorted(glob.glob(log_pattern))
    
    def get_log_stats(self) -> Dict[str, Any]:
        """
        Get statistics about current logging setup.
        
        Returns:
            Dictionary with logging statistics
        """
        log_files = self.get_log_files()
        total_size = 0
        
        for log_file in log_files:
            try:
                total_size += os.path.getsize(log_file)
            except OSError:
                pass
        
        return {
            'configured': self.configured,
            'log_directory': self.log_dir,
            'retention_days': self.retention_days,
            'log_files_count': len(log_files),
            'total_size_bytes': total_size,
            'total_size_mb': round(total_size / (1024 * 1024), 2)
        }


# Global logging manager instance
_logging_manager = LoggingManager()


def setup_logging(config: Dict[str, Any]) -> None:
    """
    Convenience function to set up logging.
    
    Args:
        config: Logging configuration dictionary
    """
    _logging_manager.setup_logging(config)


def get_logging_stats() -> Dict[str, Any]:
    """
    Get logging statistics.
    
    Returns:
        Dictionary with logging statistics
    """
    return _logging_manager.get_log_stats()


def cleanup_logs() -> None:
    """Force cleanup of old log files."""
    _logging_manager._cleanup_old_logs()


def create_logger(name: str) -> logging.Logger:
    """
    Create a logger with the given name.
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        Configured logger instance
    """
    return logging.getLogger(name)


class SecurityAuditLogger:
    """Special logger for security-related events."""
    
    def __init__(self):
        self.logger = logging.getLogger('security')
    
    def log_authentication_attempt(self, system: str, username: str, success: bool):
        """Log authentication attempts."""
        status = "SUCCESS" if success else "FAILURE"
        self.logger.info(f"Authentication {status}: {system} user={username}")
    
    def log_user_operation(self, operation: str, user_id: str, vendor: str, success: bool):
        """Log user operations for audit trail."""
        status = "SUCCESS" if success else "FAILURE"
        self.logger.info(f"User operation {status}: {operation} user={user_id} vendor={vendor}")
    
    def log_configuration_access(self, config_file: str):
        """Log configuration file access."""
        self.logger.info(f"Configuration loaded: {config_file}")
    
    def log_security_event(self, event: str, details: str = ""):
        """Log general security events."""
        message = f"Security event: {event}"
        if details:
            message += f" - {details}"
        self.logger.warning(message)


# Global security logger instance
security_logger = SecurityAuditLogger()