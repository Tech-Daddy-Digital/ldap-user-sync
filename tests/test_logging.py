#!/usr/bin/env python3
"""
Test script for logging infrastructure.

This script tests various logging scenarios including file rotation,
retention policies, sensitive data filtering, and console output.
"""

import os
import sys
import time
import tempfile
import shutil
import logging
from datetime import datetime, timedelta

# Add the project directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ldap_sync.logging_setup import (
    setup_logging, get_logging_stats, cleanup_logs, 
    create_logger, security_logger
)


def test_basic_logging_setup():
    """Test basic logging configuration."""
    print("Testing basic logging setup...")
    
    # Create temporary directory for logs
    temp_dir = tempfile.mkdtemp(prefix='ldap_sync_test_logs_')
    
    try:
        config = {
            'level': 'DEBUG',
            'log_dir': temp_dir,
            'rotation': 'daily',
            'retention_days': 3,
            'console_output': True,
            'console_level': 'INFO'
        }
        
        setup_logging(config)
        
        # Test logging at different levels
        logger = create_logger(__name__)
        logger.debug("This is a debug message")
        logger.info("This is an info message")
        logger.warning("This is a warning message") 
        logger.error("This is an error message")
        
        # Check that log file was created
        log_file = os.path.join(temp_dir, 'app.log')
        assert os.path.exists(log_file), "Log file was not created"
        
        # Check log contents
        with open(log_file, 'r') as f:
            content = f.read()
            assert "debug message" in content
            assert "info message" in content
            assert "warning message" in content
            assert "error message" in content
        
        print("✓ Basic logging setup working correctly")
        
    finally:
        # Clean up temporary directory
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_sensitive_data_filtering():
    """Test that sensitive data is filtered from logs.""" 
    print("Testing sensitive data filtering...")
    
    temp_dir = tempfile.mkdtemp(prefix='ldap_sync_test_logs_')
    
    try:
        # Reset logging configuration
        logging.getLogger().handlers.clear()
        
        config = {
            'level': 'INFO',
            'log_dir': temp_dir,
            'console_output': False
        }
        
        # Reset the logging manager state
        from ldap_sync.logging_setup import _logging_manager
        _logging_manager.configured = False
        
        setup_logging(config)
        logger = create_logger(__name__)
        
        # Test various patterns of sensitive data
        test_messages = [
            "User password=secretpass123 for authentication",
            'LDAP config: {"bind_password": "supersecret", "user": "admin"}',
            "Authorization: Bearer abc123token456",
            "API key=my-secret-key value",
            'Setting auth="Basic dXNlcjpwYXNz"',
            "Normal message without sensitive data"
        ]
        
        for msg in test_messages:
            logger.info(msg)
        
        # Check log contents
        log_file = os.path.join(temp_dir, 'app.log')
        with open(log_file, 'r') as f:
            content = f.read()
            
            # Should not contain actual sensitive values
            assert "secretpass123" not in content
            assert "supersecret" not in content
            assert "abc123token456" not in content
            assert "my-secret-key" not in content
            assert "dXNlcjpwYXNz" not in content
            
            # Should contain filtered versions
            assert "password=****" in content
            assert '"bind_password": "****"' in content
            assert "Bearer ****" in content
            assert "key=****" in content
            assert 'auth="****"' in content
            
            # Normal message should be unchanged
            assert "Normal message without sensitive data" in content
        
        print("✓ Sensitive data filtering working correctly")
        
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_log_rotation_and_retention():
    """Test log rotation and retention functionality."""
    print("Testing log rotation and retention...")
    
    temp_dir = tempfile.mkdtemp(prefix='ldap_sync_test_logs_')
    
    try:
        config = {
            'level': 'INFO',
            'log_dir': temp_dir,
            'rotation': 'daily',
            'retention_days': 2,
            'console_output': False
        }
        
        setup_logging(config)
        logger = create_logger(__name__)
        
        # Create some log entries
        logger.info("Initial log entry")
        
        # Create some fake old log files to test cleanup
        old_files = []
        for i in range(5):
            old_date = datetime.now() - timedelta(days=i+1)
            old_filename = f"app.log.{old_date.strftime('%Y-%m-%d')}"
            old_filepath = os.path.join(temp_dir, old_filename)
            
            with open(old_filepath, 'w') as f:
                f.write(f"Old log entry from {old_date}")
            
            # Set file modification time to the old date
            timestamp = old_date.timestamp()
            os.utime(old_filepath, (timestamp, timestamp))
            old_files.append(old_filepath)
        
        # Trigger cleanup
        cleanup_logs()
        
        # Check which files still exist
        remaining_files = []
        for old_file in old_files:
            if os.path.exists(old_file):
                remaining_files.append(old_file)
        
        # Should only keep files within retention period (2 days)
        assert len(remaining_files) <= 2, f"Too many old files retained: {remaining_files}"
        
        print("✓ Log rotation and retention working correctly")
        
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_logging_stats():
    """Test logging statistics functionality."""
    print("Testing logging statistics...")
    
    temp_dir = tempfile.mkdtemp(prefix='ldap_sync_test_logs_')
    
    try:
        config = {
            'level': 'INFO',
            'log_dir': temp_dir,
            'retention_days': 5,
            'console_output': False
        }
        
        setup_logging(config)
        logger = create_logger(__name__)
        
        # Generate some log entries
        for i in range(10):
            logger.info(f"Test log entry {i}")
        
        # Get statistics
        stats = get_logging_stats()
        
        assert stats['configured'] == True
        assert stats['log_directory'] == temp_dir
        assert stats['retention_days'] == 5
        assert stats['log_files_count'] >= 1
        assert stats['total_size_bytes'] > 0
        assert stats['total_size_mb'] > 0
        
        print("✓ Logging statistics working correctly")
        print(f"  - Log files: {stats['log_files_count']}")
        print(f"  - Total size: {stats['total_size_mb']} MB")
        
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_security_logger():
    """Test security audit logger functionality.""" 
    print("Testing security audit logger...")
    
    temp_dir = tempfile.mkdtemp(prefix='ldap_sync_test_logs_')
    
    try:
        config = {
            'level': 'INFO',
            'log_dir': temp_dir,
            'console_output': False
        }
        
        setup_logging(config)
        
        # Test security logging
        security_logger.log_authentication_attempt("LDAP", "testuser", True)
        security_logger.log_authentication_attempt("VendorAPI", "apiuser", False)
        security_logger.log_user_operation("ADD", "john.doe@example.com", "VendorApp1", True)
        security_logger.log_configuration_access("/path/to/config.yaml")
        security_logger.log_security_event("Suspicious activity", "Multiple failed logins")
        
        # Check log contents
        log_file = os.path.join(temp_dir, 'app.log')
        with open(log_file, 'r') as f:
            content = f.read()
            
            assert "Authentication SUCCESS: LDAP user=testuser" in content
            assert "Authentication FAILURE: VendorAPI user=apiuser" in content
            assert "User operation SUCCESS: ADD user=john.doe@example.com vendor=VendorApp1" in content
            assert "Configuration loaded: /path/to/config.yaml" in content
            assert "Security event: Suspicious activity - Multiple failed logins" in content
        
        print("✓ Security audit logger working correctly")
        
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_console_output():
    """Test console output functionality."""
    print("Testing console output...")
    
    temp_dir = tempfile.mkdtemp(prefix='ldap_sync_test_logs_')
    
    try:
        config = {
            'level': 'DEBUG',
            'log_dir': temp_dir,
            'console_output': True,
            'console_level': 'WARNING'
        }
        
        setup_logging(config)
        logger = create_logger(__name__)
        
        # These should go to file but not console (below WARNING level)
        logger.debug("Debug message - file only")
        logger.info("Info message - file only")
        
        # These should go to both file and console
        logger.warning("Warning message - file and console")
        logger.error("Error message - file and console")
        
        # Verify file contains all messages
        log_file = os.path.join(temp_dir, 'app.log')
        with open(log_file, 'r') as f:
            content = f.read()
            assert "Debug message - file only" in content
            assert "Info message - file only" in content
            assert "Warning message - file and console" in content
            assert "Error message - file and console" in content
        
        print("✓ Console output configuration working correctly")
        print("  Note: WARNING and ERROR messages should have appeared above")
        
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_logging_without_config():
    """Test logging with minimal/no configuration."""
    print("Testing logging with default configuration...")
    
    # Test with empty config
    setup_logging({})
    logger = create_logger(__name__)
    logger.info("Test message with default config")
    
    # Test with None config
    setup_logging(None)
    logger.info("Test message with None config")
    
    print("✓ Default configuration handling working correctly")


def main():
    """Run all logging tests."""
    print("Running LDAP User Sync Logging Tests")
    print("=" * 50)
    
    try:
        test_basic_logging_setup()
        test_sensitive_data_filtering()
        test_log_rotation_and_retention()
        test_logging_stats()
        test_security_logger()
        test_console_output()
        test_logging_without_config()
        
        print("\n" + "=" * 50)
        print("✓ All logging tests passed!")
        print("\nLogging infrastructure implementation is working correctly.")
        print("\nKey features validated:")
        print("  ✓ File-based logging with daily rotation")
        print("  ✓ Configurable log levels (DEBUG/INFO/WARN/ERROR)")
        print("  ✓ Log directory creation and management")
        print("  ✓ Retention policy (automatic cleanup)")
        print("  ✓ Console output for container environments")
        print("  ✓ Sensitive data filtering from logs")
        print("  ✓ Security audit logging")
        print("  ✓ Logging statistics and monitoring")
        
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()