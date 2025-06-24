#!/usr/bin/env python3
"""
Test script specifically for log rotation and retention.
"""

import os
import sys
import tempfile
import shutil
import time
from datetime import datetime, timedelta

# Add the project directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ldap_sync.logging_setup import setup_logging, create_logger, cleanup_logs


def test_log_retention():
    """Test log file retention and cleanup."""
    print("Testing log retention and cleanup...")
    
    temp_dir = tempfile.mkdtemp(prefix='ldap_sync_rotation_test_')
    
    try:
        # Reset logging
        import logging
        logging.getLogger().handlers.clear()
        from ldap_sync.logging_setup import _logging_manager
        _logging_manager.configured = False
        
        config = {
            'level': 'INFO',
            'log_dir': temp_dir,
            'retention_days': 3,
            'console_output': False
        }
        
        setup_logging(config)
        logger = create_logger(__name__)
        
        # Create some log files with different ages
        old_files = []
        for days_old in [1, 2, 3, 4, 5, 6, 7]:
            old_date = datetime.now() - timedelta(days=days_old)
            old_filename = f"app.log.{old_date.strftime('%Y-%m-%d')}"
            old_filepath = os.path.join(temp_dir, old_filename)
            
            with open(old_filepath, 'w') as f:
                f.write(f"Log entry from {old_date.strftime('%Y-%m-%d')}\n")
            
            # Set file modification time to simulate age
            timestamp = old_date.timestamp()
            os.utime(old_filepath, (timestamp, timestamp))
            old_files.append((old_filepath, days_old))
        
        print(f"Created {len(old_files)} test log files")
        
        # Trigger cleanup
        cleanup_logs()
        
        # Check which files remain
        remaining_files = []
        for filepath, days_old in old_files:
            if os.path.exists(filepath):
                remaining_files.append((filepath, days_old))
        
        print(f"Files remaining after cleanup: {len(remaining_files)}")
        for filepath, days_old in remaining_files:
            print(f"  - {os.path.basename(filepath)} ({days_old} days old)")
        
        # Should only keep files within retention period (3 days)
        if all(days_old <= 3 for _, days_old in remaining_files):
            print("✓ Log retention working correctly")
        else:
            print("⚠ Some old files were not cleaned up")
        
    except Exception as e:
        print(f"✗ Log retention test failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_log_directory_creation():
    """Test automatic log directory creation."""
    print("Testing log directory creation...")
    
    # Create a temporary parent directory
    parent_dir = tempfile.mkdtemp(prefix='ldap_sync_parent_')
    log_dir = os.path.join(parent_dir, 'nested', 'log', 'directory')
    
    try:
        # Reset logging
        import logging
        logging.getLogger().handlers.clear()
        from ldap_sync.logging_setup import _logging_manager
        _logging_manager.configured = False
        
        # Ensure the nested directory doesn't exist
        assert not os.path.exists(log_dir)
        
        config = {
            'level': 'INFO',
            'log_dir': log_dir,
            'console_output': False
        }
        
        setup_logging(config)
        logger = create_logger(__name__)
        logger.info("Test message")
        
        # Check that directory was created
        if os.path.exists(log_dir):
            log_file = os.path.join(log_dir, 'app.log')
            if os.path.exists(log_file):
                print("✓ Log directory creation working correctly")
            else:
                print("⚠ Directory created but log file missing")
        else:
            print("✗ Log directory was not created")
        
    except Exception as e:
        print(f"✗ Directory creation test failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        shutil.rmtree(parent_dir, ignore_errors=True)


def test_console_vs_file_levels():
    """Test different log levels for console vs file output."""
    print("Testing console vs file log levels...")
    
    temp_dir = tempfile.mkdtemp(prefix='ldap_sync_levels_test_')
    
    try:
        # Reset logging
        import logging
        logging.getLogger().handlers.clear()
        from ldap_sync.logging_setup import _logging_manager
        _logging_manager.configured = False
        
        config = {
            'level': 'DEBUG',          # File gets DEBUG and above
            'log_dir': temp_dir,
            'console_output': True,
            'console_level': 'ERROR'   # Console only gets ERROR and above
        }
        
        setup_logging(config)
        logger = create_logger(__name__)
        
        # Log at different levels
        logger.debug("Debug message - file only")
        logger.info("Info message - file only")
        logger.warning("Warning message - file only")
        logger.error("Error message - file and console")
        
        # Check file contents
        log_file = os.path.join(temp_dir, 'app.log')
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                content = f.read()
                
                # File should contain all levels
                has_debug = "Debug message - file only" in content
                has_info = "Info message - file only" in content
                has_warning = "Warning message - file only" in content
                has_error = "Error message - file and console" in content
                
                if has_debug and has_info and has_warning and has_error:
                    print("✓ File logging levels working correctly")
                else:
                    print(f"⚠ File logging incomplete: DEBUG={has_debug}, INFO={has_info}, WARNING={has_warning}, ERROR={has_error}")
        else:
            print("✗ Log file not created")
        
        print("Note: Only ERROR messages should appear on console above")
        
    except Exception as e:
        print(f"✗ Console vs file levels test failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def main():
    """Run log rotation and advanced logging tests."""
    print("LDAP User Sync Advanced Logging Tests")
    print("=" * 50)
    
    test_log_retention()
    print()
    test_log_directory_creation()
    print()
    test_console_vs_file_levels()
    
    print("\n" + "=" * 50)
    print("✓ Advanced logging tests completed!")


if __name__ == "__main__":
    main()