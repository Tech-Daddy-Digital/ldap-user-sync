#!/usr/bin/env python3
"""
Test runner for LDAP User Sync application.

This script runs all tests in the tests directory.
"""

import os
import sys
import subprocess

def run_test_file(test_file):
    """Run a single test file and return the result."""
    print(f"\n{'='*60}")
    print(f"Running {test_file}")
    print('='*60)
    
    try:
        result = subprocess.run([sys.executable, test_file], 
                              capture_output=False, 
                              check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Test {test_file} failed with exit code {e.returncode}")
        return False

def main():
    """Run all tests."""
    tests_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Find all test files
    test_files = []
    for file in os.listdir(tests_dir):
        if file.startswith('test_') and file.endswith('.py'):
            test_files.append(os.path.join(tests_dir, file))
    
    test_files.sort()
    
    if not test_files:
        print("No test files found!")
        return 1
    
    print(f"Found {len(test_files)} test files:")
    for test_file in test_files:
        print(f"  - {os.path.basename(test_file)}")
    
    # Run all tests
    passed = 0
    failed = 0
    
    for test_file in test_files:
        if run_test_file(test_file):
            passed += 1
        else:
            failed += 1
    
    # Summary
    print(f"\n{'='*60}")
    print("TEST SUMMARY")
    print('='*60)
    print(f"Total tests: {len(test_files)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    
    if failed == 0:
        print("\n✓ All tests passed!")
        return 0
    else:
        print(f"\n✗ {failed} test(s) failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())