#!/usr/bin/env python3
"""
Comprehensive test runner for LDAP User Sync application.

This script runs all test suites and provides detailed reporting.
"""

import os
import sys
import unittest
import time
from io import StringIO

# Add the project directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def discover_and_run_tests():
    """Discover and run all test modules."""
    
    print("LDAP User Sync - Comprehensive Test Suite")
    print("=" * 60)
    print()
    
    # Test modules to run
    test_modules = [
        'test_config_comprehensive',
        'test_ldap_client_comprehensive', 
        'test_vendor_base_comprehensive',
        'test_vendor_modules_comprehensive',
        'test_main_orchestrator_comprehensive',
        'test_notifications_comprehensive',
        'test_retry_logic_comprehensive',
        'test_integration_comprehensive',
        'test_security_comprehensive',
        'test_error_injection_comprehensive'
    ]
    
    # Track results
    results = {}
    total_tests = 0
    total_failures = 0
    total_errors = 0
    start_time = time.time()
    
    for module_name in test_modules:
        print(f"Running {module_name}...")
        print("-" * 40)
        
        # Capture test output
        test_output = StringIO()
        
        # Load and run tests
        try:
            loader = unittest.TestLoader()
            suite = loader.loadTestsFromName(module_name)
            
            runner = unittest.TextTestRunner(
                stream=test_output,
                verbosity=2,
                buffer=True
            )
            
            result = runner.run(suite)
            
            # Store results
            results[module_name] = {
                'tests_run': result.testsRun,
                'failures': len(result.failures),
                'errors': len(result.errors),
                'success': result.wasSuccessful(),
                'output': test_output.getvalue()
            }
            
            total_tests += result.testsRun
            total_failures += len(result.failures)
            total_errors += len(result.errors)
            
            # Print summary for this module
            if result.wasSuccessful():
                print(f"✓ {module_name}: {result.testsRun} tests passed")
            else:
                print(f"✗ {module_name}: {result.testsRun} tests, {len(result.failures)} failures, {len(result.errors)} errors")
                
                # Print first few failures/errors for quick diagnosis
                if result.failures:
                    print("  Failures:")
                    for test, traceback in result.failures[:2]:  # Show first 2
                        print(f"    - {test}")
                
                if result.errors:
                    print("  Errors:")
                    for test, traceback in result.errors[:2]:  # Show first 2
                        print(f"    - {test}")
            
            print()
            
        except Exception as e:
            print(f"✗ Failed to run {module_name}: {e}")
            results[module_name] = {
                'tests_run': 0,
                'failures': 0,
                'errors': 1,
                'success': False,
                'output': str(e)
            }
            total_errors += 1
            print()
    
    # Print overall summary
    end_time = time.time()
    duration = end_time - start_time
    
    print("=" * 60)
    print("COMPREHENSIVE TEST SUMMARY")
    print("=" * 60)
    print(f"Total test modules: {len(test_modules)}")
    print(f"Total tests run: {total_tests}")
    print(f"Total failures: {total_failures}")
    print(f"Total errors: {total_errors}")
    print(f"Duration: {duration:.2f} seconds")
    print()
    
    # Module-by-module breakdown
    print("Module Results:")
    print("-" * 40)
    for module_name, result in results.items():
        status = "PASS" if result['success'] else "FAIL"
        print(f"{module_name:<35} {status:>5} ({result['tests_run']} tests)")
    
    print()
    
    # Overall result
    overall_success = total_failures == 0 and total_errors == 0
    if overall_success:
        print("🎉 ALL TESTS PASSED!")
        print()
        print("Test Coverage Summary:")
        print("✓ Configuration loading and validation")
        print("✓ LDAP client functionality with mocks")
        print("✓ Vendor base class implementation")
        print("✓ Individual vendor module implementations")
        print("✓ Main orchestrator sync logic")
        print("✓ Email notification system")
        print("✓ Retry mechanism and error handling")
        print("✓ End-to-end integration scenarios")
        print("✓ Security and credential handling")
        print("✓ Error injection and failure scenarios")
        print()
        print("The LDAP User Sync application has comprehensive test coverage")
        print("and all functionality has been validated.")
        
    else:
        print("❌ SOME TESTS FAILED")
        print()
        print("Failed modules:")
        for module_name, result in results.items():
            if not result['success']:
                print(f"  - {module_name}: {result['failures']} failures, {result['errors']} errors")
        
        print()
        print("Please review the detailed output above to diagnose issues.")
    
    return overall_success


def run_specific_test_category(category):
    """Run tests for a specific category."""
    
    category_mapping = {
        'unit': [
            'test_config_comprehensive',
            'test_ldap_client_comprehensive',
            'test_vendor_base_comprehensive',
            'test_vendor_modules_comprehensive',
            'test_main_orchestrator_comprehensive',
            'test_notifications_comprehensive',
            'test_retry_logic_comprehensive'
        ],
        'integration': [
            'test_integration_comprehensive'
        ],
        'security': [
            'test_security_comprehensive'
        ],
        'error': [
            'test_error_injection_comprehensive'
        ]
    }
    
    if category not in category_mapping:
        print(f"Unknown category: {category}")
        print(f"Available categories: {', '.join(category_mapping.keys())}")
        return False
    
    print(f"Running {category} tests...")
    print("=" * 40)
    
    # Run tests for the specified category
    total_success = True
    for module_name in category_mapping[category]:
        try:
            loader = unittest.TestLoader()
            suite = loader.loadTestsFromName(module_name)
            
            runner = unittest.TextTestRunner(verbosity=2)
            result = runner.run(suite)
            
            if not result.wasSuccessful():
                total_success = False
                
        except Exception as e:
            print(f"Failed to run {module_name}: {e}")
            total_success = False
    
    return total_success


def main():
    """Main test runner entry point."""
    
    if len(sys.argv) > 1:
        category = sys.argv[1]
        success = run_specific_test_category(category)
    else:
        success = discover_and_run_tests()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()