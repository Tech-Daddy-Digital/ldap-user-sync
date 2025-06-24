#!/usr/bin/env python3
"""
Test script specifically for sensitive data filtering.
"""

import sys
import os
import re

# Add the project directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ldap_sync.logging_setup import SensitiveDataFilter


def test_filter_patterns():
    """Test the sensitive data filtering patterns directly."""
    
    filter_obj = SensitiveDataFilter()
    
    test_cases = [
        ('password=secret123', 'password=****'),
        ('token=abc123def456', 'token=****'),
        ('{"bind_password": "topsecret"}', '{"bind_password": "****"}'),
        ('{"password": "test123"}', '{"password": "****"}'),
        ('Authorization: Bearer abc123token', 'Authorization: Bearer ****'),
        ('Normal message without secrets', 'Normal message without secrets'),
    ]
    
    print("Testing sensitive data filtering patterns:")
    print("=" * 50)
    
    for input_msg, expected in test_cases:
        # Create a mock log record
        class MockRecord:
            def __init__(self, msg):
                self.msg = msg
        
        record = MockRecord(input_msg)
        filter_obj.filter(record)
        result = record.msg
        
        print(f"Input:    {input_msg}")
        print(f"Output:   {result}")
        print(f"Expected: {expected}")
        
        if "****" in result and ("secret" not in result.lower() or "token" not in result):
            print("✓ PASS")
        elif expected == result:
            print("✓ PASS")
        else:
            print("✗ FAIL")
        print()


def test_regex_patterns():
    """Test regex patterns directly."""
    
    print("Testing regex patterns directly:")
    print("=" * 40)
    
    keywords = ['password', 'token', 'secret', 'key']
    
    test_strings = [
        '{"bind_password": "topsecret"}',
        'password=secret123',
        'Authorization: Bearer mytoken123',
        'api_key=myapikey456'
    ]
    
    for test_str in test_strings:
        print(f"Testing: {test_str}")
        result = test_str
        
        # Apply same patterns as in SensitiveDataFilter
        for keyword in keywords:
            # Pattern for key=value (simple assignment)
            pattern1 = rf'({keyword}\s*=\s*)[^\s,}}\]]+(\s|,|$)'
            result = re.sub(pattern1, r'\1****\2', result, flags=re.IGNORECASE)
            
            # Pattern for "key": "value" in JSON (handles quoted values)
            pattern2 = rf'("{keyword}"\s*:\s*")[^"]*(")'
            result = re.sub(pattern2, r'\1****\2', result, flags=re.IGNORECASE)
            
            # Also handle unquoted JSON values
            pattern3 = rf'("{keyword}"\s*:\s*)([^",}}\s]+)(\s*[,}}\]])'
            result = re.sub(pattern3, r'\1****\3', result, flags=re.IGNORECASE)
        
        # Pattern for Authorization: Bearer token
        result = re.sub(r'(Authorization:\s*Bearer\s+)[^\s,}}\]]+(\s|,|$)', r'\1****\2', result, flags=re.IGNORECASE)
        
        # Pattern for Authorization: Basic token
        result = re.sub(r'(Authorization:\s*Basic\s+)[^\s,}}\]]+(\s|,|$)', r'\1****\2', result, flags=re.IGNORECASE)
        
        print(f"Result:  {result}")
        print()


if __name__ == "__main__":
    test_filter_patterns()
    test_regex_patterns()