#!/usr/bin/env python3
"""
Comprehensive unit tests for retry mechanism.
"""

import os
import sys
import unittest
import time
from unittest.mock import Mock, patch, call

# Add the project directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ldap_sync.retry import (
    RetryableError, NonRetryableError, retry_operation,
    RetryConfig, ExponentialBackoff, FixedBackoff
)


class TestRetryConfig(unittest.TestCase):
    """Test cases for RetryConfig class."""

    def test_default_configuration(self):
        """Test default retry configuration."""
        config = RetryConfig()
        
        self.assertEqual(config.max_attempts, 3)
        self.assertEqual(config.base_delay, 1.0)
        self.assertEqual(config.max_delay, 60.0)
        self.assertEqual(config.backoff_strategy, 'exponential')
        self.assertEqual(config.jitter, False)

    def test_custom_configuration(self):
        """Test custom retry configuration."""
        config = RetryConfig(
            max_attempts=5,
            base_delay=2.0,
            max_delay=120.0,
            backoff_strategy='fixed',
            jitter=True
        )
        
        self.assertEqual(config.max_attempts, 5)
        self.assertEqual(config.base_delay, 2.0)
        self.assertEqual(config.max_delay, 120.0)
        self.assertEqual(config.backoff_strategy, 'fixed')
        self.assertEqual(config.jitter, True)

    def test_configuration_validation(self):
        """Test retry configuration validation."""
        # Valid configurations should not raise
        RetryConfig(max_attempts=1, base_delay=0.1, max_delay=10.0)
        
        # Invalid configurations should raise ValueError
        with self.assertRaises(ValueError):
            RetryConfig(max_attempts=0)  # Must be >= 1
        
        with self.assertRaises(ValueError):
            RetryConfig(base_delay=-1.0)  # Must be > 0
        
        with self.assertRaises(ValueError):
            RetryConfig(max_delay=0.5, base_delay=1.0)  # max_delay < base_delay
        
        with self.assertRaises(ValueError):
            RetryConfig(backoff_strategy='invalid')  # Invalid strategy


class TestBackoffStrategies(unittest.TestCase):
    """Test cases for backoff strategies."""

    def test_fixed_backoff(self):
        """Test fixed backoff strategy."""
        backoff = FixedBackoff(base_delay=2.0)
        
        # All attempts should return the same delay
        self.assertEqual(backoff.calculate_delay(1), 2.0)
        self.assertEqual(backoff.calculate_delay(2), 2.0)
        self.assertEqual(backoff.calculate_delay(5), 2.0)

    def test_exponential_backoff(self):
        """Test exponential backoff strategy."""
        backoff = ExponentialBackoff(base_delay=1.0, max_delay=10.0)
        
        # Delays should increase exponentially
        self.assertEqual(backoff.calculate_delay(1), 1.0)  # 1.0 * 2^0
        self.assertEqual(backoff.calculate_delay(2), 2.0)  # 1.0 * 2^1
        self.assertEqual(backoff.calculate_delay(3), 4.0)  # 1.0 * 2^2
        self.assertEqual(backoff.calculate_delay(4), 8.0)  # 1.0 * 2^3
        self.assertEqual(backoff.calculate_delay(5), 10.0)  # Capped at max_delay

    def test_exponential_backoff_with_multiplier(self):
        """Test exponential backoff with custom multiplier."""
        backoff = ExponentialBackoff(base_delay=1.0, max_delay=30.0, multiplier=3.0)
        
        self.assertEqual(backoff.calculate_delay(1), 1.0)   # 1.0 * 3^0
        self.assertEqual(backoff.calculate_delay(2), 3.0)   # 1.0 * 3^1
        self.assertEqual(backoff.calculate_delay(3), 9.0)   # 1.0 * 3^2
        self.assertEqual(backoff.calculate_delay(4), 27.0)  # 1.0 * 3^3
        self.assertEqual(backoff.calculate_delay(5), 30.0)  # Capped at max_delay

    @patch('random.uniform')
    def test_exponential_backoff_with_jitter(self, mock_random):
        """Test exponential backoff with jitter."""
        mock_random.return_value = 0.5  # 50% jitter
        
        backoff = ExponentialBackoff(base_delay=2.0, max_delay=20.0, jitter=True)
        
        # With 50% jitter, delays should be scaled by 0.5 to 1.5
        # For attempt 2: base delay would be 4.0, with 50% jitter it becomes 2.0
        delay = backoff.calculate_delay(2)
        self.assertEqual(delay, 2.0)  # 4.0 * 0.5

    @patch('random.uniform')
    def test_fixed_backoff_with_jitter(self, mock_random):
        """Test fixed backoff with jitter."""
        mock_random.return_value = 0.8  # 80% jitter
        
        backoff = FixedBackoff(base_delay=5.0, jitter=True)
        
        # With 80% jitter, delay should be 5.0 * 0.8 = 4.0
        delay = backoff.calculate_delay(1)
        self.assertEqual(delay, 4.0)


class TestRetryOperation(unittest.TestCase):
    """Test cases for retry_operation function."""

    def test_successful_operation_no_retries(self):
        """Test successful operation that doesn't need retries."""
        mock_operation = Mock(return_value="success")
        
        result = retry_operation(
            operation=mock_operation,
            config=RetryConfig(max_attempts=3, base_delay=0.1)
        )
        
        self.assertEqual(result, "success")
        mock_operation.assert_called_once()

    def test_operation_succeeds_after_retries(self):
        """Test operation that succeeds after some retries."""
        mock_operation = Mock()
        mock_operation.side_effect = [
            RetryableError("First failure"),
            RetryableError("Second failure"),
            "success"  # Succeeds on third attempt
        ]
        
        with patch('time.sleep') as mock_sleep:
            result = retry_operation(
                operation=mock_operation,
                config=RetryConfig(max_attempts=3, base_delay=0.1)
            )
        
        self.assertEqual(result, "success")
        self.assertEqual(mock_operation.call_count, 3)
        # Should sleep twice (before 2nd and 3rd attempts)
        self.assertEqual(mock_sleep.call_count, 2)

    def test_operation_fails_all_retries(self):
        """Test operation that fails all retry attempts."""
        mock_operation = Mock()
        mock_operation.side_effect = RetryableError("Persistent failure")
        
        config = RetryConfig(max_attempts=3, base_delay=0.1)
        
        with patch('time.sleep'):
            with self.assertRaises(RetryableError) as context:
                retry_operation(operation=mock_operation, config=config)
        
        self.assertIn("Persistent failure", str(context.exception))
        self.assertEqual(mock_operation.call_count, 3)

    def test_non_retryable_error_no_retries(self):
        """Test that non-retryable errors are not retried."""
        mock_operation = Mock()
        mock_operation.side_effect = NonRetryableError("Critical error")
        
        config = RetryConfig(max_attempts=3, base_delay=0.1)
        
        with self.assertRaises(NonRetryableError) as context:
            retry_operation(operation=mock_operation, config=config)
        
        self.assertIn("Critical error", str(context.exception))
        mock_operation.assert_called_once()  # No retries

    def test_operation_with_arguments(self):
        """Test retry operation with function arguments."""
        mock_operation = Mock()
        mock_operation.side_effect = [
            RetryableError("Temporary failure"),
            "success"
        ]
        
        with patch('time.sleep'):
            result = retry_operation(
                operation=mock_operation,
                config=RetryConfig(max_attempts=3, base_delay=0.1),
                operation_args=("arg1", "arg2"),
                operation_kwargs={"key": "value"}
            )
        
        self.assertEqual(result, "success")
        self.assertEqual(mock_operation.call_count, 2)
        
        # Verify arguments were passed correctly
        for call in mock_operation.call_args_list:
            args, kwargs = call
            self.assertEqual(args, ("arg1", "arg2"))
            self.assertEqual(kwargs, {"key": "value"})

    def test_retry_with_exception_callback(self):
        """Test retry operation with exception callback."""
        mock_operation = Mock()
        mock_operation.side_effect = [
            RetryableError("First failure"),
            RetryableError("Second failure"),
            "success"
        ]
        
        mock_callback = Mock()
        
        with patch('time.sleep'):
            result = retry_operation(
                operation=mock_operation,
                config=RetryConfig(max_attempts=3, base_delay=0.1),
                on_exception=mock_callback
            )
        
        self.assertEqual(result, "success")
        self.assertEqual(mock_callback.call_count, 2)  # Called for each failure
        
        # Verify callback was called with correct arguments
        for i, call in enumerate(mock_callback.call_args_list):
            args, kwargs = call
            self.assertEqual(args[0], i + 1)  # Attempt number
            self.assertIsInstance(args[1], RetryableError)  # Exception

    @patch('time.sleep')
    def test_retry_timing_exponential_backoff(self, mock_sleep):
        """Test retry timing with exponential backoff."""
        mock_operation = Mock()
        mock_operation.side_effect = [
            RetryableError("Failure 1"),
            RetryableError("Failure 2"),
            RetryableError("Failure 3")
        ]
        
        config = RetryConfig(
            max_attempts=3,
            base_delay=1.0,
            backoff_strategy='exponential'
        )
        
        with self.assertRaises(RetryableError):
            retry_operation(operation=mock_operation, config=config)
        
        # Verify sleep was called with exponential delays
        expected_calls = [call(1.0), call(2.0)]  # 1.0 * 2^0, 1.0 * 2^1
        mock_sleep.assert_has_calls(expected_calls)

    @patch('time.sleep')
    def test_retry_timing_fixed_backoff(self, mock_sleep):
        """Test retry timing with fixed backoff."""
        mock_operation = Mock()
        mock_operation.side_effect = [
            RetryableError("Failure 1"),
            RetryableError("Failure 2"),
            RetryableError("Failure 3")
        ]
        
        config = RetryConfig(
            max_attempts=3,
            base_delay=2.0,
            backoff_strategy='fixed'
        )
        
        with self.assertRaises(RetryableError):
            retry_operation(operation=mock_operation, config=config)
        
        # Verify sleep was called with fixed delays
        expected_calls = [call(2.0), call(2.0)]
        mock_sleep.assert_has_calls(expected_calls)

    def test_retry_with_custom_retryable_exceptions(self):
        """Test retry with custom retryable exceptions."""
        class CustomError(Exception):
            pass
        
        mock_operation = Mock()
        mock_operation.side_effect = [
            CustomError("Custom failure"),
            "success"
        ]
        
        config = RetryConfig(
            max_attempts=3,
            base_delay=0.1,
            retryable_exceptions=(CustomError,)
        )
        
        with patch('time.sleep'):
            result = retry_operation(operation=mock_operation, config=config)
        
        self.assertEqual(result, "success")
        self.assertEqual(mock_operation.call_count, 2)

    def test_retry_with_condition_function(self):
        """Test retry with custom condition function."""
        mock_operation = Mock()
        mock_operation.side_effect = [
            ValueError("Retryable failure"),
            ValueError("Non-retryable failure"),
            "success"
        ]
        
        def should_retry(exception, attempt):
            # Only retry ValueError with "Retryable" in message
            return isinstance(exception, ValueError) and "Retryable" in str(exception)
        
        config = RetryConfig(max_attempts=3, base_delay=0.1)
        
        with patch('time.sleep'):
            with self.assertRaises(ValueError) as context:
                retry_operation(
                    operation=mock_operation,
                    config=config,
                    should_retry=should_retry
                )
        
        self.assertIn("Non-retryable failure", str(context.exception))
        self.assertEqual(mock_operation.call_count, 2)  # Stopped after non-retryable error

    def test_retry_operation_timeout(self):
        """Test retry operation with overall timeout."""
        mock_operation = Mock()
        mock_operation.side_effect = RetryableError("Persistent failure")
        
        config = RetryConfig(
            max_attempts=10,  # Would normally allow many retries
            base_delay=0.1,
            timeout=0.5  # But timeout after 0.5 seconds
        )
        
        start_time = time.time()
        
        with patch('time.sleep'):
            with self.assertRaises(TimeoutError):
                retry_operation(operation=mock_operation, config=config)
        
        elapsed = time.time() - start_time
        # Should timeout quickly (allowing for some test overhead)
        self.assertLess(elapsed, 1.0)

    def test_retry_operation_max_delay_cap(self):
        """Test that retry delays are capped at max_delay."""
        mock_operation = Mock()
        mock_operation.side_effect = RetryableError("Persistent failure")
        
        config = RetryConfig(
            max_attempts=5,
            base_delay=10.0,
            max_delay=2.0,  # Much smaller than base_delay
            backoff_strategy='exponential'
        )
        
        with patch('time.sleep') as mock_sleep:
            with self.assertRaises(RetryableError):
                retry_operation(operation=mock_operation, config=config)
        
        # All sleep calls should be capped at max_delay
        for call in mock_sleep.call_args_list:
            delay = call[0][0]
            self.assertLessEqual(delay, 2.0)


class TestRetryOperationIntegration(unittest.TestCase):
    """Integration tests for retry operation with real scenarios."""

    def test_ldap_connection_retry_scenario(self):
        """Test retry scenario simulating LDAP connection failures."""
        from ldap_sync.ldap_client import LDAPConnectionError
        
        mock_ldap_connect = Mock()
        mock_ldap_connect.side_effect = [
            LDAPConnectionError("Connection timeout"),
            LDAPConnectionError("Connection refused"),
            True  # Finally succeeds
        ]
        
        config = RetryConfig(
            max_attempts=3,
            base_delay=0.1,
            retryable_exceptions=(LDAPConnectionError,)
        )
        
        with patch('time.sleep'):
            result = retry_operation(
                operation=mock_ldap_connect,
                config=config
            )
        
        self.assertTrue(result)
        self.assertEqual(mock_ldap_connect.call_count, 3)

    def test_vendor_api_retry_scenario(self):
        """Test retry scenario simulating vendor API failures."""
        from ldap_sync.vendors.base import VendorAPIError
        
        mock_api_call = Mock()
        mock_api_call.side_effect = [
            VendorAPIError("Service unavailable", 503),
            VendorAPIError("Rate limit exceeded", 429),
            {"status": "success", "data": []}  # Finally succeeds
        ]
        
        def should_retry_api_error(exception, attempt):
            if isinstance(exception, VendorAPIError):
                # Retry on 5xx and 429 errors
                return exception.status_code >= 500 or exception.status_code == 429
            return False
        
        config = RetryConfig(max_attempts=3, base_delay=0.1)
        
        with patch('time.sleep'):
            result = retry_operation(
                operation=mock_api_call,
                config=config,
                should_retry=should_retry_api_error
            )
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(mock_api_call.call_count, 3)

    def test_notification_retry_scenario(self):
        """Test retry scenario simulating email notification failures."""
        import smtplib
        
        mock_send_email = Mock()
        mock_send_email.side_effect = [
            smtplib.SMTPServerDisconnected("Connection lost"),
            smtplib.SMTPConnectError(421, "Service not available"),
            True  # Finally succeeds
        ]
        
        config = RetryConfig(
            max_attempts=3,
            base_delay=0.1,
            retryable_exceptions=(smtplib.SMTPException,)
        )
        
        with patch('time.sleep'):
            result = retry_operation(
                operation=mock_send_email,
                config=config
            )
        
        self.assertTrue(result)
        self.assertEqual(mock_send_email.call_count, 3)

    def test_retry_decorator_usage(self):
        """Test retry functionality used as a decorator."""
        from ldap_sync.retry import retryable
        
        attempt_count = 0
        
        @retryable(max_attempts=3, base_delay=0.1)
        def flaky_function():
            nonlocal attempt_count
            attempt_count += 1
            if attempt_count < 3:
                raise RetryableError(f"Attempt {attempt_count} failed")
            return f"Success on attempt {attempt_count}"
        
        with patch('time.sleep'):
            result = flaky_function()
        
        self.assertEqual(result, "Success on attempt 3")
        self.assertEqual(attempt_count, 3)


class TestRetryOperationLogging(unittest.TestCase):
    """Test cases for retry operation logging."""

    @patch('ldap_sync.retry.logger')
    def test_retry_logging_success_after_retries(self, mock_logger):
        """Test logging when operation succeeds after retries."""
        mock_operation = Mock()
        mock_operation.side_effect = [
            RetryableError("Temporary failure"),
            "success"
        ]
        
        with patch('time.sleep'):
            result = retry_operation(
                operation=mock_operation,
                config=RetryConfig(max_attempts=3, base_delay=0.1)
            )
        
        self.assertEqual(result, "success")
        
        # Verify retry attempt was logged
        mock_logger.warning.assert_called()
        warning_call = mock_logger.warning.call_args[0][0]
        self.assertIn("Retry attempt 1", warning_call)

    @patch('ldap_sync.retry.logger')
    def test_retry_logging_final_failure(self, mock_logger):
        """Test logging when operation fails after all retries."""
        mock_operation = Mock()
        mock_operation.side_effect = RetryableError("Persistent failure")
        
        with patch('time.sleep'):
            with self.assertRaises(RetryableError):
                retry_operation(
                    operation=mock_operation,
                    config=RetryConfig(max_attempts=2, base_delay=0.1)
                )
        
        # Verify final failure was logged
        mock_logger.error.assert_called()
        error_call = mock_logger.error.call_args[0][0]
        self.assertIn("Operation failed after 2 attempts", error_call)


if __name__ == '__main__':
    unittest.main()