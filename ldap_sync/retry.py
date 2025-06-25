"""
Retry utilities for handling transient failures.

This module provides decorators and helper functions for implementing
retry logic with configurable attempts and delays.
"""

import time
import logging
import functools
from typing import Callable, Any, Tuple, Type, Union, Optional

logger = logging.getLogger(__name__)


class RetryableError(Exception):
    """Base exception for errors that should trigger retries."""
    pass


class MaxRetriesExceeded(Exception):
    """Raised when maximum retry attempts are exceeded."""
    
    def __init__(self, attempts: int, last_exception: Exception):
        self.attempts = attempts
        self.last_exception = last_exception
        super().__init__(f"Failed after {attempts} attempts: {last_exception}")


def retry(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 1.0,
    exceptions: Tuple[Type[Exception], ...] = (Exception,),
    on_retry: Optional[Callable[[int, Exception], None]] = None
):
    """
    Decorator to retry function calls on specified exceptions.
    
    Args:
        max_attempts: Maximum number of attempts (including initial call)
        delay: Initial delay between retries in seconds
        backoff: Multiplier for delay after each retry (exponential backoff)
        exceptions: Tuple of exception types to catch and retry on
        on_retry: Optional callback function called on each retry
        
    Returns:
        Decorated function
        
    Example:
        @retry(max_attempts=3, delay=2.0, backoff=2.0)
        def unreliable_function():
            # Function that might fail
            pass
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return retry_call(
                func, args, kwargs,
                max_attempts=max_attempts,
                delay=delay,
                backoff=backoff,
                exceptions=exceptions,
                on_retry=on_retry
            )
        return wrapper
    return decorator


def retry_call(
    func: Callable,
    args: tuple = (),
    kwargs: dict = None,
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 1.0,
    exceptions: Tuple[Type[Exception], ...] = (Exception,),
    on_retry: Optional[Callable[[int, Exception], None]] = None
) -> Any:
    """
    Call a function with retry logic.
    
    Args:
        func: Function to call
        args: Positional arguments for function
        kwargs: Keyword arguments for function
        max_attempts: Maximum number of attempts
        delay: Initial delay between retries
        backoff: Delay multiplier for exponential backoff
        exceptions: Exception types to catch and retry on
        on_retry: Optional callback for retry events
        
    Returns:
        Function result
        
    Raises:
        MaxRetriesExceeded: If all retry attempts fail
    """
    if kwargs is None:
        kwargs = {}
    
    last_exception = None
    current_delay = delay
    
    for attempt in range(max_attempts):
        try:
            result = func(*args, **kwargs)
            if attempt > 0:
                logger.info(f"Operation succeeded on attempt {attempt + 1}")
            return result
            
        except exceptions as e:
            last_exception = e
            
            # Don't retry on last attempt
            if attempt == max_attempts - 1:
                break
            
            # Log retry attempt
            logger.debug(f"Attempt {attempt + 1} failed with {type(e).__name__}: {e}")
            logger.debug(f"Retrying in {current_delay:.1f} seconds...")
            
            # Call retry callback if provided
            if on_retry:
                try:
                    on_retry(attempt + 1, e)
                except Exception as callback_error:
                    logger.warning(f"Retry callback failed: {callback_error}")
            
            # Wait before retry
            time.sleep(current_delay)
            current_delay *= backoff
    
    # All attempts failed
    raise MaxRetriesExceeded(max_attempts, last_exception)


def retry_with_config(config: dict):
    """
    Create retry decorator from configuration dictionary.
    
    Args:
        config: Dictionary containing retry configuration:
            - max_retries: Maximum retry attempts
            - retry_wait_seconds: Initial delay between retries
            - retry_backoff: Backoff multiplier (optional, default 1.0)
            - retryable_exceptions: List of exception names (optional)
            
    Returns:
        Retry decorator configured from the provided settings
    """
    max_attempts = config.get('max_retries', 3) + 1  # +1 for initial attempt
    delay = config.get('retry_wait_seconds', 1.0)
    backoff = config.get('retry_backoff', 1.0)
    
    # Default exceptions for network/API operations
    default_exceptions = (
        ConnectionError,
        TimeoutError,
        RetryableError
    )
    
    # Allow configuration to specify exception types
    exception_names = config.get('retryable_exceptions', [])
    if exception_names:
        import builtins
        exceptions = []
        for name in exception_names:
            try:
                exc_class = getattr(builtins, name, None)
                if exc_class and issubclass(exc_class, Exception):
                    exceptions.append(exc_class)
            except (AttributeError, TypeError):
                logger.warning(f"Unknown exception type in config: {name}")
        
        exceptions = tuple(exceptions) if exceptions else default_exceptions
    else:
        exceptions = default_exceptions
    
    return retry(
        max_attempts=max_attempts,
        delay=delay,
        backoff=backoff,
        exceptions=exceptions
    )


def is_retryable_error(exception: Exception) -> bool:
    """
    Determine if an exception should trigger a retry.
    
    Args:
        exception: Exception to check
        
    Returns:
        True if the exception indicates a transient failure
    """
    # Network-related errors
    if isinstance(exception, (ConnectionError, TimeoutError)):
        return True
    
    # Explicitly marked retryable errors
    if isinstance(exception, RetryableError):
        return True
    
    # HTTP status codes that might be transient
    if hasattr(exception, 'status_code'):
        status_code = getattr(exception, 'status_code')
        # 5xx server errors are generally retryable
        # 429 (too many requests) is retryable
        # 503 (service unavailable) is retryable
        if status_code in (429, 503) or 500 <= status_code < 600:
            return True
    
    # Check exception message for common transient failure patterns
    error_msg = str(exception).lower()
    transient_patterns = [
        'timeout',
        'connection reset',
        'connection refused',
        'network is unreachable',
        'temporary failure',
        'service unavailable',
        'too many requests'
    ]
    
    for pattern in transient_patterns:
        if pattern in error_msg:
            return True
    
    return False


def create_retry_callback(operation_name: str) -> Callable[[int, Exception], None]:
    """
    Create a standard retry callback for logging retry attempts.
    
    Args:
        operation_name: Name of the operation being retried
        
    Returns:
        Callback function for retry events
    """
    def on_retry(attempt: int, exception: Exception):
        logger.warning(f"{operation_name} failed on attempt {attempt}, "
                      f"retrying due to {type(exception).__name__}: {exception}")
    
    return on_retry