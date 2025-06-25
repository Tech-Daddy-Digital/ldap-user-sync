"""
Email notification utilities for LDAP User Sync.

This module provides functionality to send email notifications for
sync failures, errors, and operational events.
"""

import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class NotificationError(Exception):
    """Exception raised when notification sending fails."""
    pass


def send_email(subject: str, body: str, config: Dict[str, Any]) -> bool:
    """
    Send email notification using SMTP.
    
    Args:
        subject: Email subject line
        body: Email body content
        config: Notification configuration dictionary
        
    Returns:
        True if email sent successfully, False otherwise
    """
    if not config.get('enable_email', True):
        logger.debug("Email notifications disabled")
        return False
    
    try:
        # Extract SMTP configuration
        smtp_server = config.get('smtp_server')
        smtp_port = config.get('smtp_port', 587)
        smtp_username = config.get('smtp_username')
        smtp_password = config.get('smtp_password')
        smtp_tls = config.get('smtp_tls', True)
        
        email_from = config.get('email_from', smtp_username)
        email_to = config.get('email_to', [])
        
        if not smtp_server:
            logger.error("SMTP server not configured")
            return False
        
        if not email_to:
            logger.error("No email recipients configured")
            return False
        
        # Ensure email_to is a list
        if isinstance(email_to, str):
            email_to = [email_to]
        
        logger.debug(f"Sending email to {len(email_to)} recipients via {smtp_server}:{smtp_port}")
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = email_from
        msg['To'] = ', '.join(email_to)
        msg['Subject'] = subject
        
        # Add body
        msg.attach(MIMEText(body, 'plain'))
        
        # Connect to SMTP server
        if smtp_port == 465:
            # Use SSL
            server = smtplib.SMTP_SSL(smtp_server, smtp_port)
        else:
            # Use TLS
            server = smtplib.SMTP(smtp_server, smtp_port)
            if smtp_tls:
                server.starttls()
        
        # Authenticate if credentials provided
        if smtp_username and smtp_password:
            server.login(smtp_username, smtp_password)
        
        # Send email
        server.sendmail(email_from, email_to, msg.as_string())
        server.quit()
        
        logger.info(f"Email notification sent successfully: {subject}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send email notification: {e}")
        return False


def send_failure_notification(
    title: str,
    error_message: str,
    config: Dict[str, Any],
    additional_info: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Send notification for sync failures.
    
    Args:
        title: Failure title/type
        error_message: Error description
        config: Notification configuration
        additional_info: Optional additional context
        
    Returns:
        True if notification sent successfully
    """
    if not config.get('email_on_failure', True):
        logger.debug("Failure email notifications disabled")
        return False
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    subject = f"LDAP User Sync Alert: {title}"
    
    body_lines = [
        f"LDAP User Sync Failure Report",
        f"Timestamp: {timestamp}",
        f"",
        f"Failure Type: {title}",
        f"Error Message: {error_message}",
        f""
    ]
    
    if additional_info:
        body_lines.append("Additional Information:")
        for key, value in additional_info.items():
            body_lines.append(f"  {key}: {value}")
        body_lines.append("")
    
    body_lines.extend([
        "Please check the application logs for more detailed information.",
        "",
        "This is an automated message from LDAP User Sync."
    ])
    
    body = '\n'.join(body_lines)
    
    return send_email(subject, body, config)


def send_vendor_error_notification(
    vendor_name: str,
    error_count: int,
    errors: List[str],
    config: Dict[str, Any]
) -> bool:
    """
    Send notification for vendor-specific errors.
    
    Args:
        vendor_name: Name of the vendor that failed
        error_count: Number of errors encountered
        errors: List of error messages
        config: Notification configuration
        
    Returns:
        True if notification sent successfully
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    subject = f"LDAP User Sync Alert: {vendor_name} Sync Errors"
    
    body_lines = [
        f"LDAP User Sync Vendor Error Report",
        f"Timestamp: {timestamp}",
        f"",
        f"Vendor: {vendor_name}",
        f"Error Count: {error_count}",
        f"",
        f"Error Details:"
    ]
    
    # Include up to 10 error messages to avoid overly long emails
    displayed_errors = errors[:10]
    for i, error in enumerate(displayed_errors, 1):
        body_lines.append(f"  {i}. {error}")
    
    if len(errors) > 10:
        body_lines.append(f"  ... and {len(errors) - 10} more errors")
    
    body_lines.extend([
        f"",
        f"The sync for {vendor_name} has been aborted due to excessive errors.",
        f"Please check the vendor API status and configuration.",
        f"",
        f"Check the application logs for complete error details.",
        f"",
        f"This is an automated message from LDAP User Sync."
    ])
    
    body = '\n'.join(body_lines)
    
    return send_email(subject, body, config)


def send_success_summary(
    sync_stats: Dict[str, Any],
    config: Dict[str, Any]
) -> bool:
    """
    Send summary notification for successful sync.
    
    Args:
        sync_stats: Dictionary containing sync statistics
        config: Notification configuration
        
    Returns:
        True if notification sent successfully
    """
    if not config.get('email_on_success', False):
        logger.debug("Success email notifications disabled")
        return False
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Format runtime
    runtime_seconds = sync_stats.get('runtime_seconds', 0)
    if runtime_seconds > 60:
        minutes = int(runtime_seconds // 60)
        seconds = runtime_seconds % 60
        runtime_str = f"{minutes}m {seconds:.1f}s"
    else:
        runtime_str = f"{runtime_seconds:.2f} seconds"
    
    subject = "LDAP User Sync: Successful Completion"
    
    body_lines = [
        f"LDAP User Sync Summary Report",
        f"Timestamp: {timestamp}",
        f"",
        f"Sync completed successfully!",
        f"",
        f"Overall Statistics:",
        f"  Total runtime: {runtime_str}",
        f"  Vendors processed: {sync_stats.get('vendors_processed', 0)}",
        f"  Vendors failed: {sync_stats.get('vendors_failed', 0)}",
        f"  Users added: {sync_stats.get('total_users_added', 0)}",
        f"  Users removed: {sync_stats.get('total_users_removed', 0)}",
        f"  Users updated: {sync_stats.get('total_users_updated', 0)}",
        f"  Total errors: {sync_stats.get('total_errors', 0)}",
        f""
    ]
    
    # Add vendor-specific details
    vendor_details = sync_stats.get('vendor_details', {})
    if vendor_details:
        body_lines.append("Vendor Details:")
        for vendor_name, vendor_stats in vendor_details.items():
            body_lines.extend([
                f"  {vendor_name}:",
                f"    Runtime: {vendor_stats.get('runtime_seconds', 0):.2f}s",
                f"    Groups processed: {vendor_stats.get('groups_processed', 0)}",
                f"    Groups failed: {vendor_stats.get('groups_failed', 0)}",
                f"    Users added: {vendor_stats.get('users_added', 0)}",
                f"    Users removed: {vendor_stats.get('users_removed', 0)}",
                f"    Users updated: {vendor_stats.get('users_updated', 0)}",
                f"    Errors: {vendor_stats.get('errors', 0)}",
                f""
            ])
    
    body_lines.extend([
        f"This is an automated message from LDAP User Sync."
    ])
    
    body = '\n'.join(body_lines)
    
    return send_email(subject, body, config)


def send_ldap_connection_failure(
    error_message: str,
    config: Dict[str, Any],
    retry_count: int = 0
) -> bool:
    """
    Send notification for LDAP connection failures.
    
    Args:
        error_message: LDAP error description
        config: Notification configuration
        retry_count: Number of retries attempted
        
    Returns:
        True if notification sent successfully
    """
    additional_info = {
        'Component': 'LDAP Connection',
        'Retry Attempts': retry_count,
        'Impact': 'Sync operation aborted - no vendors processed'
    }
    
    return send_failure_notification(
        "LDAP Connection Failed",
        error_message,
        config,
        additional_info
    )


def send_configuration_error(
    error_message: str,
    config_path: Optional[str],
    config: Dict[str, Any]
) -> bool:
    """
    Send notification for configuration errors.
    
    Args:
        error_message: Configuration error description
        config_path: Path to configuration file
        config: Notification configuration (may be partial)
        
    Returns:
        True if notification sent successfully
    """
    additional_info = {
        'Component': 'Configuration',
        'Config Path': config_path or 'default',
        'Impact': 'Application startup failed'
    }
    
    return send_failure_notification(
        "Configuration Error",
        error_message,
        config,
        additional_info
    )


def test_notification_config(config: Dict[str, Any]) -> bool:
    """
    Test email notification configuration by sending a test email.
    
    Args:
        config: Notification configuration to test
        
    Returns:
        True if test email sent successfully
    """
    test_subject = "LDAP User Sync: Configuration Test"
    test_body = """This is a test email from LDAP User Sync.

If you receive this message, your email notification configuration is working correctly.

Test details:
- SMTP Server: {}
- SMTP Port: {}
- From Address: {}
- Recipients: {}

This is an automated test message.""".format(
        config.get('smtp_server', 'not configured'),
        config.get('smtp_port', 'not configured'),
        config.get('email_from', 'not configured'),
        ', '.join(config.get('email_to', []))
    )
    
    try:
        result = send_email(test_subject, test_body, config)
        if result:
            logger.info("Test notification sent successfully")
        else:
            logger.error("Test notification failed")
        return result
    except Exception as e:
        logger.error(f"Test notification failed with exception: {e}")
        return False