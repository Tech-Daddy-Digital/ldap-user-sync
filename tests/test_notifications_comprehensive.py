#!/usr/bin/env python3
"""
Comprehensive unit tests for email notification system.
"""

import os
import sys
import unittest
import smtplib
import tempfile
from unittest.mock import Mock, patch, MagicMock, call
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Add the project directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ldap_sync.notifications import (
    EmailNotifier, send_notification, NotificationError,
    format_error_summary, format_sync_summary
)


class TestEmailNotifier(unittest.TestCase):
    """Test cases for EmailNotifier class."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            'smtp_server': 'smtp.example.com',
            'smtp_port': 587,
            'smtp_tls': True,
            'smtp_username': 'alerts@example.com',
            'smtp_password': 'password123',
            'email_from': 'alerts@example.com',
            'email_to': ['admin1@example.com', 'admin2@example.com'],
            'timeout': 30
        }

    def test_initialization_basic_config(self):
        """Test basic EmailNotifier initialization."""
        notifier = EmailNotifier(self.config)
        
        self.assertEqual(notifier.smtp_server, 'smtp.example.com')
        self.assertEqual(notifier.smtp_port, 587)
        self.assertTrue(notifier.smtp_tls)
        self.assertEqual(notifier.smtp_username, 'alerts@example.com')
        self.assertEqual(notifier.smtp_password, 'password123')
        self.assertEqual(notifier.email_from, 'alerts@example.com')
        self.assertEqual(len(notifier.email_to), 2)
        self.assertEqual(notifier.timeout, 30)

    def test_initialization_minimal_config(self):
        """Test EmailNotifier initialization with minimal configuration."""
        minimal_config = {
            'smtp_server': 'smtp.example.com',
            'email_from': 'alerts@example.com',
            'email_to': ['admin@example.com']
        }
        
        notifier = EmailNotifier(minimal_config)
        
        self.assertEqual(notifier.smtp_port, 587)  # Default
        self.assertTrue(notifier.smtp_tls)  # Default
        self.assertIsNone(notifier.smtp_username)  # No auth
        self.assertIsNone(notifier.smtp_password)
        self.assertEqual(notifier.timeout, 30)  # Default

    def test_initialization_no_tls(self):
        """Test EmailNotifier initialization without TLS."""
        config = self.config.copy()
        config.update({
            'smtp_port': 25,
            'smtp_tls': False
        })
        
        notifier = EmailNotifier(config)
        
        self.assertEqual(notifier.smtp_port, 25)
        self.assertFalse(notifier.smtp_tls)

    def test_create_message_basic(self):
        """Test basic email message creation."""
        notifier = EmailNotifier(self.config)
        
        message = notifier._create_message(
            subject="Test Subject",
            body="Test message body"
        )
        
        self.assertIsInstance(message, MIMEText)
        self.assertEqual(message['Subject'], 'Test Subject')
        self.assertEqual(message['From'], 'alerts@example.com')
        self.assertEqual(message['To'], 'admin1@example.com, admin2@example.com')
        self.assertIn('Test message body', message.get_payload())

    def test_create_message_with_priority(self):
        """Test email message creation with priority."""
        notifier = EmailNotifier(self.config)
        
        message = notifier._create_message(
            subject="Urgent Alert",
            body="Critical error occurred",
            priority='high'
        )
        
        self.assertEqual(message['X-Priority'], '1')
        self.assertEqual(message['X-MSMail-Priority'], 'High')

    def test_create_message_multipart(self):
        """Test multipart email message creation."""
        notifier = EmailNotifier(self.config)
        
        message = notifier._create_message(
            subject="Test Subject",
            body="<html><body><h1>HTML Body</h1></body></html>",
            content_type='html'
        )
        
        self.assertIsInstance(message, MIMEMultipart)
        self.assertEqual(message['Subject'], 'Test Subject')

    @patch('smtplib.SMTP')
    def test_send_email_success_with_auth(self, mock_smtp):
        """Test successful email sending with authentication."""
        mock_server = Mock()
        mock_smtp.return_value = mock_server
        
        notifier = EmailNotifier(self.config)
        
        result = notifier.send_email(
            subject="Test Alert",
            body="Test message body"
        )
        
        self.assertTrue(result)
        
        # Verify SMTP server interaction
        mock_smtp.assert_called_once_with('smtp.example.com', 587, timeout=30)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with('alerts@example.com', 'password123')
        mock_server.send_message.assert_called_once()
        mock_server.quit.assert_called_once()

    @patch('smtplib.SMTP')
    def test_send_email_success_no_auth(self, mock_smtp):
        """Test successful email sending without authentication."""
        config = self.config.copy()
        del config['smtp_username']
        del config['smtp_password']
        
        mock_server = Mock()
        mock_smtp.return_value = mock_server
        
        notifier = EmailNotifier(config)
        
        result = notifier.send_email(
            subject="Test Alert",
            body="Test message body"
        )
        
        self.assertTrue(result)
        
        # Verify no login was attempted
        mock_server.login.assert_not_called()
        mock_server.send_message.assert_called_once()

    @patch('smtplib.SMTP')
    def test_send_email_success_no_tls(self, mock_smtp):
        """Test successful email sending without TLS."""
        config = self.config.copy()
        config['smtp_tls'] = False
        
        mock_server = Mock()
        mock_smtp.return_value = mock_server
        
        notifier = EmailNotifier(config)
        
        result = notifier.send_email(
            subject="Test Alert",
            body="Test message body"
        )
        
        self.assertTrue(result)
        
        # Verify no TLS was used
        mock_server.starttls.assert_not_called()
        mock_server.send_message.assert_called_once()

    @patch('smtplib.SMTP')
    def test_send_email_connection_error(self, mock_smtp):
        """Test email sending with connection error."""
        mock_smtp.side_effect = smtplib.SMTPConnectError(421, "Service not available")
        
        notifier = EmailNotifier(self.config)
        
        with self.assertRaises(NotificationError) as context:
            notifier.send_email("Test Subject", "Test body")
        
        self.assertIn("Failed to connect", str(context.exception))

    @patch('smtplib.SMTP')
    def test_send_email_auth_error(self, mock_smtp):
        """Test email sending with authentication error."""
        mock_server = Mock()
        mock_server.login.side_effect = smtplib.SMTPAuthenticationError(535, "Authentication failed")
        mock_smtp.return_value = mock_server
        
        notifier = EmailNotifier(self.config)
        
        with self.assertRaises(NotificationError) as context:
            notifier.send_email("Test Subject", "Test body")
        
        self.assertIn("Authentication failed", str(context.exception))

    @patch('smtplib.SMTP')
    def test_send_email_send_error(self, mock_smtp):
        """Test email sending with send error."""
        mock_server = Mock()
        mock_server.send_message.side_effect = smtplib.SMTPRecipientsRefused({
            'admin1@example.com': (550, 'User unknown')
        })
        mock_smtp.return_value = mock_server
        
        notifier = EmailNotifier(self.config)
        
        with self.assertRaises(NotificationError) as context:
            notifier.send_email("Test Subject", "Test body")
        
        self.assertIn("Failed to send", str(context.exception))

    @patch('smtplib.SMTP')
    def test_send_email_timeout_error(self, mock_smtp):
        """Test email sending with timeout error."""
        mock_smtp.side_effect = TimeoutError("Connection timed out")
        
        notifier = EmailNotifier(self.config)
        
        with self.assertRaises(NotificationError) as context:
            notifier.send_email("Test Subject", "Test body")
        
        self.assertIn("Connection timed out", str(context.exception))

    @patch('smtplib.SMTP')
    def test_send_email_cleanup_on_error(self, mock_smtp):
        """Test proper cleanup when email sending fails."""
        mock_server = Mock()
        mock_server.login.side_effect = Exception("Unexpected error")
        mock_smtp.return_value = mock_server
        
        notifier = EmailNotifier(self.config)
        
        with self.assertRaises(NotificationError):
            notifier.send_email("Test Subject", "Test body")
        
        # Verify cleanup was attempted
        mock_server.quit.assert_called_once()

    @patch('smtplib.SMTP')
    def test_send_email_with_custom_recipients(self, mock_smtp):
        """Test email sending with custom recipients."""
        mock_server = Mock()
        mock_smtp.return_value = mock_server
        
        notifier = EmailNotifier(self.config)
        
        custom_recipients = ['custom1@example.com', 'custom2@example.com']
        result = notifier.send_email(
            subject="Custom Recipients Test",
            body="Test body",
            recipients=custom_recipients
        )
        
        self.assertTrue(result)
        
        # Verify message was created with custom recipients
        call_args = mock_server.send_message.call_args[0]
        message = call_args[0]
        self.assertEqual(message['To'], 'custom1@example.com, custom2@example.com')

    def test_validate_config_valid(self):
        """Test configuration validation with valid config."""
        notifier = EmailNotifier(self.config)
        
        # Should not raise exception
        notifier._validate_config()

    def test_validate_config_missing_smtp_server(self):
        """Test configuration validation with missing SMTP server."""
        config = self.config.copy()
        del config['smtp_server']
        
        with self.assertRaises(ValueError):
            EmailNotifier(config)

    def test_validate_config_missing_email_from(self):
        """Test configuration validation with missing sender email."""
        config = self.config.copy()
        del config['email_from']
        
        with self.assertRaises(ValueError):
            EmailNotifier(config)

    def test_validate_config_missing_email_to(self):
        """Test configuration validation with missing recipient emails."""
        config = self.config.copy()
        del config['email_to']
        
        with self.assertRaises(ValueError):
            EmailNotifier(config)

    def test_validate_config_empty_email_to(self):
        """Test configuration validation with empty recipient list."""
        config = self.config.copy()
        config['email_to'] = []
        
        with self.assertRaises(ValueError):
            EmailNotifier(config)

    def test_get_connection_stats(self):
        """Test connection statistics retrieval."""
        notifier = EmailNotifier(self.config)
        stats = notifier.get_connection_stats()
        
        expected_keys = [
            'smtp_server', 'smtp_port', 'smtp_tls', 'smtp_username',
            'email_from', 'email_to_count', 'timeout'
        ]
        
        for key in expected_keys:
            self.assertIn(key, stats)
        
        self.assertEqual(stats['smtp_server'], 'smtp.example.com')
        self.assertEqual(stats['email_to_count'], 2)
        self.assertTrue(stats['smtp_tls'])


class TestNotificationFunctions(unittest.TestCase):
    """Test cases for notification utility functions."""

    def setUp(self):
        """Set up test fixtures."""
        self.notification_config = {
            'enable_email': True,
            'email_on_failure': True,
            'smtp_server': 'smtp.example.com',
            'email_from': 'alerts@example.com',
            'email_to': ['admin@example.com']
        }

    @patch('ldap_sync.notifications.EmailNotifier')
    def test_send_notification_success(self, mock_notifier_class):
        """Test successful notification sending."""
        mock_notifier = Mock()
        mock_notifier.send_email.return_value = True
        mock_notifier_class.return_value = mock_notifier
        
        result = send_notification(
            config=self.notification_config,
            subject="Test Alert",
            message="Test message",
            notification_type="failure"
        )
        
        self.assertTrue(result)
        mock_notifier.send_email.assert_called_once_with(
            subject="Test Alert",
            body="Test message",
            priority='high'
        )

    @patch('ldap_sync.notifications.EmailNotifier')
    def test_send_notification_disabled(self, mock_notifier_class):
        """Test notification sending when disabled."""
        config = self.notification_config.copy()
        config['enable_email'] = False
        
        result = send_notification(
            config=config,
            subject="Test Alert",
            message="Test message",
            notification_type="failure"
        )
        
        self.assertTrue(result)  # Should succeed (no-op)
        mock_notifier_class.assert_not_called()

    @patch('ldap_sync.notifications.EmailNotifier')
    def test_send_notification_success_type_disabled(self, mock_notifier_class):
        """Test notification sending when success notifications are disabled."""
        config = self.notification_config.copy()
        config['email_on_success'] = False
        
        result = send_notification(
            config=config,
            subject="Sync Completed",
            message="Success message",
            notification_type="success"
        )
        
        self.assertTrue(result)  # Should succeed (no-op)
        mock_notifier_class.assert_not_called()

    @patch('ldap_sync.notifications.EmailNotifier')
    def test_send_notification_failure(self, mock_notifier_class):
        """Test notification sending failure."""
        mock_notifier = Mock()
        mock_notifier.send_email.side_effect = NotificationError("Send failed")
        mock_notifier_class.return_value = mock_notifier
        
        result = send_notification(
            config=self.notification_config,
            subject="Test Alert",
            message="Test message",
            notification_type="failure"
        )
        
        self.assertFalse(result)

    def test_format_error_summary_single_error(self):
        """Test error summary formatting with single error."""
        errors = [
            {
                'vendor': 'TestApp1',
                'group': 'test_group',
                'operation': 'add_user',
                'user': 'user1',
                'error': 'API timeout'
            }
        ]
        
        summary = format_error_summary(errors)
        
        self.assertIn('TestApp1', summary)
        self.assertIn('test_group', summary)
        self.assertIn('add_user', summary)
        self.assertIn('user1', summary)
        self.assertIn('API timeout', summary)

    def test_format_error_summary_multiple_errors(self):
        """Test error summary formatting with multiple errors."""
        errors = [
            {
                'vendor': 'TestApp1',
                'group': 'test_group',
                'operation': 'add_user',
                'user': 'user1',
                'error': 'API timeout'
            },
            {
                'vendor': 'TestApp1',
                'group': 'test_group',
                'operation': 'remove_user',
                'user': 'user2',
                'error': 'User not found'
            },
            {
                'vendor': 'TestApp2',
                'group': 'other_group',
                'operation': 'update_user',
                'user': 'user3',
                'error': 'Permission denied'
            }
        ]
        
        summary = format_error_summary(errors)
        
        self.assertIn('3 errors', summary)
        self.assertIn('TestApp1', summary)
        self.assertIn('TestApp2', summary)

    def test_format_error_summary_empty(self):
        """Test error summary formatting with no errors."""
        summary = format_error_summary([])
        
        self.assertIn('No errors', summary)

    def test_format_sync_summary_basic(self):
        """Test sync summary formatting."""
        sync_results = {
            'vendors_processed': 2,
            'total_groups': 5,
            'total_users_added': 10,
            'total_users_removed': 3,
            'total_users_updated': 7,
            'total_errors': 2,
            'duration_seconds': 45.5
        }
        
        summary = format_sync_summary(sync_results)
        
        self.assertIn('2 vendors', summary)
        self.assertIn('5 groups', summary)
        self.assertIn('10 users added', summary)
        self.assertIn('3 users removed', summary)
        self.assertIn('7 users updated', summary)
        self.assertIn('2 errors', summary)
        self.assertIn('45.5 seconds', summary)

    def test_format_sync_summary_no_changes(self):
        """Test sync summary formatting with no changes."""
        sync_results = {
            'vendors_processed': 1,
            'total_groups': 2,
            'total_users_added': 0,
            'total_users_removed': 0,
            'total_users_updated': 0,
            'total_errors': 0,
            'duration_seconds': 12.3
        }
        
        summary = format_sync_summary(sync_results)
        
        self.assertIn('No changes', summary)
        self.assertIn('1 vendor', summary)
        self.assertIn('2 groups', summary)

    def test_format_sync_summary_with_vendor_details(self):
        """Test sync summary formatting with vendor details."""
        sync_results = {
            'vendors_processed': 2,
            'total_groups': 3,
            'total_users_added': 5,
            'total_users_removed': 2,
            'total_users_updated': 1,
            'total_errors': 0,
            'duration_seconds': 30.0,
            'vendor_results': [
                {
                    'name': 'TestApp1',
                    'groups_synced': 2,
                    'users_added': 3,
                    'users_removed': 1,
                    'users_updated': 1,
                    'errors': 0
                },
                {
                    'name': 'TestApp2',
                    'groups_synced': 1,
                    'users_added': 2,
                    'users_removed': 1,
                    'users_updated': 0,
                    'errors': 0
                }
            ]
        }
        
        summary = format_sync_summary(sync_results)
        
        self.assertIn('TestApp1', summary)
        self.assertIn('TestApp2', summary)
        self.assertIn('3 added', summary)  # TestApp1 details
        self.assertIn('2 added', summary)  # TestApp2 details


class TestNotificationTemplates(unittest.TestCase):
    """Test cases for notification templates."""

    def test_failure_notification_template(self):
        """Test failure notification template."""
        from ldap_sync.notifications import create_failure_notification
        
        error_details = {
            'error_type': 'LDAP Connection Error',
            'error_message': 'Failed to connect to LDAP server',
            'vendor': 'TestApp1',
            'timestamp': '2023-12-01 10:30:00'
        }
        
        subject, body = create_failure_notification(error_details)
        
        self.assertIn('LDAP User Sync', subject)
        self.assertIn('Failed', subject)
        self.assertIn('LDAP Connection Error', body)
        self.assertIn('TestApp1', body)
        self.assertIn('2023-12-01 10:30:00', body)

    def test_success_notification_template(self):
        """Test success notification template."""
        from ldap_sync.notifications import create_success_notification
        
        sync_results = {
            'vendors_processed': 2,
            'total_users_added': 5,
            'total_users_removed': 2,
            'total_users_updated': 3,
            'duration_seconds': 45.5
        }
        
        subject, body = create_success_notification(sync_results)
        
        self.assertIn('LDAP User Sync', subject)
        self.assertIn('Completed', subject)
        self.assertIn('2 vendors', body)
        self.assertIn('5 users added', body)
        self.assertIn('45.5 seconds', body)

    def test_warning_notification_template(self):
        """Test warning notification template."""
        from ldap_sync.notifications import create_warning_notification
        
        warning_details = {
            'warning_type': 'High Error Count',
            'warning_message': 'Vendor TestApp1 had 8 errors during sync',
            'vendor': 'TestApp1',
            'error_count': 8,
            'threshold': 5
        }
        
        subject, body = create_warning_notification(warning_details)
        
        self.assertIn('LDAP User Sync', subject)
        self.assertIn('Warning', subject)
        self.assertIn('High Error Count', body)
        self.assertIn('TestApp1', body)
        self.assertIn('8 errors', body)


class TestNotificationIntegration(unittest.TestCase):
    """Integration tests for notification system."""

    @patch('smtplib.SMTP')
    def test_end_to_end_notification_flow(self, mock_smtp):
        """Test complete notification flow from error to email."""
        mock_server = Mock()
        mock_smtp.return_value = mock_server
        
        config = {
            'enable_email': True,
            'email_on_failure': True,
            'smtp_server': 'smtp.example.com',
            'smtp_port': 587,
            'smtp_tls': True,
            'smtp_username': 'alerts@example.com',
            'smtp_password': 'password123',
            'email_from': 'alerts@example.com',
            'email_to': ['admin@example.com']
        }
        
        # Simulate sending a failure notification
        result = send_notification(
            config=config,
            subject="LDAP User Sync - Critical Error",
            message="Failed to connect to LDAP server after 3 retries",
            notification_type="failure"
        )
        
        self.assertTrue(result)
        
        # Verify email was sent
        mock_server.send_message.assert_called_once()
        
        # Verify message content
        call_args = mock_server.send_message.call_args[0]
        message = call_args[0]
        self.assertEqual(message['Subject'], 'LDAP User Sync - Critical Error')
        self.assertIn('Failed to connect', message.get_payload())

    def test_notification_with_invalid_config(self):
        """Test notification handling with invalid configuration."""
        invalid_config = {
            'enable_email': True,
            'smtp_server': '',  # Invalid
            'email_from': 'alerts@example.com',
            'email_to': ['admin@example.com']
        }
        
        with self.assertRaises(ValueError):
            send_notification(
                config=invalid_config,
                subject="Test",
                message="Test message",
                notification_type="failure"
            )


if __name__ == '__main__':
    unittest.main()