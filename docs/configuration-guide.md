# Configuration Guide

This guide provides comprehensive instructions for configuring the LDAP User Sync application.

## Overview

The LDAP User Sync application uses YAML configuration files to define connection settings, authentication methods, group mappings, and operational parameters. Configuration can be provided via files or environment variables for secure deployment.

## Configuration File Structure

The main configuration file (`config.yaml`) contains the following sections:

- `ldap`: LDAP server connection and authentication settings
- `vendor_apps`: List of vendor applications to synchronize with
- `logging`: Logging configuration and retention settings
- `error_handling`: Retry logic and failure thresholds
- `notifications`: Email notification settings for alerts

## LDAP Configuration

Configure your LDAP server connection:

```yaml
ldap:
  server_url: "ldaps://ldap.example.com:636"
  bind_dn: "CN=Service Account,OU=Users,DC=example,DC=com"
  bind_password: "service_account_password"
  user_base_dn: "OU=Users,DC=example,DC=com"
  user_filter: "(objectClass=person)"
  attributes: ["cn", "givenName", "sn", "mail", "sAMAccountName"]
  connection_timeout: 30
  search_timeout: 60
```

### LDAP Settings Reference

- **server_url**: LDAP server URL (use `ldaps://` for SSL/TLS)
- **bind_dn**: Distinguished name for service account authentication
- **bind_password**: Password for the bind DN (use environment variable override)
- **user_base_dn**: Base DN for user searches
- **user_filter**: LDAP filter for user objects
- **attributes**: List of user attributes to retrieve
- **connection_timeout**: Connection timeout in seconds (default: 30)
- **search_timeout**: Search operation timeout in seconds (default: 60)

### Environment Variable Overrides

Sensitive LDAP credentials can be provided via environment variables:

```bash
export LDAP_BIND_PASSWORD="actual_password"
export LDAP_SERVER_URL="ldaps://prod-ldap.example.com:636"
```

## Vendor Application Configuration

Configure one or more vendor applications for synchronization:

```yaml
vendor_apps:
  - name: "VendorApp1"
    module: "vendor_app1"
    base_url: "https://api.vendorapp1.com/v1"
    auth:
      method: "basic"
      username: "api_user"
      password: "api_password"
    format: "json"
    verify_ssl: true
    request_timeout: 30
    groups:
      - ldap_group: "CN=App1_Users,OU=Groups,DC=example,DC=com"
        vendor_group: "users"
      - ldap_group: "CN=App1_Admins,OU=Groups,DC=example,DC=com"
        vendor_group: "administrators"
```

### Vendor Settings Reference

- **name**: Human-readable name for the vendor application
- **module**: Python module name for the vendor integration
- **base_url**: Base URL for the vendor's REST API
- **auth**: Authentication configuration (see Authentication Methods)
- **format**: API data format (`json` or `xml`)
- **verify_ssl**: Enable SSL certificate verification (default: true)
- **request_timeout**: HTTP request timeout in seconds (default: 30)
- **groups**: List of LDAP to vendor group mappings

## Authentication Methods

### HTTP Basic Authentication

```yaml
auth:
  method: "basic"
  username: "api_username"
  password: "api_password"
```

### Bearer Token Authentication

```yaml
auth:
  method: "token"
  token: "your_api_token_here"
```

### OAuth2 Client Credentials

```yaml
auth:
  method: "oauth2"
  token_url: "https://api.vendor.com/oauth/token"
  client_id: "your_client_id"
  client_secret: "your_client_secret"
  scope: "user:read user:write"
```

### Environment Variable Overrides for Authentication

```bash
export VENDOR_APP1_PASSWORD="actual_api_password"
export VENDOR_APP1_TOKEN="actual_bearer_token"
export VENDOR_APP2_CLIENT_SECRET="oauth_client_secret"
```

## SSL/TLS Certificate Configuration

For custom certificate trust stores or client certificates:

```yaml
vendor_apps:
  - name: "SecureVendor"
    # ... other settings ...
    # Custom CA trust store
    truststore_file: "/etc/ssl/certs/custom-ca-bundle.pem"
    truststore_type: "PEM"
    
    # Client certificate authentication
    client_cert_file: "/etc/ssl/certs/client.pem"
    client_key_file: "/etc/ssl/private/client.key"
    
    # Alternative: PKCS#12 format
    # client_cert_file: "/etc/ssl/certs/client.p12"
    # client_cert_password: "pkcs12_password"
    # client_cert_type: "PKCS12"
```

### Certificate File Formats

- **PEM**: Standard base64-encoded certificates (recommended)
- **PKCS12**: Binary format (.p12, .pfx files)
- **JKS**: Java KeyStore format (requires `pyjks` library)

## Logging Configuration

Configure logging levels, rotation, and retention:

```yaml
logging:
  level: "INFO"
  log_dir: "logs"
  log_file: "ldap_sync.log"
  rotation: "daily"
  retention_days: 7
  console_output: true
  max_file_size: "10MB"
  backup_count: 5
```

### Logging Settings Reference

- **level**: Log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`)
- **log_dir**: Directory for log files (created if not exists)
- **log_file**: Log file name
- **rotation**: Rotation frequency (`daily`, `hourly`, `size`)
- **retention_days**: Number of days to keep log files
- **console_output**: Also output logs to console (useful for containers)
- **max_file_size**: Maximum size before rotation (when rotation=size)
- **backup_count**: Number of backup files to keep

## Error Handling Configuration

Configure retry logic and failure thresholds:

```yaml
error_handling:
  max_retries: 3
  retry_wait_seconds: 5
  retry_backoff_factor: 2.0
  max_errors_per_vendor: 10
  connection_timeout: 30
  read_timeout: 60
  critical_error_threshold: 5
```

### Error Handling Settings Reference

- **max_retries**: Maximum number of retry attempts for failed operations
- **retry_wait_seconds**: Initial wait time between retries
- **retry_backoff_factor**: Multiplier for exponential backoff
- **max_errors_per_vendor**: Maximum errors before aborting vendor sync
- **connection_timeout**: Network connection timeout
- **read_timeout**: Network read timeout
- **critical_error_threshold**: Threshold for critical error notifications

## Email Notifications

Configure SMTP settings for error notifications:

```yaml
notifications:
  enable_email: true
  email_on_failure: true
  email_on_success: false
  smtp_server: "smtp.example.com"
  smtp_port: 587
  smtp_tls: true
  smtp_username: "notifications@example.com"
  smtp_password: "smtp_password"
  email_from: "LDAP Sync <notifications@example.com>"
  email_to: 
    - "admin1@example.com"
    - "admin2@example.com"
  email_subject_prefix: "[LDAP Sync]"
```

### Email Settings Reference

- **enable_email**: Enable email notifications
- **email_on_failure**: Send emails on sync failures
- **email_on_success**: Send emails on successful sync completion
- **smtp_server**: SMTP server hostname
- **smtp_port**: SMTP server port (587 for STARTTLS, 465 for SSL)
- **smtp_tls**: Use STARTTLS encryption
- **smtp_username**: SMTP authentication username
- **smtp_password**: SMTP authentication password
- **email_from**: Sender email address
- **email_to**: List of recipient email addresses
- **email_subject_prefix**: Prefix for email subjects

## Complete Configuration Example

```yaml
# LDAP Configuration
ldap:
  server_url: "ldaps://ldap.company.com:636"
  bind_dn: "CN=ldap-sync-service,OU=Service Accounts,DC=company,DC=com"
  bind_password: "${LDAP_BIND_PASSWORD}"
  user_base_dn: "OU=Users,DC=company,DC=com"
  user_filter: "(&(objectClass=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
  attributes: ["cn", "givenName", "sn", "mail", "sAMAccountName", "employeeID"]

# Vendor Applications
vendor_apps:
  - name: "Primary Business App"
    module: "business_app"
    base_url: "https://api.businessapp.com/v2"
    auth:
      method: "oauth2"
      token_url: "https://api.businessapp.com/oauth/token"
      client_id: "${BUSINESS_APP_CLIENT_ID}"
      client_secret: "${BUSINESS_APP_CLIENT_SECRET}"
      scope: "users:manage groups:manage"
    format: "json"
    verify_ssl: true
    request_timeout: 45
    groups:
      - ldap_group: "CN=BusinessApp_Users,OU=Application Groups,DC=company,DC=com"
        vendor_group: "standard-users"
      - ldap_group: "CN=BusinessApp_Managers,OU=Application Groups,DC=company,DC=com"
        vendor_group: "managers"
      - ldap_group: "CN=BusinessApp_Admins,OU=Application Groups,DC=company,DC=com"
        vendor_group: "administrators"

  - name: "Legacy System"
    module: "legacy_system"
    base_url: "https://legacy.company.com/api"
    auth:
      method: "basic"
      username: "sync-service"
      password: "${LEGACY_SYSTEM_PASSWORD}"
    format: "xml"
    verify_ssl: true
    truststore_file: "/etc/ssl/certs/company-ca.pem"
    groups:
      - ldap_group: "CN=Legacy_Users,OU=Application Groups,DC=company,DC=com"
        vendor_group: "USERS"

# Logging Configuration
logging:
  level: "INFO"
  log_dir: "/app/logs"
  rotation: "daily"
  retention_days: 14
  console_output: true

# Error Handling
error_handling:
  max_retries: 3
  retry_wait_seconds: 10
  retry_backoff_factor: 2.0
  max_errors_per_vendor: 15
  connection_timeout: 30
  read_timeout: 120

# Notifications
notifications:
  enable_email: true
  email_on_failure: true
  email_on_success: true
  smtp_server: "smtp.company.com"
  smtp_port: 587
  smtp_tls: true
  smtp_username: "${SMTP_USERNAME}"
  smtp_password: "${SMTP_PASSWORD}"
  email_from: "LDAP User Sync <noreply@company.com>"
  email_to:
    - "it-operations@company.com"
    - "security-team@company.com"
```

## Environment Variables

All sensitive configuration values can be overridden using environment variables:

### LDAP Variables
- `LDAP_SERVER_URL`
- `LDAP_BIND_DN`
- `LDAP_BIND_PASSWORD`

### Vendor Authentication Variables
- `VENDOR_APP1_USERNAME`
- `VENDOR_APP1_PASSWORD`
- `VENDOR_APP1_TOKEN`
- `VENDOR_APP1_CLIENT_ID`
- `VENDOR_APP1_CLIENT_SECRET`

### Email Variables
- `SMTP_SERVER`
- `SMTP_USERNAME`
- `SMTP_PASSWORD`

### Configuration File Location
- `CONFIG_PATH`: Path to configuration file (default: `config.yaml`)

## Configuration Validation

The application validates configuration at startup and will report specific errors for:

- Missing required fields
- Invalid LDAP server URLs
- Unreachable vendor API endpoints
- Invalid authentication credentials
- Malformed group mappings
- Invalid email addresses
- Incorrect file paths for certificates

## Security Best Practices

1. **Use Environment Variables**: Store sensitive data in environment variables, not config files
2. **Enable SSL/TLS**: Always use encrypted connections (LDAPS, HTTPS)
3. **Verify Certificates**: Keep `verify_ssl: true` unless absolutely necessary
4. **Restrict Permissions**: Limit file permissions on configuration files (600 or 640)
5. **Service Accounts**: Use dedicated service accounts with minimal required permissions
6. **Regular Rotation**: Rotate passwords and tokens regularly
7. **Audit Logging**: Enable comprehensive logging for security auditing

## Troubleshooting Configuration Issues

### LDAP Connection Problems
- Verify server URL and port
- Check firewall connectivity
- Validate bind DN and password
- Test with ldapsearch command-line tool

### Vendor API Issues
- Verify base URL accessibility
- Check authentication credentials
- Test API endpoints manually with curl
- Review API rate limits and quotas

### SSL Certificate Issues
- Verify certificate file paths and permissions
- Check certificate expiration dates
- Validate certificate chain completeness
- Test with openssl command-line tools

### Email Notification Problems
- Verify SMTP server settings
- Check authentication credentials
- Test email connectivity with telnet
- Review firewall rules for SMTP ports

For additional troubleshooting information, see the [Troubleshooting Guide](troubleshooting-guide.md).