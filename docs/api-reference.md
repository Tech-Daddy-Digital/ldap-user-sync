# API Reference Documentation

This document provides comprehensive API reference documentation for the LDAP User Sync application components.

## Overview

The LDAP User Sync application provides several key APIs and interfaces:

- **Configuration API**: For loading and validating configuration
- **LDAP Client API**: For connecting to and querying LDAP servers
- **Vendor API Interface**: Abstract base class for vendor integrations
- **Notification API**: For sending email alerts and notifications
- **Main Orchestrator API**: Core synchronization logic

## Configuration API

### Module: `ldap_sync.config`

#### `load_config(config_path: str = None) -> Dict[str, Any]`

Loads and validates configuration from YAML file with environment variable overrides.

**Parameters:**
- `config_path` (str, optional): Path to configuration file. Defaults to `config.yaml`

**Returns:**
- `Dict[str, Any]`: Parsed and validated configuration dictionary

**Raises:**
- `FileNotFoundError`: Configuration file not found
- `yaml.YAMLError`: Invalid YAML syntax
- `ValueError`: Configuration validation failed

**Example:**
```python
from ldap_sync.config import load_config

config = load_config('/path/to/config.yaml')
print(config['ldap']['server_url'])
```

#### `validate_config(config: Dict[str, Any]) -> None`

Validates configuration structure and required fields.

**Parameters:**
- `config` (Dict[str, Any]): Configuration dictionary to validate

**Raises:**
- `ValueError`: Missing required fields or invalid values

**Example:**
```python
from ldap_sync.config import validate_config

try:
    validate_config(config)
    print("Configuration is valid")
except ValueError as e:
    print(f"Configuration error: {e}")
```

#### `get_env_override(key: str, default: Any = None) -> Any`

Gets environment variable override for configuration value.

**Parameters:**
- `key` (str): Configuration key (e.g., 'LDAP_BIND_PASSWORD')
- `default` (Any, optional): Default value if environment variable not set

**Returns:**
- `Any`: Environment variable value or default

**Example:**
```python
from ldap_sync.config import get_env_override

password = get_env_override('LDAP_BIND_PASSWORD', 'default_password')
```

## LDAP Client API

### Module: `ldap_sync.ldap_client`

#### Class: `LDAPClient`

Main class for LDAP connectivity and operations.

##### `__init__(self, config: Dict[str, Any])`

Initialize LDAP client with configuration.

**Parameters:**
- `config` (Dict[str, Any]): LDAP configuration section

**Example:**
```python
from ldap_sync.ldap_client import LDAPClient

ldap_config = {
    'server_url': 'ldaps://ldap.company.com:636',
    'bind_dn': 'CN=Service Account,OU=Users,DC=company,DC=com',
    'bind_password': 'password',
    'user_base_dn': 'OU=Users,DC=company,DC=com'
}

client = LDAPClient(ldap_config)
```

##### `connect(self) -> bool`

Establish connection to LDAP server.

**Returns:**
- `bool`: True if connection successful, False otherwise

**Raises:**
- `LDAPException`: Connection or authentication failed

**Example:**
```python
if client.connect():
    print("Connected to LDAP server")
else:
    print("Failed to connect")
```

##### `get_group_members(self, group_dn: str) -> List[Dict[str, Any]]`

Retrieve members of an LDAP group.

**Parameters:**
- `group_dn` (str): Distinguished name of the group

**Returns:**
- `List[Dict[str, Any]]`: List of user dictionaries with attributes

**Raises:**
- `LDAPException`: Group not found or query failed

**Example:**
```python
members = client.get_group_members('CN=App_Users,OU=Groups,DC=company,DC=com')
for user in members:
    print(f"User: {user['username']}, Email: {user['email']}")
```

##### `search_users(self, filter_string: str, attributes: List[str] = None) -> List[Dict[str, Any]]`

Search for users with custom filter.

**Parameters:**
- `filter_string` (str): LDAP search filter
- `attributes` (List[str], optional): Attributes to retrieve

**Returns:**
- `List[Dict[str, Any]]`: List of matching user entries

**Example:**
```python
users = client.search_users(
    '(&(objectClass=person)(mail=*@company.com))',
    ['cn', 'mail', 'sAMAccountName']
)
```

##### `disconnect(self) -> None`

Close LDAP connection.

**Example:**
```python
client.disconnect()
```

## Vendor API Interface

### Module: `ldap_sync.vendors.base`

#### Class: `VendorAPIBase`

Abstract base class for vendor API integrations.

##### `__init__(self, config: Dict[str, Any])`

Initialize vendor API client.

**Parameters:**
- `config` (Dict[str, Any]): Vendor configuration section

##### `authenticate(self) -> bool`

Perform authentication with vendor API.

**Returns:**
- `bool`: True if authentication successful

**Raises:**
- `AuthenticationError`: Authentication failed

**Implementation required in subclasses.**

##### `get_group_members(self, group_cfg: Dict[str, str]) -> List[Dict[str, Any]]`

Get members of a vendor group.

**Parameters:**
- `group_cfg` (Dict[str, str]): Group configuration with vendor_group identifier

**Returns:**
- `List[Dict[str, Any]]`: List of group members

**Required return format:**
```python
[
    {
        'username': 'user1',
        'email': 'user1@company.com',
        'first_name': 'John',
        'last_name': 'Doe',
        'user_id': 'vendor_specific_id'
    }
]
```

**Implementation required in subclasses.**

##### `add_user_to_group(self, group_cfg: Dict[str, str], user_info: Dict[str, Any]) -> bool`

Add user to vendor group.

**Parameters:**
- `group_cfg` (Dict[str, str]): Group configuration
- `user_info` (Dict[str, Any]): User information from LDAP

**Returns:**
- `bool`: True if successful

**Implementation required in subclasses.**

##### `remove_user_from_group(self, group_cfg: Dict[str, str], user_identifier: str) -> bool`

Remove user from vendor group.

**Parameters:**
- `group_cfg` (Dict[str, str]): Group configuration
- `user_identifier` (str): User identifier (username, email, or ID)

**Returns:**
- `bool`: True if successful

**Implementation required in subclasses.**

##### `update_user(self, user_identifier: str, user_info: Dict[str, Any]) -> bool`

Update user attributes in vendor system.

**Parameters:**
- `user_identifier` (str): User identifier
- `user_info` (Dict[str, Any]): Updated user information

**Returns:**
- `bool`: True if successful

**Implementation required in subclasses.**

#### Helper Methods

##### `request(self, method: str, path: str, data: Any = None, headers: Dict[str, str] = None, **kwargs) -> Any`

Make HTTP request to vendor API.

**Parameters:**
- `method` (str): HTTP method (GET, POST, PUT, DELETE)
- `path` (str): API endpoint path
- `data` (Any, optional): Request body data
- `headers` (Dict[str, str], optional): Additional headers
- `**kwargs`: Additional arguments

**Returns:**
- `Any`: Parsed response data

**Example:**
```python
response = self.request('GET', '/api/users')
users = response.get('users', [])
```

##### `get_auth_headers(self) -> Dict[str, str]`

Get authentication headers for requests.

**Returns:**
- `Dict[str, str]`: Headers with authentication

**Example:**
```python
headers = self.get_auth_headers()
# {'Authorization': 'Bearer token123'} or {'Authorization': 'Basic dXNlcjpwYXNz'}
```

## Notification API

### Module: `ldap_sync.notifications`

#### `send_email(subject: str, body: str, config: Dict[str, Any], recipients: List[str] = None) -> bool`

Send email notification.

**Parameters:**
- `subject` (str): Email subject line
- `body` (str): Email message body
- `config` (Dict[str, Any]): Notification configuration
- `recipients` (List[str], optional): Override default recipients

**Returns:**
- `bool`: True if email sent successfully

**Example:**
```python
from ldap_sync.notifications import send_email

success = send_email(
    subject="LDAP Sync Failed",
    body="Sync process encountered errors. Check logs for details.",
    config=config['notifications']
)
```

#### `format_error_notification(error: Exception, context: str) -> Tuple[str, str]`

Format error for email notification.

**Parameters:**
- `error` (Exception): Exception that occurred
- `context` (str): Context where error occurred

**Returns:**
- `Tuple[str, str]`: (subject, body) for email

**Example:**
```python
subject, body = format_error_notification(
    error=ConnectionError("LDAP server unreachable"),
    context="LDAP connection"
)
```

## Main Orchestrator API

### Module: `ldap_sync.main`

#### `run_sync(config: Dict[str, Any]) -> bool`

Execute complete synchronization process.

**Parameters:**
- `config` (Dict[str, Any]): Complete application configuration

**Returns:**
- `bool`: True if sync completed successfully

**Example:**
```python
from ldap_sync.main import run_sync
from ldap_sync.config import load_config

config = load_config()
success = run_sync(config)
```

#### `sync_vendor(ldap_client: LDAPClient, vendor_config: Dict[str, Any], vendor_api: VendorAPIBase) -> Dict[str, int]`

Synchronize single vendor application.

**Parameters:**
- `ldap_client` (LDAPClient): Connected LDAP client
- `vendor_config` (Dict[str, Any]): Vendor configuration
- `vendor_api` (VendorAPIBase): Vendor API instance

**Returns:**
- `Dict[str, int]`: Sync statistics (added, removed, updated, errors)

**Example:**
```python
stats = sync_vendor(ldap_client, vendor_config, vendor_api)
print(f"Added: {stats['added']}, Removed: {stats['removed']}")
```

#### `compare_user_lists(ldap_users: List[Dict], vendor_users: List[Dict]) -> Tuple[List, List, List]`

Compare LDAP and vendor user lists to determine sync actions.

**Parameters:**
- `ldap_users` (List[Dict]): Users from LDAP
- `vendor_users` (List[Dict]): Users from vendor system

**Returns:**
- `Tuple[List, List, List]`: (users_to_add, users_to_remove, users_to_update)

**Example:**
```python
to_add, to_remove, to_update = compare_user_lists(ldap_users, vendor_users)
```

## Exception Classes

### Module: `ldap_sync.exceptions`

#### `LDAPSyncException`

Base exception for all application errors.

#### `ConfigurationError`

Configuration validation or loading errors.

**Attributes:**
- `message` (str): Error description
- `field` (str): Configuration field that caused error

#### `LDAPConnectionError`

LDAP connection or authentication errors.

**Attributes:**
- `server_url` (str): LDAP server URL
- `error_code` (int): LDAP error code

#### `VendorAPIError`

Vendor API communication errors.

**Attributes:**
- `vendor_name` (str): Name of vendor
- `status_code` (int): HTTP status code
- `response_body` (str): API response body

#### `AuthenticationError`

Authentication failures with LDAP or vendor APIs.

**Attributes:**
- `service` (str): Service name (LDAP or vendor name)
- `method` (str): Authentication method used

## Utility Functions

### Module: `ldap_sync.utils`

#### `setup_logging(config: Dict[str, Any]) -> None`

Configure logging based on configuration.

**Parameters:**
- `config` (Dict[str, Any]): Logging configuration section

#### `retry_on_failure(func: Callable, max_retries: int = 3, wait_seconds: int = 5) -> Any`

Decorator for retrying failed operations.

**Parameters:**
- `func` (Callable): Function to retry
- `max_retries` (int): Maximum retry attempts
- `wait_seconds` (int): Seconds to wait between retries

**Example:**
```python
@retry_on_failure(max_retries=3, wait_seconds=10)
def unreliable_api_call():
    return vendor_api.get_users()
```

#### `sanitize_log_data(data: Any) -> Any`

Remove sensitive information from log data.

**Parameters:**
- `data` (Any): Data to sanitize

**Returns:**
- `Any`: Sanitized data with passwords/tokens masked

#### `create_ssl_context(config: Dict[str, Any]) -> ssl.SSLContext`

Create SSL context from configuration.

**Parameters:**
- `config` (Dict[str, Any]): SSL configuration

**Returns:**
- `ssl.SSLContext`: Configured SSL context

## Data Models

### User Data Structure

Standard user data format used throughout the application:

```python
{
    'username': str,        # Unique username/login
    'email': str,          # Email address
    'first_name': str,     # Given name
    'last_name': str,      # Surname
    'user_id': str,        # Vendor-specific ID (optional)
    'attributes': dict     # Additional attributes (optional)
}
```

### Group Configuration Structure

Group mapping configuration format:

```python
{
    'ldap_group': str,     # LDAP group DN
    'vendor_group': str,   # Vendor group identifier
    'sync_attributes': list # Attributes to sync (optional)
}
```

### Sync Statistics Structure

Synchronization operation results:

```python
{
    'added': int,          # Users added to vendor
    'removed': int,        # Users removed from vendor
    'updated': int,        # Users updated in vendor
    'errors': int,         # Number of errors encountered
    'total_processed': int # Total users processed
}
```

## Configuration Schema

### Complete Configuration Structure

```yaml
# LDAP Configuration
ldap:
  server_url: str           # Required
  bind_dn: str             # Required
  bind_password: str       # Required
  user_base_dn: str        # Required
  user_filter: str         # Optional, default: "(objectClass=person)"
  attributes: List[str]    # Optional, default: ["cn", "mail", "sAMAccountName"]
  connection_timeout: int  # Optional, default: 30
  search_timeout: int      # Optional, default: 60
  verify_ssl: bool         # Optional, default: true
  ca_cert_file: str        # Optional

# Vendor Applications
vendor_apps:
  - name: str              # Required
    module: str            # Required
    base_url: str          # Required
    auth:                  # Required
      method: str          # Required: basic, token, oauth2
      username: str        # For basic auth
      password: str        # For basic auth
      token: str           # For token auth
      token_url: str       # For OAuth2
      client_id: str       # For OAuth2
      client_secret: str   # For OAuth2
      scope: str           # For OAuth2
    format: str            # Optional, default: "json"
    verify_ssl: bool       # Optional, default: true
    request_timeout: int   # Optional, default: 30
    groups:                # Required
      - ldap_group: str    # Required
        vendor_group: str  # Required

# Logging Configuration
logging:
  level: str               # Optional, default: "INFO"
  log_dir: str            # Optional, default: "logs"
  log_file: str           # Optional, default: "ldap_sync.log"
  rotation: str           # Optional, default: "daily"
  retention_days: int     # Optional, default: 7
  console_output: bool    # Optional, default: false

# Error Handling
error_handling:
  max_retries: int        # Optional, default: 3
  retry_wait_seconds: int # Optional, default: 5
  max_errors_per_vendor: int # Optional, default: 10

# Email Notifications
notifications:
  enable_email: bool      # Optional, default: false
  email_on_failure: bool  # Optional, default: true
  email_on_success: bool  # Optional, default: false
  smtp_server: str        # Required if email enabled
  smtp_port: int          # Optional, default: 587
  smtp_tls: bool          # Optional, default: true
  smtp_username: str      # Optional
  smtp_password: str      # Optional
  email_from: str         # Required if email enabled
  email_to: List[str]     # Required if email enabled
```

## Error Codes

### LDAP Error Codes

- `LDAP_CONNECTION_FAILED`: Could not connect to LDAP server
- `LDAP_AUTH_FAILED`: LDAP authentication failed
- `LDAP_SEARCH_FAILED`: LDAP search operation failed
- `LDAP_TIMEOUT`: LDAP operation timed out

### Vendor API Error Codes

- `VENDOR_AUTH_FAILED`: Vendor API authentication failed
- `VENDOR_API_ERROR`: General vendor API error
- `VENDOR_RATE_LIMITED`: API rate limit exceeded
- `VENDOR_TIMEOUT`: API request timed out

### Configuration Error Codes

- `CONFIG_NOT_FOUND`: Configuration file not found
- `CONFIG_INVALID_YAML`: Invalid YAML syntax
- `CONFIG_MISSING_REQUIRED`: Required configuration field missing
- `CONFIG_INVALID_VALUE`: Invalid configuration value

## Performance Considerations

### Batch Processing

For large user lists, implement batch processing:

```python
def process_users_in_batches(users, batch_size=100):
    for i in range(0, len(users), batch_size):
        batch = users[i:i+batch_size]
        yield batch
```

### Connection Pooling

Reuse connections where possible:

```python
class VendorAPI(VendorAPIBase):
    def __init__(self, config):
        super().__init__(config)
        self.session = requests.Session()  # Reuse connection
```

### Caching

Cache frequently accessed data:

```python
from functools import lru_cache

@lru_cache(maxsize=100)
def get_user_by_id(self, user_id):
    return self.request('GET', f'/users/{user_id}')
```

## Security Considerations

### Credential Handling

- Never log passwords or tokens
- Use environment variables for sensitive data
- Implement secure storage for tokens

### SSL/TLS

- Always verify certificates in production
- Use strong cipher suites
- Keep certificates up to date

### Input Validation

- Validate all configuration inputs
- Sanitize user data before API calls
- Use parameterized queries where applicable

For implementation examples, see the [Vendor Integration Guide](vendor-integration-guide.md).
For troubleshooting API issues, see the [Troubleshooting Guide](troubleshooting-guide.md).