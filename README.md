# LDAP User Sync

A robust Python application for synchronizing user accounts and group memberships between LDAP directories and vendor application systems via REST APIs.

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Security](https://img.shields.io/badge/security-compliant-green.svg)]()
[![Documentation](https://img.shields.io/badge/docs-complete-blue.svg)]()
[![License](https://img.shields.io/badge/license-MIT-blue.svg)]()

## Overview

The LDAP User Sync application ensures that user information and group memberships in vendor applications stay consistent with an authoritative LDAP directory. It automates user provisioning, deprovisioning, and profile updates across multiple systems.

### Key Features

- **Multi-Vendor Support**: Extensible plugin architecture for different vendor APIs
- **Robust Error Handling**: Comprehensive retry logic and failure recovery
- **Security First**: TLS encryption, certificate validation, and secrets management
- **Comprehensive Logging**: Structured logging with rotation and retention
- **Email Notifications**: Configurable alerts for failures and important events
- **Container Ready**: Docker and Kubernetes deployment support
- **Production Ready**: Monitoring, backup, and operational procedures included

### Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   LDAP Server   │◄──►│ LDAP User Sync   │◄──►│ Vendor APIs     │
│                 │    │                  │    │                 │
│ • Users         │    │ • Sync Engine    │    │ • App1 API      │
│ • Groups        │    │ • Vendor Plugins │    │ • App2 API      │
│ • Attributes    │    │ • Error Handling │    │ • App3 API      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.8+
- Access to LDAP server
- Vendor application API credentials
- Kubernetes cluster (for production deployment)

### Installation

```bash
# Clone the repository
git clone https://github.com/company/ldap-user-sync.git
cd ldap-user-sync

# Install dependencies
pip install -r requirements.txt

# Copy and configure settings
cp config.yaml.example config.yaml
# Edit config.yaml with your settings
```

### Basic Configuration

```yaml
# config.yaml
ldap:
  server_url: "ldaps://ldap.company.com:636"
  bind_dn: "CN=Service Account,OU=Users,DC=company,DC=com"
  bind_password: "${LDAP_BIND_PASSWORD}"
  user_base_dn: "OU=Users,DC=company,DC=com"

vendor_apps:
  - name: "Business Application"
    module: "business_app"
    base_url: "https://api.businessapp.com/v1"
    auth:
      method: "basic"
      username: "sync-service"
      password: "${VENDOR_PASSWORD}"
    groups:
      - ldap_group: "CN=App_Users,OU=Groups,DC=company,DC=com"
        vendor_group: "users"
```

### Running the Application

```bash
# Set environment variables
export LDAP_BIND_PASSWORD="your_ldap_password"
export VENDOR_PASSWORD="your_vendor_password"

# Run sync
python -m ldap_sync.main

# Run with custom config
CONFIG_PATH=/path/to/config.yaml python -m ldap_sync.main
```

## Development

### Project Structure

```
ldap-user-sync/
├── ldap_sync/                 # Main application package
│   ├── __init__.py
│   ├── main.py               # Entry point and orchestration
│   ├── config.py             # Configuration management
│   ├── ldap_client.py        # LDAP connectivity
│   ├── notifications.py     # Email notifications
│   └── vendors/              # Vendor integration plugins
│       ├── __init__.py
│       ├── base.py          # Abstract base class
│       ├── vendor_app1.py   # Example vendor integration
│       └── vendor_app2.py   # Another vendor integration
├── tests/                    # Test suite
├── docs/                     # Documentation
├── helm/                     # Helm chart for deployment
├── Dockerfile               # Container image definition
├── requirements.txt         # Python dependencies
├── config.yaml.example     # Example configuration
└── README.md               # This file
```

### Running Tests

```bash
# Install test dependencies
pip install -r requirements-test.txt

# Run all tests
python tests/run_tests.py

# Run specific test file
python tests/test_ldap_client.py

# Run with coverage
coverage run tests/run_tests.py
coverage report
```

### Adding New Vendor Integrations

1. Create a new module in `ldap_sync/vendors/`
2. Extend the `VendorAPIBase` class
3. Implement required methods:
   - `authenticate()`
   - `get_group_members()`
   - `add_user_to_group()`
   - `remove_user_from_group()`
   - `update_user()`

See the [Vendor Integration Guide](docs/vendor-integration-guide.md) for detailed instructions.

### Code Quality

```bash
# Run linting
flake8 ldap_sync/
pylint ldap_sync/

# Run type checking
mypy ldap_sync/

# Format code
black ldap_sync/
isort ldap_sync/
```

## Deployment

### Docker

```bash
# Build image
docker build -t ldap-user-sync:latest .

# Run container
docker run -d \
  --name ldap-user-sync \
  -v /path/to/config.yaml:/app/config.yaml:ro \
  -e LDAP_BIND_PASSWORD="password" \
  ldap-user-sync:latest
```

### Kubernetes

```bash
# Install with Helm
helm install ldap-user-sync ./helm \
  --namespace ldap-user-sync \
  --create-namespace \
  --set ldap.bindPassword="your_password"

# Check deployment
kubectl get all -n ldap-user-sync
```

For detailed deployment instructions, see the [Deployment Guide](docs/deployment-guide.md).

## Configuration

### Environment Variables

Key environment variables for configuration override:

- `CONFIG_PATH`: Path to configuration file
- `LDAP_BIND_PASSWORD`: LDAP service account password
- `VENDOR_APP1_PASSWORD`: Vendor API credentials
- `SMTP_PASSWORD`: SMTP authentication password

### Configuration Sections

- **ldap**: LDAP server connection and authentication
- **vendor_apps**: List of vendor applications to sync
- **logging**: Log levels, rotation, and retention
- **error_handling**: Retry logic and failure thresholds
- **notifications**: Email notification settings

For comprehensive configuration options, see the [Configuration Guide](docs/configuration-guide.md).

## Monitoring

### Health Checks

```bash
# Check application health
curl http://localhost:8080/health

# Detailed health check
curl http://localhost:8080/health/detailed
```

### Metrics

The application exposes Prometheus metrics:

- `ldap_sync_operations_total` - Total sync operations
- `ldap_sync_duration_seconds` - Sync operation duration
- `ldap_sync_errors_total` - Total sync errors
- `ldap_sync_users_processed` - Users processed in last sync

### Logging

Structured JSON logging with configurable levels:

```json
{
  "timestamp": "2024-01-15T10:30:45Z",
  "level": "INFO",
  "message": "Sync completed successfully",
  "vendor": "BusinessApp",
  "users_added": 5,
  "users_removed": 2,
  "users_updated": 3
}
```

For monitoring setup, see the [Monitoring Procedures](docs/monitoring-procedures.md).

## Security

### Security Features

- **Encryption**: TLS 1.2+ for all connections
- **Authentication**: Service account-based access
- **Secrets Management**: Kubernetes Secrets integration
- **Audit Logging**: Comprehensive security event logging
- **Network Security**: Network policies and firewall rules

### Security Best Practices

- Use environment variables for sensitive data
- Enable certificate verification
- Implement network segmentation
- Regular security scanning
- Audit trail maintenance

For security procedures, see the [Security Procedures](docs/security-procedures.md).

## Operations

### Backup and Recovery

- **Configuration**: Daily automated backups
- **Logs**: Continuous backup with 90-day retention
- **Recovery**: Tested procedures with RTO < 30 minutes

### Maintenance

- **Updates**: Monthly security updates
- **Health Checks**: Daily monitoring
- **Performance**: Quarterly optimization reviews

For operational procedures, see:
- [Backup and Recovery Procedures](docs/backup-recovery-procedures.md)
- [Maintenance Procedures](docs/maintenance-procedures.md)

## Troubleshooting

### Common Issues

1. **LDAP Connection Failed**
   ```bash
   # Test LDAP connectivity
   telnet ldap.company.com 636
   ```

2. **Vendor API Authentication Failed**
   ```bash
   # Test API credentials
   curl -u username:password https://api.vendor.com/health
   ```

3. **High Memory Usage**
   - Check log retention settings
   - Monitor user count per group
   - Consider batch processing optimization

For comprehensive troubleshooting, see the [Troubleshooting Guide](docs/troubleshooting-guide.md).

## Contributing

### Development Workflow

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

### Code Standards

- Follow PEP 8 style guidelines
- Write comprehensive tests
- Document all public APIs
- Use type hints where appropriate

### Commit Messages

Use conventional commit format:

```
feat: add support for OAuth2 authentication
fix: resolve memory leak in LDAP client
docs: update deployment guide
test: add integration tests for vendor API
```

## Documentation

### Available Documentation

- [Configuration Guide](docs/configuration-guide.md) - Complete configuration reference
- [Deployment Guide](docs/deployment-guide.md) - Deployment instructions for all environments
- [Vendor Integration Guide](docs/vendor-integration-guide.md) - Developer guide for new integrations
- [API Reference](docs/api-reference.md) - Complete API documentation
- [Troubleshooting Guide](docs/troubleshooting-guide.md) - Common issues and solutions
- [Security Procedures](docs/security-procedures.md) - Security best practices and procedures
- [Monitoring Procedures](docs/monitoring-procedures.md) - Monitoring and alerting setup
- [Backup and Recovery Procedures](docs/backup-recovery-procedures.md) - Backup and disaster recovery
- [Maintenance Procedures](docs/maintenance-procedures.md) - Operational maintenance procedures

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

### Getting Help

- **Documentation**: Check the [docs/](docs/) directory
- **Issues**: Report bugs via GitHub Issues
- **Internal Support**: Contact the IT Operations team
- **Security Issues**: Report to security@company.com

### FAQ

**Q: How often does the sync run?**
A: By default, every 6 hours. Configurable via CronJob schedule.

**Q: What happens if a vendor API is down?**
A: The sync will retry with exponential backoff, then send an alert and continue with other vendors.

**Q: Can I run a test sync without making changes?**
A: Yes, use the dry-run mode: `python -m ldap_sync.main --dry-run`

**Q: How do I add a new vendor application?**
A: See the [Vendor Integration Guide](docs/vendor-integration-guide.md) for step-by-step instructions.

**Q: What data is synchronized?**
A: User identity (username, email, first name, last name) and group memberships.

## Changelog

### Version 1.0.0 (2024-01-15)

- Initial release
- Multi-vendor sync support
- Comprehensive error handling
- Email notifications
- Container deployment
- Full documentation suite

### Roadmap

- **v1.1**: Dry-run mode implementation
- **v1.2**: Advanced attribute mapping
- **v1.3**: Concurrent processing capabilities
- **v1.4**: Enhanced monitoring and analytics

---

**LDAP User Sync** - Keeping your user directories in perfect sync. 🔄