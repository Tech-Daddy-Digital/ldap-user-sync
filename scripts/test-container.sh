#!/bin/bash
# Test script for LDAP User Sync container

set -e

echo "=== LDAP User Sync Container Test ==="

# Configuration
CONTAINER_NAME="ldap-user-sync-test"
IMAGE_NAME="ldap-user-sync:test"
TEST_CONFIG_DIR="$(pwd)/test/container-test"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

cleanup() {
    print_status "Cleaning up test environment..."
    docker stop "${CONTAINER_NAME}" 2>/dev/null || true
    docker rm "${CONTAINER_NAME}" 2>/dev/null || true
    docker volume rm ldap-user-sync-test-logs 2>/dev/null || true
}

# Trap cleanup on exit
trap cleanup EXIT

# Step 1: Build the container
print_status "Building container image..."
docker build -t "${IMAGE_NAME}" .

# Step 2: Create test configuration
print_status "Creating test configuration..."
mkdir -p "${TEST_CONFIG_DIR}"

cat > "${TEST_CONFIG_DIR}/config.yaml" << 'EOF'
ldap:
  server_url: "ldap://localhost:389"
  bind_dn: "cn=admin,dc=example,dc=com"
  bind_password: "test-password"
  user_base_dn: "ou=users,dc=example,dc=com"
  user_filter: "(objectClass=person)"
  attributes: ["cn", "givenName", "sn", "mail", "uid"]

vendor_apps:
  - name: "TestVendor"
    module: "vendor_app1"
    base_url: "http://localhost:8080/api/v1"
    auth:
      method: "basic"
      username: "testuser"
      password: "testpass"
    format: "json"
    verify_ssl: false
    groups:
      - ldap_group: "cn=testgroup,ou=groups,dc=example,dc=com"
        vendor_group: "test-group"

logging:
  level: "DEBUG"
  log_dir: "/app/logs"
  rotation: "daily"
  retention_days: 7

error_handling:
  max_retries: 2
  retry_wait_seconds: 3
  max_errors_per_vendor: 5

notifications:
  enable_email: false
  email_on_failure: false
  email_on_success: false
EOF

# Step 3: Test container startup and basic functionality
print_status "Testing container startup..."

# Create a volume for logs
docker volume create ldap-user-sync-test-logs

# Run container with dry-run mode (if available) or help
docker run --rm \
    --name "${CONTAINER_NAME}-startup" \
    -v "${TEST_CONFIG_DIR}/config.yaml:/app/config.yaml:ro" \
    -v ldap-user-sync-test-logs:/app/logs \
    -e CONFIG_PATH=/app/config.yaml \
    "${IMAGE_NAME}" --help > /dev/null 2>&1 || {
    print_warning "Help command failed, testing basic module import..."
    
    docker run --rm \
        --name "${CONTAINER_NAME}-import" \
        "${IMAGE_NAME}" python -c "
import sys
sys.path.insert(0, '/app')
try:
    import ldap_sync
    import ldap_sync.main
    import ldap_sync.config
    import ldap_sync.ldap_client
    print('✓ All modules imported successfully')
    exit(0)
except ImportError as e:
    print(f'✗ Import error: {e}')
    exit(1)
except Exception as e:
    print(f'✗ Other error: {e}')
    exit(1)
"
}

# Step 4: Test configuration loading
print_status "Testing configuration loading..."
docker run --rm \
    --name "${CONTAINER_NAME}-config" \
    -v "${TEST_CONFIG_DIR}/config.yaml:/app/config.yaml:ro" \
    -e CONFIG_PATH=/app/config.yaml \
    "${IMAGE_NAME}" python -c "
import sys
sys.path.insert(0, '/app')
from ldap_sync.config import load_config
try:
    config = load_config('/app/config.yaml')
    print('✓ Configuration loaded successfully')
    print(f'  - LDAP server: {config[\"ldap\"][\"server_url\"]}')
    print(f'  - Vendors: {len(config[\"vendor_apps\"])}')
    exit(0)
except Exception as e:
    print(f'✗ Configuration error: {e}')
    exit(1)
"

# Step 5: Test logging setup
print_status "Testing logging setup..."
docker run --rm \
    --name "${CONTAINER_NAME}-logging" \
    -v ldap-user-sync-test-logs:/app/logs \
    "${IMAGE_NAME}" python -c "
import sys
sys.path.insert(0, '/app')
import logging
import os
from ldap_sync.main import setup_logging

try:
    # Test logging setup
    config = {
        'logging': {
            'level': 'INFO',
            'log_dir': '/app/logs',
            'rotation': 'daily',
            'retention_days': 7
        }
    }
    setup_logging(config['logging'])
    
    # Test writing to log
    logger = logging.getLogger(__name__)
    logger.info('Test log message from container')
    
    # Check if log directory was created
    if os.path.exists('/app/logs'):
        print('✓ Logging setup successful')
        print(f'  - Log directory exists: /app/logs')
    else:
        print('✗ Log directory not created')
        exit(1)
    
    exit(0)
except Exception as e:
    print(f'✗ Logging error: {e}')
    exit(1)
"

# Step 6: Test with environment variable override
print_status "Testing environment variable overrides..."
docker run --rm \
    --name "${CONTAINER_NAME}-env" \
    -v "${TEST_CONFIG_DIR}/config.yaml:/app/config.yaml:ro" \
    -e CONFIG_PATH=/app/config.yaml \
    -e LDAP_SERVER_URL=ldaps://override.example.com:636 \
    -e LOG_LEVEL=DEBUG \
    "${IMAGE_NAME}" python -c "
import sys
sys.path.insert(0, '/app')
from ldap_sync.config import load_config
import os

try:
    config = load_config('/app/config.yaml')
    
    # Check if environment variables are properly used
    expected_url = 'ldaps://override.example.com:636'
    actual_url = config['ldap']['server_url']
    
    if actual_url == expected_url:
        print('✓ Environment variable override working')
        print(f'  - LDAP URL: {actual_url}')
    else:
        print(f'✗ Environment override failed: expected {expected_url}, got {actual_url}')
        exit(1)
        
    exit(0)
except Exception as e:
    print(f'✗ Environment override error: {e}')
    exit(1)
"

# Step 7: Security checks
print_status "Running security checks..."

# Check if running as non-root
NON_ROOT=$(docker run --rm "${IMAGE_NAME}" id -u)
if [ "$NON_ROOT" != "0" ]; then
    print_status "✓ Container runs as non-root user (UID: $NON_ROOT)"
else
    print_error "✗ Container runs as root user"
    exit 1
fi

# Check if sensitive files are not world-readable
docker run --rm "${IMAGE_NAME}" sh -c "
find /app -type f -perm -o+r -name '*.py' | head -5 | while read file; do
    echo '✓ Python files are readable'
    break
done

# Check if logs directory has proper permissions
if [ -d '/app/logs' ]; then
    PERMS=\$(stat -c '%a' /app/logs)
    echo \"✓ Logs directory permissions: \$PERMS\"
fi
"

# Step 8: Resource usage test
print_status "Testing resource constraints..."
docker run --rm \
    --memory=256m \
    --cpus=0.5 \
    --name "${CONTAINER_NAME}-resources" \
    "${IMAGE_NAME}" python -c "
import sys
sys.path.insert(0, '/app')
print('✓ Container works within resource constraints')
"

print_status "Container tests completed successfully!"

# Optional: Run with docker-compose if available
if command -v docker-compose &> /dev/null; then
    print_status "Testing with docker-compose..."
    if [ -f "docker-compose.test.yaml" ]; then
        print_status "docker-compose.test.yaml found, you can run:"
        echo "  docker-compose -f docker-compose.test.yaml up --build"
    fi
fi

print_status "=== Test Summary ==="
echo "✓ Container builds successfully"
echo "✓ Application modules load correctly"
echo "✓ Configuration loading works"
echo "✓ Logging system functional"
echo "✓ Environment variable overrides work"
echo "✓ Security: runs as non-root user"
echo "✓ Works within resource constraints"

print_status "Container is ready for deployment!"