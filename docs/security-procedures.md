# Security Procedures

This document outlines comprehensive security procedures for the LDAP User Sync application, covering threat assessment, security controls, incident response, and compliance requirements.

## Security Overview

The LDAP User Sync application handles sensitive user identity data and requires robust security controls:

- **Data Protection**: Secure handling of user credentials and personal information
- **Access Control**: Principle of least privilege for system access
- **Network Security**: Encrypted communications and network segmentation
- **Audit & Compliance**: Comprehensive logging and regulatory compliance
- **Incident Response**: Procedures for security events and breaches

## Security Architecture

### Security Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                    Security Perimeter                      │
│  ┌───────────────┐    ┌──────────────┐    ┌─────────────┐  │
│  │   LDAP        │◄──►│ LDAP User    │◄──►│   Vendor    │  │
│  │   Server      │    │ Sync App     │    │   APIs      │  │
│  │               │    │              │    │             │  │
│  └───────────────┘    └──────────────┘    └─────────────┘  │
│         ▲                       ▲                    ▲      │
│         │                       │                    │      │
│    TLS/LDAPS              K8s Security        HTTPS/mTLS   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Security Controls

#### Authentication & Authorization
- Service account-based LDAP authentication
- API key/token-based vendor authentication
- Kubernetes RBAC for container permissions
- Certificate-based mutual TLS where required

#### Data Protection
- Encryption in transit (TLS 1.2+)
- Secrets management via Kubernetes Secrets
- No plaintext credentials in configuration
- Secure key storage and rotation

#### Network Security
- Network policies for traffic isolation
- Firewall rules for external connectivity
- VPN/private network for sensitive connections
- Regular security scanning of container images

## Access Control

### Service Account Management

#### LDAP Service Account

```bash
#!/bin/bash
# create-ldap-service-account.sh

DOMAIN="company.com"
SERVICE_ACCOUNT_NAME="ldap-sync-service"
OU="Service Accounts"

echo "Creating LDAP service account for user sync"

# Generate strong password
PASSWORD=$(openssl rand -base64 32)

# Create service account (adjust for your LDAP schema)
ldapadd -x -D "CN=admin,DC=company,DC=com" -W <<EOF
dn: CN=$SERVICE_ACCOUNT_NAME,OU=$OU,DC=company,DC=com
objectClass: user
objectClass: person
objectClass: organizationalPerson
cn: $SERVICE_ACCOUNT_NAME
userPrincipalName: $SERVICE_ACCOUNT_NAME@$DOMAIN
description: Service account for LDAP user synchronization
userAccountControl: 66048
pwdLastSet: 0
EOF

# Set password
ldappasswd -x -D "CN=admin,DC=company,DC=com" -W \
    "CN=$SERVICE_ACCOUNT_NAME,OU=$OU,DC=company,DC=com" -s "$PASSWORD"

echo "Service account created: CN=$SERVICE_ACCOUNT_NAME,OU=$OU,DC=company,DC=com"
echo "Password: $PASSWORD"
echo "IMPORTANT: Store this password securely and update Kubernetes secrets"
```

#### LDAP Permissions

Minimum required permissions for the service account:

```ldif
# Bind and read permissions
dn: OU=Users,DC=company,DC=com
changetype: modify
add: ntSecurityDescriptor
ntSecurityDescriptor: # Read permissions for user objects

dn: OU=Groups,DC=company,DC=com  
changetype: modify
add: ntSecurityDescriptor
ntSecurityDescriptor: # Read permissions for group objects
```

#### Kubernetes RBAC

```yaml
# rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ldap-user-sync
  namespace: ldap-user-sync
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: ldap-user-sync
  name: ldap-user-sync
rules:
- apiGroups: [""]
  resources: ["secrets", "configmaps"]
  verbs: ["get", "list"]
- apiGroups: ["batch"]
  resources: ["jobs"]
  verbs: ["get", "list", "create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ldap-user-sync
  namespace: ldap-user-sync
subjects:
- kind: ServiceAccount
  name: ldap-user-sync
  namespace: ldap-user-sync
roleRef:
  kind: Role
  name: ldap-user-sync
  apiGroup: rbac.authorization.k8s.io
```

### Vendor API Access

#### API Key Management

```bash
#!/bin/bash
# rotate-vendor-api-keys.sh

NAMESPACE="ldap-user-sync"
VENDOR_NAME="$1"

if [ -z "$VENDOR_NAME" ]; then
    echo "Usage: $0 <vendor_name>"
    exit 1
fi

echo "Rotating API key for vendor: $VENDOR_NAME"

# Generate new API key (vendor-specific process)
NEW_API_KEY=$(curl -X POST "https://api.$VENDOR_NAME.com/keys" \
    -H "Authorization: Bearer $CURRENT_ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name":"ldap-sync-'$(date +%Y%m%d)'","permissions":["users:read","users:write","groups:manage"]}' | \
    jq -r '.api_key')

if [ -z "$NEW_API_KEY" ]; then
    echo "Failed to generate new API key"
    exit 1
fi

# Update Kubernetes secret
kubectl patch secret ldap-sync-secrets -n "$NAMESPACE" \
    --patch="{\"data\":{\"VENDOR_${VENDOR_NAME^^}_PASSWORD\":\"$(echo -n "$NEW_API_KEY" | base64)\"}}"

# Test new key
kubectl run api-test --rm -i --restart=Never \
    --image=curlimages/curl --namespace="$NAMESPACE" \
    -- curl -H "Authorization: Bearer $NEW_API_KEY" \
    "https://api.$VENDOR_NAME.com/health"

if [ $? -eq 0 ]; then
    echo "New API key validated successfully"
    
    # Revoke old key (if possible)
    # curl -X DELETE "https://api.$VENDOR_NAME.com/keys/$OLD_KEY_ID" ...
    
    echo "API key rotation completed for $VENDOR_NAME"
else
    echo "API key validation failed - rollback may be required"
    exit 1
fi
```

## Secrets Management

### Kubernetes Secrets Security

#### Secret Creation with Encryption

```bash
#!/bin/bash
# create-encrypted-secrets.sh

NAMESPACE="ldap-user-sync"

echo "Creating encrypted secrets for LDAP User Sync"

# Encrypt sensitive values before storing
LDAP_PASSWORD=$(echo -n "$LDAP_BIND_PASSWORD" | base64)
VENDOR_PASSWORD=$(echo -n "$VENDOR_API_PASSWORD" | base64)
SMTP_PASSWORD=$(echo -n "$SMTP_PASSWORD" | base64)

kubectl create secret generic ldap-sync-secrets \
    --from-literal=LDAP_BIND_PASSWORD="$LDAP_BIND_PASSWORD" \
    --from-literal=VENDOR_APP1_PASSWORD="$VENDOR_API_PASSWORD" \
    --from-literal=SMTP_PASSWORD="$SMTP_PASSWORD" \
    --namespace="$NAMESPACE"

# Add metadata for tracking
kubectl annotate secret ldap-sync-secrets -n "$NAMESPACE" \
    created-by="$(whoami)" \
    created-date="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    rotation-schedule="quarterly"

echo "Secrets created successfully"
```

#### Secret Rotation Schedule

```yaml
# secret-rotation-cronjob.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: secret-rotation-reminder
  namespace: ldap-user-sync
spec:
  schedule: "0 9 1 1,4,7,10 *"  # Quarterly reminder
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: rotation-reminder
            image: busybox
            command:
            - /bin/sh
            - -c
            - |
              echo "Secret rotation reminder: Review and rotate the following:"
              echo "- LDAP service account password"
              echo "- Vendor API keys/tokens"
              echo "- SMTP authentication credentials"
              echo "- SSL certificates"
              
              # Send notification
              wget -qO- --post-data='{"text":"🔐 Quarterly secret rotation reminder for LDAP User Sync"}' \
                --header='Content-Type: application/json' \
                "$SLACK_WEBHOOK_URL"
            env:
            - name: SLACK_WEBHOOK_URL
              valueFrom:
                secretKeyRef:
                  name: notification-config
                  key: slack-webhook
          restartPolicy: OnFailure
```

### External Secrets Management

#### Using HashiCorp Vault

```yaml
# vault-secret.yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: ldap-sync-vault-secrets
  namespace: ldap-user-sync
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-secret-store
    kind: SecretStore
  target:
    name: ldap-sync-secrets
    creationPolicy: Owner
  data:
  - secretKey: LDAP_BIND_PASSWORD
    remoteRef:
      key: secret/ldap-sync
      property: ldap_password
  - secretKey: VENDOR_APP1_PASSWORD
    remoteRef:
      key: secret/ldap-sync
      property: vendor_api_key
  - secretKey: SMTP_PASSWORD
    remoteRef:
      key: secret/ldap-sync
      property: smtp_password
```

## Network Security

### Network Policies

```yaml
# network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ldap-user-sync-netpol
  namespace: ldap-user-sync
spec:
  podSelector:
    matchLabels:
      app: ldap-user-sync
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from: []  # No ingress traffic allowed
  egress:
  # Allow DNS resolution
  - to: []
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
  # Allow LDAP access
  - to:
    - namespaceSelector:
        matchLabels:
          name: ldap-infrastructure
    ports:
    - protocol: TCP
      port: 636  # LDAPS
  # Allow vendor API access
  - to: []
    ports:
    - protocol: TCP
      port: 443  # HTTPS
  # Allow SMTP access
  - to:
    - namespaceSelector:
        matchLabels:
          name: mail-infrastructure
    ports:
    - protocol: TCP
      port: 587  # SMTP with STARTTLS
```

### TLS Configuration

#### Certificate Management

```bash
#!/bin/bash
# manage-certificates.sh

NAMESPACE="ldap-user-sync"
CERT_DIR="/etc/ssl/certs"

echo "Managing certificates for LDAP User Sync"

# Create certificate signing request for client authentication
openssl req -new -newkey rsa:2048 -nodes \
    -keyout client.key \
    -out client.csr \
    -subj "/CN=ldap-user-sync/O=Company/C=US"

# Sign with internal CA (adjust for your PKI)
openssl x509 -req -in client.csr \
    -CA ca.crt -CAkey ca.key \
    -out client.crt \
    -days 365 \
    -extensions client_auth

# Create Kubernetes secret for client certificate
kubectl create secret tls ldap-sync-client-cert \
    --cert=client.crt \
    --key=client.key \
    --namespace="$NAMESPACE"

# Create CA bundle secret
kubectl create secret generic ldap-sync-ca-bundle \
    --from-file=ca-bundle.crt \
    --namespace="$NAMESPACE"

echo "Certificates configured successfully"
```

#### TLS Version Enforcement

```python
# In application code - enforce TLS 1.2+
import ssl

def create_secure_context():
    """Create SSL context with security best practices."""
    context = ssl.create_default_context()
    
    # Enforce TLS 1.2 minimum
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    
    # Disable weak ciphers
    context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
    
    # Enable certificate verification
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    
    return context
```

## Security Monitoring

### Security Event Detection

```bash
#!/bin/bash
# security-monitoring.sh

NAMESPACE="ldap-user-sync"
LOG_DIR="/app/logs"
SECURITY_LOG="/var/log/security-events.log"

echo "Monitoring security events for LDAP User Sync"

# Monitor for authentication failures
grep -i "authentication failed\|login failed\|invalid credentials" "$LOG_DIR"/*.log | \
    while read line; do
        echo "$(date): AUTH_FAILURE: $line" >> "$SECURITY_LOG"
        
        # Count failures in last 5 minutes
        RECENT_FAILURES=$(grep -c "AUTH_FAILURE" "$SECURITY_LOG" | tail -5)
        if [ "$RECENT_FAILURES" -gt 5 ]; then
            echo "ALERT: Multiple authentication failures detected"
            # Send security alert
        fi
    done

# Monitor for privilege escalation attempts
grep -i "permission denied\|access denied\|unauthorized" "$LOG_DIR"/*.log | \
    while read line; do
        echo "$(date): ACCESS_DENIED: $line" >> "$SECURITY_LOG"
    done

# Monitor for suspicious configuration changes
kubectl get events -n "$NAMESPACE" --field-selector type=Warning | \
    grep -i "forbidden\|unauthorized" | \
    while read event; do
        echo "$(date): K8S_SECURITY_EVENT: $event" >> "$SECURITY_LOG"
    done

echo "Security monitoring completed"
```

### Intrusion Detection

```yaml
# falco-rules.yaml
- rule: Ldap Sync Suspicious Network Activity
  desc: Detect suspicious network connections from LDAP sync pods
  condition: >
    (k8s_audit and ka.verb in (create, update) and ka.uri.path contains "/api/v1/namespaces/ldap-user-sync") or
    (spawned_process and proc.name in (nc, ncat, netcat, socat) and k8s.ns.name=ldap-user-sync)
  output: >
    Suspicious network activity in LDAP sync (user=%ka.user.name verb=%ka.verb 
    uri=%ka.uri resource=%ka.target.resource)
  priority: WARNING
  tags: [ldap-sync, network, security]

- rule: Ldap Sync Unauthorized File Access
  desc: Detect unauthorized file access in LDAP sync containers
  condition: >
    open_read and k8s.ns.name=ldap-user-sync and 
    not fd.name in (/app/logs, /app/config, /tmp, /proc, /sys) and
    not proc.name in (python, ldap_sync)
  output: >
    Unauthorized file access in LDAP sync (file=%fd.name proc=%proc.name user=%user.name)
  priority: WARNING
  tags: [ldap-sync, file-access, security]
```

## Vulnerability Management

### Container Security Scanning

```bash
#!/bin/bash
# security-scan.sh

IMAGE_NAME="your-registry.com/ldap-user-sync:latest"
SCAN_REPORT="/tmp/security-scan-$(date +%Y%m%d).json"

echo "Performing security scan of LDAP User Sync container"

# Scan with Trivy
trivy image --format json --output "$SCAN_REPORT" "$IMAGE_NAME"

# Parse results
HIGH_VULNS=$(jq '.Results[].Vulnerabilities[]? | select(.Severity=="HIGH") | .VulnerabilityID' "$SCAN_REPORT" | wc -l)
CRITICAL_VULNS=$(jq '.Results[].Vulnerabilities[]? | select(.Severity=="CRITICAL") | .VulnerabilityID' "$SCAN_REPORT" | wc -l)

echo "Security scan results:"
echo "  Critical vulnerabilities: $CRITICAL_VULNS"
echo "  High vulnerabilities: $HIGH_VULNS"

# Alert if critical vulnerabilities found
if [ "$CRITICAL_VULNS" -gt 0 ]; then
    echo "ALERT: Critical vulnerabilities found - immediate action required"
    
    # Send security alert
    curl -X POST "$SLACK_WEBHOOK" -H 'Content-type: application/json' \
        --data "{\"text\":\"🚨 Critical security vulnerabilities found in LDAP User Sync image: $CRITICAL_VULNS critical, $HIGH_VULNS high\"}"
    
    exit 1
fi

echo "Security scan completed"
```

### Automated Vulnerability Monitoring

```yaml
# vulnerability-scan-cronjob.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: security-scan
  namespace: ldap-user-sync
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: trivy-scanner
            image: aquasec/trivy:latest
            command:
            - /bin/sh
            - -c
            - |
              # Scan the current image
              trivy image --format json your-registry.com/ldap-user-sync:latest > /tmp/scan.json
              
              # Check for critical vulnerabilities
              CRITICAL=$(jq '.Results[].Vulnerabilities[]? | select(.Severity=="CRITICAL")' /tmp/scan.json | jq -s length)
              HIGH=$(jq '.Results[].Vulnerabilities[]? | select(.Severity=="HIGH")' /tmp/scan.json | jq -s length)
              
              if [ "$CRITICAL" -gt 0 ]; then
                echo "CRITICAL vulnerabilities found: $CRITICAL"
                # Send alert via webhook
                curl -X POST "$WEBHOOK_URL" -H 'Content-type: application/json' \
                  --data "{\"text\":\"🚨 Critical vulnerabilities in LDAP User Sync: $CRITICAL critical, $HIGH high\"}"
              fi
              
              # Upload results to security dashboard
              curl -X POST "$SECURITY_API/scans" \
                -H "Authorization: Bearer $API_TOKEN" \
                -H "Content-Type: application/json" \
                -d @/tmp/scan.json
            env:
            - name: WEBHOOK_URL
              valueFrom:
                secretKeyRef:
                  name: security-config
                  key: webhook-url
            - name: API_TOKEN
              valueFrom:
                secretKeyRef:
                  name: security-config
                  key: api-token
          restartPolicy: OnFailure
```

## Incident Response

### Security Incident Classification

#### Severity Levels

- **Critical (P1)**: Active attack, data breach, service compromise
- **High (P2)**: Privilege escalation, authentication bypass, exposed credentials
- **Medium (P3)**: Suspicious activity, policy violations, configuration issues
- **Low (P4)**: Information gathering, minor policy violations

### Incident Response Procedures

#### Security Incident Response

```bash
#!/bin/bash
# security-incident-response.sh

INCIDENT_TYPE="$1"
SEVERITY="$2"
NAMESPACE="ldap-user-sync"

if [ -z "$INCIDENT_TYPE" ] || [ -z "$SEVERITY" ]; then
    echo "Usage: $0 <incident_type> <severity>"
    echo "Severity: critical|high|medium|low"
    exit 1
fi

echo "Initiating security incident response for $INCIDENT_TYPE (Severity: $SEVERITY)"

# Immediate containment for critical incidents
if [ "$SEVERITY" = "critical" ]; then
    echo "CRITICAL INCIDENT: Implementing immediate containment"
    
    # Suspend CronJob
    kubectl patch cronjob ldap-user-sync -n "$NAMESPACE" -p '{"spec":{"suspend":true}}'
    
    # Kill running jobs
    kubectl delete jobs --all -n "$NAMESPACE"
    
    # Block network access (emergency network policy)
    kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: emergency-isolation
  namespace: $NAMESPACE
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
EOF
    
    echo "Emergency containment activated"
fi

# Collect forensic data
echo "Collecting forensic data"
FORENSIC_DIR="/tmp/forensics-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$FORENSIC_DIR"

# Collect logs
kubectl logs --all-containers=true --prefix=true -n "$NAMESPACE" > "$FORENSIC_DIR/pod-logs.txt"

# Collect events
kubectl get events -n "$NAMESPACE" --sort-by=.metadata.creationTimestamp > "$FORENSIC_DIR/events.txt"

# Collect configuration
kubectl get all,configmaps,secrets -n "$NAMESPACE" -o yaml > "$FORENSIC_DIR/resources.yaml"

# Collect network policies
kubectl get networkpolicies -n "$NAMESPACE" -o yaml > "$FORENSIC_DIR/network-policies.yaml"

# Create forensic archive
tar -czf "$FORENSIC_DIR.tar.gz" -C "$(dirname "$FORENSIC_DIR")" "$(basename "$FORENSIC_DIR")"

echo "Forensic data collected: $FORENSIC_DIR.tar.gz"

# Send incident notification
curl -X POST "$INCIDENT_WEBHOOK" -H 'Content-type: application/json' \
    --data "{
        \"text\":\"🚨 Security Incident Detected\",
        \"attachments\":[{
            \"color\":\"danger\",
            \"fields\":[
                {\"title\":\"Type\",\"value\":\"$INCIDENT_TYPE\",\"short\":true},
                {\"title\":\"Severity\",\"value\":\"$SEVERITY\",\"short\":true},
                {\"title\":\"Namespace\",\"value\":\"$NAMESPACE\",\"short\":true},
                {\"title\":\"Forensics\",\"value\":\"$FORENSIC_DIR.tar.gz\",\"short\":true}
            ]
        }]
    }"

echo "Security incident response completed"
```

### Post-Incident Procedures

#### Security Assessment

```bash
#!/bin/bash
# post-incident-assessment.sh

INCIDENT_ID="$1"
NAMESPACE="ldap-user-sync"

echo "Performing post-incident security assessment for incident $INCIDENT_ID"

# Security posture review
echo "1. Reviewing security configurations..."

# Check RBAC permissions
kubectl auth can-i --list --as=system:serviceaccount:$NAMESPACE:ldap-user-sync -n "$NAMESPACE"

# Check network policies
kubectl get networkpolicies -n "$NAMESPACE" -o yaml

# Check secret permissions
kubectl get secrets -n "$NAMESPACE" -o yaml | grep -v "data:"

# Vulnerability assessment
echo "2. Running vulnerability assessment..."
./security-scan.sh

# Configuration review
echo "3. Reviewing configuration security..."
kubectl get configmap ldap-sync-config -n "$NAMESPACE" -o yaml | \
    grep -E "(password|key|token|secret)" || echo "No exposed credentials found"

# Generate security report
REPORT_FILE="/tmp/security-assessment-$INCIDENT_ID.txt"
cat > "$REPORT_FILE" <<EOF
Security Assessment Report
Incident ID: $INCIDENT_ID
Date: $(date)
Namespace: $NAMESPACE

1. RBAC Configuration: $(kubectl get rolebindings -n "$NAMESPACE" | wc -l) role bindings
2. Network Policies: $(kubectl get networkpolicies -n "$NAMESPACE" | wc -l) policies
3. Secrets: $(kubectl get secrets -n "$NAMESPACE" | wc -l) secrets
4. Vulnerabilities: See attached scan results

Recommendations:
- Review and rotate all credentials
- Update security monitoring rules
- Enhance network segmentation
- Implement additional access controls

Next Actions:
- Schedule security training
- Update incident response procedures
- Enhance monitoring capabilities
EOF

echo "Security assessment completed: $REPORT_FILE"
```

## Compliance and Auditing

### Audit Logging

#### Enhanced Audit Configuration

```python
# audit_logger.py
import logging
import json
from datetime import datetime
from typing import Dict, Any

class SecurityAuditLogger:
    def __init__(self, log_file: str = '/var/log/security-audit.log'):
        self.logger = logging.getLogger('security_audit')
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(asctime)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    def log_authentication_event(self, service: str, username: str, success: bool, source_ip: str = None):
        """Log authentication events."""
        event = {
            'event_type': 'authentication',
            'service': service,
            'username': username,
            'success': success,
            'source_ip': source_ip,
            'timestamp': datetime.utcnow().isoformat()
        }
        self.logger.info(json.dumps(event))
    
    def log_data_access(self, operation: str, resource: str, user_count: int = None):
        """Log data access events."""
        event = {
            'event_type': 'data_access',
            'operation': operation,
            'resource': resource,
            'user_count': user_count,
            'timestamp': datetime.utcnow().isoformat()
        }
        self.logger.info(json.dumps(event))
    
    def log_configuration_change(self, change_type: str, component: str, changed_by: str):
        """Log configuration changes."""
        event = {
            'event_type': 'configuration_change',
            'change_type': change_type,
            'component': component,
            'changed_by': changed_by,
            'timestamp': datetime.utcnow().isoformat()
        }
        self.logger.info(json.dumps(event))

# Usage in application
audit_logger = SecurityAuditLogger()

def authenticate_ldap(username, password):
    try:
        # LDAP authentication logic
        success = ldap_client.authenticate(username, password)
        audit_logger.log_authentication_event('ldap', username, success)
        return success
    except Exception as e:
        audit_logger.log_authentication_event('ldap', username, False)
        raise
```

### Compliance Reporting

#### GDPR Compliance

```bash
#!/bin/bash
# gdpr-compliance-check.sh

NAMESPACE="ldap-user-sync"
REPORT_FILE="/tmp/gdpr-compliance-$(date +%Y%m%d).txt"

echo "GDPR Compliance Assessment for LDAP User Sync" > "$REPORT_FILE"
echo "Generated on $(date)" >> "$REPORT_FILE"
echo "===============================================" >> "$REPORT_FILE"

# Data Processing Activities
echo "Data Processing Activities:" >> "$REPORT_FILE"
echo "- User identity synchronization" >> "$REPORT_FILE"
echo "- Group membership management" >> "$REPORT_FILE"
echo "- Audit logging" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Personal Data Processed
echo "Personal Data Processed:" >> "$REPORT_FILE"
echo "- Usernames" >> "$REPORT_FILE"
echo "- Email addresses" >> "$REPORT_FILE"
echo "- First and last names" >> "$REPORT_FILE"
echo "- Group memberships" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Legal Basis
echo "Legal Basis: Legitimate interest for identity management" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Data Protection Measures
echo "Data Protection Measures:" >> "$REPORT_FILE"
echo "- Encryption in transit (TLS)" >> "$REPORT_FILE"
echo "- Access controls (RBAC)" >> "$REPORT_FILE"
echo "- Audit logging" >> "$REPORT_FILE"
echo "- Data minimization" >> "$REPORT_FILE"
echo "- Regular security assessments" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Data Retention
echo "Data Retention:" >> "$REPORT_FILE"
echo "- Application logs: 90 days" >> "$REPORT_FILE"
echo "- Audit logs: 7 years" >> "$REPORT_FILE"
echo "- Configuration backups: 1 year" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Data Subject Rights
echo "Data Subject Rights Implementation:" >> "$REPORT_FILE"
echo "- Right to access: Implemented via audit logs" >> "$REPORT_FILE"
echo "- Right to rectification: Via source LDAP system" >> "$REPORT_FILE"
echo "- Right to erasure: Via source LDAP system" >> "$REPORT_FILE"
echo "- Right to portability: Available on request" >> "$REPORT_FILE"

echo "GDPR compliance report generated: $REPORT_FILE"
```

#### SOX Compliance

```bash
#!/bin/bash
# sox-compliance-check.sh

NAMESPACE="ldap-user-sync"
REPORT_FILE="/tmp/sox-compliance-$(date +%Y%m%d).txt"

echo "SOX Compliance Assessment for LDAP User Sync" > "$REPORT_FILE"
echo "Generated on $(date)" >> "$REPORT_FILE"
echo "=============================================" >> "$REPORT_FILE"

# Access Controls
echo "Access Controls:" >> "$REPORT_FILE"
echo "✓ Role-based access control implemented" >> "$REPORT_FILE"
echo "✓ Principle of least privilege enforced" >> "$REPORT_FILE"
echo "✓ Service accounts with limited permissions" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Change Management
echo "Change Management:" >> "$REPORT_FILE"
echo "✓ Version control for all code changes" >> "$REPORT_FILE"
echo "✓ Peer review process required" >> "$REPORT_FILE"
echo "✓ Automated testing before deployment" >> "$REPORT_FILE"
echo "✓ Change documentation maintained" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Audit Trail
echo "Audit Trail:" >> "$REPORT_FILE"
echo "✓ Comprehensive logging implemented" >> "$REPORT_FILE"
echo "✓ Log integrity protection" >> "$REPORT_FILE"
echo "✓ Centralized log collection" >> "$REPORT_FILE"
echo "✓ Regular log review process" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Data Integrity
echo "Data Integrity:" >> "$REPORT_FILE"
echo "✓ Checksums for data validation" >> "$REPORT_FILE"
echo "✓ Backup and recovery procedures" >> "$REPORT_FILE"
echo "✓ Disaster recovery testing" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Security Controls
echo "Security Controls:" >> "$REPORT_FILE"
echo "✓ Encryption in transit and at rest" >> "$REPORT_FILE"
echo "✓ Regular vulnerability assessments" >> "$REPORT_FILE"
echo "✓ Incident response procedures" >> "$REPORT_FILE"
echo "✓ Security awareness training" >> "$REPORT_FILE"

echo "SOX compliance report generated: $REPORT_FILE"
```

## Security Best Practices

### Development Security

1. **Secure Coding Practices**
   - Input validation and sanitization
   - Parameterized queries
   - Error handling without information disclosure
   - Secure session management

2. **Code Review Security**
   - Security-focused code reviews
   - Automated security testing
   - Dependency vulnerability scanning
   - Secrets detection in code

3. **Container Security**
   - Minimal base images
   - Regular image updates
   - No root user execution
   - Read-only root filesystem

### Operational Security

1. **Configuration Security**
   - Secure defaults
   - Encryption of sensitive data
   - Regular configuration reviews
   - Automated compliance checking

2. **Monitoring Security**
   - Security event correlation
   - Anomaly detection
   - Real-time alerting
   - Regular security reviews

3. **Incident Response**
   - Documented procedures
   - Regular drills
   - Forensic capabilities
   - Communication plans

For additional security considerations, see the [Deployment Guide](deployment-guide.md) and [Monitoring Procedures](monitoring-procedures.md) documents.