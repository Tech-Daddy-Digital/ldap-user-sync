# Deployment Guide

This guide provides comprehensive instructions for deploying the LDAP User Sync application in various environments.

## Overview

The LDAP User Sync application is designed for containerized deployment with support for:

- Docker containers
- Kubernetes deployments
- Helm chart installations
- Scheduled execution via CronJobs
- Configuration management via ConfigMaps and Secrets

## Prerequisites

### System Requirements

- **Container Runtime**: Docker 20.10+ or containerd
- **Orchestration**: Kubernetes 1.20+ (for Kubernetes deployments)
- **Package Manager**: Helm 3.7+ (for Helm deployments)
- **Resources**: 
  - CPU: 100m minimum, 500m recommended
  - Memory: 128Mi minimum, 512Mi recommended
  - Storage: 1Gi for logs and temporary data

### Network Requirements

- **LDAP Server**: Port 389 (LDAP) or 636 (LDAPS)
- **Vendor APIs**: Port 443 (HTTPS) or 80 (HTTP)
- **SMTP Server**: Port 25, 587 (STARTTLS), or 465 (SSL)
- **Outbound Internet**: For package downloads during build

### Access Requirements

- **LDAP Service Account**: Read access to user and group objects
- **Vendor API Credentials**: User management permissions
- **SMTP Credentials**: Email sending permissions (if notifications enabled)

## Docker Deployment

### Building the Container Image

```bash
# Build the Docker image
docker build -t ldap-user-sync:latest .

# Tag for registry
docker tag ldap-user-sync:latest your-registry.com/ldap-user-sync:v1.0.0

# Push to registry
docker push your-registry.com/ldap-user-sync:v1.0.0
```

### Running with Docker

#### Basic Run

```bash
docker run -d \
  --name ldap-user-sync \
  -v /path/to/config.yaml:/app/config.yaml:ro \
  -v /path/to/logs:/app/logs \
  -e LDAP_BIND_PASSWORD="your_password" \
  ldap-user-sync:latest
```

#### Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  ldap-user-sync:
    image: ldap-user-sync:latest
    container_name: ldap-user-sync
    restart: unless-stopped
    volumes:
      - ./config.yaml:/app/config.yaml:ro
      - ./logs:/app/logs
      - ./certs:/app/certs:ro
    environment:
      - LDAP_BIND_PASSWORD=${LDAP_BIND_PASSWORD}
      - VENDOR_APP1_PASSWORD=${VENDOR_APP1_PASSWORD}
      - SMTP_PASSWORD=${SMTP_PASSWORD}
    networks:
      - ldap-sync-network

networks:
  ldap-sync-network:
    driver: bridge
```

Create `.env` file:

```bash
LDAP_BIND_PASSWORD=your_ldap_password
VENDOR_APP1_PASSWORD=your_vendor_password
SMTP_PASSWORD=your_smtp_password
```

Run with:

```bash
docker-compose up -d
```

#### Scheduled Execution

Use cron on the Docker host:

```bash
# Add to crontab (crontab -e)
0 */6 * * * docker run --rm -v /path/to/config.yaml:/app/config.yaml:ro -v /path/to/logs:/app/logs ldap-user-sync:latest
```

## Kubernetes Deployment

### Namespace Setup

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: ldap-user-sync
  labels:
    name: ldap-user-sync
```

### ConfigMap for Configuration

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ldap-sync-config
  namespace: ldap-user-sync
data:
  config.yaml: |
    ldap:
      server_url: "ldaps://ldap.company.com:636"
      bind_dn: "CN=ldap-sync-service,OU=Service Accounts,DC=company,DC=com"
      bind_password: "${LDAP_BIND_PASSWORD}"
      user_base_dn: "OU=Users,DC=company,DC=com"
      user_filter: "(objectClass=person)"
      attributes: ["cn", "givenName", "sn", "mail", "sAMAccountName"]
    
    vendor_apps:
      - name: "Business Application"
        module: "business_app"
        base_url: "https://api.businessapp.com/v1"
        auth:
          method: "basic"
          username: "sync-service"
          password: "${VENDOR_APP1_PASSWORD}"
        format: "json"
        verify_ssl: true
        groups:
          - ldap_group: "CN=BusinessApp_Users,OU=Groups,DC=company,DC=com"
            vendor_group: "users"
    
    logging:
      level: "INFO"
      log_dir: "/app/logs"
      rotation: "daily"
      retention_days: 7
      console_output: true
    
    error_handling:
      max_retries: 3
      retry_wait_seconds: 10
      max_errors_per_vendor: 10
    
    notifications:
      enable_email: true
      email_on_failure: true
      smtp_server: "smtp.company.com"
      smtp_port: 587
      smtp_tls: true
      smtp_username: "${SMTP_USERNAME}"
      smtp_password: "${SMTP_PASSWORD}"
      email_from: "LDAP Sync <noreply@company.com>"
      email_to:
        - "it-ops@company.com"
```

### Secrets for Sensitive Data

```yaml
# secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: ldap-sync-secrets
  namespace: ldap-user-sync
type: Opaque
data:
  # Base64 encoded values
  LDAP_BIND_PASSWORD: eW91cl9sZGFwX3Bhc3N3b3Jk
  VENDOR_APP1_PASSWORD: eW91cl92ZW5kb3JfcGFzc3dvcmQ=
  SMTP_USERNAME: c210cF91c2VybmFtZQ==
  SMTP_PASSWORD: c210cF9wYXNzd29yZA==
```

Create secrets:

```bash
# Create secrets from command line
kubectl create secret generic ldap-sync-secrets \
  --from-literal=LDAP_BIND_PASSWORD='your_ldap_password' \
  --from-literal=VENDOR_APP1_PASSWORD='your_vendor_password' \
  --from-literal=SMTP_USERNAME='smtp_username' \
  --from-literal=SMTP_PASSWORD='smtp_password' \
  --namespace=ldap-user-sync
```

### CronJob for Scheduled Execution

```yaml
# cronjob.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: ldap-user-sync
  namespace: ldap-user-sync
spec:
  schedule: "0 */6 * * *"  # Every 6 hours
  timeZone: "UTC"
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 3
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          containers:
          - name: ldap-user-sync
            image: your-registry.com/ldap-user-sync:v1.0.0
            imagePullPolicy: Always
            resources:
              requests:
                memory: "128Mi"
                cpu: "100m"
              limits:
                memory: "512Mi"
                cpu: "500m"
            env:
            - name: CONFIG_PATH
              value: "/app/config/config.yaml"
            envFrom:
            - secretRef:
                name: ldap-sync-secrets
            volumeMounts:
            - name: config
              mountPath: /app/config
              readOnly: true
            - name: logs
              mountPath: /app/logs
            - name: certs
              mountPath: /app/certs
              readOnly: true
          volumes:
          - name: config
            configMap:
              name: ldap-sync-config
          - name: logs
            persistentVolumeClaim:
              claimName: ldap-sync-logs
          - name: certs
            secret:
              secretName: ldap-sync-certs
              optional: true
          imagePullSecrets:
          - name: registry-credentials
```

### Persistent Volume for Logs

```yaml
# pvc.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ldap-sync-logs
  namespace: ldap-user-sync
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
  storageClassName: standard
```

### Apply Kubernetes Resources

```bash
# Apply all resources
kubectl apply -f namespace.yaml
kubectl apply -f configmap.yaml
kubectl apply -f secrets.yaml
kubectl apply -f pvc.yaml
kubectl apply -f cronjob.yaml

# Verify deployment
kubectl get all -n ldap-user-sync
```

## Helm Chart Deployment

### Chart Structure

```
helm/
├── Chart.yaml
├── values.yaml
├── templates/
│   ├── configmap.yaml
│   ├── secret.yaml
│   ├── cronjob.yaml
│   ├── pvc.yaml
│   └── rbac.yaml
└── values/
    ├── dev.yaml
    ├── staging.yaml
    └── prod.yaml
```

### Chart.yaml

```yaml
apiVersion: v2
name: ldap-user-sync
description: LDAP User Synchronization Application
type: application
version: 1.0.0
appVersion: "1.0.0"
keywords:
  - ldap
  - user-sync
  - identity
home: https://github.com/company/ldap-user-sync
sources:
  - https://github.com/company/ldap-user-sync
maintainers:
  - name: IT Operations
    email: it-ops@company.com
```

### values.yaml

```yaml
# Default values for ldap-user-sync
replicaCount: 1

image:
  repository: your-registry.com/ldap-user-sync
  tag: "v1.0.0"
  pullPolicy: IfNotPresent

imagePullSecrets: []

nameOverride: ""
fullnameOverride: ""

# CronJob configuration
cronjob:
  schedule: "0 */6 * * *"
  timeZone: "UTC"
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 3
  concurrencyPolicy: Forbid
  suspend: false

# Resource limits
resources:
  requests:
    memory: "128Mi"
    cpu: "100m"
  limits:
    memory: "512Mi"
    cpu: "500m"

# Persistent volume for logs
persistence:
  enabled: true
  storageClass: ""
  accessMode: ReadWriteOnce
  size: 1Gi

# LDAP configuration
ldap:
  serverUrl: "ldaps://ldap.company.com:636"
  bindDn: "CN=ldap-sync-service,OU=Service Accounts,DC=company,DC=com"
  bindPassword: ""  # Set via values override or secret
  userBaseDn: "OU=Users,DC=company,DC=com"
  userFilter: "(objectClass=person)"
  attributes:
    - "cn"
    - "givenName"
    - "sn"
    - "mail"
    - "sAMAccountName"

# Vendor applications
vendorApps:
  - name: "Business Application"
    module: "business_app"
    baseUrl: "https://api.businessapp.com/v1"
    auth:
      method: "basic"
      username: "sync-service"
      password: ""  # Set via values override or secret
    format: "json"
    verifySsl: true
    groups:
      - ldapGroup: "CN=BusinessApp_Users,OU=Groups,DC=company,DC=com"
        vendorGroup: "users"

# Logging configuration
logging:
  level: "INFO"
  logDir: "/app/logs"
  rotation: "daily"
  retentionDays: 7
  consoleOutput: true

# Error handling
errorHandling:
  maxRetries: 3
  retryWaitSeconds: 10
  maxErrorsPerVendor: 10

# Email notifications
notifications:
  enableEmail: true
  emailOnFailure: true
  emailOnSuccess: false
  smtpServer: "smtp.company.com"
  smtpPort: 587
  smtpTls: true
  smtpUsername: ""  # Set via values override or secret
  smtpPassword: ""  # Set via values override or secret
  emailFrom: "LDAP Sync <noreply@company.com>"
  emailTo:
    - "it-ops@company.com"

# Secrets (external secret management)
existingSecret: ""

# Node selector
nodeSelector: {}

# Tolerations
tolerations: []

# Affinity
affinity: {}
```

### Environment-Specific Values

Create `values/prod.yaml`:

```yaml
# Production values
image:
  tag: "v1.0.0"

cronjob:
  schedule: "0 2,8,14,20 * * *"  # Every 6 hours starting at 2 AM

resources:
  requests:
    memory: "256Mi"
    cpu: "200m"
  limits:
    memory: "1Gi"
    cpu: "1000m"

persistence:
  size: 5Gi
  storageClass: "fast-ssd"

ldap:
  serverUrl: "ldaps://ldap-prod.company.com:636"

logging:
  level: "INFO"
  retentionDays: 30

errorHandling:
  maxRetries: 5
  maxErrorsPerVendor: 20

notifications:
  emailOnSuccess: true
  emailTo:
    - "it-ops@company.com"
    - "security@company.com"
```

### Helm Templates

#### ConfigMap Template

```yaml
# templates/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ include "ldap-user-sync.fullname" . }}-config
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "ldap-user-sync.labels" . | nindent 4 }}
data:
  config.yaml: |
    ldap:
      server_url: {{ .Values.ldap.serverUrl | quote }}
      bind_dn: {{ .Values.ldap.bindDn | quote }}
      bind_password: "${LDAP_BIND_PASSWORD}"
      user_base_dn: {{ .Values.ldap.userBaseDn | quote }}
      user_filter: {{ .Values.ldap.userFilter | quote }}
      attributes: {{ .Values.ldap.attributes | toYaml | nindent 8 }}
    
    vendor_apps:
    {{- range .Values.vendorApps }}
      - name: {{ .name | quote }}
        module: {{ .module | quote }}
        base_url: {{ .baseUrl | quote }}
        auth:
          method: {{ .auth.method | quote }}
          username: {{ .auth.username | quote }}
          password: "${VENDOR_{{ .name | upper | replace " " "_" }}_PASSWORD}"
        format: {{ .format | quote }}
        verify_ssl: {{ .verifySsl }}
        groups:
        {{- range .groups }}
          - ldap_group: {{ .ldapGroup | quote }}
            vendor_group: {{ .vendorGroup | quote }}
        {{- end }}
    {{- end }}
    
    logging:
      level: {{ .Values.logging.level | quote }}
      log_dir: {{ .Values.logging.logDir | quote }}
      rotation: {{ .Values.logging.rotation | quote }}
      retention_days: {{ .Values.logging.retentionDays }}
      console_output: {{ .Values.logging.consoleOutput }}
    
    error_handling:
      max_retries: {{ .Values.errorHandling.maxRetries }}
      retry_wait_seconds: {{ .Values.errorHandling.retryWaitSeconds }}
      max_errors_per_vendor: {{ .Values.errorHandling.maxErrorsPerVendor }}
    
    notifications:
      enable_email: {{ .Values.notifications.enableEmail }}
      email_on_failure: {{ .Values.notifications.emailOnFailure }}
      email_on_success: {{ .Values.notifications.emailOnSuccess }}
      smtp_server: {{ .Values.notifications.smtpServer | quote }}
      smtp_port: {{ .Values.notifications.smtpPort }}
      smtp_tls: {{ .Values.notifications.smtpTls }}
      smtp_username: "${SMTP_USERNAME}"
      smtp_password: "${SMTP_PASSWORD}"
      email_from: {{ .Values.notifications.emailFrom | quote }}
      email_to: {{ .Values.notifications.emailTo | toYaml | nindent 8 }}
```

### Deploy with Helm

```bash
# Add your Helm repository
helm repo add your-repo https://charts.company.com
helm repo update

# Install in development
helm install ldap-user-sync your-repo/ldap-user-sync \
  --namespace ldap-user-sync \
  --create-namespace \
  --values values/dev.yaml \
  --set ldap.bindPassword="your_ldap_password" \
  --set vendorApps[0].auth.password="your_vendor_password"

# Install in production
helm install ldap-user-sync your-repo/ldap-user-sync \
  --namespace ldap-user-sync \
  --create-namespace \
  --values values/prod.yaml \
  --set ldap.bindPassword="your_ldap_password" \
  --set vendorApps[0].auth.password="your_vendor_password"

# Upgrade deployment
helm upgrade ldap-user-sync your-repo/ldap-user-sync \
  --namespace ldap-user-sync \
  --values values/prod.yaml

# Uninstall
helm uninstall ldap-user-sync --namespace ldap-user-sync
```

## Configuration Management

### External Secrets Management

#### Using Kubernetes Secrets

```yaml
# external-secret.yaml (using External Secrets Operator)
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: ldap-sync-secrets
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
      key: ldap-sync/ldap
      property: bind_password
  - secretKey: VENDOR_APP1_PASSWORD
    remoteRef:
      key: ldap-sync/vendor-app1
      property: password
  - secretKey: SMTP_PASSWORD
    remoteRef:
      key: ldap-sync/smtp
      property: password
```

#### Using AWS Secrets Manager

```yaml
# aws-secret-store.yaml
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: aws-secrets-manager
  namespace: ldap-user-sync
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-west-2
      auth:
        secretRef:
          accessKeyIDSecretRef:
            name: aws-credentials
            key: access-key-id
          secretAccessKeySecretRef:
            name: aws-credentials
            key: secret-access-key
```

### Environment-Specific Deployments

#### Development Environment

```bash
# Deploy to development
helm install ldap-user-sync-dev ./helm \
  --namespace ldap-user-sync-dev \
  --create-namespace \
  --values helm/values/dev.yaml \
  --set image.tag="dev-latest"
```

#### Staging Environment

```bash
# Deploy to staging
helm install ldap-user-sync-staging ./helm \
  --namespace ldap-user-sync-staging \
  --create-namespace \
  --values helm/values/staging.yaml \
  --set image.tag="v1.0.0-rc1"
```

#### Production Environment

```bash
# Deploy to production
helm install ldap-user-sync-prod ./helm \
  --namespace ldap-user-sync-prod \
  --create-namespace \
  --values helm/values/prod.yaml \
  --set image.tag="v1.0.0"
```

## Monitoring and Observability

### Health Checks

Add health check endpoints to your application:

```yaml
# health-check.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: health-check-script
data:
  health-check.sh: |
    #!/bin/bash
    # Check if last sync was successful
    LAST_LOG=$(find /app/logs -name "*.log" -type f -exec ls -t {} + | head -1)
    if [ -z "$LAST_LOG" ]; then
      echo "No log files found"
      exit 1
    fi
    
    # Check for recent errors
    RECENT_ERRORS=$(tail -100 "$LAST_LOG" | grep -c "ERROR")
    if [ "$RECENT_ERRORS" -gt 5 ]; then
      echo "Too many recent errors: $RECENT_ERRORS"
      exit 1
    fi
    
    echo "Health check passed"
    exit 0
```

### Logging and Monitoring

#### Centralized Logging

```yaml
# fluent-bit-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluent-bit-config
data:
  fluent-bit.conf: |
    [INPUT]
        Name tail
        Path /app/logs/*.log
        Tag ldap-sync.*
        Parser json
        DB /var/log/flb_ldap_sync.db
        Mem_Buf_Limit 5MB
    
    [OUTPUT]
        Name es
        Match ldap-sync.*
        Host elasticsearch.logging.svc.cluster.local
        Port 9200
        Index ldap-sync
        Type _doc
```

#### Prometheus Metrics

Add metrics collection to your application:

```python
# In your application
from prometheus_client import Counter, Histogram, Gauge, start_http_server

# Define metrics
sync_total = Counter('ldap_sync_total', 'Total number of sync operations')
sync_duration = Histogram('ldap_sync_duration_seconds', 'Time spent on sync operations')
sync_errors = Counter('ldap_sync_errors_total', 'Total number of sync errors')
users_synced = Gauge('ldap_sync_users_current', 'Current number of users synced')

# Use in your code
with sync_duration.time():
    # Perform sync
    sync_total.inc()
    if error:
        sync_errors.inc()
```

## Backup and Recovery

### Configuration Backup

```bash
# Backup Kubernetes resources
kubectl get configmap ldap-sync-config -o yaml > backup/configmap.yaml
kubectl get secret ldap-sync-secrets -o yaml > backup/secrets.yaml
kubectl get cronjob ldap-user-sync -o yaml > backup/cronjob.yaml

# Backup Helm values
helm get values ldap-user-sync > backup/helm-values.yaml
```

### Log Backup

```yaml
# log-backup-cronjob.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: log-backup
spec:
  schedule: "0 1 * * 0"  # Weekly on Sunday at 1 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: alpine:latest
            command:
            - /bin/sh
            - -c
            - |
              apk add --no-cache aws-cli
              tar -czf /tmp/logs-$(date +%Y%m%d).tar.gz /app/logs
              aws s3 cp /tmp/logs-$(date +%Y%m%d).tar.gz s3://backup-bucket/ldap-sync-logs/
            volumeMounts:
            - name: logs
              mountPath: /app/logs
            env:
            - name: AWS_ACCESS_KEY_ID
              valueFrom:
                secretKeyRef:
                  name: aws-credentials
                  key: access-key-id
            - name: AWS_SECRET_ACCESS_KEY
              valueFrom:
                secretKeyRef:
                  name: aws-credentials
                  key: secret-access-key
          volumes:
          - name: logs
            persistentVolumeClaim:
              claimName: ldap-sync-logs
          restartPolicy: OnFailure
```

## Troubleshooting Deployments

### Common Issues

1. **Image Pull Errors**
   ```bash
   # Check image pull secrets
   kubectl get pods -n ldap-user-sync
   kubectl describe pod <pod-name> -n ldap-user-sync
   
   # Verify image exists
   docker pull your-registry.com/ldap-user-sync:v1.0.0
   ```

2. **Configuration Errors**
   ```bash
   # Check ConfigMap
   kubectl get configmap ldap-sync-config -o yaml
   
   # Check Secrets
   kubectl get secret ldap-sync-secrets -o yaml
   
   # Validate configuration
   kubectl exec -it <pod-name> -- cat /app/config/config.yaml
   ```

3. **Connectivity Issues**
   ```bash
   # Test LDAP connectivity
   kubectl exec -it <pod-name> -- nslookup ldap.company.com
   kubectl exec -it <pod-name> -- telnet ldap.company.com 636
   
   # Test vendor API connectivity
   kubectl exec -it <pod-name> -- curl -I https://api.vendor.com/health
   ```

4. **Resource Constraints**
   ```bash
   # Check resource usage
   kubectl top pods -n ldap-user-sync
   kubectl describe pod <pod-name> -n ldap-user-sync
   
   # Check node resources
   kubectl top nodes
   ```

### Debugging Commands

```bash
# View logs
kubectl logs -f cronjob/ldap-user-sync -n ldap-user-sync

# Get job status
kubectl get jobs -n ldap-user-sync

# Describe failed jobs
kubectl describe job <job-name> -n ldap-user-sync

# Get events
kubectl get events --sort-by=.metadata.creationTimestamp -n ldap-user-sync

# Execute debug session
kubectl exec -it <pod-name> -n ldap-user-sync -- /bin/bash
```

## Security Considerations

### RBAC Configuration

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
  name: ldap-user-sync
  namespace: ldap-user-sync
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
  - Egress
  egress:
  - to: []
    ports:
    - protocol: TCP
      port: 636  # LDAPS
    - protocol: TCP
      port: 443  # HTTPS
    - protocol: TCP
      port: 587  # SMTP
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: TCP
      port: 53   # DNS
    - protocol: UDP
      port: 53   # DNS
```

### Pod Security Standards

```yaml
# pod-security.yaml
apiVersion: v1
kind: Pod
metadata:
  name: ldap-user-sync
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: ldap-user-sync
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: logs
      mountPath: /app/logs
  volumes:
  - name: tmp
    emptyDir: {}
  - name: logs
    persistentVolumeClaim:
      claimName: ldap-sync-logs
```

## Performance Optimization

### Resource Tuning

```yaml
# Optimized resource allocation
resources:
  requests:
    memory: "256Mi"
    cpu: "200m"
  limits:
    memory: "1Gi"
    cpu: "1000m"
```

### Horizontal Pod Autoscaling

```yaml
# hpa.yaml (for long-running deployments)
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: ldap-user-sync-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: ldap-user-sync
  minReplicas: 1
  maxReplicas: 3
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

## Maintenance and Updates

### Rolling Updates

```bash
# Update image version
helm upgrade ldap-user-sync ./helm \
  --set image.tag="v1.1.0" \
  --namespace ldap-user-sync

# Rollback if needed
helm rollback ldap-user-sync 1 --namespace ldap-user-sync
```

### Configuration Updates

```bash
# Update configuration
kubectl patch configmap ldap-sync-config \
  --patch '{"data":{"config.yaml":"new-config-content"}}' \
  --namespace ldap-user-sync

# Restart to pick up changes
kubectl delete job --all -n ldap-user-sync
```

For additional deployment troubleshooting, see the [Troubleshooting Guide](troubleshooting-guide.md).