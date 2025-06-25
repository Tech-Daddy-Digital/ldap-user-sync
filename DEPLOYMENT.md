# LDAP User Sync - Deployment Guide

This guide covers the containerization and deployment of the LDAP User Sync application using Docker and Kubernetes.

## Table of Contents

1. [Container Deployment](#container-deployment)
2. [Kubernetes Deployment](#kubernetes-deployment)
3. [Configuration Management](#configuration-management)
4. [Monitoring and Logging](#monitoring-and-logging)
5. [Security Considerations](#security-considerations)
6. [Troubleshooting](#troubleshooting)

## Container Deployment

### Building the Container

The application uses a multi-stage Docker build for optimization:

```bash
# Build the container
./scripts/build-container.sh

# Build with custom registry
REGISTRY=your-registry.com REPOSITORY=ldap-user-sync TAG=1.0.0 ./scripts/build-container.sh

# Build and push to registry
PUSH=true ./scripts/build-container.sh

# Build with security scanning
SCAN=true ./scripts/build-container.sh
```

### Container Features

- **Multi-stage build**: Optimized for size and security
- **Non-root user**: Runs as UID 10001 for security
- **Health checks**: Built-in health check endpoint
- **Environment variable support**: Full configuration via environment variables
- **Log directory**: Persistent log storage at `/app/logs`
- **Security hardening**: Minimal attack surface, no unnecessary packages

### Testing the Container

```bash
# Run comprehensive container tests
./scripts/test-container.sh

# Test with docker-compose
docker-compose -f docker-compose.test.yaml up --build

# Manual container testing
docker run --rm \
    -v $(pwd)/config.yaml:/app/config.yaml:ro \
    -e LOG_LEVEL=DEBUG \
    ldap-user-sync:latest
```

## Kubernetes Deployment

### Using Helm (Recommended)

#### Quick Start

```bash
# Deploy with default values
./scripts/deploy-helm.sh

# Deploy with custom values
RELEASE_NAME=my-ldap-sync \
NAMESPACE=sync-system \
ENV_VALUES_FILE=examples/values-production.yaml \
./scripts/deploy-helm.sh

# Deploy with specific image tag
IMAGE_TAG=1.0.0 SCHEDULE="0 3 * * *" ./scripts/deploy-helm.sh

# Dry-run deployment
DRY_RUN=true ./scripts/deploy-helm.sh
```

#### Helm Chart Structure

```
helm/ldap-user-sync/
├── Chart.yaml                 # Chart metadata
├── values.yaml               # Default values
├── templates/
│   ├── cronjob.yaml          # CronJob definition
│   ├── configmap.yaml        # Configuration management
│   ├── secret.yaml           # Secret management
│   ├── serviceaccount.yaml   # Service account
│   ├── pvc.yaml              # Persistent volume claim
│   ├── _helpers.tpl          # Template helpers
│   └── NOTES.txt             # Post-install notes
└── charts/                   # Dependencies (none currently)
```

### Manual Kubernetes Deployment

```bash
# Apply test deployment
kubectl apply -f k8s/test-deployment.yaml

# Create from Helm template
helm template ldap-user-sync helm/ldap-user-sync \
    --values examples/values-production.yaml \
    --namespace production > deployment.yaml
kubectl apply -f deployment.yaml
```

### Environment-Specific Deployments

#### Development
```bash
helm upgrade --install ldap-user-sync-dev helm/ldap-user-sync \
    --namespace development \
    --values examples/values-development.yaml \
    --create-namespace
```

#### Production
```bash
helm upgrade --install ldap-user-sync helm/ldap-user-sync \
    --namespace production \
    --values examples/values-production.yaml \
    --create-namespace
```

## Configuration Management

### Configuration Sources (Priority Order)

1. **Environment Variables**: Highest priority
2. **Kubernetes Secrets**: For sensitive data
3. **ConfigMaps**: For non-sensitive configuration
4. **Default Values**: Fallback values

### Environment Variable Mapping

| Environment Variable | Configuration Path | Example |
|---------------------|-------------------|---------|
| `LDAP_SERVER_URL` | `ldap.server_url` | `ldaps://ldap.company.com:636` |
| `LDAP_BIND_PASSWORD` | `ldap.bind_password` | From secret |
| `VENDOR1_BASE_URL` | `vendor_apps[0].base_url` | `https://api.vendor.com/v1` |
| `LOG_LEVEL` | `logging.level` | `INFO` |

### Secret Management

#### Using Kubernetes Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ldap-sync-secrets
type: Opaque
data:
  ldap-bind-password: <base64-encoded-password>
  vendor1-username: <base64-encoded-username>
  vendor1-password: <base64-encoded-password>
  smtp-password: <base64-encoded-smtp-password>
```

#### Using External Secret Management

```yaml
# Example with External Secrets Operator
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
spec:
  provider:
    vault:
      server: "https://vault.company.com"
      path: "secret"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "ldap-sync"
---
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: ldap-sync-secrets
spec:
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: ldap-sync-secrets
  data:
  - secretKey: ldap-bind-password
    remoteRef:
      key: ldap-sync
      property: ldap_password
```

## Monitoring and Logging

### Log Aggregation

The application supports multiple logging configurations:

#### Fluentd Integration
```bash
# Apply logging configuration
kubectl apply -f k8s/logging-config.yaml
```

#### Log Rotation
- **Container logs**: Automatically rotated by Kubernetes
- **Persistent logs**: Configured via logrotate in the container
- **Retention**: Configurable (default 7 days for container, 30 days for persistent)

### Monitoring with Prometheus

#### Metrics Available
- Job success/failure rates
- Job duration
- Resource usage
- Custom application metrics

#### Alerts Configuration
```bash
# Apply Prometheus rules
kubectl apply -f k8s/logging-config.yaml
```

#### Grafana Dashboard
- Import the dashboard from `k8s/logging-config.yaml`
- Monitor job performance, success rates, and resource usage

### Health Checks

```bash
# Check CronJob status
kubectl get cronjob ldap-user-sync -n production

# View recent jobs
kubectl get jobs -l app.kubernetes.io/instance=ldap-user-sync -n production

# Check logs
kubectl logs -l app.kubernetes.io/instance=ldap-user-sync -n production --tail=100

# Manual job trigger
kubectl create job --from=cronjob/ldap-user-sync ldap-user-sync-manual -n production
```

## Security Considerations

### Container Security

- **Non-root execution**: Runs as UID 10001
- **Read-only root filesystem**: Prevents container tampering
- **Minimal base image**: Reduces attack surface
- **No shell access**: No shell in production images
- **Security context**: Proper Kubernetes security context

### Network Security

- **TLS enforcement**: All external connections use TLS
- **Certificate validation**: Configurable certificate validation
- **Network policies**: Recommended for production deployments

```yaml
# Example NetworkPolicy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ldap-user-sync-netpol
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: ldap-user-sync
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: TCP
      port: 53
    - protocol: UDP
      port: 53
  - to: []
    ports:
    - protocol: TCP
      port: 636  # LDAPS
    - protocol: TCP
      port: 443  # HTTPS for vendor APIs
```

### RBAC Configuration

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ldap-user-sync
rules:
- apiGroups: [""]
  resources: ["configmaps", "secrets"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ldap-user-sync
subjects:
- kind: ServiceAccount
  name: ldap-user-sync
roleRef:
  kind: Role
  name: ldap-user-sync
  apiGroup: rbac.authorization.k8s.io
```

## Troubleshooting

### Common Issues

#### 1. Job Failures

```bash
# Check job status
kubectl describe job <job-name> -n <namespace>

# Check pod logs
kubectl logs <pod-name> -n <namespace>

# Check events
kubectl get events -n <namespace> --sort-by='.lastTimestamp'
```

#### 2. Configuration Issues

```bash
# Validate ConfigMap
kubectl get configmap ldap-user-sync-config -o yaml

# Check secret mounting
kubectl describe pod <pod-name> -n <namespace>

# Test configuration loading
kubectl exec <pod-name> -n <namespace> -- python -c "
from ldap_sync.config import load_config
config = load_config('/app/config.yaml')
print('Config loaded successfully')
"
```

#### 3. Network Connectivity

```bash
# Test LDAP connectivity from pod
kubectl exec <pod-name> -n <namespace> -- nc -zv <ldap-server> 636

# Test vendor API connectivity
kubectl exec <pod-name> -n <namespace> -- curl -I <vendor-api-url>

# Check DNS resolution
kubectl exec <pod-name> -n <namespace> -- nslookup <hostname>
```

#### 4. Resource Issues

```bash
# Check resource usage
kubectl top pods -n <namespace>

# Check resource limits
kubectl describe pod <pod-name> -n <namespace> | grep -A 5 "Limits:"

# Check node resources
kubectl describe node <node-name>
```

### Debug Mode

Enable debug mode for troubleshooting:

```bash
# Deploy with debug configuration
helm upgrade ldap-user-sync helm/ldap-user-sync \
    --set logging.level=DEBUG \
    --set cronjob.schedule="*/5 * * * *" \
    --set cronjob.suspend=false
```

### Log Analysis

```bash
# Search for specific errors
kubectl logs -l app.kubernetes.io/name=ldap-user-sync | grep ERROR

# Follow logs in real-time
kubectl logs -f deployment/ldap-user-sync

# Export logs for analysis
kubectl logs ldap-user-sync-<job-id> > sync-logs.txt
```

### Performance Tuning

#### Resource Optimization

```yaml
# Recommended production resources
resources:
  requests:
    cpu: 200m
    memory: 512Mi
  limits:
    cpu: 1000m
    memory: 1Gi
```

#### Scheduling Optimization

```yaml
# Avoid peak hours
schedule: "0 2 * * *"  # 2 AM daily

# Stagger multiple instances
schedule: "0 2 * * 1,3,5"  # Mon, Wed, Fri
```

## Deployment Checklist

### Pre-deployment

- [ ] Container image built and tested
- [ ] Configuration reviewed and validated
- [ ] Secrets created and properly encoded
- [ ] Network policies defined (if required)
- [ ] Monitoring and alerting configured

### Deployment

- [ ] Helm chart validated with `helm lint`
- [ ] Dry-run deployment successful
- [ ] Chart deployed to staging environment
- [ ] Integration tests passed
- [ ] Production deployment completed

### Post-deployment

- [ ] CronJob created and scheduled
- [ ] Manual job test successful
- [ ] Logs flowing to aggregation system
- [ ] Monitoring alerts configured
- [ ] Documentation updated
- [ ] Team trained on operations

---

For additional support, refer to the main [CLAUDE.md](CLAUDE.md) documentation or check the application logs for specific error messages.