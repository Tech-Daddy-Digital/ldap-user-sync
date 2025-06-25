# Backup and Recovery Procedures

This document outlines comprehensive backup and recovery procedures for the LDAP User Sync application and its associated data.

## Overview

The LDAP User Sync application requires backup and recovery procedures for:

- **Configuration Data**: Application configuration files, secrets, and certificates
- **Log Data**: Historical sync logs for audit and troubleshooting
- **State Information**: Sync history and operational metadata
- **Container Images**: Application container images and dependencies
- **Deployment Artifacts**: Kubernetes manifests, Helm charts, and deployment configurations

## Backup Strategy

### Backup Components

#### 1. Configuration Backup

**What to Backup:**
- Configuration files (`config.yaml`)
- Kubernetes ConfigMaps and Secrets
- SSL certificates and keys
- Helm values files

**Backup Frequency:** Daily or on change

**Retention Policy:** 30 days for daily backups, 12 months for monthly archives

#### 2. Log Data Backup

**What to Backup:**
- Application logs
- Audit logs
- Error logs
- Performance metrics data

**Backup Frequency:** Daily

**Retention Policy:** 90 days for operational logs, 7 years for audit logs

#### 3. Deployment Artifacts

**What to Backup:**
- Kubernetes manifests
- Helm charts
- CI/CD pipelines
- Infrastructure as Code (IaC) templates

**Backup Frequency:** On change (version controlled)

**Retention Policy:** Indefinite (version control history)

### Backup Implementation

#### Kubernetes Resource Backup

##### Using Velero

```yaml
# velero-backup-schedule.yaml
apiVersion: velero.io/v1
kind: Schedule
metadata:
  name: ldap-user-sync-daily
  namespace: velero
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  template:
    includedNamespaces:
    - ldap-user-sync
    storageLocation: aws-s3-backup
    volumeSnapshotLocations:
    - aws-ebs
    ttl: 720h0m0s  # 30 days
    metadata:
      labels:
        backup-type: "daily"
        application: "ldap-user-sync"
```

##### Manual Kubernetes Backup

```bash
#!/bin/bash
# backup-k8s-resources.sh

NAMESPACE="ldap-user-sync"
BACKUP_DIR="/backup/kubernetes/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup ConfigMaps
kubectl get configmaps -n "$NAMESPACE" -o yaml > "$BACKUP_DIR/configmaps.yaml"

# Backup Secrets (excluding sensitive data)
kubectl get secrets -n "$NAMESPACE" -o yaml | \
  sed 's/data:.*/data: <REDACTED>/' > "$BACKUP_DIR/secrets.yaml"

# Backup CronJobs
kubectl get cronjobs -n "$NAMESPACE" -o yaml > "$BACKUP_DIR/cronjobs.yaml"

# Backup PersistentVolumeClaims
kubectl get pvc -n "$NAMESPACE" -o yaml > "$BACKUP_DIR/pvc.yaml"

# Backup ServiceAccounts and RBAC
kubectl get serviceaccounts,roles,rolebindings -n "$NAMESPACE" -o yaml > "$BACKUP_DIR/rbac.yaml"

# Create archive
tar -czf "/backup/kubernetes/ldap-user-sync-k8s-$(date +%Y%m%d_%H%M%S).tar.gz" -C "$(dirname "$BACKUP_DIR")" "$(basename "$BACKUP_DIR")"

# Cleanup temporary directory
rm -rf "$BACKUP_DIR"

echo "Kubernetes backup completed: /backup/kubernetes/ldap-user-sync-k8s-$(date +%Y%m%d_%H%M%S).tar.gz"
```

#### Log Data Backup

##### Automated Log Backup

```bash
#!/bin/bash
# backup-logs.sh

SOURCE_DIR="/app/logs"
BACKUP_BASE="/backup/logs"
S3_BUCKET="s3://company-backups/ldap-user-sync/logs"
DATE=$(date +%Y%m%d)

# Create backup directory
BACKUP_DIR="$BACKUP_BASE/$DATE"
mkdir -p "$BACKUP_DIR"

# Copy logs
cp -r "$SOURCE_DIR"/* "$BACKUP_DIR/"

# Compress logs
tar -czf "$BACKUP_BASE/logs-$DATE.tar.gz" -C "$BACKUP_BASE" "$DATE"

# Upload to S3
aws s3 cp "$BACKUP_BASE/logs-$DATE.tar.gz" "$S3_BUCKET/"

# Cleanup local backup
rm -rf "$BACKUP_DIR"
rm -f "$BACKUP_BASE/logs-$DATE.tar.gz"

# Remove old S3 backups (keep 90 days)
aws s3 ls "$S3_BUCKET/" | awk '{print $4}' | \
  grep 'logs-' | sort | head -n -90 | \
  while read file; do
    aws s3 rm "$S3_BUCKET/$file"
  done

echo "Log backup completed for $DATE"
```

##### Kubernetes CronJob for Log Backup

```yaml
# log-backup-cronjob.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: log-backup
  namespace: ldap-user-sync
spec:
  schedule: "0 3 * * *"  # Daily at 3 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: amazon/aws-cli:latest
            command:
            - /bin/sh
            - -c
            - |
              # Install required tools
              apk add --no-cache tar gzip
              
              # Create backup
              DATE=$(date +%Y%m%d)
              cd /app/logs
              tar -czf "/tmp/logs-$DATE.tar.gz" .
              
              # Upload to S3
              aws s3 cp "/tmp/logs-$DATE.tar.gz" "s3://company-backups/ldap-user-sync/logs/"
              
              # Cleanup old backups
              aws s3 ls "s3://company-backups/ldap-user-sync/logs/" | \
                awk '{print $4}' | grep 'logs-' | sort | head -n -90 | \
                while read file; do
                  aws s3 rm "s3://company-backups/ldap-user-sync/logs/$file"
                done
              
              echo "Backup completed for $DATE"
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
            - name: AWS_DEFAULT_REGION
              value: "us-west-2"
            volumeMounts:
            - name: logs
              mountPath: /app/logs
              readOnly: true
          volumes:
          - name: logs
            persistentVolumeClaim:
              claimName: ldap-sync-logs
          restartPolicy: OnFailure
```

#### Configuration Backup

##### Secure Configuration Backup

```bash
#!/bin/bash
# backup-config.sh

NAMESPACE="ldap-user-sync"
BACKUP_DIR="/backup/config/$(date +%Y%m%d_%H%M%S)"
S3_BUCKET="s3://company-backups/ldap-user-sync/config"

mkdir -p "$BACKUP_DIR"

# Backup ConfigMaps
kubectl get configmap ldap-sync-config -n "$NAMESPACE" -o yaml > "$BACKUP_DIR/config.yaml"

# Backup Secrets metadata (not values)
kubectl get secret ldap-sync-secrets -n "$NAMESPACE" -o yaml | \
  yq eval 'del(.data)' - > "$BACKUP_DIR/secrets-structure.yaml"

# Backup certificates (if using cert-manager)
kubectl get certificates -n "$NAMESPACE" -o yaml > "$BACKUP_DIR/certificates.yaml"

# Backup Helm values
helm get values ldap-user-sync -n "$NAMESPACE" > "$BACKUP_DIR/helm-values.yaml"

# Create encrypted archive
tar -czf "$BACKUP_DIR.tar.gz" -C "$(dirname "$BACKUP_DIR")" "$(basename "$BACKUP_DIR")"

# Encrypt with GPG
gpg --cipher-algo AES256 --compress-algo 1 --s2k-cipher-algo AES256 \
    --s2k-digest-algo SHA512 --s2k-mode 3 --s2k-count 65536 \
    --symmetric --output "$BACKUP_DIR.tar.gz.gpg" "$BACKUP_DIR.tar.gz"

# Upload to S3
aws s3 cp "$BACKUP_DIR.tar.gz.gpg" "$S3_BUCKET/"

# Cleanup
rm -rf "$BACKUP_DIR"
rm -f "$BACKUP_DIR.tar.gz"

echo "Configuration backup completed: $BACKUP_DIR.tar.gz.gpg"
```

#### Container Image Backup

##### Image Registry Backup

```bash
#!/bin/bash
# backup-container-images.sh

REGISTRY="your-registry.com"
REPOSITORY="ldap-user-sync"
BACKUP_REGISTRY="backup-registry.com"

# Get list of image tags
TAGS=$(crane ls "$REGISTRY/$REPOSITORY")

for TAG in $TAGS; do
    IMAGE="$REGISTRY/$REPOSITORY:$TAG"
    BACKUP_IMAGE="$BACKUP_REGISTRY/$REPOSITORY:$TAG"
    
    echo "Backing up $IMAGE to $BACKUP_IMAGE"
    
    # Pull, tag, and push to backup registry
    docker pull "$IMAGE"
    docker tag "$IMAGE" "$BACKUP_IMAGE"
    docker push "$BACKUP_IMAGE"
    
    # Save as tar file for offline backup
    docker save "$IMAGE" | gzip > "/backup/images/${REPOSITORY}_${TAG}.tar.gz"
    
    # Upload to S3
    aws s3 cp "/backup/images/${REPOSITORY}_${TAG}.tar.gz" \
        "s3://company-backups/ldap-user-sync/images/"
    
    # Cleanup local files
    rm -f "/backup/images/${REPOSITORY}_${TAG}.tar.gz"
    docker rmi "$IMAGE" "$BACKUP_IMAGE"
done

echo "Container image backup completed"
```

## Recovery Procedures

### Disaster Recovery Scenarios

#### Scenario 1: Configuration Loss

**Problem:** Configuration files or Kubernetes ConfigMaps/Secrets are lost or corrupted.

**Recovery Steps:**

1. **Identify the Issue:**
   ```bash
   # Check if ConfigMap exists
   kubectl get configmap ldap-sync-config -n ldap-user-sync
   
   # Check if Secrets exist
   kubectl get secret ldap-sync-secrets -n ldap-user-sync
   ```

2. **Restore from Backup:**
   ```bash
   # Download latest backup
   aws s3 cp s3://company-backups/ldap-user-sync/config/latest.tar.gz.gpg ./
   
   # Decrypt backup
   gpg --decrypt latest.tar.gz.gpg > latest.tar.gz
   
   # Extract backup
   tar -xzf latest.tar.gz
   
   # Restore ConfigMap
   kubectl apply -f config/config.yaml
   
   # Recreate Secrets (requires manual input of sensitive values)
   kubectl apply -f config/secrets-structure.yaml
   ```

3. **Update Sensitive Values:**
   ```bash
   # Update passwords and tokens
   kubectl patch secret ldap-sync-secrets -n ldap-user-sync \
     --patch='{"data":{"LDAP_BIND_PASSWORD":"'$(echo -n 'new_password' | base64)'"}}'
   ```

4. **Verify Recovery:**
   ```bash
   # Test configuration
   kubectl exec -it <pod-name> -n ldap-user-sync -- \
     python -m ldap_sync.config --validate /app/config/config.yaml
   ```

#### Scenario 2: Complete Namespace Loss

**Problem:** Entire Kubernetes namespace with all resources is lost.

**Recovery Steps:**

1. **Recreate Namespace:**
   ```bash
   kubectl create namespace ldap-user-sync
   ```

2. **Restore from Velero Backup:**
   ```bash
   # List available backups
   velero backup get
   
   # Restore from backup
   velero restore create --from-backup ldap-user-sync-daily-20240115
   
   # Monitor restore progress
   velero restore describe ldap-user-sync-daily-20240115
   ```

3. **Alternative Manual Restore:**
   ```bash
   # Download and extract Kubernetes backup
   aws s3 cp s3://company-backups/ldap-user-sync/kubernetes/latest.tar.gz ./
   tar -xzf latest.tar.gz
   
   # Apply resources in order
   kubectl apply -f backup/configmaps.yaml
   kubectl apply -f backup/secrets.yaml  # Update sensitive values first
   kubectl apply -f backup/pvc.yaml
   kubectl apply -f backup/rbac.yaml
   kubectl apply -f backup/cronjobs.yaml
   ```

4. **Restore Log Data:**
   ```bash
   # Download log backup
   aws s3 cp s3://company-backups/ldap-user-sync/logs/logs-20240115.tar.gz ./
   
   # Create temporary pod for log restoration
   kubectl run restore-pod --image=busybox -n ldap-user-sync --rm -it -- sh
   
   # Inside pod, extract logs to PVC
   tar -xzf logs-20240115.tar.gz -C /app/logs/
   ```

#### Scenario 3: Data Corruption

**Problem:** Log data or configuration is corrupted but resources exist.

**Recovery Steps:**

1. **Assess Corruption:**
   ```bash
   # Check log file integrity
   find /app/logs -name "*.log" -exec file {} \; | grep -v text
   
   # Check configuration syntax
   python -c "import yaml; yaml.safe_load(open('config.yaml'))"
   ```

2. **Restore Specific Components:**
   ```bash
   # Restore configuration only
   kubectl patch configmap ldap-sync-config -n ldap-user-sync \
     --patch-file restored-config.yaml
   
   # Restart application to pick up changes
   kubectl delete job --all -n ldap-user-sync
   ```

3. **Restore Log Data:**
   ```bash
   # Mount PVC and restore logs
   kubectl run log-restore --image=busybox -n ldap-user-sync \
     --overrides='{"spec":{"containers":[{"name":"restore","image":"busybox","command":["sleep","3600"],"volumeMounts":[{"name":"logs","mountPath":"/app/logs"}]}],"volumes":[{"name":"logs","persistentVolumeClaim":{"claimName":"ldap-sync-logs"}}]}}'
   
   # Copy restored logs
   kubectl cp restored-logs/ ldap-user-sync/log-restore:/app/logs/
   
   # Cleanup
   kubectl delete pod log-restore -n ldap-user-sync
   ```

#### Scenario 4: Container Image Loss

**Problem:** Container images are lost or corrupted in registry.

**Recovery Steps:**

1. **Restore from Backup Registry:**
   ```bash
   # Pull from backup registry
   docker pull backup-registry.com/ldap-user-sync:v1.0.0
   
   # Tag for primary registry
   docker tag backup-registry.com/ldap-user-sync:v1.0.0 \
     your-registry.com/ldap-user-sync:v1.0.0
   
   # Push to primary registry
   docker push your-registry.com/ldap-user-sync:v1.0.0
   ```

2. **Restore from Archive:**
   ```bash
   # Download image archive
   aws s3 cp s3://company-backups/ldap-user-sync/images/ldap-user-sync_v1.0.0.tar.gz ./
   
   # Load image
   gunzip -c ldap-user-sync_v1.0.0.tar.gz | docker load
   
   # Push to registry
   docker push your-registry.com/ldap-user-sync:v1.0.0
   ```

### Recovery Testing

#### Scheduled Recovery Tests

```bash
#!/bin/bash
# test-recovery.sh

TEST_NAMESPACE="ldap-user-sync-test"
BACKUP_DATE="20240115"

echo "Starting recovery test..."

# Create test namespace
kubectl create namespace "$TEST_NAMESPACE" || true

# Restore from backup
aws s3 cp "s3://company-backups/ldap-user-sync/kubernetes/ldap-user-sync-k8s-$BACKUP_DATE.tar.gz" ./
tar -xzf "ldap-user-sync-k8s-$BACKUP_DATE.tar.gz"

# Apply resources to test namespace
sed "s/namespace: ldap-user-sync/namespace: $TEST_NAMESPACE/g" backup/*.yaml | kubectl apply -f -

# Wait for deployment
kubectl wait --for=condition=available --timeout=300s deployment -l app=ldap-user-sync -n "$TEST_NAMESPACE"

# Run basic functionality test
kubectl exec -n "$TEST_NAMESPACE" deployment/ldap-user-sync -- \
  python -m ldap_sync.main --dry-run --config /app/config/config.yaml

if [ $? -eq 0 ]; then
    echo "Recovery test PASSED"
else
    echo "Recovery test FAILED"
fi

# Cleanup test namespace
kubectl delete namespace "$TEST_NAMESPACE"

rm -rf backup/
rm -f "ldap-user-sync-k8s-$BACKUP_DATE.tar.gz"

echo "Recovery test completed"
```

#### Monthly Recovery Drill

```yaml
# recovery-drill-cronjob.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: recovery-drill
  namespace: ldap-user-sync
spec:
  schedule: "0 4 1 * *"  # First day of month at 4 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: recovery-test
            image: your-registry.com/ldap-user-sync:latest
            command:
            - /bin/bash
            - -c
            - |
              # Download test script
              curl -O https://internal-tools.company.com/scripts/test-recovery.sh
              chmod +x test-recovery.sh
              
              # Run recovery test
              ./test-recovery.sh
              
              # Send results to monitoring
              if [ $? -eq 0 ]; then
                curl -X POST https://monitoring.company.com/api/events \
                  -H "Content-Type: application/json" \
                  -d '{"event":"recovery_test_success","service":"ldap-user-sync"}'
              else
                curl -X POST https://monitoring.company.com/api/events \
                  -H "Content-Type: application/json" \
                  -d '{"event":"recovery_test_failure","service":"ldap-user-sync"}'
              fi
            env:
            - name: KUBECONFIG
              value: /etc/kubeconfig/config
            volumeMounts:
            - name: kubeconfig
              mountPath: /etc/kubeconfig
              readOnly: true
          volumes:
          - name: kubeconfig
            secret:
              secretName: recovery-test-kubeconfig
          restartPolicy: OnFailure
```

## Backup Monitoring

### Backup Health Checks

```bash
#!/bin/bash
# check-backup-health.sh

S3_BUCKET="s3://company-backups/ldap-user-sync"
ALERT_EMAIL="ops@company.com"

# Check recent backups
LATEST_CONFIG=$(aws s3 ls "$S3_BUCKET/config/" | tail -1 | awk '{print $1" "$2}')
LATEST_LOGS=$(aws s3 ls "$S3_BUCKET/logs/" | tail -1 | awk '{print $1" "$2}')
LATEST_K8S=$(aws s3 ls "$S3_BUCKET/kubernetes/" | tail -1 | awk '{print $1" "$2}')

# Check if backups are recent (within 48 hours)
CURRENT_TIME=$(date +%s)
CONFIG_TIME=$(date -d "$LATEST_CONFIG" +%s)
LOGS_TIME=$(date -d "$LATEST_LOGS" +%s)
K8S_TIME=$(date -d "$LATEST_K8S" +%s)

THRESHOLD=172800  # 48 hours in seconds

if [ $((CURRENT_TIME - CONFIG_TIME)) -gt $THRESHOLD ]; then
    echo "WARNING: Configuration backup is older than 48 hours"
    echo "Configuration backup stale" | mail -s "Backup Alert" "$ALERT_EMAIL"
fi

if [ $((CURRENT_TIME - LOGS_TIME)) -gt $THRESHOLD ]; then
    echo "WARNING: Log backup is older than 48 hours"
    echo "Log backup stale" | mail -s "Backup Alert" "$ALERT_EMAIL"
fi

if [ $((CURRENT_TIME - K8S_TIME)) -gt $THRESHOLD ]; then
    echo "WARNING: Kubernetes backup is older than 48 hours"
    echo "Kubernetes backup stale" | mail -s "Backup Alert" "$ALERT_EMAIL"
fi

echo "Backup health check completed"
```

### Backup Metrics

```python
# backup_metrics.py
from prometheus_client import Gauge, Counter, start_http_server
import boto3
import time
from datetime import datetime, timedelta

# Define metrics
backup_age_hours = Gauge('backup_age_hours', 'Age of last backup in hours', ['backup_type'])
backup_size_bytes = Gauge('backup_size_bytes', 'Size of last backup in bytes', ['backup_type'])
backup_success_total = Counter('backup_success_total', 'Total successful backups', ['backup_type'])
backup_failure_total = Counter('backup_failure_total', 'Total failed backups', ['backup_type'])

def collect_backup_metrics():
    s3 = boto3.client('s3')
    bucket = 'company-backups'
    prefix = 'ldap-user-sync'
    
    backup_types = ['config', 'logs', 'kubernetes', 'images']
    
    for backup_type in backup_types:
        try:
            # List objects in backup type directory
            response = s3.list_objects_v2(
                Bucket=bucket,
                Prefix=f'{prefix}/{backup_type}/',
                MaxKeys=1
            )
            
            if 'Contents' in response:
                latest_object = max(response['Contents'], key=lambda x: x['LastModified'])
                
                # Calculate age in hours
                age = datetime.now(latest_object['LastModified'].tzinfo) - latest_object['LastModified']
                backup_age_hours.labels(backup_type=backup_type).set(age.total_seconds() / 3600)
                
                # Set size
                backup_size_bytes.labels(backup_type=backup_type).set(latest_object['Size'])
                
        except Exception as e:
            print(f"Error collecting metrics for {backup_type}: {e}")
            backup_failure_total.labels(backup_type=backup_type).inc()

if __name__ == '__main__':
    start_http_server(8000)
    while True:
        collect_backup_metrics()
        time.sleep(300)  # Update every 5 minutes
```

## Best Practices

### Security

1. **Encrypt Backups:** Always encrypt sensitive backups
2. **Access Control:** Limit access to backup storage
3. **Audit Trails:** Log all backup and recovery operations
4. **Key Management:** Securely manage encryption keys

### Performance

1. **Incremental Backups:** Use incremental backups for large datasets
2. **Compression:** Compress backups to reduce storage costs
3. **Parallel Processing:** Use parallel uploads for large backups
4. **Storage Classes:** Use appropriate S3 storage classes

### Operational

1. **Regular Testing:** Test recovery procedures monthly
2. **Documentation:** Keep recovery procedures up to date
3. **Automation:** Automate backup processes
4. **Monitoring:** Monitor backup health and age

### Compliance

1. **Retention Policies:** Follow regulatory requirements
2. **Data Classification:** Classify backup data appropriately
3. **Geographic Distribution:** Store backups in multiple regions
4. **Audit Requirements:** Maintain audit trails for compliance

## Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO)

### Service Level Objectives

| Component | RPO | RTO | Notes |
|-----------|-----|-----|-------|
| Configuration | 1 hour | 15 minutes | Critical for operations |
| Application Logs | 24 hours | 30 minutes | For troubleshooting |
| Audit Logs | 1 hour | 1 hour | Compliance requirement |
| Container Images | 24 hours | 1 hour | Can rebuild if necessary |
| Deployment State | 1 hour | 30 minutes | Kubernetes resources |

### Recovery Priorities

1. **Priority 1 (Critical):** Configuration and secrets recovery
2. **Priority 2 (High):** Application deployment restoration
3. **Priority 3 (Medium):** Recent log data recovery
4. **Priority 4 (Low):** Historical log data recovery

For additional operational procedures, see the [Maintenance Procedures](maintenance-procedures.md) document.