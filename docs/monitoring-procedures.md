# Monitoring and Alerting Setup Procedures

This document outlines the procedures for setting up comprehensive monitoring and alerting for the LDAP User Sync application.

## Overview

Effective monitoring of the LDAP User Sync application requires:

- **Application Metrics**: Sync success/failure rates, operation counts, execution times
- **Infrastructure Metrics**: Resource usage, network connectivity, storage
- **Log Monitoring**: Error patterns, security events, operational insights
- **Alerting Rules**: Proactive notification of issues and failures
- **Dashboards**: Visual representation of system health and performance

## Metrics Collection

### Application Metrics

#### Core Sync Metrics

```python
# Example metrics to collect
sync_operations_total = Counter('ldap_sync_operations_total', 'Total sync operations', ['vendor', 'operation', 'status'])
sync_duration_seconds = Histogram('ldap_sync_duration_seconds', 'Time spent on sync operations', ['vendor'])
sync_users_processed = Gauge('ldap_sync_users_processed', 'Number of users processed', ['vendor', 'group'])
sync_errors_total = Counter('ldap_sync_errors_total', 'Total sync errors', ['vendor', 'error_type'])
ldap_connection_status = Gauge('ldap_connection_status', 'LDAP connection status (1=connected, 0=disconnected)')
vendor_api_response_time = Histogram('vendor_api_response_time_seconds', 'Vendor API response time', ['vendor', 'endpoint'])
```

#### Custom Metrics Implementation

Add to your main sync application:

```python
from prometheus_client import start_http_server, Counter, Histogram, Gauge
import time

# Define metrics
SYNC_OPERATIONS = Counter('ldap_sync_operations_total', 'Total sync operations', ['vendor', 'operation', 'status'])
SYNC_DURATION = Histogram('ldap_sync_duration_seconds', 'Sync operation duration', ['vendor'])
SYNC_ERRORS = Counter('ldap_sync_errors_total', 'Total sync errors', ['vendor', 'error_type'])
USERS_PROCESSED = Gauge('ldap_sync_users_processed', 'Users processed in last sync', ['vendor'])

def instrument_sync_operation(vendor_name: str):
    """Decorator to instrument sync operations with metrics."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                SYNC_OPERATIONS.labels(vendor=vendor_name, operation='sync', status='success').inc()
                return result
            except Exception as e:
                SYNC_OPERATIONS.labels(vendor=vendor_name, operation='sync', status='error').inc()
                SYNC_ERRORS.labels(vendor=vendor_name, error_type=type(e).__name__).inc()
                raise
            finally:
                duration = time.time() - start_time
                SYNC_DURATION.labels(vendor=vendor_name).observe(duration)
        return wrapper
    return decorator

# Usage in sync code
@instrument_sync_operation('vendor_app1')
def sync_vendor_app1():
    # Sync logic here
    pass
```

### Infrastructure Metrics

#### Kubernetes Metrics

Monitor resource usage and health:

```yaml
# ServiceMonitor for Prometheus scraping
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: ldap-user-sync
  namespace: ldap-user-sync
spec:
  selector:
    matchLabels:
      app: ldap-user-sync
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics
```

#### Resource Monitoring

```yaml
# PodMonitor for job-based applications
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: ldap-user-sync-jobs
spec:
  selector:
    matchLabels:
      app: ldap-user-sync
  podMetricsEndpoints:
  - port: metrics
    interval: 30s
```

## Log Monitoring

### Centralized Logging Setup

#### Fluent Bit Configuration

```yaml
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
        Refresh_Interval 10

    [FILTER]
        Name modify
        Match ldap-sync.*
        Add service ldap-user-sync
        Add environment ${ENVIRONMENT}

    [OUTPUT]
        Name elasticsearch
        Match ldap-sync.*
        Host elasticsearch.logging.svc.cluster.local
        Port 9200
        Index ldap-sync-${ENVIRONMENT}
        Type _doc
        Logstash_Format On
        Logstash_Prefix ldap-sync
        Time_Key @timestamp
        Generate_ID On
```

#### Structured Logging Format

Configure application to output structured logs:

```python
import logging
import json
from datetime import datetime

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add extra fields if present
        if hasattr(record, 'vendor'):
            log_entry['vendor'] = record.vendor
        if hasattr(record, 'operation'):
            log_entry['operation'] = record.operation
        if hasattr(record, 'user_count'):
            log_entry['user_count'] = record.user_count
            
        return json.dumps(log_entry)

# Configure logging
def setup_structured_logging():
    logger = logging.getLogger()
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
```

### Log Analysis and Alerting

#### Elasticsearch Queries

Key queries for monitoring:

```json
# Error rate query
{
  "query": {
    "bool": {
      "must": [
        {"term": {"service": "ldap-user-sync"}},
        {"term": {"level": "ERROR"}},
        {"range": {"@timestamp": {"gte": "now-5m"}}}
      ]
    }
  },
  "aggs": {
    "error_count": {"value_count": {"field": "message"}}
  }
}

# Sync completion query
{
  "query": {
    "bool": {
      "must": [
        {"term": {"service": "ldap-user-sync"}},
        {"match": {"message": "sync completed successfully"}},
        {"range": {"@timestamp": {"gte": "now-1h"}}}
      ]
    }
  }
}

# Authentication failure query
{
  "query": {
    "bool": {
      "must": [
        {"term": {"service": "ldap-user-sync"}},
        {"match": {"message": "authentication failed"}},
        {"range": {"@timestamp": {"gte": "now-15m"}}}
      ]
    }
  }
}
```

## Alerting Rules

### Prometheus Alerting Rules

```yaml
# alerting-rules.yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: ldap-user-sync-alerts
  namespace: ldap-user-sync
spec:
  groups:
  - name: ldap-user-sync
    rules:
    # High error rate alert
    - alert: LDAPSyncHighErrorRate
      expr: |
        (
          rate(ldap_sync_errors_total[5m]) / 
          rate(ldap_sync_operations_total[5m])
        ) > 0.1
      for: 2m
      labels:
        severity: warning
        service: ldap-user-sync
      annotations:
        summary: "High error rate in LDAP User Sync"
        description: "Error rate is {{ $value | humanizePercentage }} for the last 5 minutes"

    # Sync failure alert
    - alert: LDAPSyncFailed
      expr: |
        increase(ldap_sync_operations_total{status="error"}[10m]) > 0
      for: 1m
      labels:
        severity: critical
        service: ldap-user-sync
      annotations:
        summary: "LDAP sync operation failed"
        description: "Sync operation failed for vendor {{ $labels.vendor }}"

    # Long sync duration alert
    - alert: LDAPSyncLongDuration
      expr: |
        histogram_quantile(0.95, rate(ldap_sync_duration_seconds_bucket[10m])) > 300
      for: 5m
      labels:
        severity: warning
        service: ldap-user-sync
      annotations:
        summary: "LDAP sync taking too long"
        description: "95th percentile sync duration is {{ $value }}s"

    # No recent sync alert
    - alert: LDAPSyncStale
      expr: |
        time() - max(ldap_sync_operations_total) > 86400
      for: 5m
      labels:
        severity: warning
        service: ldap-user-sync
      annotations:
        summary: "No recent LDAP sync operations"
        description: "No sync operations detected in the last 24 hours"

    # LDAP connection down
    - alert: LDAPConnectionDown
      expr: |
        ldap_connection_status == 0
      for: 1m
      labels:
        severity: critical
        service: ldap-user-sync
      annotations:
        summary: "LDAP connection is down"
        description: "Unable to connect to LDAP server"

    # Vendor API errors
    - alert: VendorAPIErrors
      expr: |
        increase(ldap_sync_errors_total{error_type="VendorAPIError"}[5m]) > 5
      for: 2m
      labels:
        severity: warning
        service: ldap-user-sync
      annotations:
        summary: "High vendor API error rate"
        description: "Multiple vendor API errors for {{ $labels.vendor }}"
```

### ElastAlert Rules

For log-based alerting:

```yaml
# elastalert-rules.yaml
name: ldap-sync-authentication-failures
type: frequency
index: ldap-sync-*
num_events: 3
timeframe:
  minutes: 5

filter:
- terms:
    level: ["ERROR"]
- query:
    match:
      message: "authentication failed"

alert:
- "email"

email:
- "ops-team@company.com"

subject: "LDAP Sync Authentication Failures"
body_type: body

body: |
  Multiple authentication failures detected in LDAP User Sync:
  
  Time: {0}
  Environment: {1}
  
  Recent errors:
  {2}

---
name: ldap-sync-no-recent-activity
type: flatline
index: ldap-sync-*
threshold: 1
timeframe:
  hours: 6

filter:
- query:
    match:
      message: "sync completed"

alert:
- "email"

email:
- "ops-team@company.com"

subject: "LDAP Sync - No Recent Activity"
body: |
  No LDAP sync activity detected in the last 6 hours.
  
  This may indicate:
  - CronJob not running
  - Application failure
  - Configuration issues
  
  Please investigate immediately.
```

## Dashboards

### Grafana Dashboard Configuration

#### Main Operational Dashboard

```json
{
  "dashboard": {
    "title": "LDAP User Sync - Operations",
    "panels": [
      {
        "title": "Sync Success Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "rate(ldap_sync_operations_total{status=\"success\"}[5m]) / rate(ldap_sync_operations_total[5m])",
            "legendFormat": "Success Rate"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "unit": "percentunit",
            "min": 0,
            "max": 1,
            "thresholds": {
              "steps": [
                {"color": "red", "value": 0},
                {"color": "yellow", "value": 0.9},
                {"color": "green", "value": 0.95}
              ]
            }
          }
        }
      },
      {
        "title": "Sync Operations Over Time",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(ldap_sync_operations_total{status=\"success\"}[5m])",
            "legendFormat": "Success - {{vendor}}"
          },
          {
            "expr": "rate(ldap_sync_operations_total{status=\"error\"}[5m])",
            "legendFormat": "Error - {{vendor}}"
          }
        ]
      },
      {
        "title": "Sync Duration",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.50, rate(ldap_sync_duration_seconds_bucket[5m]))",
            "legendFormat": "50th percentile"
          },
          {
            "expr": "histogram_quantile(0.95, rate(ldap_sync_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Users Processed by Vendor",
        "type": "table",
        "targets": [
          {
            "expr": "ldap_sync_users_processed",
            "legendFormat": "{{vendor}} - {{group}}"
          }
        ]
      },
      {
        "title": "Error Breakdown",
        "type": "piechart",
        "targets": [
          {
            "expr": "sum by (error_type) (rate(ldap_sync_errors_total[5m]))",
            "legendFormat": "{{error_type}}"
          }
        ]
      }
    ]
  }
}
```

#### Infrastructure Dashboard

```json
{
  "dashboard": {
    "title": "LDAP User Sync - Infrastructure",
    "panels": [
      {
        "title": "Pod CPU Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(container_cpu_usage_seconds_total{pod=~\"ldap-user-sync.*\"}[5m])",
            "legendFormat": "{{pod}}"
          }
        ]
      },
      {
        "title": "Pod Memory Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "container_memory_usage_bytes{pod=~\"ldap-user-sync.*\"} / 1024 / 1024",
            "legendFormat": "{{pod}}"
          }
        ]
      },
      {
        "title": "Network I/O",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(container_network_receive_bytes_total{pod=~\"ldap-user-sync.*\"}[5m])",
            "legendFormat": "RX - {{pod}}"
          },
          {
            "expr": "rate(container_network_transmit_bytes_total{pod=~\"ldap-user-sync.*\"}[5m])",
            "legendFormat": "TX - {{pod}}"
          }
        ]
      },
      {
        "title": "Job Status",
        "type": "table",
        "targets": [
          {
            "expr": "kube_job_status_succeeded{job_name=~\"ldap-user-sync.*\"}",
            "legendFormat": "{{job_name}}"
          }
        ]
      }
    ]
  }
}
```

### Kibana Dashboards

#### Log Analysis Dashboard

```json
{
  "version": "7.15.0",
  "objects": [
    {
      "attributes": {
        "title": "LDAP User Sync - Logs",
        "type": "dashboard",
        "description": "Log analysis for LDAP User Sync operations",
        "panelsJSON": "[{\"version\":\"7.15.0\",\"type\":\"visualization\",\"gridData\":{\"x\":0,\"y\":0,\"w\":24,\"h\":15},\"panelIndex\":\"1\",\"embeddableConfig\":{},\"panelRefName\":\"panel_1\"}]",
        "timeRestore": false,
        "kibanaSavedObjectMeta": {
          "searchSourceJSON": "{\"query\":{\"match_all\":{}},\"filter\":[]}"
        }
      },
      "references": [
        {
          "name": "panel_1",
          "type": "visualization",
          "id": "log-level-breakdown"
        }
      ]
    }
  ]
}
```

## Health Checks

### Application Health Check

Implement health check endpoint:

```python
from flask import Flask, jsonify
import datetime

app = Flask(__name__)

@app.route('/health')
def health_check():
    """Basic health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'service': 'ldap-user-sync'
    })

@app.route('/health/detailed')
def detailed_health_check():
    """Detailed health check with dependencies."""
    health_status = {
        'status': 'healthy',
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'checks': {}
    }
    
    # Check LDAP connectivity
    try:
        ldap_client = LDAPClient(config['ldap'])
        if ldap_client.connect():
            health_status['checks']['ldap'] = 'healthy'
        else:
            health_status['checks']['ldap'] = 'unhealthy'
            health_status['status'] = 'degraded'
    except Exception as e:
        health_status['checks']['ldap'] = f'error: {str(e)}'
        health_status['status'] = 'unhealthy'
    
    # Check vendor APIs
    for vendor in config['vendor_apps']:
        vendor_name = vendor['name']
        try:
            vendor_api = get_vendor_api(vendor)
            if vendor_api.authenticate():
                health_status['checks'][vendor_name] = 'healthy'
            else:
                health_status['checks'][vendor_name] = 'auth_failed'
                health_status['status'] = 'degraded'
        except Exception as e:
            health_status['checks'][vendor_name] = f'error: {str(e)}'
            health_status['status'] = 'unhealthy'
    
    return jsonify(health_status)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

### Kubernetes Health Checks

```yaml
# Add to CronJob template
spec:
  template:
    spec:
      containers:
      - name: ldap-user-sync
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
```

## Notification Channels

### Slack Integration

```python
import requests
import json

def send_slack_alert(webhook_url: str, message: str, channel: str = None):
    """Send alert to Slack channel."""
    payload = {
        'text': message,
        'username': 'LDAP Sync Monitor',
        'icon_emoji': ':warning:'
    }
    
    if channel:
        payload['channel'] = channel
    
    response = requests.post(webhook_url, json=payload)
    return response.status_code == 200

# Usage in alerting
def handle_sync_failure(error_details):
    message = f"""
    🚨 LDAP User Sync Failed
    
    Environment: {os.environ.get('ENVIRONMENT', 'unknown')}
    Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    Error: {error_details}
    
    Please check logs for more details.
    """
    
    send_slack_alert(
        webhook_url=config['notifications']['slack_webhook'],
        message=message,
        channel='#ops-alerts'
    )
```

### PagerDuty Integration

```python
import requests

def trigger_pagerduty_incident(routing_key: str, description: str, severity: str = 'error'):
    """Trigger PagerDuty incident."""
    payload = {
        'routing_key': routing_key,
        'event_action': 'trigger',
        'payload': {
            'summary': description,
            'severity': severity,
            'source': 'ldap-user-sync',
            'component': 'sync-application',
            'group': 'identity-management',
            'class': 'sync-failure'
        }
    }
    
    response = requests.post(
        'https://events.pagerduty.com/v2/enqueue',
        json=payload,
        headers={'Content-Type': 'application/json'}
    )
    
    return response.status_code == 202
```

## Monitoring Checklist

### Pre-Production Setup

- [ ] Metrics collection configured
- [ ] Log aggregation setup
- [ ] Alerting rules defined
- [ ] Dashboards created
- [ ] Health checks implemented
- [ ] Notification channels tested
- [ ] Runbooks documented

### Production Monitoring

- [ ] Monitor sync success/failure rates
- [ ] Track sync duration and performance
- [ ] Monitor resource usage
- [ ] Alert on authentication failures
- [ ] Track user synchronization counts
- [ ] Monitor vendor API health
- [ ] Set up log retention policies

### Operational Procedures

- [ ] Define escalation procedures
- [ ] Create incident response playbooks
- [ ] Schedule regular monitoring reviews
- [ ] Test alert channels monthly
- [ ] Review and update thresholds quarterly
- [ ] Conduct monitoring drills

## Troubleshooting Monitoring Issues

### Common Problems

1. **Missing Metrics**
   - Check metric exposition endpoint
   - Verify ServiceMonitor configuration
   - Check Prometheus targets

2. **False Alerts**
   - Review alert thresholds
   - Analyze historical data
   - Adjust alert conditions

3. **Missing Logs**
   - Verify log shipping configuration
   - Check log format compatibility
   - Review retention policies

4. **Dashboard Issues**
   - Validate metric queries
   - Check data source configuration
   - Review time range settings

For additional monitoring guidance, see the [Troubleshooting Guide](troubleshooting-guide.md).