# Troubleshooting Guide

This guide provides solutions for common issues encountered when deploying and operating the LDAP User Sync application.

## General Troubleshooting Approach

### 1. Check Application Logs

First, examine the application logs for error messages:

```bash
# Docker deployment
docker logs ldap-user-sync

# Kubernetes deployment
kubectl logs -f cronjob/ldap-user-sync -n ldap-user-sync

# Local file system
tail -f logs/ldap_sync.log
```

### 2. Verify Configuration

Check configuration file syntax and values:

```bash
# Validate YAML syntax
python -c "import yaml; yaml.safe_load(open('config.yaml'))"

# Check configuration in container
kubectl exec -it <pod-name> -- cat /app/config/config.yaml
```

### 3. Test Network Connectivity

Verify network access to required services:

```bash
# Test LDAP connectivity
telnet ldap.company.com 636
openssl s_client -connect ldap.company.com:636

# Test vendor API connectivity
curl -I https://api.vendor.com/health
nslookup api.vendor.com

# Test SMTP connectivity
telnet smtp.company.com 587
```

## LDAP Connection Issues

### Issue: LDAP Server Unreachable

**Symptoms:**
- Connection timeout errors
- "Name or service not known" errors
- Network unreachable messages

**Solutions:**

1. **Verify LDAP server URL and port:**
   ```yaml
   ldap:
     server_url: "ldaps://ldap.company.com:636"  # Check hostname and port
   ```

2. **Test DNS resolution:**
   ```bash
   nslookup ldap.company.com
   dig ldap.company.com
   ```

3. **Check firewall rules:**
   ```bash
   # Test connectivity
   telnet ldap.company.com 636
   nc -zv ldap.company.com 636
   ```

4. **Verify SSL/TLS configuration:**
   ```bash
   # Test SSL connection
   openssl s_client -connect ldap.company.com:636 -servername ldap.company.com
   ```

### Issue: LDAP Authentication Failed

**Symptoms:**
- "Invalid credentials" errors
- "Bind operation failed" messages
- Authentication timeout

**Solutions:**

1. **Verify bind DN format:**
   ```yaml
   ldap:
     bind_dn: "CN=Service Account,OU=Users,DC=company,DC=com"  # Full DN required
   ```

2. **Check password:**
   ```bash
   # Test with ldapsearch
   ldapsearch -H ldaps://ldap.company.com:636 \
     -D "CN=Service Account,OU=Users,DC=company,DC=com" \
     -W -b "DC=company,DC=com" "(objectClass=person)" cn
   ```

3. **Verify service account permissions:**
   - Ensure account has read access to user and group objects
   - Check account is not disabled or expired
   - Verify password policy compliance

4. **Check for account lockout:**
   ```bash
   # Check account status in LDAP
   ldapsearch -H ldaps://ldap.company.com:636 \
     -D "CN=Admin,DC=company,DC=com" -W \
     -b "CN=Service Account,OU=Users,DC=company,DC=com" \
     "(objectClass=*)" accountExpires userAccountControl
   ```

### Issue: Group Members Not Found

**Symptoms:**
- Empty group membership results
- "Group not found" errors
- Incorrect user count

**Solutions:**

1. **Verify group DN:**
   ```yaml
   groups:
     - ldap_group: "CN=App_Users,OU=Groups,DC=company,DC=com"  # Check exact DN
   ```

2. **Test group query:**
   ```bash
   # Test group lookup
   ldapsearch -H ldaps://ldap.company.com:636 \
     -D "CN=Service Account,OU=Users,DC=company,DC=com" -W \
     -b "CN=App_Users,OU=Groups,DC=company,DC=com" \
     "(objectClass=*)" member
   ```

3. **Check membership strategy:**
   ```python
   # For Active Directory, use memberOf lookup
   ldap:
     user_filter: "(&(objectClass=person)(memberOf=CN=App_Users,OU=Groups,DC=company,DC=com))"
   
   # For traditional LDAP, query group object
   # Application automatically handles both methods
   ```

4. **Verify user base DN:**
   ```yaml
   ldap:
     user_base_dn: "OU=Users,DC=company,DC=com"  # Should contain target users
   ```

### Issue: SSL Certificate Errors

**Symptoms:**
- "Certificate verify failed" errors
- SSL handshake failures
- Untrusted certificate warnings

**Solutions:**

1. **Disable SSL verification (testing only):**
   ```yaml
   ldap:
     verify_ssl: false  # Only for testing!
   ```

2. **Add custom CA certificate:**
   ```yaml
   ldap:
     ca_cert_file: "/app/certs/company-ca.pem"
   ```

3. **Export and install certificate:**
   ```bash
   # Get certificate
   openssl s_client -connect ldap.company.com:636 -servername ldap.company.com < /dev/null 2>/dev/null | openssl x509 -outform PEM > ldap-cert.pem
   
   # Add to container
   cp ldap-cert.pem /usr/local/share/ca-certificates/
   update-ca-certificates
   ```

## Vendor API Issues

### Issue: Vendor API Authentication Failed

**Symptoms:**
- 401 Unauthorized responses
- "Invalid credentials" from vendor API
- Authentication token expired

**Solutions:**

1. **Verify API credentials:**
   ```yaml
   vendor_apps:
     - auth:
         method: "basic"
         username: "correct_username"
         password: "correct_password"
   ```

2. **Test API credentials manually:**
   ```bash
   # Test basic auth
   curl -u username:password https://api.vendor.com/users
   
   # Test token auth
   curl -H "Authorization: Bearer your_token" https://api.vendor.com/users
   ```

3. **Check OAuth2 token flow:**
   ```bash
   # Test OAuth2 token request
   curl -X POST https://api.vendor.com/oauth/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=client_credentials&client_id=your_id&client_secret=your_secret"
   ```

4. **Verify token expiration handling:**
   - Check if vendor module implements token refresh
   - Verify token lifetime in vendor configuration

### Issue: Vendor API Rate Limiting

**Symptoms:**
- 429 Too Many Requests responses
- Sync operations slow or failing
- Rate limit exceeded errors

**Solutions:**

1. **Implement rate limiting in vendor module:**
   ```python
   import time
   from datetime import datetime, timedelta
   
   def _check_rate_limit(self):
       if self.requests_this_minute >= self.rate_limit:
           sleep_time = 60 - (datetime.now() - self.minute_start).seconds
           time.sleep(sleep_time)
           self.requests_this_minute = 0
           self.minute_start = datetime.now()
   ```

2. **Reduce concurrent requests:**
   ```yaml
   vendor_apps:
     - request_timeout: 60  # Increase timeout
       max_concurrent_requests: 5  # Limit concurrency
   ```

3. **Add retry logic with backoff:**
   ```python
   import random
   
   def retry_with_backoff(self, operation, max_retries=3):
       for attempt in range(max_retries):
           try:
               return operation()
           except RateLimitError:
               if attempt < max_retries - 1:
                   backoff = (2 ** attempt) + random.uniform(0, 1)
                   time.sleep(backoff)
               else:
                   raise
   ```

### Issue: Vendor API Data Format Errors

**Symptoms:**
- JSON parsing errors
- XML parsing failures
- Unexpected response format

**Solutions:**

1. **Verify API response format:**
   ```bash
   # Check actual API response
   curl -H "Authorization: Bearer token" https://api.vendor.com/users | jq .
   ```

2. **Handle different response formats:**
   ```python
   def _parse_response(self, response_data):
       if self.config.get('format') == 'json':
           return json.loads(response_data)
       elif self.config.get('format') == 'xml':
           return ET.fromstring(response_data)
       else:
           raise ValueError(f"Unsupported format: {self.config.get('format')}")
   ```

3. **Add response validation:**
   ```python
   def get_group_members(self, group_cfg):
       response = self.request('GET', f'/groups/{group_cfg["vendor_group"]}/members')
       
       if not isinstance(response, dict):
           raise ValueError(f"Expected dict response, got {type(response)}")
       
       if 'members' not in response:
           raise ValueError("Response missing 'members' field")
       
       return self._parse_members(response['members'])
   ```

## Configuration Issues

### Issue: YAML Syntax Errors

**Symptoms:**
- Application fails to start
- Configuration parsing errors
- "YAML syntax error" messages

**Solutions:**

1. **Validate YAML syntax:**
   ```bash
   # Python validation
   python -c "import yaml; yaml.safe_load(open('config.yaml'))"
   
   # Online validators
   # Use yamllint or online YAML validators
   ```

2. **Check indentation:**
   ```yaml
   # Correct indentation (2 spaces)
   vendor_apps:
     - name: "App1"
       auth:
         method: "basic"
   
   # Incorrect (mixed tabs/spaces)
   vendor_apps:
   	- name: "App1"
   	  auth:
   		method: "basic"
   ```

3. **Quote special characters:**
   ```yaml
   # Quote values with special characters
   ldap:
     bind_password: "password@123!"
     server_url: "ldaps://ldap.company.com:636"
   ```

### Issue: Environment Variable Override Not Working

**Symptoms:**
- Hardcoded values used instead of environment variables
- "Environment variable not found" errors
- Secrets not properly injected

**Solutions:**

1. **Verify environment variable format:**
   ```bash
   # Check environment variables are set
   env | grep LDAP
   env | grep VENDOR
   env | grep SMTP
   ```

2. **Check variable naming convention:**
   ```bash
   # Correct format
   export LDAP_BIND_PASSWORD="password123"
   export VENDOR_APP1_PASSWORD="vendorpass"
   
   # Check in config
   bind_password: "${LDAP_BIND_PASSWORD}"
   ```

3. **Debug environment variable expansion:**
   ```python
   import os
   print(f"LDAP_BIND_PASSWORD = {os.environ.get('LDAP_BIND_PASSWORD', 'NOT_SET')}")
   ```

### Issue: Missing Required Configuration

**Symptoms:**
- "Required field missing" errors
- Application exits during startup
- Configuration validation failures

**Solutions:**

1. **Check required fields:**
   ```yaml
   # Minimum required configuration
   ldap:
     server_url: "ldaps://ldap.company.com:636"
     bind_dn: "CN=Service Account,OU=Users,DC=company,DC=com"
     bind_password: "password"
     user_base_dn: "OU=Users,DC=company,DC=com"
   
   vendor_apps:
     - name: "App1"
       module: "vendor_app1"
       base_url: "https://api.vendor.com"
       auth:
         method: "basic"
         username: "user"
         password: "pass"
       groups:
         - ldap_group: "CN=Group,OU=Groups,DC=company,DC=com"
           vendor_group: "group_id"
   ```

2. **Use configuration validation:**
   ```python
   def validate_config(config):
       required_fields = ['ldap', 'vendor_apps']
       for field in required_fields:
           if field not in config:
               raise ValueError(f"Missing required field: {field}")
   ```

## Container and Kubernetes Issues

### Issue: Image Pull Errors

**Symptoms:**
- "ImagePullBackOff" status
- "ErrImagePull" errors
- Authentication failures to registry

**Solutions:**

1. **Check image name and tag:**
   ```bash
   # Verify image exists
   docker pull your-registry.com/ldap-user-sync:v1.0.0
   ```

2. **Create image pull secret:**
   ```bash
   kubectl create secret docker-registry registry-credentials \
     --docker-server=your-registry.com \
     --docker-username=username \
     --docker-password=password \
     --docker-email=email@company.com
   ```

3. **Add image pull secret to deployment:**
   ```yaml
   spec:
     imagePullSecrets:
     - name: registry-credentials
   ```

### Issue: Pod Crashes or Restarts

**Symptoms:**
- CrashLoopBackOff status
- Pod restarts repeatedly
- Exit code 1 or other error codes

**Solutions:**

1. **Check pod logs:**
   ```bash
   kubectl logs <pod-name> -n ldap-user-sync
   kubectl logs <pod-name> -n ldap-user-sync --previous
   ```

2. **Check resource limits:**
   ```bash
   kubectl describe pod <pod-name> -n ldap-user-sync
   kubectl top pod <pod-name> -n ldap-user-sync
   ```

3. **Increase resource limits:**
   ```yaml
   resources:
     requests:
       memory: "256Mi"
       cpu: "200m"
     limits:
       memory: "1Gi"
       cpu: "1000m"
   ```

4. **Debug with shell access:**
   ```bash
   kubectl exec -it <pod-name> -n ldap-user-sync -- /bin/bash
   ```

### Issue: ConfigMap or Secret Not Mounted

**Symptoms:**
- Configuration file not found
- Environment variables not set
- Permission denied errors

**Solutions:**

1. **Verify ConfigMap exists:**
   ```bash
   kubectl get configmap ldap-sync-config -n ldap-user-sync -o yaml
   ```

2. **Check volume mounts:**
   ```yaml
   volumeMounts:
   - name: config
     mountPath: /app/config
     readOnly: true
   volumes:
   - name: config
     configMap:
       name: ldap-sync-config
   ```

3. **Verify Secret exists:**
   ```bash
   kubectl get secret ldap-sync-secrets -n ldap-user-sync
   kubectl describe secret ldap-sync-secrets -n ldap-user-sync
   ```

## Performance Issues

### Issue: Slow LDAP Queries

**Symptoms:**
- Long sync execution times
- LDAP query timeouts
- High memory usage

**Solutions:**

1. **Optimize LDAP filters:**
   ```yaml
   ldap:
     user_filter: "(&(objectClass=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
   ```

2. **Limit attributes retrieved:**
   ```yaml
   ldap:
     attributes: ["cn", "givenName", "sn", "mail", "sAMAccountName"]  # Only required fields
   ```

3. **Implement pagination:**
   ```python
   def get_group_members_paged(self, group_dn, page_size=1000):
       all_members = []
       cookie = None
       
       while True:
           response = self.connection.search(
               search_base=group_dn,
               search_filter='(objectClass=*)',
               attributes=['member'],
               paged_size=page_size,
               paged_cookie=cookie
           )
           
           # Process results
           members = self.connection.response
           all_members.extend(members)
           
           cookie = self.connection.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
           if not cookie:
               break
       
       return all_members
   ```

### Issue: High Memory Usage

**Symptoms:**
- Pod killed due to memory limits
- Out of memory errors
- Slow garbage collection

**Solutions:**

1. **Process users in batches:**
   ```python
   def sync_users_batched(self, users, batch_size=100):
       for i in range(0, len(users), batch_size):
           batch = users[i:i+batch_size]
           self.process_user_batch(batch)
           # Force garbage collection
           import gc
           gc.collect()
   ```

2. **Use generators instead of lists:**
   ```python
   def get_users_generator(self, group_dn):
       for entry in self.connection.extend.standard.paged_search(
           search_base=group_dn,
           search_filter='(objectClass=person)',
           attributes=['cn', 'mail'],
           paged_size=100
       ):
           yield entry
   ```

3. **Increase memory limits:**
   ```yaml
   resources:
     limits:
       memory: "2Gi"  # Increase from default
   ```

## Email Notification Issues

### Issue: SMTP Authentication Failed

**Symptoms:**
- "Authentication failed" in email logs
- Emails not being sent
- SMTP connection errors

**Solutions:**

1. **Verify SMTP credentials:**
   ```bash
   # Test SMTP connection
   telnet smtp.company.com 587
   ```

2. **Check TLS settings:**
   ```yaml
   notifications:
     smtp_server: "smtp.company.com"
     smtp_port: 587
     smtp_tls: true  # Use STARTTLS
     # Or for SSL:
     # smtp_port: 465
     # smtp_ssl: true
   ```

3. **Test with manual SMTP:**
   ```python
   import smtplib
   
   smtp = smtplib.SMTP('smtp.company.com', 587)
   smtp.starttls()
   smtp.login('username', 'password')
   smtp.quit()
   ```

### Issue: Emails Not Delivered

**Symptoms:**
- No error messages but emails not received
- Emails in spam folder
- Delivery delays

**Solutions:**

1. **Check email format:**
   ```yaml
   notifications:
     email_from: "LDAP Sync <noreply@company.com>"  # Proper format
     email_to:
       - "admin@company.com"  # Valid email addresses
   ```

2. **Add SPF/DKIM records:**
   ```dns
   # Add to DNS
   company.com. IN TXT "v=spf1 include:_spf.smtp-provider.com ~all"
   ```

3. **Check firewall rules:**
   ```bash
   # Test SMTP connectivity
   nc -zv smtp.company.com 587
   ```

## Log Analysis and Debugging

### Common Log Patterns

1. **Successful sync:**
   ```
   2024-01-15 10:00:01 [INFO] Starting LDAP sync process
   2024-01-15 10:00:02 [INFO] Connected to LDAP server: ldap.company.com
   2024-01-15 10:00:03 [INFO] Processing vendor: BusinessApp
   2024-01-15 10:00:05 [INFO] Group sync completed: 5 added, 2 removed, 3 updated
   2024-01-15 10:00:06 [INFO] Sync process completed successfully
   ```

2. **LDAP connection failure:**
   ```
   2024-01-15 10:00:01 [ERROR] Failed to connect to LDAP server: ldap.company.com
   2024-01-15 10:00:01 [ERROR] Connection timeout after 30 seconds
   2024-01-15 10:00:01 [ERROR] Sending notification email to administrators
   ```

3. **Vendor API errors:**
   ```
   2024-01-15 10:00:03 [WARNING] Vendor API error: 429 Too Many Requests
   2024-01-15 10:00:03 [INFO] Retrying in 10 seconds (attempt 1/3)
   2024-01-15 10:00:13 [INFO] Retry successful
   ```

### Log Analysis Commands

```bash
# Find error patterns
grep -i error logs/ldap_sync.log | tail -20

# Count sync operations
grep -c "added\|removed\|updated" logs/ldap_sync.log

# Check for failed authentications
grep -i "authentication failed\|invalid credentials" logs/ldap_sync.log

# Monitor real-time logs
tail -f logs/ldap_sync.log | grep -i "error\|warning"

# Extract performance metrics
grep "sync completed" logs/ldap_sync.log | awk '{print $1, $2, $NF}'
```

## Recovery Procedures

### Recover from Failed Sync

1. **Identify the issue:**
   ```bash
   # Check last sync status
   tail -50 logs/ldap_sync.log | grep -E "(ERROR|completed)"
   ```

2. **Fix configuration if needed:**
   ```bash
   # Validate configuration
   python -m ldap_sync.config --validate config.yaml
   ```

3. **Manual sync verification:**
   ```bash
   # Run in dry-run mode (if implemented)
   python -m ldap_sync.main --dry-run --config config.yaml
   ```

### Data Consistency Check

```python
# Example script to verify sync state
def verify_sync_state():
    ldap_users = get_ldap_group_members('CN=App_Users,OU=Groups,DC=company,DC=com')
    vendor_users = get_vendor_group_members('users')
    
    ldap_emails = {user['email'] for user in ldap_users}
    vendor_emails = {user['email'] for user in vendor_users}
    
    missing_in_vendor = ldap_emails - vendor_emails
    extra_in_vendor = vendor_emails - ldap_emails
    
    print(f"Users missing in vendor: {len(missing_in_vendor)}")
    print(f"Extra users in vendor: {len(extra_in_vendor)}")
    
    return missing_in_vendor, extra_in_vendor
```

## Getting Help

### Collecting Diagnostic Information

When reporting issues, collect the following:

1. **Application logs:**
   ```bash
   # Recent logs
   tail -500 logs/ldap_sync.log > diagnostic-logs.txt
   ```

2. **Configuration (sanitized):**
   ```bash
   # Remove sensitive data before sharing
   sed 's/password: .*/password: "***"/' config.yaml > diagnostic-config.yaml
   ```

3. **Environment information:**
   ```bash
   # System info
   kubectl version
   docker version
   python --version
   
   # Pod information
   kubectl describe pod <pod-name> -n ldap-user-sync > pod-info.txt
   ```

4. **Network connectivity tests:**
   ```bash
   # Test external connectivity
   nslookup ldap.company.com > connectivity-test.txt
   curl -I https://api.vendor.com/health >> connectivity-test.txt
   ```

### Support Channels

- **Internal Documentation**: Check CLAUDE.md for project-specific guidance
- **Logs Analysis**: Use centralized logging system if available
- **Team Communication**: Contact the development/operations team
- **Vendor Support**: Contact vendor technical support for API issues

### Escalation Procedures

1. **Level 1**: Check this troubleshooting guide
2. **Level 2**: Consult team documentation and run books
3. **Level 3**: Engage development team for code issues
4. **Level 4**: Contact vendor support for API-related problems
5. **Level 5**: Escalate to infrastructure team for platform issues