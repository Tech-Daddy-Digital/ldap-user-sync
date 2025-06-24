# Python Application for LDAP to Vendor Application User Sync – Specifications

## Overview and Purpose

This specification describes a Python application (PA) designed to **synchronize user accounts and group memberships** between an LDAP directory and one or more external Vendor Application (VA) systems via their REST APIs. The goal is to ensure that user information and group membership in each vendor application stay consistent with the authoritative LDAP source. The PA will run as an automated job (manually triggered during development, and on a schedule in production via a container/cron deployment) to perform the following for each configured LDAP group and corresponding vendor application group:

* Retrieve the list of users (and relevant attributes) from an LDAP group.
* Retrieve the list of users (and their details) from the corresponding group in the vendor application via REST API.
* **Compare** these lists to identify discrepancies:

  * Users present in the vendor app group but **not in LDAP** – these will be removed from the vendor app group.
  * Users present in the LDAP group but **not in the vendor app** – these will be added to the vendor app (and placed in the correct group).
  * Users present in both, but with **out-of-date attributes** – their attributes (first name, last name, email, etc.) will be updated in the vendor app to match LDAP.
* Repeat the above for multiple group mappings (if configured).
* Support **multiple vendor applications** in one run – the PA can sync several vendor systems sequentially, according to configuration.
* Provide robust logging, error handling, and notifications:

  * Log all actions and changes for audit and debugging, with log rotation and retention.
  * Gracefully handle connection issues with retries, and send email alerts if a system is down or if multiple errors occur.
* Be extensible to support new vendor application types with minimal changes to the core code (plug-in modular architecture).

**Key objectives:** Automate user provisioning/deprovisioning and profile updates across systems, minimize manual admin work, and maintain consistency between LDAP and various applications.

## Functional Requirements

* **LDAP Integration:** Use the `ldap3` library to connect to the LDAP server and query user group memberships. The PA should be able to bind to LDAP (using configured credentials) and fetch:

  * Members of a given group (or multiple groups) in LDAP.
  * For each member, retrieve attributes like first name, last name, email, and any identifier needed to match with the vendor app (e.g. username or email).
* **Vendor API Integration:** Connect to each Vendor Application’s REST API (over HTTPS) to manage users. The PA should:

  * Retrieve the list of users (and their details) in a specified group/role on the vendor side.
  * Add a new user to the vendor app group (if they exist in LDAP but not in vendor).
  * Remove a user from the vendor app group (if they are not in the corresponding LDAP group).
  * Update an existing user’s profile information in the vendor app (if attributes differ from LDAP).
* **One-to-One Group Mapping:** Support configuration of multiple LDAP groups to corresponding vendor application groups. Each mapping defines which LDAP group maps to which vendor group. The sync logic ensures that for each mapping, the membership is mirrored:

  * **Adding users:** If a user is found in the LDAP group but not in the vendor’s group, the user will be created/added in the vendor app **and** assigned to that group.
  * **Removing users:** If a user is in the vendor app’s group but is no longer in the LDAP group, remove that user’s membership from the vendor group. (If the user is not a member of any mapped LDAP group, they should ultimately have no corresponding group memberships in the vendor system. However, the system will not delete the user’s account entirely unless specified – it will just remove group memberships. The vendor app may handle an account with no groups as an inactive or limited account.)
  * **Updating users:** For users present in both, compare their **first name**, **last name**, and **email** (and any other mapped fields). If any differences are found, call the vendor API to update those fields to match LDAP. This ensures profile data is up-to-date.
  * **Multiple group memberships:** If a user belongs to multiple configured LDAP groups, the PA should ensure the user has the corresponding multiple group memberships in the vendor app. Users can have more than one group in the vendor system if the LDAP data indicates so. The PA will handle each group mapping separately; a user appearing in multiple groups will be processed in each relevant group sync. (The design will avoid removing a user from a vendor group if they still belong to that group’s corresponding LDAP group. Each group mapping is handled independently to reflect the LDAP state for that group.)
* **Multiple Vendor Application Support:** The application should be able to sync with **multiple vendor applications** in one execution. For example, if two different systems (e.g., “App1” and “App2”) need LDAP sync, the PA will handle each in turn. Configuration will allow defining multiple vendor app entries (each with its own connection info, auth, and group mappings). The core logic will iterate through each configured vendor and perform the sync. The design must be modular so that adding support for a new vendor application requires **adding a new module/plugin** for that vendor’s API integration, and minimal or no changes to the main synchronization code.
* **Authentication to APIs:** Support various authentication methods for connecting to vendor REST APIs, in a **configurable** manner:

  * **Basic Auth:** (current use-case) Use HTTP Basic Authentication with username and password supplied in config (the PA will encode credentials and include in the Authorization header for each request).
  * **Bearer/API Token:** Allow using an API token or bearer token if provided (e.g., include a static token in headers).
  * **OAuth2:** Design the system to accommodate OAuth2 or other common auth flows in the future. For example, for OAuth2 Client Credentials flow, the config might include token endpoint, client ID/secret, etc., and the PA could retrieve and refresh a token. *(Full OAuth implementation can be a future enhancement, but the design will not preclude it.)*
  * **Mutual TLS (Client Certificate):** Potentially support client certificate authentication if a vendor requires it. This would involve providing a client certificate and private key (e.g., via a PKCS#12 file) to establish the HTTPS connection.
  * The authentication method for each vendor app will be specified in configuration, and the PA will handle the low-level details accordingly.
* **Data Format (JSON/XML):** The PA should be able to communicate with vendor APIs using JSON or XML as needed. Ideally this is configurable per vendor or per API endpoint:

  * For modern REST APIs using JSON, the PA will send requests with JSON payloads and parse JSON responses.
  * If an API uses XML (SOAP or XML-based REST), the PA should be capable of constructing XML requests and parsing XML responses. This can be toggled by a config setting (e.g., `response_format: "json"` or `"xml"` for the vendor).
  * The internal logic or vendor module will handle parsing the appropriate format. (If needed, use Python’s `json` library for JSON and `xml.etree.ElementTree` or similar for XML.)
* **Configurability:** The application’s behavior should be driven by a configuration file or parameters, so it can be adapted without code changes. Configuration should cover:

  * LDAP connection details (server URL, port, use of SSL, bind DN, password, base DN for searches, etc.).
  * The list of group mappings (LDAP group DN or name -> vendor app group identifier) for each vendor.
  * Vendor API connection details (base URL, authentication info, any required headers).
  * Logging settings (log level, log file location, retention).
  * Retry and timeout settings for network calls.
  * Notification settings (email server, recipients).
  * SSL certificate and truststore details for secure connections.
* **Logging:** Implement robust logging for transparency and debugging:

  * All major actions (e.g., connecting to LDAP, connecting to vendor, adding a user, removing a user, updating a user, any errors) should be logged with appropriate severity (INFO for normal ops, WARN for recoverable issues, ERROR for failures).
  * Logs should be written to files in a `logs/` subdirectory by default.
  * Implement **log rotation**: create a new logfile each day at midnight, and archive the old logs. Logs older than a certain number of days (configurable, e.g., X days) should be automatically deleted or not kept (to avoid unlimited growth). For example, keep the last 7 days of logs by default.
  * The log level (e.g., DEBUG, INFO, WARN, ERROR) should be configurable. In debug mode, include detailed information (like API request/response summaries, etc., but be careful not to log sensitive info like passwords).
  * Log format should include timestamps and context to make it human-readable and easy to follow.
* **Error Handling and Resilience:** The application should be resilient to failures and not abort on single errors:

  * **Connection failures:** If the LDAP server or a vendor API is temporarily unreachable or returns an authentication error, the PA should implement a **retry mechanism**. The number of retries and wait interval between retries should be configurable. For example, if a vendor API call fails due to network error or 5xx status, retry up to N times with a M-second delay.
  * If after all retries a critical connection cannot be established (e.g., LDAP down or vendor API down), the PA should log an ERROR and optionally **send an email notification** to alert administrators of the outage. It should then safely stop processing that particular sync (e.g., skip that vendor or exit if LDAP is completely down), rather than continuing in a faulty state.
  * **Data operation failures:** If an attempt to add/update/remove a specific user fails (e.g., vendor API returns an error for that user operation), the error should be caught and logged, but the PA should continue processing the remaining users. These individual failures should not crash the whole application.
  * However, if **multiple such data failures** occur in one vendor’s sync (indicating a systemic issue, like the API is consistently rejecting updates), the PA should detect this. If the number of errors in one vendor sync exceeds a threshold (configurable, e.g., more than X failures), the PA should:

    * Log a critical error that the sync for that vendor encountered many failures.
    * Optionally send an email notification summarizing the issue (e.g., “Vendor XYZ sync encountered 10 errors, aborting.”).
    * Abort further processing for that vendor (skip remaining operations for it) to avoid thrashing, then move on to the next vendor (if any).
* **Notifications:** Integrate an email notification system for important events (using SMTP):

  * On **total failure** of a sync cycle or a critical part (like unable to connect to a vendor after retries, or LDAP query fails, etc.), send an alert email to a configured recipient list. The email should include which system failed and basic error info (for example, “LDAP to VendorA sync failed: LDAP server not reachable” or “VendorB API authentication failed – sync aborted”).
  * On **partial failures** where a vendor sync had to be aborted due to repeated errors, send a notification email about that event.
  * (Optional/future) The system could also send summary emails on successful sync (e.g., number of users added/removed/updated), but this is not a primary requirement now. For now, focus on failure notifications.
  * Email settings (SMTP server, port, sender, recipients, credentials if needed) should be in config. The email sending should be done in a safe way (catch exceptions from the SMTP library and log errors if email fails, to not crash the app).

## Non-Functional Requirements and Considerations

* **Extensibility:** The codebase should be organized to allow easy addition of new vendor integrations. This implies:

  * Use a plugin/module architecture for vendor-specific logic. The main application should not need to be heavily modified to add a new vendor; instead, one can drop in a new module (or class) that knows how to talk to that vendor’s API.
  * The PA will discover or import vendor modules based on configuration. For example, the config for a vendor might include a `"type"` or `"module"` identifier that corresponds to a Python module or class name. The main program will use this to dynamically load the appropriate module.
  * Define a clear interface that each vendor module must implement (e.g., methods like `get_users(group)`, `add_user(group, user_info)`, `remove_user(group, user_id)`, `update_user(group, user_info)` etc.), so the main sync logic can call these generically.
* **Security:**

  * Credentials for LDAP and vendor APIs should be handled securely. They will be provided via configuration (which might be a file or environment variables). In a container environment, sensitive values (like passwords, API keys) might be injected via environment or Kubernetes secrets. The PA should be able to read these without exposing them (e.g., do not print passwords in logs).
  * When writing logs, avoid dumping sensitive data (no plain-text passwords or secrets). If including request details, scrub authorization headers or tokens.
  * Use TLS for all network connections: LDAP over LDAPS or StartTLS if possible, and HTTPS for vendor APIs. Certificate verification should be enabled by default (unless explicitly disabled in config for testing).
  * Provide options for custom certificate trust: if corporate CAs or self-signed certs are used, allow specifying truststore files.
* **Configuration Management:** The application should be configured externally so that no code changes are needed for different environments:

  * During development, a simple config file (YAML or JSON) can be used to specify all needed parameters.
  * In production (containerized via Helm chart), the config can be passed in through environment variables or a mounted file. The PA should support both methods if possible. For example, it might load a YAML config file by default, but any config key could be overridden by an environment variable (this can be achieved by reading env vars and replacing config values accordingly).
  * The configuration format should be human-readable and allow complex structures (since we have multiple nested settings). **YAML** is a good choice for clarity, but JSON or even a Python .ini file could also work. We will proceed assuming YAML for examples (since Helm integrates well with YAML).
  * The app must validate the config at startup and ensure required fields are present (e.g., at least one vendor configured, LDAP settings present, etc.).
* **Performance:** This tool is expected to handle moderate volumes of users (likely dozens to hundreds per group, possibly thousands in large cases). It is not intended for real-time syncing but rather periodic batch runs (e.g., daily or hourly). As such:

  * A straightforward sequential processing is acceptable. There is no immediate need for multi-threading or async, though the design shouldn’t preclude adding concurrency for performance if needed in future.
  * Network calls and LDAP queries should be optimized where possible (e.g., use LDAP filters to only retrieve needed attributes, handle pagination if a group has extremely many members, etc.).
  * The application will likely run as a short-lived process (especially if invoked by cron or a K8s CronJob), so any memory used will be freed on exit. Just ensure no significant memory leaks and clean up connections (close LDAP connection, etc., at end of run).
* **Deployment:** Ultimately, this application will run inside a container (Docker) in a Kubernetes environment. Some deployment considerations:

  * The app should be packaged with all its dependencies (e.g., via a Dockerfile that installs `ldap3` and any other required libraries).
  * The configuration can be supplied via a ConfigMap or environment variables in the Helm chart. Ensure the app can easily consume those (for example, mount a config file to a known path inside the container, or set environment variables like `LDAP_SERVER`, `VA1_URL`, etc.).
  * For scheduling, using a Kubernetes CronJob to run the container periodically might be preferable. Alternatively, the container could run as a persistent service with an internal scheduler (like a sleep loop or using a scheduling library to trigger sync). This detail can be decided later; the app itself will simply perform a sync on each invocation. It should **exit gracefully** after completing a sync if not running continuously.

With the above requirements in mind, the next sections detail the design and the steps to implement this system.

## System Design and Architecture

### High-Level Workflow

1. **Startup & Configuration Load:** When the PA starts, it will load configuration from a file (e.g., `config.yaml`) or environment. It verifies that necessary settings (LDAP server, at least one vendor config, etc.) are present. It also configures logging according to the settings (creating log directory/handlers, setting log level).
2. **Initialize Connections:**

   * Establish connection to the LDAP server (bind using credentials from config). If the LDAP connection fails, the process will retry a few times. On persistent failure, log an error and send notification email, then abort the run.
   * For each vendor application configured, prepare any needed connection details. For example, no actual connection may be needed upfront if using HTTP Basic (each API call will include auth), but if a token or session is needed (OAuth2 or login call), perform that to obtain a token. Also, set up SSL context with appropriate certificates if needed for that vendor.
3. **Synchronization Loop:** For each **vendor application** (one by one):

   * Load or instantiate the vendor’s integration module/class. (The system will use the config’s `type` or `module` field to determine which module to load. For example, a config might specify `module: "vendor_x"` which corresponds to a Python module file `vendors/vendor_x.py` implementing the required interface. The PA uses Python’s importlib to import it.)
   * Within the vendor, iterate over each **group mapping** defined for that vendor:

     * Query LDAP for the members of the specified LDAP group (the LDAP group DN or name is given in config). Retrieve a list of user entries (with attributes like name and email). This could be done by:

       * Using `Connection.search()` in ldap3 on the group DN to get the `member` attribute (which yields user DNs), then fetching each user entry, **or**
       * Searching for all user entries that have `memberOf = <group DN>` (especially if using Active Directory, which automatically populates memberOf on user objects), retrieving the needed attributes in one go.
       * The attributes retrieved should include those needed for comparison and for adding to vendor: likely the user's unique identifier (sAMAccountName or uid), first name (givenName or cn), last name (sn), and email (mail). These attribute names may be configurable if using a non-AD LDAP schema.
       * Store the LDAP user list (e.g., as a dictionary keyed by username or email for quick lookup, containing attribute values).
     * Query the vendor application (via the vendor module’s API client) for the list of users in the corresponding vendor group. Likely the vendor API provides an endpoint like “List users in group X” or a way to filter users by group. The vendor module will handle this detail and return a list of users (with their attributes) from the vendor.

       * Each user from vendor should include at least an identifier (username or email) and the same fields (first name, last name, email) for comparison.
       * The vendor module might need to call different endpoints, e.g., one to list group members and possibly additional calls to get user details if not all info is returned. This is encapsulated in the module.
     * Compare the two sets of users:

       * Determine the set of **users to remove** from the vendor group: those present in the vendor’s list but not in the LDAP list. (These are accounts that likely should no longer have access because they’re no longer in the LDAP group.)
       * Determine the set of **users to add**: those in the LDAP group but missing in the vendor group.
       * Determine the set of **users to update**: those that exist in both lists but have mismatched attributes. For each such user, identify which fields differ (first name, last name, email) and prepare an update.
     * Execute the synchronization actions:

       * For each user to remove: call the vendor module’s `remove_user_from_group` (or equivalent) to remove that user’s membership. This could be a DELETE request or similar via the vendor’s API. If the vendor API only supports removing the user entirely or removing their group membership, handle accordingly (preferably just remove group membership).

         * Log each removal (INFO level).
         * If a removal fails (API error), log a WARN/ERROR. Continue to next user.
       * For each user to add: call the vendor module’s `add_user_to_group` or user creation method. This might involve two steps if the vendor distinguishes user creation and group assignment:

         * If the user doesn’t exist at all in vendor, create a new user with the required attributes (via API). Then add/assign them to the group.
         * If the vendor’s API allows adding by just specifying the group and some user identifier, that might implicitly create the user (not likely, but possible).
         * Provide all necessary attributes from LDAP when creating the user (e.g., name and email). If the vendor requires additional fields, the config or module may supply defaults or mappings.
         * Log each addition.
         * If an addition fails, log the error and continue.
       * For each user to update: call the vendor module’s `update_user` method to modify the user’s profile in the vendor system. Provide the changed fields. E.g., if the user got married and last name changed in LDAP, update last name in vendor; or if email updated, etc.

         * If the vendor API doesn’t have a specific “update user” but has separate calls (like one for name, one for email), the module will abstract that.
         * Log each update along with which fields were changed.
         * If an update fails, log the error and continue.
     * After processing adds/removes/updates for the group, you may want to double-check or log the final state (e.g., "After sync, VendorX Group Y members count = Z").
   * Proceed to the next group mapping for the same vendor and repeat the above steps. Each group is handled independently.
   * If any serious errors occurred that caused an abort of this vendor’s processing (as per the error handling rules), skip the remaining groups for this vendor and proceed to the next vendor.
   * Ensure any resources for this vendor are cleaned up if needed (e.g., if the vendor module held an open session or token, it can be closed or invalidated if necessary).
4. **Completion:** After all vendors have been processed, close the LDAP connection (if still open) and flush/close log files. If running as a one-off job, exit. If running as a service with schedule, sleep until next cycle or end as appropriate.
5. Throughout the process, the application should track counts of actions (e.g., X users added, Y removed, Z updated for each group) and include these in logs. If configured, send out any required email notifications for errors encountered.
6. The next run (if scheduled) will repeat the process, picking up any new changes since the last run.

### Component Design

To achieve the above, the application will be structured into modular components:

* **Configuration Loader:** A module that knows how to read the configuration (YAML/JSON file, or environment variables) and produce a structured config object or dictionary that other components can use. This will also handle defaults and validation (e.g., ensure mandatory fields are present).
* **LDAP Connector (ldap\_client):** A module responsible for connecting to LDAP and performing queries:

  * It will utilize `ldap3` to connect using the provided server URI (LDAP or LDAPS), bind DN and password. It should support StartTLS or LDAPS if specified.
  * Provide a function to get members of a given group DN. Possibly provide two functions or a parameter to either:

    * Get all user DNs in the group (by reading the group’s member attribute), then fetch attributes of those users.
    * Or query directly for user entries with memberOf = group.
  * Return the list of user data (maybe as a list of dicts or a dict mapping a user key to attributes).
  * This module can also abstract paging if needed (the `ldap3` library supports paging for large results).
* **Vendor Base Interface:** Define an abstract base class or interface (could be just a documented expected set of functions) for vendor integration modules. For example, define a class `VendorAPIBase` in a core module with methods like:

  * `authenticate()` (if needed) – to perform any login or token retrieval. Could be a no-op for basic auth.
  * `get_group_members(group_cfg)` – returns list of users in the specified group (the group\_cfg could contain the vendor group identifier).
  * `add_user_to_group(group_cfg, user_info)` – ensure a user represented by `user_info` (which could contain username and attributes) exists in the vendor and assign them to the group.
  * `remove_user_from_group(group_cfg, user_identifier)` – remove the user (identified by username or ID) from that group.
  * `update_user(user_identifier, user_info)` – update the user’s profile attributes.
  * Optionally, separate `create_user(user_info)` and `assign_user_to_group(group, user)` if needed, or have `add_user_to_group` internally handle both creation and assignment.
  * The base class can provide common utilities, e.g., an HTTP client wrapper using Python’s `http.client` (or `urllib`) to make GET/POST/PUT/DELETE calls with the appropriate base URL and authentication headers. It can also handle switching between JSON or XML based on config, and setting up SSL contexts.
* **Vendor Modules:** For each vendor application type, implement a module (or class) that extends the base interface and implements the specifics:

  * E.g., `vendors/vendorA.py` might define `class VendorAAPI(VendorAPIBase): ...` implementing those methods for Vendor A’s API endpoints and data formats.
  * The module can be designed to be initialized with the vendor-specific config (like API URL, credentials, group mappings, etc.).
  * It will know the endpoint URLs and payload formats for that vendor.
  * For example, VendorAAPI.get\_group\_members might call an endpoint like `GET /api/groups/{group_id}/members` and return a list of user dicts. VendorBAPI might have a different endpoint or require first getting group ID by name, etc.
  * Each vendor module handles its own authentication method: if basic auth, perhaps the base class covers it by always sending a header. If a token is needed, the module might implement authenticate() to fetch and store a token, and the base class’s HTTP methods could use it.
* **Sync Orchestrator (main logic):** The core of the application that ties everything together. This could be in a `main.py` script or a `SyncManager` class:

  * It loads the config, sets up logging.
  * Instantiates the LDAP connector and verifies LDAP connectivity.
  * Iterates over each vendor configuration, loads the appropriate vendor module/class (for example via `importlib.import_module` using a module name from config, or a factory that maps a vendor type to its class).
  * For each vendor, calls its methods to get group members and perform syncing as described in the workflow.
  * Uses the LDAP connector to get LDAP members for each group.
  * Contains the logic for comparing lists and determining adds/removes/updates.
  * Handles exceptions and errors around those calls: implementing retries where needed (for example, wrap network calls in a retry loop).
  * Calls the notification module if needed on error conditions.
* **Logging Component:** While Python’s built-in logging can be configured directly in the main script, we might have a small utility or just configure it in code:

  * Use `logging` module with `logging.FileHandler` or `TimedRotatingFileHandler` for rotation. For example, configure one handler that rotates at midnight and keeps X days of backups.
  * Ensure the log directory exists or create it at startup.
  * Possibly have separate loggers for different parts (LDAP vs vendor), or just use one logger with contextual messages.
  * This can be configured in a function e.g., `setup_logging(config)`.
* **Notification/Email Utility:** A small module or function to send emails using `smtplib`:

  * Reads SMTP server details and credentials from config.
  * Composes an email (subject, body) given an event or error details.
  * Sends it to the recipients. Use TLS if required by SMTP config.
  * To be used by the main logic when a notification condition is met.
* **Certificate/SSL Handling:**

  * If custom truststore or keystore is specified in config, the application should load these for HTTPS connections to vendor APIs.
  * Use Python’s `ssl` module to create an `SSLContext`. For **PKCS#12** or **JKS** files: Python doesn’t natively read those formats for trust stores, so the strategy will be:

    * For a **JKS** truststore: use a library like `pyjks` to load the JKS file, extract the certificates, and then use `SSLContext.load_verify_locations()` with a temporary PEM file or the certificate data. Alternatively, require the JKS to be converted to PEM beforehand (could be done as part of deploying config).
    * For a **PKCS#12** file containing CA certificates or client cert: use the `ssl` module’s `load_cert_chain` if it’s a client cert (though that typically expects PEM, not PKCS12). We might need to use `OpenSSL.crypto` or `cryptography` library to load a .p12, then use an SSLContext with `load_cert_chain` (for client cert) and `load_verify_locations` (for CA cert).
    * Make the certificate usage configurable: e.g., config could have fields `cert_file` (path to client cert PEM or PKCS12), `cert_file_password`, `truststore_file` (path to CA bundle or JKS), `truststore_password`, etc.
    * The default if none specified is to use the system CA certificates (i.e., default verification) unless verification is turned off (config `verify_ssl: false`).
  * Implementing full JKS/PKCS12 support is complex but the design acknowledges it. Initially, it might be acceptable to require conversion to PEM, but since the requirement explicitly mentions them, we’ll account for it by using appropriate libraries or documentation on how to handle them.

### Configuration Structure

Below is an example of how the configuration might be structured (using YAML for clarity). This covers all necessary settings:

```yaml
# LDAP server configuration
ldap:
  server_url: "ldaps://ldap.example.com:636"    # LDAP URL (use ldaps:// for SSL)
  bind_dn: "CN=Service Account,OU=Users,DC=example,DC=com"  # Bind (service account) DN
  bind_password: "supersecret"   # Password for the bind DN (could be injected via env)
  user_base_dn: "OU=Users,DC=example,DC=com"    # Base DN where user accounts reside (for searching)
  # Optionally, filters or attributes to retrieve
  user_filter: "(objectClass=person)"          # Base filter for users (will be combined with group membership filter)
  attributes: ["cn", "givenName", "sn", "mail", "sAMAccountName"]  # Attributes to fetch for users
  # If using memberOf search strategy, no need for group search base, else:
  group_dn_map: {}   # (Not needed if group DNs are provided directly in mappings below)
  
# Vendor applications configuration
vendor_apps:
  - name: "VendorApp1"
    module: "vendor_app1"      # Python module or type identifier for this vendor's API integration
    base_url: "https://api.vendorapp1.com/v1"   # Base URL for API
    auth:
      method: "basic" 
      username: "api_user1"
      password: "api_password1"
      # method could also be "token" or "oauth2" with respective fields (e.g., token value or oauth details)
    format: "json"             # Data format for API (json or xml)
    verify_ssl: true           # Whether to verify SSL certs
    # truststore/keystore settings (if custom certs are needed)
    truststore_file: "/path/to/truststore.jks"
    truststore_password: "changeit"
    truststore_type: "JKS"     # or "PKCS12" or "PEM"
    # If client auth needed
    keystore_file: "/path/to/client_cert.p12"
    keystore_password: "pkcs12-password"
    keystore_type: "PKCS12"
    # Group mappings for this vendor
    groups:
      - ldap_group: "CN=App1_Basic_Users,OU=Groups,DC=example,DC=com"
        vendor_group: "basic_users"   # could be an ID or name as needed by API
      - ldap_group: "CN=App1_Admins,OU=Groups,DC=example,DC=com"
        vendor_group: "admins"
      
  - name: "VendorApp2"
    module: "vendor_app2"
    base_url: "https://api.vendorapp2.com/rest"
    auth:
      method: "token"
      token: "abcdef1234567890"    # use this token in Authorization header
    format: "xml"
    verify_ssl: true
    groups:
      - ldap_group: "CN=App2_Users,OU=Groups,DC=example,DC=com"
        vendor_group: "App2UsersGroupID123"
        
# Logging configuration
logging:
  level: "INFO"
  log_dir: "logs"
  rotation: "daily"       # or could be "midnight" meaning daily rotation
  retention_days: 7       # keep logs for 7 days
  
# Error handling / Notifications
error_handling:
  max_retries: 3              # number of retries for connections/API calls
  retry_wait_seconds: 5       # wait 5 seconds between retries
  max_errors_per_vendor: 5    # if more than 5 errors occur in one vendor sync, abort it
notifications:
  enable_email: true
  email_on_failure: true
  email_on_success: false     # (could be used later for success summaries)
  smtp_server: "smtp.example.com"
  smtp_port: 587
  smtp_tls: true
  smtp_username: "alerts@example.com"
  smtp_password: "smtppass"
  email_from: "alerts@example.com"
  email_to: ["admin1@example.com", "admin2@example.com"]
```

*Note:* In a real deployment via Helm, these values might be populated from Kubernetes secrets or Helm values. The application could also support environment variable overrides like `LDAP_BIND_PASSWORD` to avoid putting sensitive passwords directly in a file. The config structure is flexible and can be adjusted as needed.

### Extensibility for New Vendors

To add a new vendor integration in the future, the expected steps would be:

* Write a new module in the `vendors/` package, implementing the necessary class with the required methods (following the interface of others). This includes handling that vendor’s auth, and the endpoints for listing users, adding, removing, updating.
* Add an entry in the configuration for the new vendor, with `module` name matching the new module, and any specific settings needed (auth, base\_url, etc.).
* The main application, which dynamically loads modules based on config, will automatically pick it up and attempt to use it. If the new module adheres to the interface, the core logic won’t need changes.
* This design minimizes changes to core code when integrating new systems.

### Logging and Monitoring

In addition to file logging, consider integrating with container logging best practices:

* The container could be configured to also output logs to stdout/stderr for cluster aggregation (depending on operational preference). The application can log to file and also echo critical messages to console.
* For monitoring, if this becomes critical, one could add metrics (count of changes, etc.) or health check endpoints if running continuously. Initially, not needed due to batch run nature.

## Detailed Implementation Plan (Task Breakdown)

Below is a comprehensive list of tasks and steps required to implement the Python application. This serves as a development to-do list and ensures every aspect of the specification is covered.

* [ ] **Project Setup and Structure**:

  * [ ] Initialize a new Python project (e.g., create a Git repository for the code).
  * [ ] Create a main package directory for the application, e.g., `ldap_sync/` (or another appropriate name).
  * [ ] Within this package, set up sub-modules:

    * [ ] `ldap_sync/config.py` – for configuration loading and management.
    * [ ] `ldap_sync/ldap_client.py` – for LDAP connectivity and queries.
    * [ ] `ldap_sync/vendors/` – a package to hold vendor integration modules (create an `__init__.py` and possibly base classes here).
    * [ ] `ldap_sync/vendors/base.py` – define the `VendorAPIBase` class (interface with default behaviors).
    * [ ] `ldap_sync/main.py` – the entry point script that orchestrates the sync process.
    * [ ] `ldap_sync/util/` (optional) – for utility modules like logging setup, email notifications, etc. (Or those can be in separate modules such as `ldap_sync/logging_setup.py`, `ldap_sync/notifications.py`).
  * [ ] Ensure the project can be installed or run easily (e.g., consider adding a `setup.py` or use as a module, though not strictly required if just running via Python).
  * [ ] Add a requirements file (`requirements.txt` or Pipfile) including needed libraries: `ldap3`, (and possibly `pyjks`, `cryptography` if handling PKCS12, etc., and maybe `PyYAML` for config if using YAML).

* [ ] **Configuration Management Implementation**:

  * [ ] Decide on the configuration file format (e.g., YAML for its readability). Install a parser like PyYAML if using YAML.
  * [ ] Implement `config.py` to load the config:

    * [ ] Write a function to read a config file (`config.yaml`) from the filesystem. (During development, use a path on disk; in container, this could be mounted at a known location or specified via env variable like `CONFIG_PATH`).
    * [ ] Parse the file into a Python dictionary or a custom Config class. If using YAML, use `yaml.safe_load`.
    * [ ] Implement validation of the config:

      * [ ] Ensure at least one vendor entry exists in `vendor_apps`. If none, log an error and exit.
      * [ ] Check that for each vendor in config, required fields like `name`, `module`, `base_url`, `auth.method`, and `groups` are provided.
      * [ ] Check LDAP config presence (server\_url, bind\_dn, etc.).
      * [ ] If any required field is missing or misconfigured, raise a clear error or exception.
    * [ ] Allow environment variable overrides: for example, if an env var `LDAP_BIND_PASSWORD` is set, use that over the value in file. Similarly handle other sensitive fields or possibly the entire config via env. This could be done by checking known env vars after loading file, or by using a library that merges env vars into config.

      * [ ] At minimum, implement override for passwords (LDAP and any vendor basic auth password, SMTP password) via env variables for security.
    * [ ] Support multiple vendor configurations as a list. The loader should produce structures like a list or dict of vendor configs that the main loop can iterate over.
    * [ ] If needed, also parse/normalize the group mappings (e.g., ensure LDAP group DNs are proper format, etc.).
  * [ ] Provide a way to specify config location (e.g., check an environment var or command-line argument for config path, default to `config.yaml`).
  * [ ] Test the config loader with a sample config to ensure it populates data structures correctly.

* [ ] **Logging Setup**:

  * [ ] Create a function (e.g., `setup_logging(config)`) in a utility module or in `main.py` before other operations.
  * [ ] In this function, use the Python `logging` module:

    * [ ] Determine the log directory from config (default “logs”). Ensure this directory exists (create it if not).
    * [ ] Set up a log filename pattern, e.g., `app.log` (for current log) which will be rotated. Optionally include date in filename if easier.
    * [ ] Use `logging.handlers.TimedRotatingFileHandler` for daily rotation:

      * [ ] Configure it to rotate at midnight each day (`when='midnight', interval=1`).
      * [ ] Set `backupCount` to the number of days to retain (from config, e.g., 7).
      * [ ] This will automatically manage old files (e.g., `app.log.2023-12-01`, etc., deleting those beyond 7 days).
    * [ ] Alternatively, implement manual deletion of files older than X days in the log directory (if not using `backupCount`).
    * [ ] Set the logging level from config (DEBUG/INFO/WARN/ERROR).
    * [ ] Define a format for log messages, e.g., `"%(asctime)s [%(levelname)s] %(name)s - %(message)s"`.
    * [ ] Attach the handler to the root logger (or a specific named logger for our app).
    * [ ] Also consider logging to console (stream handler) especially during development or if running in a container that doesn’t persist log files. Possibly send INFO+ to file and WARN+ to console. (This could be configurable.)
  * [ ] Ensure that after setup, using `logging.getLogger(__name__)` in modules will use this configuration. We might simply use the root logger for simplicity.
  * [ ] Test logging by outputting a startup message and verifying the file is created and rotates properly.

* [ ] **LDAP Integration Implementation**:

  * [ ] In `ldap_client.py`, implement an LDAPClient class (or simple functions) that will:

    * [ ] Initialize connection to LDAP in its constructor (or connect method). Use `ldap3.Server` and `ldap3.Connection`. For example:

      * [ ] Create `Server(config['ldap']['server_url'], use_ssl=True/False, ... )` depending on URL scheme or a config flag.
      * [ ] Create `Connection(server, user=config['ldap']['bind_dn'], password=config['ldap']['bind_password'], auto_bind=True)` inside a try/except.
      * [ ] If connection fails, log an ERROR. Implement retry logic here: for example, try up to `max_retries` times with a delay if `auto_bind` fails or connection not successful.
      * [ ] If still unable to bind after retries, raise an exception or return an error status to main (which will trigger email notification and stop the app).
    * [ ] Implement `get_group_members(ldap_group_dn)` method:

      * [ ] **Approach 1:** Use the group DN and search for its "member" attribute:

        * Perform `conn.search(search_base=ldap_group_dn, search_filter="(objectClass=groupOfNames)"` (filter might differ if using AD (objectClass=group) or other LDAP schema).
        * Request the "member" attribute in attributes list (or "\*" to get all, but better to limit).
        * If found, retrieve the `member` values – this will be a list of DNs of users.
        * For each user DN in that list, do another search or a `conn.search(base=user_dn, search_scope=BASE, attributes=[...])` to get the user’s attributes. (Alternatively, one could do a single search with `search_base=user_base_dn` and filter `(memberOf=group_dn)`.)
      * [ ] **Approach 2:** Use memberOf reverse lookup (works well in Active Directory):

        * Construct a search filter like `(&(memberOf={ldap_group_dn})(objectClass=person))` applied at some broader base (e.g., the `user_base_dn` from config or the domain base).
        * Use this filter to retrieve all user entries in that group in one query, requesting the needed attributes.
        * This can be more efficient if supported.
      * [ ] The implementation can choose based on config or try one approach. For AD, using memberOf is straightforward. For generic LDAP without memberOf, one must read the group’s member list.
      * [ ] Make sure to handle pagination if the results might exceed server’s limit (ldap3 can use `paged_size` parameter in search).
      * [ ] Return the results in a convenient structure: perhaps a dict mapping a unique key (like `sAMAccountName` or `uid` or email) to a dict of attributes. And/or a list of dicts.
      * [ ] Only include attributes specified (from config or defaults: first name, last name, email, etc.). For example, map `givenName` to first name, `sn` to last name.
      * [ ] If any LDAP query fails, handle exceptions (log error). Possibly retry once if a query fails due to a glitch.
    * [ ] Implement any cleanup needed, e.g., a method to close the connection (though ldap3 auto unbinds on delete of Connection, but explicit unbind is good).
  * [ ] Write unit tests or at least run the LDAP client functions against a test LDAP (if available) or mock, to ensure correctness of filter logic.

* [ ] **Vendor API Base Class** (`vendors/base.py`):

  * [ ] Define a class `VendorAPIBase` that other vendor classes will inherit from. Include common functionality:

    * [ ] `__init__(self, config)` – store common info like base URL, auth config, etc. Possibly set up an `http.client.HTTPSConnection` object here if reusing one connection (could also create new for each request; http.client allows keeping connection open for multiple requests which might be fine within one run).

      * [ ] If using a persistent `HTTPSConnection`, build it with host from base\_url. Alternatively, use Python’s `urllib.request` or `requests` equivalent using basic libs.
      * [ ] However, since we prefer `http.client`, perhaps use it directly: parse base URL to get host, and use `HTTPSConnection(host, context=ssl_context)` for SSL.
      * [ ] Create an `ssl.SSLContext` if needed: if `verify_ssl` is false, use `ssl._create_unverified_context()`. If truststore is provided, load it:

        * [ ] If truststore\_type is PEM, use `SSLContext.load_verify_locations(cafile=path)`.
        * [ ] If JKS, use `pyjks` to load and then create a CA file or directly add to context via `load_verify_locations(cadata=cert_data)`.
        * [ ] If PKCS12 for truststore, possibly convert P12 to PEM (maybe using `cryptography` to extract certs) then load.
        * [ ] If a client keystore (P12) is provided (with client cert and key), use `SSLContext.load_cert_chain()` with that (after extraction if needed, because `load_cert_chain` expects PEM files for cert and key – if given a .p12, need to break it into cert.pem and key.pem or use an alternate approach).
        * [ ] This is advanced; may implement a simplified approach first (e.g., require PEM) and note that full JKS/P12 support can be added with additional parsing.
      * [ ] Save the connection and context for use in requests.
      * [ ] Save auth details (username/password or token) for use when sending requests.
    * [ ] Authentication handling:

      * [ ] If `auth.method` is "basic", prepare an Authorization header value `Basic base64(username:password)`.
      * [ ] If "token", prepare `Authorization: Bearer <token>` or `Authorization: Token <token>` depending on convention (maybe allow specifying the header name or type in config if needed, but assume Bearer token).
      * [ ] If "oauth2", if a token URL and client creds are given, implement a method to fetch the token (this could be done in `authenticate()` method if called).
      * [ ] Store whatever headers or tokens needed for subsequent calls.
    * [ ] HTTP request helper:

      * [ ] Implement a method `request(method, path, body=None, headers=None)` that sends an HTTP request using `http.client`:

        * [ ] Ensure the connection is established (for `HTTPSConnection`, it connects on first request).
        * [ ] Build the full URL path (base path + given path if the base URL has some prefix).
        * [ ] If body is a dict and format is JSON, do `json.dumps` and set `Content-Type: application/json`. If format is XML and body is given maybe as an XML string or Element, ensure proper string and `Content-Type: application/xml`.
        * [ ] Always include an Authorization header as prepared from auth method (unless the call is to an auth endpoint).
        * [ ] If any other headers required (maybe some vendor needs API version header), allow passing them or define in config.
        * [ ] Call `self.http_conn.request(method, url, body, headers)` and then `getresponse()`.
        * [ ] Read the response data and status. If response is JSON, parse it via `json.loads`. If XML, parse via `ElementTree.fromstring` or similar.
        * [ ] Return the parsed data (and possibly status code).
        * [ ] If status indicates an error (>=400), handle accordingly: maybe raise an exception or return an error indicator. The main sync logic will decide on retry or failure from this.
      * [ ] Include basic error handling for the request (connection errors, timeouts). Use try/except around the request, and on exception, either retry (in the sync logic) or raise to let sync logic handle it.
    * [ ] The base class might leave actual implementations of `get_group_members`, `add_user_to_group`, etc., as abstract (just define their signature), or provide a generic approach if the vendor’s API structure is known to follow a pattern. However, since each vendor might differ, likely these will be overridden. But we can implement some common patterns:

      * [ ] e.g., if a vendor’s group members can be fetched at `GET /groups/<group>/members`, maybe use a convention if the config can provide the endpoint patterns. This might be too generic; simpler to implement in each subclass.
    * [ ] If appropriate, implement a default `authenticate()` in base that does nothing for basic/token, or handles OAuth2 token retrieval if config given (so subclasses don’t duplicate that).
    * [ ] Provide utility methods for logging within vendor operations (like logging a standardized message for add/remove).
  * [ ] Ensure the base class is documented so that developers adding new vendors know what to implement.

* [ ] **Implement Vendor Module(s)**:

  * [ ] At least implement one concrete vendor integration to test the framework. For instance, if VendorApp1 is a known system, implement `vendors/vendor_app1.py`:

    * [ ] Create a class e.g. `VendorApp1API(VendorAPIBase)` that inherits the base.
    * [ ] Implement `get_group_members(group_cfg)`:

      * [ ] Use `self.request("GET", f"/groups/{group_cfg['vendor_group']}/members")` or the appropriate endpoint. (The exact path depends on actual API; this is illustrative.)
      * [ ] Parse the response (the base request may already return parsed JSON/XML).
      * [ ] Convert the response into a uniform list of user dicts with keys like "username"/"email", "first\_name", "last\_name", etc. Possibly the API returns these keys differently, so map them.
      * [ ] Return this list.
    * [ ] Implement `add_user_to_group(group_cfg, user_info)`:

      * [ ] Possibly two steps: If the API requires creating a user first:

        * [ ] Prepare a payload for user creation (with user\_info's attributes).
        * [ ] Call `self.request("POST", "/users", body=payload)` or similar.
        * [ ] If the API allows directly adding to group with user details, use that.
      * [ ] If user creation call succeeded or if user already exists, call the endpoint to add the user to the group: e.g., `self.request("POST", f"/groups/{group}/members", body={"user": user_id})` or something as per API.
      * [ ] Handle cases: the user might already exist in the system (maybe by email/username). If the creation returns conflict, perhaps retrieve the user ID and proceed to group assignment.
      * [ ] Log the actions.
      * [ ] Return success or handle failure (maybe raise exception or return False on error).
    * [ ] Implement `remove_user_from_group(group_cfg, user_identifier)`:

      * [ ] Call the appropriate endpoint, e.g., `DELETE /groups/{group}/members/{user_id}` or `DELETE /users/{user_id}/groups/{group}` depending on API design.
      * [ ] If the API requires just removing the group membership vs deleting user account, ensure the correct call. We do **not** want to delete the user entirely if they might still be in another group; just remove membership.
      * [ ] Log the removal with user id.
    * [ ] Implement `update_user(user_identifier, user_info)`:

      * [ ] Call the user update endpoint, e.g., `PUT /users/{user_id}` with the fields that changed. Provide body like `{"firstName": ..., "lastName": ..., "email": ...}`.
      * [ ] Alternatively, some APIs might have separate endpoints or require specifying only changed fields.
      * [ ] Only update the necessary fields to match LDAP (avoid overwriting fields not concerned).
      * [ ] Log what is being updated.
    * [ ] Test this module with dummy data or a mocked API if possible.
  * [ ] If there’s a second vendor expected soon (VendorApp2), implement a `vendor_app2.py` similarly to ensure multiple modules can be handled. If VendorApp2 has significantly different style (e.g., uses XML or token auth), this helps test those differences:

    * [ ] For XML, possibly use Python’s XML libraries to construct request or parse responses (unless the base class handles it via an option).
    * [ ] For token auth, ensure the base class correctly attaches the token header.
  * [ ] In each vendor module, handle any peculiarities (like if the API paginates results, loop to get all pages in `get_group_members`; or if it needs a special header, include it).
  * [ ] Ensure that any exceptions raised in these modules propagate up for the main loop to handle (or catch and convert to error returns as appropriate).

* [ ] **Main Synchronization Logic** (`main.py`):

  * [ ] Import the necessary modules (config loader, ldap\_client, logging setup, notification, etc.).
  * [ ] In the `main()` function (or if using `if __name__ == "__main__":`):

    * [ ] Load configuration (call the config loader to get config dict).
    * [ ] Initialize logging by calling `setup_logging(config['logging'])`.
    * [ ] Log a startup message with timestamp and maybe config summary (mask sensitive info).
    * [ ] Initialize LDAP connection: create an instance of LDAPClient with config. If it fails to bind:

      * [ ] If exception or error returned, send an email notification (if enabled) about LDAP connection failure, and exit the program (since nothing can proceed without LDAP).
    * [ ] Loop over each vendor configuration in `config['vendor_apps']`:

      * [ ] Use importlib to import the vendor module. For example:

        * [ ] `module_name = config_v['module']` (e.g., "vendor\_app1"), then do `vendor_module = importlib.import_module(f"ldap_sync.vendors.{module_name}")`.
        * [ ] From that module, find the vendor class. We could standardize class naming (e.g., each module has a class named `API` or `VendorAPI`). Or config could specify class name. Or simply have the module define a function to create an instance. Simpler: assume one class, and use introspection to find a subclass of VendorAPIBase in it.
        * [ ] Instantiate the vendor API class with the vendor’s config (pass in things like base\_url, auth info, etc.). e.g., `vendor_api = vendor_module.VendorAPI(config_v)` if we know class name or if module returns an instance.
      * [ ] Call an `authenticate()` on the vendor if needed (for example, if OAuth2 flow needed to get token). For basic and token, this might do nothing.
      * [ ] For each group mapping in `config_v['groups']`:

        * [ ] Extract `ldap_group` (DN or name) and `vendor_group` (ID or name).
        * [ ] Use LDAP client to get members of `ldap_group`. This returns LDAP users list/dict.
        * [ ] Use vendor\_api to get members of `vendor_group` from the vendor system.
        * [ ] Compare the membership:

          * [ ] Create sets or lists of identifiers for easy comparison. Decide on the key for identity – likely email or username. (For example, use email address as the unique key to match LDAP user to vendor user, if both sides have email. Or use sAMAccountName vs vendor username if they correlate. The config or code may fix this – e.g., assume username in LDAP equals username in vendor, or email equals email.)
          * [ ] Identify `to_add` = all users in LDAP list whose identifier is not in vendor list.
          * [ ] Identify `to_remove` = all users in vendor list whose identifier is not in LDAP list.
          * [ ] Identify `to_update` = all users in intersection of both lists where some attributes differ.

            * [ ] For each user in the intersection: compare first name, last name, email (and any other attributes considered). If any mismatch, include in update list.
            * [ ] It might be useful to compute exactly which fields differ for logging.
        * [ ] Execute removals:

          * [ ] For each user in `to_remove`:

            * [ ] Call `vendor_api.remove_user_from_group(group_cfg, user_id)` (where `user_id` could be some unique identifier – possibly we pass the whole user object or just identifier depending on interface).
            * [ ] Implement retry around this call if it fails due to transient error: e.g., if an HTTP error occurs, try again up to `max_retries`.
            * [ ] If it fails permanently (exception or error status), log an error. Count this failure.
            * [ ] If the number of failures for this vendor exceeds threshold (`max_errors_per_vendor`), abort further actions for this vendor: break out of group loop.
          * [ ] Log a message for each successful removal (e.g., "Removed user X from group Y in VendorApp1").
        * [ ] If error threshold triggered and aborting vendor, break out and proceed to next vendor after sending an alert (see below).
        * [ ] Execute additions:

          * [ ] For each user in `to_add`:

            * [ ] Gather the user’s details from LDAP (we have it in the LDAP list).
            * [ ] Call `vendor_api.add_user_to_group(group_cfg, user_info)`. Inside, this might create the user and/or assign to group.
            * [ ] Retry on failure similarly as above.
            * [ ] If fails, log error and count it. If error count exceeds threshold, break out and abort vendor processing.
            * [ ] Log each successful add ("Added user X to VendorApp1 (group Y)").
        * [ ] Execute updates:

          * [ ] For each user in `to_update`:

            * [ ] Prepare the updated fields (e.g., from LDAP data).
            * [ ] Call `vendor_api.update_user(user_id, updated_info)`.
            * [ ] Retry on failure if needed.
            * [ ] Log success ("Updated user X in VendorApp1: email changed, last name changed").
            * [ ] Count failures similarly.
          * [ ] If any update fails, decide if that alone triggers threshold. (Probably treat similarly, increment failure count).
        * [ ] After processing one group, if not aborted, log a summary for that group (e.g., "Group X: N added, M removed, K updated").
      * [ ] After all groups for the vendor are done (or aborted):

        * [ ] If aborted due to errors:

          * [ ] Log a warning like "Aborted syncing remaining groups for VendorApp1 due to multiple errors."
          * [ ] If notifications enabled, send an email about this vendor failure (include vendor name and error count, perhaps list of failed operations).
        * [ ] Otherwise, log info "Completed sync for VendorApp1 successfully."
      * [ ] Ensure to close or clean any vendor connections if needed (not usually needed for HTTP, but if using sessions or tokens, maybe invalidate token if necessary, though typically not required).
    * [ ] After looping all vendors, close LDAP connection (if not already done).
    * [ ] If the run completed fully or partially:

      * [ ] If any vendor was skipped or had errors, and email notifications are on, ensure those emails have been sent.
      * [ ] Optionally, if email\_on\_success is enabled (not by default), send a summary email of what was done (could be an enhancement).
    * [ ] Exit the program with an appropriate exit code (0 if success, non-zero if any failures occurred).
  * [ ] Wrap the main execution in try/except at top level to catch any unexpected exceptions and log them, so the program doesn’t crash silently. In case of an unhandled exception, ensure an email is sent if possible and exit non-zero.
  * [ ] Test the main loop with a simulated scenario:

    * [ ] Create dummy data structures for LDAP results and fake vendor module with hardcoded responses to simulate adds/removes, to ensure the logic flows correctly.
    * [ ] Or perform an integration test against a real LDAP test instance and a dummy HTTP server.

* [ ] **Retry Logic**:

  * [ ] Implement a decorator or helper function for retrying operations (to avoid duplicating code). For example, a function `retry(operation, retries, wait, on_exception_types=(...))` that attempts the operation and catches exceptions or checks error codes, and retries.
  * [ ] Use this for:

    * [ ] LDAP connection (on connection exception).
    * [ ] Vendor API calls (on network errors or HTTP 500 errors, etc.). Possibly not on 4xx errors (like 401 Unauthorized may not benefit from retry unless credentials were updated).
    * [ ] Fine-tune: perhaps do not retry on certain errors (e.g., 4xx client errors indicating bad request won’t fix by retrying).
  * [ ] Ensure that between retries, the code sleeps for the configured `retry_wait_seconds`.
  * [ ] Use logging to record when a retry is happening (maybe at DEBUG level).
  * [ ] Make the `max_retries` and `retry_wait_seconds` configurable via `config['error_handling']`.
  * [ ] Test the retry logic by simulating a failing call that succeeds on second attempt.

* [ ] **Email Notification Implementation**:

  * [ ] In `notifications.py` (or similar), implement a function `send_email(subject, body, config)` that uses Python’s `smtplib.SMTP`:

    * [ ] Connect to the SMTP server (with TLS if `smtp_tls` is true: use `SMTP.starttls()` after connecting on port 587).
    * [ ] Login with `smtp_username` and `smtp_password` if provided.
    * [ ] Construct an email message (you can use Python’s `email.mime.text.MIMEText` for the body and `email.mime.multipart` if needed, or just build a simple text message string with headers).
    * [ ] Send the email to the recipients.
    * [ ] Wrap in try/except to catch any SMTP exceptions, log them as errors but do not crash the app if email fails.
  * [ ] This function will be called by main when certain conditions are met:

    * [ ] If LDAP connection failed (subject like "LDAP Sync - LDAP Connection Failed").
    * [ ] If a vendor sync was aborted due to errors (subject like "LDAP Sync - VendorApp1 errors").
    * [ ] If any other unexpected exception happens.
    * [ ] Possibly include in the body the error details (exception messages) and maybe a snippet of log or counts of operations if relevant.
    * [ ] Keep the email content brief but informative (since logs will contain full detail).
  * [ ] Test the email function with a real or dummy SMTP (perhaps using a test SMTP server or a service like MailHog in dev) to ensure emails can be sent.

* [ ] **Finish and Review**:

  * [ ] Go through the entire code flow and ensure all configuration options are used and all requirements are met.
  * [ ] Double-check that adding a new vendor module only requires adding the module and updating config (try making a mock second vendor to see if main picks it up without code change).
  * [ ] Review error handling paths to ensure one failure doesn’t cascade incorrectly.
  * [ ] Test the application in a controlled environment:

    * [ ] Possibly set up a test LDAP with a test group and a dummy vendor API (could be a small Flask app simulating endpoints) to do an end-to-end dry run.
    * [ ] Verify that adding a user in LDAP causes the script to add in vendor (and vice versa for removal).
    * [ ] Induce an error (like wrong password for vendor) to see if retries and emails work.
  * [ ] Once satisfied, prepare for containerization:

    * [ ] Write a Dockerfile that:

      * FROM a Python base image (preferably slim).
      * Copy the project code into the image.
      * Install dependencies (pip install ldap3, PyYAML, etc.).
      * Set the entrypoint to run the main script (e.g., `python -m ldap_sync.main` or similar).
    * [ ] Build and test the Docker image locally.
    * [ ] In a Helm chart, you would mount the config (maybe as a ConfigMap to `/app/config.yaml`) and set environment for any secrets; ensure the app can pick those up.
    * [ ] Test running the container with various config override scenarios.
  * [ ] Documentation:

    * [ ] Update README or documentation in the repo to explain how to configure and run the application, how to add new vendors, etc. (This specification can serve as a basis for that documentation.)

## Additional Considerations and Future Enhancements

* **Dry-run Mode:** It may be useful to implement a “dry-run” or “preview” mode where the application goes through the motions of comparing and determining changes, and logs what it *would* do (adds/removes/updates) without actually calling the vendor APIs to make changes. This can be helpful for testing or auditing. This could be triggered by a config setting or command-line flag.
* **Attribute Mapping:** Currently, we assume first name, last name, and email are the main fields to sync. In the future, if more attributes need to be synchronized (phone number, department, etc.), the design should allow adding those relatively easily. One could make the list of attributes to sync configurable. The vendor modules would need to map additional fields accordingly.
* **User Identifier Flexibility:** We assume a common identifier (like email or username) to match users between LDAP and vendor. In some cases, this might need to be configurable (for example, use `employeeID` or another attribute). Future improvements could allow specifying which LDAP attribute corresponds to the vendor’s username/ID if not email.
* **Deleting Users:** The current approach does not delete user accounts from the vendor entirely; it only manages group memberships. This is usually safer. However, if needed (say, if a user is removed from all relevant LDAP groups, perhaps they should be fully deactivated or removed in the vendor), that logic could be added. It would require tracking if a user has no remaining group memberships after sync and possibly calling a deactivation API. This is an edge scenario and can be handled per vendor policy.
* **Concurrency:** If the number of vendors or groups grows, the runtime might increase. In the future, adding parallel processing (for example, processing multiple vendor apps in parallel threads, or multiple groups in parallel) could speed it up. The current design is sequential for simplicity and to avoid race conditions (especially if the same user could be in multiple groups).
* **Better Error Categorization:** The error threshold is a simple count. In the future, one might want to distinguish between non-critical errors (like one user fails to update) vs critical ones (API down). The logic could be extended to immediately abort on certain critical failures (e.g., authentication failure should probably abort that vendor immediately, not keep trying other calls).
* **Logging Improvement:** Ensure that sensitive data (like passwords, API tokens) never appear in logs. Perhaps use placeholder when logging config info (e.g., "password=\*\*\*\*").
* **Testing:** Develop unit tests for each component. For LDAP client, one could use the `ldap3` library’s mock strategy or connect to a test LDAP. For vendor modules, consider using the Python `unittest.mock` to simulate API responses. Automated tests will increase confidence as the code grows.
* **Maintenance:** When adding new vendor modules or new features, update the configuration documentation and ensure backward compatibility (e.g., if adding new config fields, provide defaults so existing configs still work).

By completing the tasks above and adhering to the design, we will have a robust Python application that meets the requirements. This spec can be used as a roadmap to implement the system step by step and to verify that all aspects (from configuration through error handling and notifications) are covered.
