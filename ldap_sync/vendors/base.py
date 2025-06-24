"""
Base vendor API interface and common functionality.

This module defines the abstract base class that all vendor integrations must implement,
along with common HTTP client functionality and SSL/authentication handling.
"""

import json
import ssl
import base64
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Union
from urllib.parse import urlparse, urljoin
from http.client import HTTPSConnection, HTTPConnection, HTTPResponse
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)


class VendorAPIError(Exception):
    """Base exception for vendor API errors."""
    pass


class VendorAuthenticationError(VendorAPIError):
    """Raised when authentication to vendor API fails."""
    pass


class VendorAPIBase(ABC):
    """
    Abstract base class for vendor API integrations.
    
    All vendor modules must inherit from this class and implement the required methods.
    Provides common HTTP client functionality and authentication handling.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize vendor API client.
        
        Args:
            config: Vendor configuration dictionary
        """
        self.config = config
        self.name = config['name']
        self.base_url = config['base_url']
        self.auth_config = config['auth']
        self.format = config.get('format', 'json').lower()
        self.verify_ssl = config.get('verify_ssl', True)
        
        # Parse base URL
        self.parsed_url = urlparse(self.base_url)
        self.host = self.parsed_url.netloc
        self.base_path = self.parsed_url.path.rstrip('/')
        
        # HTTP connection
        self.connection = None
        self.ssl_context = None
        
        # Authentication state
        self.auth_headers = {}
        self.authenticated = False
        
        # Initialize SSL context and authentication
        self._setup_ssl_context()
        self._setup_authentication()
    
    def _setup_ssl_context(self):
        """Set up SSL context based on configuration."""
        if self.parsed_url.scheme != 'https':
            return
        
        if not self.verify_ssl:
            # Create unverified context
            self.ssl_context = ssl._create_unverified_context()
            logger.warning(f"SSL verification disabled for {self.name}")
            return
        
        # Create default context
        self.ssl_context = ssl.create_default_context()
        
        # Load custom truststore if specified
        truststore_file = self.config.get('truststore_file')
        if truststore_file:
            self._load_truststore(truststore_file)
        
        # Load client certificate if specified
        keystore_file = self.config.get('keystore_file')
        if keystore_file:
            self._load_client_cert(keystore_file)
    
    def _load_truststore(self, truststore_file: str):
        """Load custom truststore/CA certificates."""
        truststore_type = self.config.get('truststore_type', 'PEM').upper()
        truststore_password = self.config.get('truststore_password')
        
        try:
            if truststore_type == 'PEM':
                self.ssl_context.load_verify_locations(cafile=truststore_file)
                logger.info(f"Loaded PEM truststore: {truststore_file}")
            
            elif truststore_type == 'JKS':
                # Handle JKS truststore using pyjks
                try:
                    import pyjks
                    keystore = pyjks.KeyStore.load(truststore_file, truststore_password)
                    
                    # Extract certificates and create temporary PEM data
                    ca_certs = []
                    for alias, cert in keystore.certs.items():
                        ca_certs.append(cert.cert)
                    
                    if ca_certs:
                        # Convert to PEM format and load
                        ca_data = b'\n'.join(ca_certs)
                        self.ssl_context.load_verify_locations(cadata=ca_data)
                        logger.info(f"Loaded JKS truststore: {truststore_file}")
                    
                except ImportError:
                    logger.error("pyjks library not available for JKS truststore support")
                    raise VendorAPIError("JKS truststore requires pyjks library")
            
            elif truststore_type == 'PKCS12':
                # Handle PKCS12 truststore using cryptography
                try:
                    from cryptography.hazmat.primitives import serialization
                    from cryptography import x509
                    
                    with open(truststore_file, 'rb') as f:
                        p12_data = f.read()
                    
                    # Load PKCS12 and extract certificates
                    private_key, certificate, additional_certificates = serialization.pkcs12.load_key_and_certificates(
                        p12_data, truststore_password.encode() if truststore_password else None
                    )
                    
                    # Convert certificates to PEM and load
                    ca_certs = []
                    if certificate:
                        ca_certs.append(certificate.public_bytes(serialization.Encoding.PEM))
                    for cert in (additional_certificates or []):
                        ca_certs.append(cert.public_bytes(serialization.Encoding.PEM))
                    
                    if ca_certs:
                        ca_data = b'\n'.join(ca_certs)
                        self.ssl_context.load_verify_locations(cadata=ca_data)
                        logger.info(f"Loaded PKCS12 truststore: {truststore_file}")
                
                except ImportError:
                    logger.error("cryptography library not available for PKCS12 truststore support")
                    raise VendorAPIError("PKCS12 truststore requires cryptography library")
            
        except Exception as e:
            logger.error(f"Failed to load truststore {truststore_file}: {e}")
            raise VendorAPIError(f"Truststore loading failed: {e}")
    
    def _load_client_cert(self, keystore_file: str):
        """Load client certificate for mutual TLS."""
        keystore_type = self.config.get('keystore_type', 'PEM').upper()
        keystore_password = self.config.get('keystore_password')
        
        try:
            if keystore_type == 'PEM':
                # Assume separate cert and key files or combined PEM
                self.ssl_context.load_cert_chain(keystore_file, password=keystore_password)
                logger.info(f"Loaded PEM client certificate: {keystore_file}")
            
            elif keystore_type == 'PKCS12':
                # Extract cert and key from PKCS12 and create temporary PEM files
                try:
                    from cryptography.hazmat.primitives import serialization
                    
                    with open(keystore_file, 'rb') as f:
                        p12_data = f.read()
                    
                    private_key, certificate, _ = serialization.pkcs12.load_key_and_certificates(
                        p12_data, keystore_password.encode() if keystore_password else None
                    )
                    
                    if private_key and certificate:
                        # Create temporary PEM files
                        import tempfile
                        
                        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as cert_file:
                            cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))
                            cert_path = cert_file.name
                        
                        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as key_file:
                            key_file.write(private_key.private_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.PKCS8,
                                encryption_algorithm=serialization.NoEncryption()
                            ))
                            key_path = key_file.name
                        
                        self.ssl_context.load_cert_chain(cert_path, key_path)
                        logger.info(f"Loaded PKCS12 client certificate: {keystore_file}")
                
                except ImportError:
                    logger.error("cryptography library not available for PKCS12 client certificate")
                    raise VendorAPIError("PKCS12 client certificate requires cryptography library")
            
        except Exception as e:
            logger.error(f"Failed to load client certificate {keystore_file}: {e}")
            raise VendorAPIError(f"Client certificate loading failed: {e}")
    
    def _setup_authentication(self):
        """Set up authentication headers based on configuration."""
        auth_method = self.auth_config.get('method', '').lower()
        
        if auth_method == 'basic':
            username = self.auth_config.get('username')
            password = self.auth_config.get('password')
            if username and password:
                credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
                self.auth_headers['Authorization'] = f"Basic {credentials}"
                logger.debug(f"Configured Basic authentication for {self.name}")
            else:
                logger.error(f"Basic auth configured but missing username or password for {self.name}")
        
        elif auth_method == 'token' or auth_method == 'bearer':
            token = self.auth_config.get('token')
            if token:
                self.auth_headers['Authorization'] = f"Bearer {token}"
                logger.debug(f"Configured Bearer token authentication for {self.name}")
            else:
                logger.error(f"Token auth configured but missing token for {self.name}")
        
        elif auth_method == 'oauth2':
            # OAuth2 configuration validation
            client_id = self.auth_config.get('client_id')
            client_secret = self.auth_config.get('client_secret')
            token_url = self.auth_config.get('token_url')
            
            if not all([client_id, client_secret, token_url]):
                logger.error(f"OAuth2 auth configured but missing required fields (client_id, client_secret, token_url) for {self.name}")
            else:
                logger.debug(f"OAuth2 authentication configured for {self.name}")
                # OAuth2 tokens will be obtained in authenticate() method
        
        elif auth_method == 'mtls' or auth_method == 'mutual_tls':
            # Mutual TLS uses client certificates - already handled in SSL setup
            logger.debug(f"Mutual TLS authentication configured for {self.name}")
        
        else:
            if auth_method:
                logger.warning(f"Unknown authentication method '{auth_method}' for {self.name}")
            else:
                logger.debug(f"No authentication method configured for {self.name}")
    
    def _oauth2_get_token(self) -> bool:
        """
        Retrieve OAuth2 access token using client credentials flow.
        
        Returns:
            True if token was successfully obtained
        """
        auth_method = self.auth_config.get('method', '').lower()
        if auth_method != 'oauth2':
            return True  # Not OAuth2, so no token needed
        
        client_id = self.auth_config.get('client_id')
        client_secret = self.auth_config.get('client_secret')
        token_url = self.auth_config.get('token_url')
        scope = self.auth_config.get('scope', '')
        
        if not all([client_id, client_secret, token_url]):
            logger.error(f"OAuth2 configuration incomplete for {self.name}")
            return False
        
        try:
            # Parse token URL
            from urllib.parse import urlparse
            parsed_token_url = urlparse(token_url)
            
            # Create temporary connection for token request
            if parsed_token_url.scheme == 'https':
                token_conn = HTTPSConnection(parsed_token_url.netloc, context=self.ssl_context, timeout=30)
            else:
                token_conn = HTTPConnection(parsed_token_url.netloc, timeout=30)
            
            # Prepare token request
            token_data = {
                'grant_type': 'client_credentials',
                'client_id': client_id,
                'client_secret': client_secret
            }
            
            if scope:
                token_data['scope'] = scope
            
            # URL encode the data
            from urllib.parse import urlencode
            token_body = urlencode(token_data)
            
            token_headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            }
            
            logger.debug(f"Requesting OAuth2 token for {self.name}")
            token_conn.request('POST', parsed_token_url.path or '/', token_body, token_headers)
            
            response = token_conn.getresponse()
            response_data = response.read().decode('utf-8')
            
            if response.status == 200:
                try:
                    token_response = json.loads(response_data)
                    access_token = token_response.get('access_token')
                    
                    if access_token:
                        self.auth_headers['Authorization'] = f"Bearer {access_token}"
                        
                        # Store token expiry if provided
                        expires_in = token_response.get('expires_in')
                        if expires_in:
                            import time
                            self._token_expires_at = time.time() + int(expires_in) - 60  # 60 second buffer
                        
                        logger.info(f"Successfully obtained OAuth2 token for {self.name}")
                        return True
                    else:
                        logger.error(f"OAuth2 response missing access_token for {self.name}")
                        return False
                        
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON in OAuth2 token response for {self.name}: {e}")
                    return False
            else:
                logger.error(f"OAuth2 token request failed for {self.name}: {response.status} {response.reason}")
                return False
                
        except Exception as e:
            logger.error(f"OAuth2 token request error for {self.name}: {e}")
            return False
        
        finally:
            try:
                token_conn.close()
            except:
                pass
    
    def _is_oauth2_token_valid(self) -> bool:
        """Check if OAuth2 token is still valid."""
        if not hasattr(self, '_token_expires_at'):
            return False
        
        import time
        return time.time() < self._token_expires_at
    
    def _get_connection(self) -> Union[HTTPSConnection, HTTPConnection]:
        """Get or create HTTP connection."""
        if self.connection:
            return self.connection
        
        if self.parsed_url.scheme == 'https':
            self.connection = HTTPSConnection(
                self.host,
                context=self.ssl_context,
                timeout=30
            )
        else:
            self.connection = HTTPConnection(self.host, timeout=30)
        
        return self.connection
    
    def request(self, method: str, path: str, body: Optional[Dict] = None, 
                headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Make HTTP request to vendor API.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            path: API endpoint path (relative to base_url)
            body: Request body data
            headers: Additional headers
            
        Returns:
            Parsed response data
            
        Raises:
            VendorAPIError: If request fails
        """
        # Build full path
        full_path = urljoin(self.base_path + '/', path.lstrip('/'))
        
        # Prepare headers
        request_headers = dict(self.auth_headers)
        if headers:
            request_headers.update(headers)
        
        # Prepare body
        request_body = None
        if body is not None:
            if self.format == 'json':
                request_body = json.dumps(body)
                request_headers['Content-Type'] = 'application/json'
            elif self.format == 'xml':
                # Basic XML serialization - vendor modules can override for complex XML
                request_body = self._dict_to_xml(body)
                request_headers['Content-Type'] = 'application/xml'
        
        # Make request with automatic OAuth2 token refresh
        max_auth_retries = 1
        for auth_attempt in range(max_auth_retries + 1):
            try:
                conn = self._get_connection()
                
                logger.debug(f"Making {method} request to {self.host}{full_path}")
                conn.request(method, full_path, request_body, request_headers)
                
                response = conn.getresponse()
                response_data = response.read().decode('utf-8')
                
                logger.debug(f"Response status: {response.status} {response.reason}")
                
                # Handle HTTP errors
                if response.status >= 400:
                    if response.status == 401:
                        # Handle authentication error
                        auth_method = self.auth_config.get('method', '').lower()
                        
                        # For OAuth2, try to refresh token once
                        if auth_method == 'oauth2' and auth_attempt < max_auth_retries:
                            logger.info(f"401 error received, attempting to refresh OAuth2 token for {self.name}")
                            if self._oauth2_get_token():
                                # Update headers with new token and retry
                                request_headers.update(self.auth_headers)
                                continue
                        
                        raise VendorAuthenticationError(f"Authentication failed for {self.name}")
                    else:
                        raise VendorAPIError(f"HTTP {response.status}: {response.reason}")
                
                # Parse response
                if self.format == 'json':
                    return json.loads(response_data) if response_data else {}
                elif self.format == 'xml':
                    return self._xml_to_dict(response_data) if response_data else {}
                else:
                    return {'raw': response_data}
                    
            except (VendorAPIError, VendorAuthenticationError):
                # If this was our last auth attempt, re-raise
                if auth_attempt >= max_auth_retries:
                    raise
                # Otherwise continue to next auth attempt
            except (ConnectionError, OSError) as e:
                raise VendorAPIError(f"Connection error to {self.name}: {e}")
            except json.JSONDecodeError as e:
                raise VendorAPIError(f"Invalid JSON response from {self.name}: {e}")
            except Exception as e:
                raise VendorAPIError(f"Request failed for {self.name}: {e}")
        
        # Should not reach here
        raise VendorAPIError(f"Request failed after {max_auth_retries + 1} attempts")
    
    def _dict_to_xml(self, data: Dict) -> str:
        """Convert dictionary to basic XML (can be overridden by vendor modules)."""
        root = ET.Element('request')
        for key, value in data.items():
            elem = ET.SubElement(root, key)
            elem.text = str(value)
        return ET.tostring(root, encoding='unicode')
    
    def _xml_to_dict(self, xml_data: str) -> Dict:
        """Convert XML to dictionary (can be overridden by vendor modules)."""
        try:
            root = ET.fromstring(xml_data)
            result = {}
            for child in root:
                result[child.tag] = child.text
            return result
        except ET.ParseError as e:
            raise VendorAPIError(f"Invalid XML response: {e}")
    
    def close_connection(self):
        """Close HTTP connection."""
        if self.connection:
            try:
                self.connection.close()
            except Exception as e:
                logger.warning(f"Error closing connection for {self.name}: {e}")
            finally:
                self.connection = None
    
    # Abstract methods that vendor modules must implement
    
    def authenticate(self) -> bool:
        """
        Perform any additional authentication steps (e.g., OAuth2 token retrieval).
        
        This default implementation handles OAuth2 client credentials flow.
        Vendor modules can override this method for custom authentication flows.
        
        Returns:
            True if authentication successful
        """
        auth_method = self.auth_config.get('method', '').lower()
        
        if auth_method == 'oauth2':
            # Check if we need to get or refresh the OAuth2 token
            if not hasattr(self, '_token_expires_at') or not self._is_oauth2_token_valid():
                return self._oauth2_get_token()
            else:
                logger.debug(f"OAuth2 token still valid for {self.name}")
                return True
        
        elif auth_method in ['basic', 'token', 'bearer', 'mtls', 'mutual_tls']:
            # These auth methods are handled in _setup_authentication
            return True
        
        elif not auth_method:
            # No authentication required
            return True
        
        else:
            logger.warning(f"Unknown authentication method '{auth_method}' for {self.name}")
            return False
    
    @abstractmethod
    def get_group_members(self, group_cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Get list of users in the specified vendor group.
        
        Args:
            group_cfg: Group configuration (contains vendor_group identifier)
            
        Returns:
            List of user dictionaries with standardized fields
        """
        pass
    
    @abstractmethod
    def add_user_to_group(self, group_cfg: Dict[str, Any], user_info: Dict[str, Any]) -> bool:
        """
        Add user to vendor group (create user if needed).
        
        Args:
            group_cfg: Group configuration
            user_info: User data from LDAP
            
        Returns:
            True if successful
        """
        pass
    
    @abstractmethod
    def remove_user_from_group(self, group_cfg: Dict[str, Any], user_identifier: str) -> bool:
        """
        Remove user from vendor group.
        
        Args:
            group_cfg: Group configuration
            user_identifier: User identifier (email, username, etc.)
            
        Returns:
            True if successful
        """
        pass
    
    @abstractmethod
    def update_user(self, user_identifier: str, user_info: Dict[str, Any]) -> bool:
        """
        Update user attributes in vendor system.
        
        Args:
            user_identifier: User identifier
            user_info: Updated user data
            
        Returns:
            True if successful
        """
        pass
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close_connection()