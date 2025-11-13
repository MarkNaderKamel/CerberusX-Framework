#!/usr/bin/env python3
"""
Network Utilities - Shared resilient networking layer for Cerberus Agents
Provides retry logic, exponential backoff, provider fallback, and configurable timeouts
"""

import time
import random
import logging
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class NetworkConfig:
    """Configuration for resilient network operations"""
    timeout: int = 30
    max_retries: int = 3
    backoff_factor: float = 2.0
    jitter: bool = True
    verify_ssl: bool = True
    user_agent: str = "Cerberus-Agents/17.0 (Security Assessment)"


class ResilientHTTPClient:
    """
    HTTP client with automatic retry, exponential backoff, and provider fallback
    
    Features:
    - Exponential backoff with jitter
    - Automatic retry on transient failures
    - Provider fallback for redundancy
    - Configurable timeouts
    - Connection pooling
    - Telemetry and metrics
    """
    
    def __init__(self, config: Optional[NetworkConfig] = None):
        self.config = config or NetworkConfig()
        self.session = self._create_session()
        self.metrics = {
            'requests_total': 0,
            'requests_success': 0,
            'requests_failed': 0,
            'retries_total': 0,
            'fallbacks_used': 0
        }
    
    def _create_session(self) -> requests.Session:
        """Create configured session with retry strategy"""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=self.config.max_retries,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
            backoff_factor=self.config.backoff_factor,
            raise_on_status=False
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=20)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        session.headers.update({
            'User-Agent': self.config.user_agent
        })
        
        return session
    
    def http_get(self, url: str, params: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None, 
                 headers: Optional[Dict[str, str]] = None, allow_redirects: bool = True) -> Optional[requests.Response]:
        """
        Resilient HTTP GET with retry and exponential backoff
        
        Args:
            url: Target URL
            params: Query parameters
            timeout: Request timeout (uses config default if None)
            headers: Additional headers
            allow_redirects: Follow redirects
        
        Returns:
            Response object or None if all retries failed
        """
        timeout = timeout or self.config.timeout
        self.metrics['requests_total'] += 1
        
        request_headers = dict(self.session.headers)
        if headers:
            request_headers.update(headers)
        
        for attempt in range(self.config.max_retries + 1):
            try:
                logger.debug(f"HTTP GET {url} (attempt {attempt + 1}/{self.config.max_retries + 1})")
                
                response = self.session.get(
                    url,
                    params=params,
                    headers=request_headers,
                    timeout=timeout,
                    verify=self.config.verify_ssl,
                    allow_redirects=allow_redirects
                )
                
                if response.status_code < 500:
                    self.metrics['requests_success'] += 1
                    return response
                
                logger.warning(f"Server error {response.status_code}, retrying...")
                
            except requests.exceptions.Timeout:
                logger.warning(f"Timeout on {url}, attempt {attempt + 1}/{self.config.max_retries + 1}")
                self.metrics['retries_total'] += 1
                
            except requests.exceptions.ConnectionError:
                logger.warning(f"Connection error on {url}, attempt {attempt + 1}/{self.config.max_retries + 1}")
                self.metrics['retries_total'] += 1
                
            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                self.metrics['retries_total'] += 1
            
            if attempt < self.config.max_retries:
                sleep_time = self._calculate_backoff(attempt)
                logger.debug(f"Backing off for {sleep_time:.2f} seconds")
                time.sleep(sleep_time)
        
        self.metrics['requests_failed'] += 1
        logger.error(f"All retry attempts exhausted for {url}")
        return None
    
    def http_post(self, url: str, data: Optional[Dict[str, Any]] = None, json: Optional[Dict[str, Any]] = None, 
                  timeout: Optional[int] = None, headers: Optional[Dict[str, str]] = None) -> Optional[requests.Response]:
        """
        Resilient HTTP POST with retry and exponential backoff
        
        Args:
            url: Target URL
            data: Form data
            json: JSON payload
            timeout: Request timeout
            headers: Additional headers
        
        Returns:
            Response object or None if all retries failed
        """
        timeout = timeout or self.config.timeout
        self.metrics['requests_total'] += 1
        
        request_headers = dict(self.session.headers)
        if headers:
            request_headers.update(headers)
        
        for attempt in range(self.config.max_retries + 1):
            try:
                logger.debug(f"HTTP POST {url} (attempt {attempt + 1}/{self.config.max_retries + 1})")
                
                response = self.session.post(
                    url,
                    data=data,
                    json=json,
                    headers=request_headers,
                    timeout=timeout,
                    verify=self.config.verify_ssl
                )
                
                if response.status_code < 500:
                    self.metrics['requests_success'] += 1
                    return response
                
                logger.warning(f"Server error {response.status_code}, retrying...")
                
            except requests.exceptions.Timeout:
                logger.warning(f"Timeout on {url}, attempt {attempt + 1}/{self.config.max_retries + 1}")
                self.metrics['retries_total'] += 1
                
            except requests.exceptions.ConnectionError:
                logger.warning(f"Connection error on {url}, attempt {attempt + 1}/{self.config.max_retries + 1}")
                self.metrics['retries_total'] += 1
                
            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                self.metrics['retries_total'] += 1
            
            if attempt < self.config.max_retries:
                sleep_time = self._calculate_backoff(attempt)
                time.sleep(sleep_time)
        
        self.metrics['requests_failed'] += 1
        return None
    
    def http_get_with_fallback(self, url_providers: List[Callable[[], str]], 
                               params: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None) -> Optional[requests.Response]:
        """
        HTTP GET with provider fallback mechanism
        
        Args:
            url_providers: List of functions that generate URLs (primary, fallback1, fallback2, ...)
            params: Query parameters
            timeout: Request timeout
        
        Returns:
            Response from first successful provider or None
        """
        for i, provider in enumerate(url_providers):
            try:
                url = provider()
                logger.info(f"Trying provider {i + 1}/{len(url_providers)}: {url}")
                
                response = self.http_get(url, params=params, timeout=timeout)
                
                if response and response.status_code == 200:
                    if i > 0:
                        self.metrics['fallbacks_used'] += 1
                        logger.info(f"✅ Fallback provider {i + 1} succeeded")
                    return response
                
                logger.warning(f"Provider {i + 1} failed or returned non-200 status")
                
            except Exception as e:
                logger.warning(f"Provider {i + 1} exception: {e}")
                continue
        
        logger.error("All providers exhausted")
        return None
    
    def _calculate_backoff(self, attempt: int) -> float:
        """Calculate exponential backoff with optional jitter"""
        backoff = self.config.backoff_factor ** attempt
        
        if self.config.jitter:
            jitter = random.uniform(0, backoff * 0.3)
            backoff += jitter
        
        return min(backoff, 60)
    
    def get_metrics(self) -> Dict[str, int]:
        """Get telemetry metrics"""
        return self.metrics.copy()
    
    def reset_metrics(self):
        """Reset telemetry counters"""
        for key in self.metrics:
            self.metrics[key] = 0


class ProviderRegistry:
    """
    Registry of alternative providers for various services
    Enables automatic fallback when primary services fail
    """
    
    CERTIFICATE_TRANSPARENCY_PROVIDERS = [
        lambda domain: f"https://crt.sh/?q=%.{domain}&output=json",
        lambda domain: f"https://api.hackertarget.com/hostsearch/?q={domain}",
        lambda domain: f"https://crt.sh/?q={domain}&output=json"
    ]
    
    SHODAN_ALTERNATIVES = [
        "https://api.shodan.io",
        "https://internetdb.shodan.io"
    ]
    
    WHOIS_PROVIDERS = [
        "https://www.whois.com/whois",
        "https://who.is/whois",
        "https://whois.domaintools.com"
    ]
    
    @staticmethod
    def get_ct_providers(domain: str) -> List[Callable[[], str]]:
        """Get certificate transparency providers for domain"""
        return [lambda d=domain: provider(d) for provider in ProviderRegistry.CERTIFICATE_TRANSPARENCY_PROVIDERS]


def create_resilient_client(timeout: int = 30, max_retries: int = 3, 
                           backoff_factor: float = 2.0) -> ResilientHTTPClient:
    """
    Factory function to create configured resilient HTTP client
    
    Args:
        timeout: Default timeout in seconds
        max_retries: Maximum retry attempts
        backoff_factor: Exponential backoff multiplier
    
    Returns:
        Configured ResilientHTTPClient instance
    """
    config = NetworkConfig(
        timeout=timeout,
        max_retries=max_retries,
        backoff_factor=backoff_factor,
        jitter=True,
        verify_ssl=True
    )
    return ResilientHTTPClient(config)


def http_get_resilient(url: str, timeout: int = 30, max_retries: int = 3) -> Optional[requests.Response]:
    """
    Quick resilient HTTP GET - convenience function
    
    Args:
        url: Target URL
        timeout: Request timeout
        max_retries: Maximum retry attempts
    
    Returns:
        Response or None
    """
    client = create_resilient_client(timeout=timeout, max_retries=max_retries)
    return client.http_get(url)


def http_get_with_fallback(domain: str, provider_type: str = "ct", 
                           timeout: int = 30) -> Optional[requests.Response]:
    """
    HTTP GET with automatic provider fallback
    
    Args:
        domain: Target domain
        provider_type: Provider type ('ct' for certificate transparency)
        timeout: Request timeout
    
    Returns:
        Response from first successful provider
    """
    client = create_resilient_client(timeout=timeout)
    
    if provider_type == "ct":
        providers = ProviderRegistry.get_ct_providers(domain)
        return client.http_get_with_fallback(providers, timeout=timeout)
    
    return None


def main():
    """CLI entry point for network utilities testing"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Resilient Network Utilities Library")
    parser.add_argument('--test', action='store_true', help='Run test suite')
    parser.add_argument('--url', help='Test URL with resilient GET')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout in seconds')
    parser.add_argument('--retries', type=int, default=3, help='Max retries')
    parser.add_argument('--authorized', action='store_true', help='Authorization (auto-granted)')
    
    args = parser.parse_args()
    
    if args.test:
        logger.setLevel(logging.DEBUG)
        print("🧪 Testing ResilientHTTPClient...")
        
        client = create_resilient_client(timeout=10, max_retries=2)
        
        print("\n1. Testing successful request:")
        response = client.http_get("https://httpbin.org/get")
        if response:
            print(f"✅ Success: {response.status_code}")
        
        print("\n2. Testing timeout handling:")
        response = client.http_get("https://httpbin.org/delay/5", timeout=2)
        
        print("\n3. Testing provider fallback:")
        response = http_get_with_fallback("example.com", provider_type="ct", timeout=15)
        if response:
            print(f"✅ Fallback successful: {response.status_code}")
        
        print(f"\n📊 Metrics: {client.get_metrics()}")
    
    elif args.url:
        client = create_resilient_client(timeout=args.timeout, max_retries=args.retries)
        response = client.http_get(args.url)
        if response:
            print(f"✅ Success: {response.status_code}")
            print(f"📊 Metrics: {client.get_metrics()}")
        else:
            print(f"❌ Request failed after {args.retries} retries")
    
    else:
        parser.print_help()
        print("\n📚 Network Utilities Library - Resilient HTTP Client")
        print("Features: Retry logic, exponential backoff, provider fallback, telemetry")
        print("\nExample usage:")
        print("  python -m cerberus_agents.network_utils --test")
        print("  python -m cerberus_agents.network_utils --url https://example.com")


if __name__ == "__main__":
    main()
