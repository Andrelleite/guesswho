"""
Async HTTP Requester Module
Handles concurrent HTTP requests with timing and response capture
"""

import aiohttp
import asyncio
import time
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass, field
from .evasion import EvasionManager


@dataclass
class Response:
    """Response data structure"""
    username: str
    status_code: int
    response_time: float
    content_length: int
    body: str
    headers: Dict[str, str]
    cookies: Dict[str, str] = field(default_factory=dict)
    redirect_chain: List[Tuple[int, str]] = field(default_factory=list)  # [(status, url), ...]
    final_url: str = ""
    
    
class AsyncRequester:
    """Handles asynchronous HTTP requests"""
    
    def __init__(self, timeout: int = 10, max_concurrent: int = 50, evasion_manager: Optional[EvasionManager] = None):
        """
        Initialize the requester
        
        Args:
            timeout: Request timeout in seconds
            max_concurrent: Maximum concurrent requests
            evasion_manager: Optional evasion manager for advanced techniques
        """
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.session: Optional[aiohttp.ClientSession] = None
        self.evasion_manager = evasion_manager
        
    async def __aenter__(self):
        """Async context manager entry"""
        connector = aiohttp.TCPConnector(limit=self.max_concurrent, limit_per_host=self.max_concurrent)
        self.session = aiohttp.ClientSession(
            timeout=self.timeout,
            connector=connector
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
            
    async def make_request(
        self,
        url: str,
        username: str,
        method: str = "POST",
        data: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        cookies: Optional[Dict] = None,
        placeholder: str = "FUZZ"
    ) -> Response:
        """
        Make a single HTTP request
        
        Args:
            url: Target URL
            username: Username to test
            method: HTTP method
            data: Request data (will replace placeholder with username)
            headers: Request headers
            cookies: Request cookies
            placeholder: Placeholder to replace with username
            
        Returns:
            Response object with timing and content
        """
        # Apply timing jitter for evasion
        if self.evasion_manager:
            await self.evasion_manager.apply_jitter()
            
        # Replace placeholder in URL
        target_url = url.replace(placeholder, username)
            
        # Replace placeholder in data
        request_data = None
        if data:
            request_data = {}
            for key, value in data.items():
                if isinstance(value, str):
                    request_data[key] = value.replace(placeholder, username)
                else:
                    request_data[key] = value
                        
        # Prepare headers with evasion
        request_headers = {}
        if headers:
            for key, value in headers.items():
                if isinstance(value, str):
                    request_headers[key] = value.replace(placeholder, username)
                else:
                    request_headers[key] = value
            
        # Apply evasion techniques
        if self.evasion_manager:
            # Add/override User-Agent
            ua = self.evasion_manager.get_user_agent()
            if ua:
                request_headers["User-Agent"] = ua
            
            # Apply header randomization
            request_headers = self.evasion_manager.get_headers(request_headers)
        
        # Get proxy if configured
        proxy = None
        if self.evasion_manager:
            proxy = self.evasion_manager.get_proxy()
            
        start_time = time.time()
        redirect_chain = []
        final_url = target_url
        
        try:
            # Follow redirects manually to capture chain
            current_url = target_url
            max_redirects = 10
            redirect_count = 0
            
            while redirect_count < max_redirects:
                # Detect if we should send as JSON or form data
                is_json = False
                if request_headers:
                    content_type = request_headers.get('Content-Type', '').lower()
                    is_json = 'application/json' in content_type
                
                # Also detect JSON by structure (nested dicts)
                if not is_json and request_data:
                    for value in request_data.values():
                        if isinstance(value, dict):
                            is_json = True
                            break
                
                # Build request kwargs
                request_kwargs = {
                    "method": method,
                    "url": current_url,
                    "headers": request_headers,
                    "cookies": cookies,
                    "allow_redirects": False,
                    "ssl": False  # Allow self-signed certificates
                }
                
                # Add body data - use json= for JSON, data= for form data
                if redirect_count == 0 and request_data:
                    if is_json:
                        request_kwargs["json"] = request_data
                    else:
                        request_kwargs["data"] = request_data
                
                # Add proxy if configured
                if proxy:
                    request_kwargs["proxy"] = proxy
                
                async with self.session.request(**request_kwargs) as response:
                    status = response.status
                    body = await response.text()
                    response_headers = dict(response.headers)
                    response_cookies = {c.key: c.value for c in response.cookies.values()}
                    
                    # Check if redirect
                    if status in (301, 302, 303, 307, 308):
                        location = response_headers.get('Location', '')
                        if location:
                            redirect_chain.append((status, current_url))
                            # Handle relative URLs
                            if location.startswith('/'):
                                from urllib.parse import urlparse, urljoin
                                current_url = urljoin(current_url, location)
                            else:
                                current_url = location
                            redirect_count += 1
                            continue
                    
                    # No redirect, final response
                    final_url = current_url
                    response_time = time.time() - start_time
                    
                    return Response(
                        username=username,
                        status_code=status,
                        response_time=response_time,
                        content_length=len(body),
                        body=body,
                        headers=response_headers,
                        cookies=response_cookies,
                        redirect_chain=redirect_chain,
                        final_url=final_url
                    )
            
            # Too many redirects
            response_time = time.time() - start_time
            return Response(
                username=username,
                status_code=310,  # Custom: too many redirects
                response_time=response_time,
                content_length=0,
                body="Too many redirects",
                headers={},
                cookies={},
                redirect_chain=redirect_chain,
                final_url=current_url
            )
                
        except asyncio.TimeoutError:
            response_time = time.time() - start_time
            return Response(
                username=username,
                status_code=0,
                response_time=response_time,
                content_length=0,
                body="",
                headers={},
                cookies={},
                redirect_chain=[],
                final_url=target_url
            )
            
        except Exception as e:
            response_time = time.time() - start_time
            return Response(
                username=username,
                status_code=-1,
                response_time=response_time,
                content_length=0,
                body=str(e),
                headers={},
                cookies={},
                redirect_chain=[],
                final_url=target_url
            )
