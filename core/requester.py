"""
Async HTTP Requester Module
Handles concurrent HTTP requests with timing and response capture
"""

import aiohttp
import asyncio
import time
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass, field


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
    
    def __init__(self, timeout: int = 10, max_concurrent: int = 50):
        """
        Initialize the requester
        
        Args:
            timeout: Request timeout in seconds
            max_concurrent: Maximum concurrent requests
        """
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.session: Optional[aiohttp.ClientSession] = None
        
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
        async with self.semaphore:
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
                        
            # Replace placeholder in headers
            request_headers = {}
            if headers:
                for key, value in headers.items():
                    if isinstance(value, str):
                        request_headers[key] = value.replace(placeholder, username)
                    else:
                        request_headers[key] = value
            
            start_time = time.time()
            redirect_chain = []
            final_url = target_url
            
            try:
                # Follow redirects manually to capture chain
                current_url = target_url
                max_redirects = 10
                redirect_count = 0
                
                while redirect_count < max_redirects:
                    async with self.session.request(
                        method=method,
                        url=current_url,
                        data=request_data if redirect_count == 0 else None,
                        headers=request_headers,
                        cookies=cookies,
                        allow_redirects=False,
                        ssl=False  # Allow self-signed certificates
                    ) as response:
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
