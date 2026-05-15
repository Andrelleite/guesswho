"""
Main Fuzzer Engine
Coordinates user enumeration fuzzing operations
"""

import asyncio
from typing import List, Dict, Optional
from pathlib import Path
from tqdm import tqdm
from .requester import AsyncRequester, Response
from .analyzer import ResponseAnalyzer
from .evasion import EvasionManager


class UserEnumFuzzer:
    """Main fuzzing engine for user enumeration"""
    
    def __init__(
        self,
        url: str,
        wordlist: str,
        method: str = "POST",
        data: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        cookies: Optional[Dict] = None,
        placeholder: str = "FUZZ",
        timeout: int = 15,
        concurrency: int = 10,
        delay: float = 0.0,
        min_confidence: float = 0.6,
        verbose: bool = False,
        evasion_manager: Optional[EvasionManager] = None
    ):
        """
        Initialize the fuzzer
        
        Args:
            url: Target URL (use FUZZ as placeholder for username)
            wordlist: Path to username wordlist
            method: HTTP method (GET, POST, PUT, etc.)
            data: Request body data (use FUZZ as placeholder)
            headers: Custom headers
            cookies: Custom cookies
            placeholder: Placeholder string to replace with usernames
            timeout: Request timeout in seconds
            concurrency: Number of concurrent requests
            delay: Seconds to sleep inside semaphore after each request (rate limiting)
            min_confidence: Minimum confidence threshold for reporting
            verbose: Enable verbose output
            evasion_manager: Optional evasion manager for advanced techniques
        """
        self.url = url
        self.wordlist = wordlist
        self.method = method.upper()
        self.data = data or {}
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.placeholder = placeholder
        self.timeout = timeout
        self.concurrency = concurrency
        self.delay = delay
        self.min_confidence = min_confidence
        self.verbose = verbose
        self.evasion_manager = evasion_manager
        
        self.analyzer = ResponseAnalyzer(verbose=verbose)
        
    def load_wordlist(self) -> List[str]:
        """Load usernames from wordlist file"""
        wordlist_path = Path(self.wordlist)
        
        if not wordlist_path.exists():
            raise FileNotFoundError(f"Wordlist not found: {self.wordlist}")
            
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            usernames = [line.strip() for line in f if line.strip()]
            
        return usernames
        
    async def fuzz(self) -> List[Dict]:
        """
        Execute the fuzzing operation
        
        Returns:
            List of potential valid usernames with confidence scores
        """
        usernames = self.load_wordlist()
        
        if not usernames:
            raise ValueError("No usernames found in wordlist")
            
        print(f"[*] Loaded {len(usernames)} usernames from wordlist")
        print(f"[*] Target: {self.url}")
        print(f"[*] Method: {self.method}")
        print(f"[*] Concurrency: {self.concurrency}")
        print(f"[*] Starting enumeration...")
        print()
        
        # Create progress bar
        pbar = tqdm(total=len(usernames), desc="Fuzzing", unit="req")
        
        # Print evasion stats if enabled
        if self.evasion_manager:
            stats = self.evasion_manager.get_stats()
            if stats['user_agent_rotation']:
                print(f"[*] User-Agent Rotation: {stats['ua_count']} signatures")
            if stats['proxy_enabled']:
                print(f"[*] Proxy: {stats['proxy_count']} proxies ({'rotating' if stats['proxy_rotation'] else 'random'})")
            if stats['header_randomization']:
                print(f"[*] Header Randomization: Enabled")
            if stats['jitter_range'] != 'disabled':
                print(f"[*] Timing Jitter: {stats['jitter_range']}")
            print()
        
        async with AsyncRequester(timeout=self.timeout, max_concurrent=self.concurrency, delay=self.delay, evasion_manager=self.evasion_manager) as requester:
            # Create tasks for all requests
            tasks = []
            for username in usernames:
                task = self._fuzz_username(requester, username, pbar)
                tasks.append(task)
                
            # Execute all tasks concurrently
            await asyncio.gather(*tasks)
            
        pbar.close()
        
        # Analyze results
        print("\n[*] Analysis complete. Processing results...")
        results = self.analyzer.analyze(min_confidence=self.min_confidence)
        
        # Get statistics
        stats = self.analyzer.get_statistics()
        
        return {
            "results": results,
            "statistics": stats
        }
        
    async def _fuzz_username(self, requester: AsyncRequester, username: str, pbar: tqdm):
        """Fuzz a single username"""
        response = await requester.make_request(
            url=self.url,
            username=username,
            method=self.method,
            data=self.data,
            headers=self.headers,
            cookies=self.cookies,
            placeholder=self.placeholder
        )
        
        self.analyzer.add_response(response)
        pbar.update(1)
        
        if self.verbose:
            tqdm.write(f"[DEBUG] {username}: Status={response.status_code}, "
                      f"Time={response.response_time:.3f}s, Length={response.content_length}")
