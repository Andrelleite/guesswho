"""
Evasion module for GuessWho - Advanced techniques to avoid detection
Implements User-Agent rotation, proxy chains, timing jitter, and header randomization
"""

import random
import time
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
import asyncio

@dataclass
class EvasionConfig:
    """Configuration for evasion techniques"""
    user_agent_rotation: bool = False
    user_agents_file: Optional[str] = None
    random_headers: bool = False
    proxy_enabled: bool = False
    proxy_list: Optional[List[str]] = None
    proxy_rotation: bool = False
    jitter_min: float = 0.0
    jitter_max: float = 0.0
    http2_enabled: bool = False
    
    def __post_init__(self):
        """Validate configuration"""
        if self.jitter_min < 0 or self.jitter_max < 0:
            raise ValueError("Jitter values must be positive")
        if self.jitter_min > self.jitter_max:
            raise ValueError("jitter_min cannot be greater than jitter_max")


class UserAgentRotator:
    """Manages User-Agent rotation with a database of real browser signatures"""
    
    # Comprehensive list of real User-Agent strings from various browsers and devices
    DEFAULT_USER_AGENTS = [
        # Chrome on Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        # Chrome on macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        # Chrome on Linux
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        # Firefox on Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
        # Firefox on macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
        # Firefox on Linux
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        # Safari on macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
        # Safari on iOS
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        # Edge on Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
        # Edge on macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        # Chrome on Android
        "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 11) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
        # Opera
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
        # Brave
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Brave/120.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Brave/120.0.0.0",
    ]
    
    def __init__(self, user_agents_file: Optional[str] = None):
        """Initialize with default or custom user agents"""
        self.user_agents = []
        
        if user_agents_file:
            try:
                with open(user_agents_file, 'r') as f:
                    self.user_agents = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                print(f"[!] User-Agent file not found: {user_agents_file}, using defaults")
                self.user_agents = self.DEFAULT_USER_AGENTS.copy()
        else:
            self.user_agents = self.DEFAULT_USER_AGENTS.copy()
        
        random.shuffle(self.user_agents)
        self.current_index = 0
    
    def get_random(self) -> str:
        """Get a random User-Agent string"""
        return random.choice(self.user_agents)
    
    def get_next(self) -> str:
        """Get next User-Agent in rotation"""
        ua = self.user_agents[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.user_agents)
        return ua


class ProxyManager:
    """Manages proxy rotation and selection"""
    
    def __init__(self, proxy_list: Optional[List[str]] = None, rotation: bool = True):
        """
        Initialize proxy manager
        
        Args:
            proxy_list: List of proxy URLs (http://host:port or socks5://host:port)
            rotation: Whether to rotate through proxies
        """
        self.proxies = proxy_list or []
        self.rotation = rotation
        self.current_index = 0
        
        if self.proxies:
            random.shuffle(self.proxies)
    
    def get_proxy(self) -> Optional[Dict[str, str]]:
        """Get proxy configuration for aiohttp"""
        if not self.proxies:
            return None
        
        if self.rotation:
            proxy_url = self.proxies[self.current_index]
            self.current_index = (self.current_index + 1) % len(self.proxies)
        else:
            proxy_url = random.choice(self.proxies)
        
        # Format for aiohttp
        return {"http": proxy_url, "https": proxy_url}
    
    @staticmethod
    def load_from_file(filepath: str) -> List[str]:
        """Load proxies from file (one per line)"""
        try:
            with open(filepath, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"[!] Proxy file not found: {filepath}")
            return []


class HeaderRandomizer:
    """Randomizes HTTP headers to avoid fingerprinting"""
    
    ACCEPT_LANGUAGES = [
        "en-US,en;q=0.9",
        "en-GB,en;q=0.9",
        "en-US,en;q=0.9,es;q=0.8",
        "en-US,en;q=0.9,fr;q=0.8",
        "de-DE,de;q=0.9,en;q=0.8",
        "fr-FR,fr;q=0.9,en;q=0.8",
        "es-ES,es;q=0.9,en;q=0.8",
        "pt-BR,pt;q=0.9,en;q=0.8",
        "ja-JP,ja;q=0.9,en;q=0.8",
        "zh-CN,zh;q=0.9,en;q=0.8",
    ]
    
    ACCEPT_ENCODINGS = [
        "gzip, deflate, br",
        "gzip, deflate",
        "br, gzip, deflate",
    ]
    
    ACCEPT_TYPES = [
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "application/json,text/plain,*/*;q=0.8",
    ]
    
    DNT_VALUES = ["1", None]  # Do Not Track
    
    @staticmethod
    def get_random_headers(base_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Generate randomized headers"""
        headers = base_headers.copy() if base_headers else {}
        
        # Randomize Accept-Language
        headers["Accept-Language"] = random.choice(HeaderRandomizer.ACCEPT_LANGUAGES)
        
        # Randomize Accept-Encoding
        headers["Accept-Encoding"] = random.choice(HeaderRandomizer.ACCEPT_ENCODINGS)
        
        # Randomize Accept
        if "Accept" not in headers:
            headers["Accept"] = random.choice(HeaderRandomizer.ACCEPT_TYPES)
        
        # Randomly include DNT header
        dnt = random.choice(HeaderRandomizer.DNT_VALUES)
        if dnt:
            headers["DNT"] = dnt
        
        # Randomly include additional headers
        if random.random() > 0.5:
            headers["Upgrade-Insecure-Requests"] = "1"
        
        if random.random() > 0.5:
            headers["Sec-Fetch-Dest"] = random.choice(["document", "empty"])
            headers["Sec-Fetch-Mode"] = random.choice(["navigate", "cors", "no-cors"])
            headers["Sec-Fetch-Site"] = random.choice(["none", "same-origin", "cross-site"])
        
        return headers


class TimingJitter:
    """Adds random delays between requests to avoid pattern detection"""
    
    def __init__(self, min_delay: float = 0.0, max_delay: float = 0.0):
        """
        Initialize timing jitter
        
        Args:
            min_delay: Minimum delay in seconds
            max_delay: Maximum delay in seconds
        """
        self.min_delay = min_delay
        self.max_delay = max_delay
    
    async def delay(self):
        """Apply random delay"""
        if self.max_delay > 0:
            delay = random.uniform(self.min_delay, self.max_delay)
            await asyncio.sleep(delay)
    
    def get_delay(self) -> float:
        """Get random delay value without applying it"""
        if self.max_delay > 0:
            return random.uniform(self.min_delay, self.max_delay)
        return 0.0


class EvasionManager:
    """Central manager for all evasion techniques"""
    
    def __init__(self, config: EvasionConfig):
        """Initialize evasion manager with configuration"""
        self.config = config
        
        # Initialize components
        self.ua_rotator = None
        if config.user_agent_rotation:
            self.ua_rotator = UserAgentRotator(config.user_agents_file)
        
        self.proxy_manager = None
        if config.proxy_enabled and config.proxy_list:
            self.proxy_manager = ProxyManager(config.proxy_list, config.proxy_rotation)
        
        self.header_randomizer = HeaderRandomizer() if config.random_headers else None
        
        self.timing_jitter = TimingJitter(config.jitter_min, config.jitter_max)
    
    def get_user_agent(self) -> Optional[str]:
        """Get User-Agent for request"""
        if self.ua_rotator:
            return self.ua_rotator.get_next()
        return None
    
    def get_proxy(self) -> Optional[Dict[str, str]]:
        """Get proxy configuration"""
        if self.proxy_manager:
            return self.proxy_manager.get_proxy()
        return None
    
    def get_headers(self, base_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Get headers with randomization applied"""
        if self.header_randomizer:
            return self.header_randomizer.get_random_headers(base_headers)
        return base_headers or {}
    
    async def apply_jitter(self):
        """Apply timing jitter"""
        await self.timing_jitter.delay()
    
    def get_stats(self) -> Dict[str, any]:
        """Get evasion statistics"""
        return {
            "user_agent_rotation": self.config.user_agent_rotation,
            "ua_count": len(self.ua_rotator.user_agents) if self.ua_rotator else 0,
            "proxy_enabled": self.config.proxy_enabled,
            "proxy_count": len(self.proxy_manager.proxies) if self.proxy_manager else 0,
            "proxy_rotation": self.config.proxy_rotation,
            "header_randomization": self.config.random_headers,
            "jitter_range": f"{self.config.jitter_min}-{self.config.jitter_max}s" if self.config.jitter_max > 0 else "disabled",
            "http2_enabled": self.config.http2_enabled
        }
