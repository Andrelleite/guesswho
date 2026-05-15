#!/usr/bin/env python3
"""
GuessWho - Fast User Enumeration Fuzzing Tool
A high-performance tool for detecting user enumeration vulnerabilities
"""

import argparse
import asyncio
import sys
import json
from pathlib import Path
from colorama import init, Fore, Style

from core.fuzzer import UserEnumFuzzer
from core.evasion import EvasionConfig, EvasionManager, ProxyManager

# Initialize colorama for cross-platform colored output
init(autoreset=True)


def print_banner():
    """Print tool banner"""
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║   {Fore.RED}   ██████╗ {Fore.YELLOW}██╗   ██╗{Fore.GREEN}███████╗{Fore.CYAN}███████╗{Fore.MAGENTA}███████╗{Fore.RED}██╗    ██╗{Fore.YELLOW}██╗  ██╗{Fore.GREEN} ██████╗  {Fore.CYAN}║
║   {Fore.RED}  ██╔════╝ {Fore.YELLOW}██║   ██║{Fore.GREEN}██╔════╝{Fore.CYAN}██╔════╝{Fore.MAGENTA}██╔════╝{Fore.RED}██║    ██║{Fore.YELLOW}██║  ██║{Fore.GREEN}██╔═══██╗ {Fore.CYAN}║
║   {Fore.RED}  ██║  ███╗{Fore.YELLOW}██║   ██║{Fore.GREEN}█████╗  {Fore.CYAN}███████╗{Fore.MAGENTA}███████╗{Fore.RED}██║ █╗ ██║{Fore.YELLOW}███████║{Fore.GREEN}██║   ██║ {Fore.CYAN}║
║   {Fore.RED}  ██║   ██║{Fore.YELLOW}██║   ██║{Fore.GREEN}██╔══╝  {Fore.CYAN}╚════██║{Fore.MAGENTA}╚════██║{Fore.RED}██║███╗██║{Fore.YELLOW}██╔══██║{Fore.GREEN}██║   ██║ {Fore.CYAN}║
║   {Fore.RED}  ╚██████╔╝{Fore.YELLOW}╚██████╔╝{Fore.GREEN}███████╗{Fore.CYAN}███████║{Fore.MAGENTA}███████║{Fore.RED}╚███╔███╔╝{Fore.YELLOW}██║  ██║{Fore.GREEN}╚██████╔╝ {Fore.CYAN}║
║   {Fore.RED}   ╚═════╝ {Fore.YELLOW} ╚═════╝ {Fore.GREEN}╚══════╝{Fore.CYAN}╚══════╝{Fore.MAGENTA}╚══════╝{Fore.RED} ╚══╝╚══╝ {Fore.YELLOW}╚═╝  ╚═╝{Fore.GREEN} ╚═════╝  {Fore.CYAN}║
║                                                                       ║
║              {Fore.YELLOW}⚡ Next-Gen User Enumeration Framework ⚡{Fore.CYAN}               ║
║                                                                       ║
║   {Fore.GREEN}[+]{Fore.WHITE} Async Engine    {Fore.CYAN}│{Fore.GREEN} [+]{Fore.WHITE} 11 Detection Methods {Fore.CYAN}│{Fore.GREEN} [+]{Fore.WHITE} Smart Analysis {Fore.CYAN}  ║
║   {Fore.GREEN}[+]{Fore.WHITE} WAF Evasion     {Fore.CYAN}│{Fore.GREEN} [+]{Fore.WHITE} Proxy Rotation      {Fore.CYAN}│{Fore.GREEN} [+]{Fore.WHITE} 1000+ req/s    {Fore.CYAN}  ║
║                                                                       ║
║   {Fore.MAGENTA}Version: 1.1.0{Fore.CYAN}  │  {Fore.YELLOW}Phase: 1.2 Complete{Fore.CYAN}  │  {Fore.RED}github.com/Andrelleite{Fore.CYAN}  ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)


def parse_data(data_str: str) -> dict:
    """Parse data string into dictionary"""
    if not data_str:
        return {}
        
    try:
        # Try to parse as JSON first
        return json.loads(data_str)
    except json.JSONDecodeError:
        # Parse as key=value pairs
        result = {}
        for pair in data_str.split('&'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                result[key] = value
        return result


def parse_headers(headers_list: list) -> dict:
    """Parse header list into dictionary"""
    if not headers_list:
        return {}
        
    headers = {}
    for header in headers_list:
        if ':' in header:
            key, value = header.split(':', 1)
            headers[key.strip()] = value.strip()
    return headers


def _bar(value: int, total: int, width: int = 30) -> str:
    """Return a filled bar proportional to value/total."""
    filled = int(round(width * value / total)) if total else 0
    return "█" * filled + "░" * (width - filled)


def _status_color(code: int) -> str:
    if code == 0:
        return Fore.RED
    if code < 300:
        return Fore.GREEN
    if code < 400:
        return Fore.CYAN
    if code < 500:
        return Fore.YELLOW
    return Fore.RED


def _timing_histogram(responses_data: list, width: int = 40, bins: int = 10) -> str:
    """Build an ASCII timing histogram from a list of (time, is_outlier) tuples."""
    if not responses_data:
        return ""
    times = [t for t, _ in responses_data]
    lo, hi = min(times), max(times)
    if hi == lo:
        return ""
    step = (hi - lo) / bins
    buckets = [0] * bins
    outlier_buckets = [False] * bins
    for t, is_outlier in responses_data:
        idx = min(int((t - lo) / step), bins - 1)
        buckets[idx] += 1
        if is_outlier:
            outlier_buckets[idx] = True
    max_count = max(buckets) or 1
    lines = []
    for i in range(bins):
        label = f"{lo + i * step:.3f}s"
        bar_len = int(round(width * buckets[i] / max_count))
        color = Fore.RED if outlier_buckets[i] else Fore.CYAN
        bar = color + "█" * bar_len + Style.RESET_ALL + "░" * (width - bar_len)
        lines.append(f"  {label:>9} │{bar}│ {buckets[i]}")
    return "\n".join(lines)


def print_results(results: dict, fuzzer=None):
    """Print fuzzing results and a visual statistics graph."""
    findings = results["results"]
    stats = results["statistics"]

    # ── RESULTS ──────────────────────────────────────────────────────────
    print(f"\n{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[+] ENUMERATION RESULTS{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}\n")

    if findings:
        print(f"{Fore.GREEN}[+] Found {len(findings)} potential valid username(s):{Style.RESET_ALL}\n")
        for username, confidence, reason in findings:
            color = Fore.GREEN if confidence >= 0.8 else Fore.YELLOW
            print(f"{color}[!] {username}{Style.RESET_ALL}")
            print(f"    Confidence: {color}{confidence:.0%}{Style.RESET_ALL}")
            print(f"    Indicators: {reason}")
            print()
    else:
        print(f"{Fore.RED}[-] No valid usernames detected{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    This could mean:{Style.RESET_ALL}")
        print(f"    - The endpoint is not vulnerable to user enumeration")
        print(f"    - None of the tested usernames are valid")
        print(f"    - The detection threshold is too high (try lowering --min-confidence)")
        print()

    # ── STATISTICS ───────────────────────────────────────────────────────
    print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[+] STATISTICS{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}\n")

    total     = stats.get('total', 0)
    success   = stats.get('successful', 0)
    failed    = stats.get('failed', 0)
    avg_time  = stats.get('avg_response_time', 0)
    min_time  = stats.get('min_response_time', 0)
    max_time  = stats.get('max_response_time', 0)
    avg_len   = stats.get('avg_content_length', 0)
    uniq_len  = stats.get('unique_lengths', 0)

    print(f"  Total requests      : {total}")
    print(f"  Successful          : {success}")
    print(f"  Failed              : {failed}")
    print(f"  Avg response time   : {avg_time:.3f}s  (min {min_time:.3f}s / max {max_time:.3f}s)")
    print(f"  Avg content length  : {avg_len:.0f} bytes  ({uniq_len} unique lengths)\n")

    # ── GRAPH 1: Status code distribution ────────────────────────────────
    status_codes = stats.get('status_codes', {})
    if status_codes:
        print(f"  {Fore.YELLOW}┌─ Status Code Distribution {'─'*38}┐{Style.RESET_ALL}")
        bar_total = max(status_codes.values()) or 1
        for code in sorted(status_codes):
            count = status_codes[code]
            color = _status_color(code)
            bar = _bar(count, bar_total, width=32)
            pct = count / total * 100 if total else 0
            print(f"  {Fore.YELLOW}│{Style.RESET_ALL}  {color}{code}{Style.RESET_ALL}  {color}{bar}{Style.RESET_ALL}  {count:>6} ({pct:5.1f}%)")
        print(f"  {Fore.YELLOW}└{'─'*67}┘{Style.RESET_ALL}\n")

    # ── GRAPH 2: Content length distribution ─────────────────────────────
    len_dist = stats.get('length_distribution', {})
    if len_dist and len(len_dist) > 1:
        print(f"  {Fore.YELLOW}┌─ Content Length Distribution {'─'*35}┐{Style.RESET_ALL}")
        bar_total = max(len_dist.values()) or 1
        for length in sorted(len_dist):
            count = len_dist[length]
            bar = _bar(count, bar_total, width=32)
            pct = count / success * 100 if success else 0
            print(f"  {Fore.YELLOW}│{Style.RESET_ALL}  {Fore.CYAN}{length:>5}B{Style.RESET_ALL}  {Fore.CYAN}{bar}{Style.RESET_ALL}  {count:>6} ({pct:5.1f}%)")
        print(f"  {Fore.YELLOW}└{'─'*67}┘{Style.RESET_ALL}\n")

    # ── GRAPH 3: Response time histogram ─────────────────────────────────
    timing_data = stats.get('timing_data', [])
    if timing_data and len(timing_data) >= 5:
        print(f"  {Fore.YELLOW}┌─ Response Time Distribution {'─'*36}┐{Style.RESET_ALL}")
        hist = _timing_histogram(timing_data, width=38, bins=10)
        if hist:
            for line in hist.splitlines():
                print(f"  {Fore.YELLOW}│{Style.RESET_ALL}{line}")
        print(f"  {Fore.YELLOW}│{Style.RESET_ALL}  {Fore.RED}Red = timing outlier (potential valid user){Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}└{'─'*67}┘{Style.RESET_ALL}\n")

    # ── GRAPH 4: Confidence scores of findings ────────────────────────────
    if findings:
        print(f"  {Fore.YELLOW}┌─ Detected User Confidence Scores {'─'*31}┐{Style.RESET_ALL}")
        for username, confidence, _ in findings:
            color = Fore.GREEN if confidence >= 0.8 else Fore.YELLOW
            bar = _bar(int(confidence * 100), 100, width=32)
            print(f"  {Fore.YELLOW}│{Style.RESET_ALL}  {color}{username:<20}{Style.RESET_ALL}  {color}{bar}{Style.RESET_ALL}  {confidence:.0%}")
        print(f"  {Fore.YELLOW}└{'─'*67}┘{Style.RESET_ALL}\n")

    print()


def save_results(results: dict, output_file: str):
    """Save results to a file"""
    findings = results["results"]
    
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        f.write("GuessWho - User Enumeration Results\n")
        f.write("=" * 70 + "\n\n")
        
        if findings:
            f.write(f"Found {len(findings)} potential valid username(s):\n\n")
            for username, confidence, reason in findings:
                f.write(f"Username: {username}\n")
                f.write(f"Confidence: {confidence:.0%}\n")
                f.write(f"Indicators: {reason}\n")
                f.write("-" * 70 + "\n")
        else:
            f.write("No valid usernames detected\n")
            
        f.write("\n" + "=" * 70 + "\n")
        f.write("Statistics\n")
        f.write("=" * 70 + "\n\n")
        
        stats = results["statistics"]
        for key, value in stats.items():
            f.write(f"{key}: {value}\n")
            
    print(f"{Fore.GREEN}[+] Results saved to: {output_file}{Style.RESET_ALL}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="GuessWho - Fast User Enumeration Fuzzing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic POST request fuzzing
  python guesswho.py -u "http://example.com/api/login" -w wordlist.txt -d "username=FUZZ&password=test123"
  
  # Forgot password endpoint
  python guesswho.py -u "http://example.com/forgot-password" -w emails.txt -d '{"email":"FUZZ"}' -H "Content-Type: application/json"
  
  # Custom placeholder and high concurrency
  python guesswho.py -u "http://example.com/check-user/USERNAME" -w users.txt --placeholder USERNAME -c 100
  
  # Save results to file
  python guesswho.py -u "http://example.com/api/register" -w users.txt -d "email=FUZZ@test.com" -o results.txt
  
  # Verbose mode for debugging
  python guesswho.py -u "http://example.com/login" -w users.txt -d "user=FUZZ" -v
        """
    )
    
    # Required arguments
    parser.add_argument('-u', '--url', required=True, help='Target URL (use FUZZ or custom placeholder)')
    parser.add_argument('-w', '--wordlist', required=True, help='Path to username/email wordlist')
    
    # Request configuration
    parser.add_argument('-X', '--method', default='POST', help='HTTP method (default: POST)')
    parser.add_argument('-d', '--data', default='', help='POST data (e.g., "username=FUZZ&password=test" or JSON)')
    parser.add_argument('-H', '--header', action='append', dest='headers', help='Custom header (can be used multiple times)')
    parser.add_argument('--cookie', help='Cookie data')
    parser.add_argument('--placeholder', default='FUZZ', help='Placeholder to replace with username (default: FUZZ)')
    
    # Performance tuning
    parser.add_argument(
        '-T', '--timing', type=int, choices=[1, 2, 3, 4, 5], default=3,
        metavar='LEVEL',
        help=(
            'Timing template 1-5 (default: 3). '
            'T1=Sneaky(1c/2s), T2=Polite(3c/0.5s), '
            'T3=Normal(10c/15s), T4=Aggressive(25c/8s), T5=Insane(50c/5s). '
            'Overridden by -c/-t/--delay if set explicitly.'
        )
    )
    parser.add_argument('-c', '--concurrency', type=int, default=None,
                        help='Override concurrent requests (overrides -T)')
    parser.add_argument('-t', '--timeout', type=int, default=None,
                        help='Override request timeout in seconds (overrides -T)')
    parser.add_argument('--delay', type=float, default=None,
                        help='Override per-request delay in seconds (overrides -T)')
    
    # Analysis configuration
    parser.add_argument('--min-confidence', type=float, default=0.6, 
                       help='Minimum confidence threshold 0.0-1.0 (default: 0.6)')
    
    # Output options
    parser.add_argument('-o', '--output', help='Save results to file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--no-banner', action='store_true', help='Disable banner')
    
    # Evasion options (Phase 1.2: Advanced Evasion Techniques)
    evasion_group = parser.add_argument_group('evasion options', 'Advanced techniques to avoid detection')
    evasion_group.add_argument('--user-agent-rotation', action='store_true',
                             help='Enable User-Agent rotation (30+ signatures)')
    evasion_group.add_argument('--user-agents-file', metavar='FILE',
                             help='Custom User-Agent list file (one per line)')
    evasion_group.add_argument('--random-headers', action='store_true',
                             help='Randomize HTTP headers (Accept-Language, encoding, etc.)')
    evasion_group.add_argument('--proxy', metavar='URL',
                             help='Use proxy (http://host:port or socks5://host:port)')
    evasion_group.add_argument('--proxy-file', metavar='FILE',
                             help='File with proxy list (one per line)')
    evasion_group.add_argument('--proxy-rotation', action='store_true',
                             help='Rotate through proxies instead of random selection')
    evasion_group.add_argument('--jitter', metavar='MIN-MAX',
                             help='Random delay between requests, e.g., "0.1-0.5" seconds')
    
    args = parser.parse_args()

    # ── Timing templates ───────────────────────────────────────────────────
    # Each entry: (concurrency, timeout_secs, delay_secs, label)
    TIMING_TEMPLATES = {
        1: (1,  30, 2.0,  "Sneaky    — 1 concurrent, 2s delay,   30s timeout"),
        2: (3,  20, 0.5,  "Polite    — 3 concurrent, 0.5s delay, 20s timeout"),
        3: (10, 15, 0.0,  "Normal    — 10 concurrent, no delay,  15s timeout"),
        4: (25,  8, 0.0,  "Aggressive— 25 concurrent, no delay,   8s timeout"),
        5: (50,  5, 0.0,  "Insane    — 50 concurrent, no delay,   5s timeout"),
    }
    t_concurrency, t_timeout, t_delay, t_label = TIMING_TEMPLATES[args.timing]
    # Explicit -c / -t / --delay override the template
    concurrency = args.concurrency if args.concurrency is not None else t_concurrency
    timeout     = args.timeout     if args.timeout     is not None else t_timeout
    delay       = args.delay       if args.delay       is not None else t_delay
    
    # Print banner
    if not args.no_banner:
        print_banner()

    # Show timing config
    _, _, _, t_label = TIMING_TEMPLATES[args.timing]
    overrides = []
    if args.concurrency is not None: overrides.append(f"-c {concurrency}")
    if args.timeout     is not None: overrides.append(f"-t {timeout}")
    if args.delay       is not None: overrides.append(f"--delay {delay}")
    override_note = f"  (overrides: {', '.join(overrides)})" if overrides else ""
    print(f"{Fore.CYAN}[*] Timing: T{args.timing} — {t_label}{override_note}{Style.RESET_ALL}")
        
    # Parse data and headers
    data = parse_data(args.data)
    headers = parse_headers(args.headers)
    cookies = parse_data(args.cookie) if args.cookie else {}
    
    # Validate placeholder is in URL or data
    if args.placeholder not in args.url and args.placeholder not in args.data:
        print(f"{Fore.RED}[!] Error: Placeholder '{args.placeholder}' not found in URL or data{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Make sure to include '{args.placeholder}' in either the URL or data{Style.RESET_ALL}")
        sys.exit(1)
    
    # Setup evasion if any evasion options are enabled
    evasion_manager = None
    if any([args.user_agent_rotation, args.random_headers, args.proxy, args.proxy_file, args.jitter]):
        try:
            # Parse jitter
            jitter_min, jitter_max = 0.0, 0.0
            if args.jitter:
                try:
                    parts = args.jitter.split('-')
                    if len(parts) == 2:
                        jitter_min = float(parts[0])
                        jitter_max = float(parts[1])
                    else:
                        print(f"{Fore.RED}[!] Invalid jitter format. Use: MIN-MAX (e.g., 0.1-0.5){Style.RESET_ALL}")
                        sys.exit(1)
                except ValueError:
                    print(f"{Fore.RED}[!] Jitter values must be numbers{Style.RESET_ALL}")
                    sys.exit(1)
            
            # Load proxies
            proxy_list = []
            if args.proxy_file:
                proxy_list = ProxyManager.load_from_file(args.proxy_file)
                if not proxy_list:
                    print(f"{Fore.YELLOW}[!] Warning: No proxies loaded from file{Style.RESET_ALL}")
            elif args.proxy:
                proxy_list = [args.proxy]
            
            # Create evasion config
            evasion_config = EvasionConfig(
                user_agent_rotation=args.user_agent_rotation,
                user_agents_file=args.user_agents_file,
                random_headers=args.random_headers,
                proxy_enabled=bool(proxy_list),
                proxy_list=proxy_list if proxy_list else None,
                proxy_rotation=args.proxy_rotation,
                jitter_min=jitter_min,
                jitter_max=jitter_max
            )
            
            evasion_manager = EvasionManager(evasion_config)
            print(f"{Fore.CYAN}[*] Evasion techniques enabled{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error setting up evasion: {e}{Style.RESET_ALL}")
            sys.exit(1)
        
    try:
        # Create fuzzer instance
        fuzzer = UserEnumFuzzer(
            url=args.url,
            wordlist=args.wordlist,
            method=args.method,
            data=data,
            headers=headers,
            cookies=cookies,
            placeholder=args.placeholder,
            timeout=timeout,
            concurrency=concurrency,
            delay=delay,
            min_confidence=args.min_confidence,
            verbose=args.verbose
        )
        
        # Run fuzzing
        results = asyncio.run(fuzzer.fuzz())
        
        # Print results
        print_results(results)
        
        # Save to file if requested
        if args.output:
            save_results(results, args.output)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
