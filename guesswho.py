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

# Initialize colorama for cross-platform colored output
init(autoreset=True)


def print_banner():
    """Print tool banner"""
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════╗
║                                                       ║
║   {Fore.YELLOW}  ██████╗ ██╗   ██╗███████╗███████╗███████╗     {Fore.CYAN} ║
║   {Fore.YELLOW} ██╔════╝ ██║   ██║██╔════╝██╔════╝██╔════╝     {Fore.CYAN} ║
║   {Fore.YELLOW} ██║  ███╗██║   ██║█████╗  ███████╗███████╗     {Fore.CYAN} ║
║   {Fore.YELLOW} ██║   ██║██║   ██║██╔══╝  ╚════██║╚════██║     {Fore.CYAN} ║
║   {Fore.YELLOW} ╚██████╔╝╚██████╔╝███████╗███████║███████║     {Fore.CYAN} ║
║   {Fore.YELLOW}  ╚═════╝  ╚═════╝ ╚══════╝╚══════╝╚══════╝     {Fore.CYAN} ║
║                                                       ║
║   {Fore.YELLOW}            WHO - User Enumeration Tool          {Fore.CYAN} ║
║   {Fore.GREEN}        Fast, Accurate, Security Testing         {Fore.CYAN} ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝{Style.RESET_ALL}
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


def print_results(results: dict):
    """Print fuzzing results in a formatted way"""
    findings = results["results"]
    stats = results["statistics"]
    
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[+] ENUMERATION RESULTS{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    
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
        
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[+] STATISTICS{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    
    print(f"Total requests:        {stats.get('total', 0)}")
    print(f"Successful responses:  {stats.get('successful', 0)}")
    print(f"Failed requests:       {stats.get('failed', 0)}")
    print(f"Avg response time:     {stats.get('avg_response_time', 0):.3f}s")
    print(f"Min response time:     {stats.get('min_response_time', 0):.3f}s")
    print(f"Max response time:     {stats.get('max_response_time', 0):.3f}s")
    print(f"Avg content length:    {stats.get('avg_content_length', 0):.0f} bytes")
    print(f"Unique content lengths: {stats.get('unique_lengths', 0)}")
    
    if 'status_codes' in stats:
        print(f"\nStatus code distribution:")
        for code, count in sorted(stats['status_codes'].items()):
            print(f"  {code}: {count}")
    
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
    parser.add_argument('-c', '--concurrency', type=int, default=50, help='Number of concurrent requests (default: 50)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    
    # Analysis configuration
    parser.add_argument('--min-confidence', type=float, default=0.6, 
                       help='Minimum confidence threshold 0.0-1.0 (default: 0.6)')
    
    # Output options
    parser.add_argument('-o', '--output', help='Save results to file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--no-banner', action='store_true', help='Disable banner')
    
    args = parser.parse_args()
    
    # Print banner
    if not args.no_banner:
        print_banner()
        
    # Parse data and headers
    data = parse_data(args.data)
    headers = parse_headers(args.headers)
    cookies = parse_data(args.cookie) if args.cookie else {}
    
    # Validate placeholder is in URL or data
    if args.placeholder not in args.url and args.placeholder not in args.data:
        print(f"{Fore.RED}[!] Error: Placeholder '{args.placeholder}' not found in URL or data{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Make sure to include '{args.placeholder}' in either the URL or data{Style.RESET_ALL}")
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
            timeout=args.timeout,
            concurrency=args.concurrency,
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
