# GuessWho 🔍

**Fast User Enumeration Fuzzing Tool with Advanced Evasion**

GuessWho is a high-performance security testing tool designed to detect user enumeration vulnerabilities in web applications. It's faster than Burp Intruder and combines the best features of tools like ffuf, gobuster, and Burp Suite for specialized user enumeration testing.

**✨ NEW in v1.1.0**: Advanced evasion techniques including User-Agent rotation, proxy support, header randomization, and timing jitter!

## 🎯 Features

### Core Features
- **⚡ Lightning Fast**: Asynchronous HTTP requests with configurable concurrency (up to 100+ concurrent requests)
- **🧠 Intelligent Analysis**: 11 detection techniques:
  - Status code analysis (80% confidence)
  - Response timing analysis with z-score (60% confidence)
  - Content length comparison (70% confidence)
  - Pattern matching in response bodies (90% confidence)
  - HTTP header analysis (75% confidence)
  - Redirect chain tracking (85% confidence)
  - Cookie analysis (70% confidence)
  - Response similarity with Levenshtein distance (75% confidence)
  - JSON/XML structure analysis (80% confidence)
  - Advanced timing histogram analysis (65% confidence)
  - Rate limiting detection (60% confidence)
- **🎨 Beautiful Output**: Color-coded results with progress bars and confidence scores
- **📊 Detailed Statistics**: Response time metrics, status code distribution, and more
- **💾 Export Results**: Save findings to text files

### 🥷 Advanced Evasion (v1.1.0 - Phase 1.2)
- **User-Agent Rotation**: 30+ real browser signatures to avoid fingerprinting
- **Proxy Support**: HTTP/SOCKS4/SOCKS5 proxy chains with rotation or random selection
- **Header Randomization**: Intelligent HTTP header variation to defeat pattern detection
- **Timing Jitter**: Configurable random delays to avoid rate-based detection
- **Multiple Techniques**: Combine evasion methods for maximum stealth

[📖 Read the complete Evasion Guide →](EVASION.md)

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone <repo-url>
cd guesswho

# Install dependencies
pip install -r requirements.txt

# Make executable (optional)
chmod +x guesswho.py
```

### Basic Usage

```bash
# Test a login endpoint
python guesswho.py -u "http://example.com/api/login" \
                   -w wordlists/usernames.txt \
                   -d "username=FUZZ&password=test123"

# Test forgot password endpoint with JSON
python guesswho.py -u "http://example.com/api/forgot-password" \
                   -w wordlists/emails.txt \
                   -d '{"email":"FUZZ"}' \
                   -H "Content-Type: application/json"

# Test registration endpoint
python guesswho.py -u "http://example.com/register" \
                   -w wordlists/usernames.txt \
                   -d "username=FUZZ&email=test@test.com&password=Pass123"
```

## 📖 Usage Examples

### Login Page Testing

```bash
python guesswho.py -u "http://target.com/login" \
                   -w wordlists/usernames.txt \
                   -d "username=FUZZ&password=wrongpass"
```

### Password Reset Testing

```bash
python guesswho.py -u "http://target.com/reset-password" \
                   -w wordlists/emails.txt \
                   -d '{"email":"FUZZ"}' \
                   -H "Content-Type: application/json"
```

### Account Creation Testing

```bash
python guesswho.py -u "http://target.com/api/register" \
                   -w wordlists/usernames.txt \
                   -d "user=FUZZ&email=test@test.com"
```

### REST API Endpoint

```bash
python guesswho.py -u "http://api.target.com/users/FUZZ" \
                   -w wordlists/usernames.txt \
                   -X GET
```

### Custom Placeholder

```bash
python guesswho.py -u "http://target.com/check/USERNAME" \
                   -w wordlists/usernames.txt \
                   --placeholder USERNAME
```

### High Performance Mode

```bash
python guesswho.py -u "http://target.com/api/check-user" \
                   -w large-wordlist.txt \
                   -d "username=FUZZ" \
                   -c 100 \
                   -t 5
```

### With Authentication

```bash
python guesswho.py -u "http://target.com/admin/check-user" \
                   -w wordlists/usernames.txt \
                   -d "username=FUZZ" \
                   -H "Authorization: Bearer YOUR_TOKEN" \
                   --cookie "session=abc123"
```

### 🥷 With Evasion Techniques (NEW in v1.1.0)

```bash
# User-Agent rotation
python guesswho.py -u "http://target.com/login" \
                   -w wordlists/usernames.txt \
                   -d "user=FUZZ&pass=test" \
                   --user-agent-rotation

# Combined evasion (stealth mode)
python guesswho.py -u "http://target.com/api/check" \
                   -w wordlists/users.txt \
                   -d '{"username":"FUZZ"}' \
                   -H "Content-Type: application/json" \
                   --user-agent-rotation \
                   --random-headers \
                   --proxy-file proxies.txt \
                   --proxy-rotation \
                   --jitter 0.5-1.5 \
                   -c 10

# WAF bypass example
python guesswho.py -u "https://protected-site.com/login" \
                   -w users.txt \
                   -d "username=FUZZ&password=test" \
                   --user-agent-rotation \
                   --random-headers \
                   --jitter 0.3-0.8 \
                   -c 20
```

**[📖 Complete Evasion Guide and Best Practices →](EVASION.md)**

## 🎛️ Command Line Options

### Required Arguments

- `-u, --url`: Target URL (use FUZZ or custom placeholder for username position)
- `-w, --wordlist`: Path to username/email wordlist file

### Request Configuration

- `-X, --method`: HTTP method (default: POST)
- `-d, --data`: Request body data (supports form data or JSON)
- `-H, --header`: Custom headers (can be used multiple times)
- `--cookie`: Cookie data
- `--placeholder`: Custom placeholder string (default: FUZZ)

### Evasion Options (NEW in v1.1.0)

- `--user-agent-rotation`: Enable User-Agent rotation (30+ signatures)
- `--user-agents-file FILE`: Custom User-Agent list file
- `--random-headers`: Randomize HTTP headers to avoid fingerprinting
- `--proxy URL`: Use proxy (http://host:port or socks5://host:port)
- `--proxy-file FILE`: File with proxy list (one per line)
- `--proxy-rotation`: Rotate through proxies instead of random selection
- `--jitter MIN-MAX`: Random delay between requests (e.g., "0.1-0.5" seconds)

### Performance Tuning

- `-c, --concurrency`: Number of concurrent requests (default: 50)
- `-t, --timeout`: Request timeout in seconds (default: 10)

### Analysis Configuration

- `--min-confidence`: Minimum confidence threshold 0.0-1.0 (default: 0.6)
  - 0.6 = Medium confidence (balanced)
  - 0.8 = High confidence (fewer false positives)
  - 0.4 = Low confidence (more results, may include false positives)

### Output Options

- `-o, --output`: Save results to file
- `-v, --verbose`: Enable verbose output (shows each request)
- `--no-banner`: Disable banner

## 🔬 How It Works

GuessWho uses multiple analysis techniques to identify valid usernames:

### 1. **Status Code Analysis** (80% confidence)
Detects when specific usernames receive different HTTP status codes compared to the majority.

### 2. **Response Timing Analysis** (60% confidence)
Identifies usernames with statistically significant response time differences (using z-score analysis).

### 3. **Content Length Analysis** (70% confidence)
Finds responses with different content lengths, indicating different backend logic paths.

### 4. **Pattern Matching** (90% confidence)
Searches for specific strings in response bodies:
- "user exists"
- "account found"
- "email sent"
- "password reset"
- "check your email"
- "already registered"
- "username taken"
- And more...

### 5. **Confidence Scoring**
Combines multiple indicators with bonuses for corroborating evidence, providing an overall confidence score for each finding.

## 📊 Understanding Results

### Confidence Levels

- **90-100%**: Very high confidence - multiple strong indicators
- **80-89%**: High confidence - strong single indicator or multiple medium indicators
- **70-79%**: Good confidence - reliable indicator present
- **60-69%**: Medium confidence - worth investigating

### Example Output

```
[+] Found 3 potential valid username(s):

[!] admin
    Confidence: 95%
    Indicators: Different status code (80%) | Pattern match: Password reset message (90%)

[!] support
    Confidence: 72%
    Indicators: Different content length (70%)

[!] john.doe
    Confidence: 85%
    Indicators: Response timing anomaly (60%) | Different status code (80%)
```

## 🛡️ Detection Techniques Explained

### Common User Enumeration Vulnerabilities

1. **Different Error Messages**
   - Invalid user: "Invalid username or password"
   - Valid user: "Invalid password"

2. **Different Status Codes**
   - Invalid user: 404 Not Found
   - Valid user: 401 Unauthorized

3. **Response Time Differences**
   - Invalid user: Fast response (no database lookup)
   - Valid user: Slower response (password verification)

4. **Different Response Lengths**
   - Different error messages result in different HTML lengths

5. **Specific Success Indicators**
   - "Password reset email sent"
   - "Check your email for verification link"
   - "Username already taken"

## 🎓 Use Cases

### Security Testing
- Penetration testing of authentication systems
- Bug bounty hunting
- Security audits
- Vulnerability assessment

### Common Vulnerable Endpoints
- `/login` - Login pages
- `/register` - Registration pages
- `/forgot-password` - Password reset
- `/api/users/check` - Username availability
- `/reset` - Account recovery
- `/verify` - Email verification

## ⚙️ Advanced Configuration

### Creating Custom Wordlists

```bash
# Generate email variations
echo "admin\ntest\nuser" | sed 's/$/@example.com/' > emails.txt

# Combine multiple wordlists
cat wordlist1.txt wordlist2.txt | sort -u > combined.txt
```

### Testing Multiple Endpoints

```bash
#!/bin/bash
# test-multiple.sh

endpoints=(
    "http://target.com/login"
    "http://target.com/register"
    "http://target.com/forgot-password"
)

for endpoint in "${endpoints[@]}"; do
    echo "Testing: $endpoint"
    python guesswho.py -u "$endpoint" -w wordlists/usernames.txt -d "username=FUZZ"
    echo "---"
done
```

### Performance Optimization

For best performance:
- Start with `-c 50` and increase if the server handles it well
- Use `-t 5` for faster timeouts if responses are typically quick
- Monitor your network connection and target server load
- Use `--min-confidence 0.8` to reduce noise in results

## 🚨 Ethical Usage

**IMPORTANT**: This tool is for authorized security testing only!

- ✅ Use on systems you own or have written permission to test
- ✅ Use for legitimate security assessments
- ✅ Use for educational purposes in controlled environments
- ❌ Do NOT use on systems without authorization
- ❌ Do NOT use for malicious purposes
- ❌ Do NOT perform DoS attacks (use reasonable concurrency)

**You are responsible for ensuring you have proper authorization before testing any system.**

## 📝 Troubleshooting

### No Results Found

1. Lower the confidence threshold: `--min-confidence 0.4`
2. Check if the endpoint is actually vulnerable
3. Verify your wordlist contains valid usernames
4. Enable verbose mode: `-v`

### Connection Errors

1. Check if the target is reachable: `curl <url>`
2. Verify SSL/TLS issues aren't blocking requests
3. Reduce concurrency: `-c 10`
4. Increase timeout: `-t 20`

### Rate Limiting

1. Reduce concurrency: `-c 5`
2. Add delays (modify code or use proxy)
3. Use different source IPs (advanced)

## 🔧 Development

### Project Structure

```
guesswho/
├── core/
│   ├── __init__.py      # Package initialization
│   ├── requester.py     # Async HTTP request handler
│   ├── analyzer.py      # Response analysis engine
│   └── fuzzer.py        # Main fuzzing coordinator
├── wordlists/
│   ├── usernames.txt    # Sample username wordlist
│   └── emails.txt       # Sample email wordlist
├── guesswho.py          # Main CLI interface
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

### Contributing

Contributions are welcome! Areas for improvement:
- Additional analysis techniques
- More response patterns
- Output formats (JSON, CSV, XML)
- Web UI
- Proxy support
- Plugin system

## 📜 License

This tool is provided for educational and authorized security testing purposes only.

## 🙏 Acknowledgments

Inspired by:
- ffuf - Fast web fuzzer
- gobuster - Directory/DNS/VHost busting tool
- Burp Suite Intruder - Web application security testing

## 📞 Support

For issues, questions, or contributions, please open an issue in the repository.

---

**Happy (Ethical) Hacking! 🔒**
