# 🥷 Phase 1.2: Advanced Evasion Techniques - COMPLETED ✅

GuessWho v1.1.0 now includes sophisticated evasion techniques to avoid detection during user enumeration testing.

## 🚀 New Features

### 1. User-Agent Rotation
Automatically rotate through 30+ real browser signatures to avoid fingerprinting.

```bash
# Use built-in User-Agent database
python guesswho.py -u "http://target.com/login" -w users.txt -d "user=FUZZ" --user-agent-rotation

# Use custom User-Agent file
python guesswho.py -u "http://target.com/login" -w users.txt -d "user=FUZZ" --user-agents-file my-agents.txt
```

**Built-in User-Agents include:**
- Chrome (Windows, macOS, Linux, Android)
- Firefox (Windows, macOS, Linux)
- Safari (macOS, iOS)
- Edge (Windows, macOS)
- Opera, Brave, and more

### 2. Proxy Support
Route requests through proxy chains (HTTP/SOCKS4/SOCKS5) with rotation or random selection.

```bash
# Single proxy
python guesswho.py -u "http://target.com/login" -w users.txt -d "user=FUZZ" --proxy http://proxy.com:8080

# Proxy list with rotation
python guesswho.py -u "http://target.com/login" -w users.txt -d "user=FUZZ" --proxy-file proxies.txt --proxy-rotation

# Proxy list with random selection
python guesswho.py -u "http://target.com/login" -w users.txt -d "user=FUZZ" --proxy-file proxies.txt
```

**Proxy Format (proxies.txt):**
```
http://proxy1.example.com:8080
http://proxy2.example.com:3128
socks5://proxy3.example.com:1080
```

### 3. Header Randomization
Randomize HTTP headers to avoid fingerprinting:
- `Accept-Language` (10+ language combinations)
- `Accept-Encoding` (gzip, deflate, br variations)
- `Accept` (multiple MIME type preferences)
- `DNT` (Do Not Track)
- `Sec-Fetch-*` headers

```bash
python guesswho.py -u "http://target.com/login" -w users.txt -d "user=FUZZ" --random-headers
```

### 4. Timing Jitter
Add random delays between requests to avoid pattern detection.

```bash
# Random delay between 0.1 and 0.5 seconds
python guesswho.py -u "http://target.com/login" -w users.txt -d "user=FUZZ" --jitter 0.1-0.5

# Random delay between 0.5 and 2.0 seconds (stealth mode)
python guesswho.py -u "http://target.com/login" -w users.txt -d "user=FUZZ" --jitter 0.5-2.0
```

## 🔥 Combined Evasion

Use multiple techniques together for maximum stealth:

```bash
python guesswho.py \
  -u "http://target.com/login" \
  -w users.txt \
  -d "username=FUZZ&password=test123" \
  --user-agent-rotation \
  --random-headers \
  --proxy-file proxies.txt \
  --proxy-rotation \
  --jitter 0.2-0.8 \
  -c 20
```

**Output:**
```
[*] Evasion techniques enabled
[*] User-Agent Rotation: 30 signatures
[*] Proxy: 5 proxies (rotating)
[*] Header Randomization: Enabled
[*] Timing Jitter: 0.2-0.8s
[*] Starting enumeration...
```

## 📊 Performance Impact

| Technique | Speed Impact | Detection Avoidance |
|-----------|-------------|---------------------|
| User-Agent Rotation | ~0% | ⭐⭐⭐ |
| Header Randomization | ~0% | ⭐⭐⭐ |
| Proxy (no rotation) | ~10-50% | ⭐⭐⭐⭐ |
| Proxy (with rotation) | ~10-50% | ⭐⭐⭐⭐⭐ |
| Jitter (0.1-0.5s) | ~50% | ⭐⭐⭐⭐ |
| Jitter (0.5-2.0s) | ~80% | ⭐⭐⭐⭐⭐ |

## 🎯 Best Practices

### Stealth Mode (Maximum Evasion)
```bash
python guesswho.py \
  -u "http://target.com/api/check-user" \
  -w users.txt \
  -d '{"email":"FUZZ@company.com"}' \
  -H "Content-Type: application/json" \
  --user-agent-rotation \
  --random-headers \
  --proxy-file proxies.txt \
  --proxy-rotation \
  --jitter 1.0-3.0 \
  -c 10
```

### Balanced Mode (Speed + Evasion)
```bash
python guesswho.py \
  -u "http://target.com/login" \
  -w users.txt \
  -d "user=FUZZ&pass=test" \
  --user-agent-rotation \
  --random-headers \
  --jitter 0.1-0.3 \
  -c 30
```

### Speed Mode (Minimal Evasion)
```bash
python guesswho.py \
  -u "http://target.com/login" \
  -w users.txt \
  -d "user=FUZZ&pass=test" \
  --user-agent-rotation \
  -c 100
```

## 🔍 Detection Bypass

### WAF/IDS Evasion
- **User-Agent rotation**: Defeats signature-based detection
- **Header randomization**: Breaks fingerprinting patterns
- **Timing jitter**: Avoids rate-based detection
- **Proxy rotation**: Bypasses IP-based blocking

### Rate Limiting
- Use `--jitter` with appropriate delays
- Reduce concurrency (`-c 10` or less)
- Use `--proxy-rotation` to distribute across IPs

### Example: Bypassing Cloudflare
```bash
python guesswho.py \
  -u "https://target.com/api/login" \
  -w users.txt \
  -d '{"username":"FUZZ","password":"test"}' \
  -H "Content-Type: application/json" \
  -H "Origin: https://target.com" \
  -H "Referer: https://target.com/login" \
  --user-agent-rotation \
  --random-headers \
  --jitter 0.5-1.5 \
  -c 5
```

## 📝 Creating Custom User-Agent Files

Create `my-agents.txt`:
```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15
Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0
# Add more User-Agents...
```

Use it:
```bash
python guesswho.py -u "http://target.com/api" -w users.txt --user-agents-file my-agents.txt
```

## 🚨 Ethical Usage

⚠️ **WARNING**: Evasion techniques should only be used for:
- Authorized penetration testing
- Bug bounty programs (within scope)
- Security research on your own systems

**DO NOT** use these features to:
- Attack systems without authorization
- Bypass security controls maliciously
- Evade detection for illegal activities

## 🎓 Technical Implementation

The evasion system is built with:
- **`core/evasion.py`**: Modular evasion framework
- **`UserAgentRotator`**: 30+ real browser signatures
- **`ProxyManager`**: HTTP/SOCKS4/SOCKS5 support with rotation
- **`HeaderRandomizer`**: Intelligent header variation
- **`TimingJitter`**: Async random delays
- **`EvasionManager`**: Centralized coordination

All techniques are:
- ✅ Async/await compatible
- ✅ Zero performance overhead (when disabled)
- ✅ Configurable and composable
- ✅ Thread-safe for concurrent operations

## 🔄 Roadmap Integration

✅ **Phase 1.2: Advanced Evasion Techniques** (COMPLETED)
- [x] User-Agent rotation (30+ real signatures)
- [x] Proxy chain support (HTTP/SOCKS4/SOCKS5)
- [x] Random timing/jitter between requests
- [x] Header randomization and fingerprint evasion
- [ ] HTTP/2 and HTTP/3 support (coming in v1.2.0)
- [ ] TLS fingerprint randomization (coming in v1.2.0)
- [ ] IPv6 support (coming in v1.2.0)

---

**Version:** 1.1.0  
**Phase:** 1.2 - Advanced Evasion Techniques  
**Status:** ✅ RELEASED  
**Date:** May 15, 2026
