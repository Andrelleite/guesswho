# Testing GuessWho

This guide shows you how to test GuessWho to see it in action.

## Option 1: Local Test Server (Recommended)

We've included a test server with intentional user enumeration vulnerabilities.

### Setup

```bash
# Install Flask
pip install flask

# Or use the test requirements file
pip install -r test_requirements.txt
```

### Run the Test Server

```bash
python test_server.py
```

The server will start on `http://localhost:5000` with these vulnerable endpoints:
- **Valid users**: admin, john, sarah, user, test, support
- **Valid emails**: admin@example.com, john@example.com, support@example.com

### Test Cases

Open a new terminal and run these tests:

#### 1. Status Code Enumeration
```bash
python guesswho.py -u "http://localhost:5000/login" \
                   -w wordlists/usernames.txt \
                   -d "username=FUZZ&password=wrongpass"
```
**Expected**: Should find admin, john, sarah, user, test, support (different status codes)

#### 2. Timing-Based Enumeration
```bash
python guesswho.py -u "http://localhost:5000/login-timing" \
                   -w wordlists/usernames.txt \
                   -d "username=FUZZ&password=test" \
                   -c 10
```
**Expected**: Should detect valid users by response time differences (use lower concurrency for timing tests)

#### 3. Message-Based Enumeration (Forgot Password)
```bash
python guesswho.py -u "http://localhost:5000/forgot-password" \
                   -w wordlists/emails.txt \
                   -d "email=FUZZ"
```
**Expected**: Should find valid emails by detecting "password reset" messages

#### 4. Content Length Enumeration (Registration)
```bash
python guesswho.py -u "http://localhost:5000/register" \
                   -w wordlists/usernames.txt \
                   -d "username=FUZZ"
```
**Expected**: Should find existing users by response length differences

#### 5. REST API Enumeration (GET Request)
```bash
python guesswho.py -u "http://localhost:5000/api/user/FUZZ" \
                   -w wordlists/usernames.txt \
                   -X GET
```
**Expected**: Should find valid users via status code differences

#### 6. Secure Endpoint (Should NOT Find Users)
```bash
python guesswho.py -u "http://localhost:5000/secure-login" \
                   -w wordlists/usernames.txt \
                   -d "username=FUZZ&password=test"
```
**Expected**: Should find NO valid users (proper implementation)

### High Performance Test

```bash
python guesswho.py -u "http://localhost:5000/login" \
                   -w wordlists/usernames.txt \
                   -d "username=FUZZ&password=test" \
                   -c 50 \
                   -v
```

## Option 2: Public Vulnerable Apps

You can also test against intentionally vulnerable applications (make sure you have permission):

### DVWA (Damn Vulnerable Web Application)

```bash
# Install DVWA with Docker
docker run --rm -it -p 80:80 vulnerables/web-dvwa

# Test login
python guesswho.py -u "http://localhost/login.php" \
                   -w wordlists/usernames.txt \
                   -d "username=FUZZ&password=test"
```

### WebGoat

```bash
# Install WebGoat
docker run -p 8080:8080 webgoat/webgoat

# Test various endpoints
python guesswho.py -u "http://localhost:8080/WebGoat/login" \
                   -w wordlists/usernames.txt \
                   -d "username=FUZZ&password=test"
```

### OWASP Juice Shop

```bash
# Install Juice Shop
docker run -p 3000:3000 bkimminich/juice-shop

# Test registration endpoint
python guesswho.py -u "http://localhost:3000/api/Users" \
                   -w wordlists/emails.txt \
                   -d '{"email":"FUZZ","password":"Test123!"}' \
                   -H "Content-Type: application/json"
```

## Option 3: Manual Test (No Server Needed)

Test the tool's basic functionality:

```bash
# This will fail to connect, but you can verify the tool runs
python guesswho.py -u "http://httpbin.org/post" \
                   -w wordlists/usernames.txt \
                   -d "username=FUZZ" \
                   -c 5
```

## Understanding Results

### Good Detection (High Confidence)
```
[!] admin
    Confidence: 95%
    Indicators: Different status code (80%) | Pattern match: Password reset message (90%)
```
This is a strong finding with multiple indicators.

### Medium Confidence
```
[!] john
    Confidence: 70%
    Indicators: Different content length (70%)
```
Worth investigating but verify manually.

### Low Confidence
Below 60% confidence won't be shown by default. Use `--min-confidence 0.4` to see them.

## Troubleshooting

### No Results Found
```bash
# Lower confidence threshold
python guesswho.py -u "http://localhost:5000/login" \
                   -w wordlists/usernames.txt \
                   -d "username=FUZZ&password=test" \
                   --min-confidence 0.4
```

### See What's Happening
```bash
# Enable verbose mode
python guesswho.py -u "http://localhost:5000/login" \
                   -w wordlists/usernames.txt \
                   -d "username=FUZZ&password=test" \
                   -v
```

### Connection Issues
```bash
# Reduce concurrency and increase timeout
python guesswho.py -u "http://localhost:5000/login" \
                   -w wordlists/usernames.txt \
                   -d "username=FUZZ&password=test" \
                   -c 5 \
                   -t 20
```

## Performance Benchmarks

Test the tool's speed:

```bash
# Time a test run
time python guesswho.py -u "http://localhost:5000/login" \
                        -w wordlists/usernames.txt \
                        -d "username=FUZZ&password=test"
```

With the default wordlist (35 users) and concurrency of 50:
- Expected time: 1-3 seconds
- Requests per second: 10-35 req/s (depends on endpoint)

## Creating Custom Test Wordlists

```bash
# Create a larger test wordlist
cat wordlists/usernames.txt wordlists/usernames.txt wordlists/usernames.txt > wordlists/test-large.txt

# Test with larger list
python guesswho.py -u "http://localhost:5000/login" \
                   -w wordlists/test-large.txt \
                   -d "username=FUZZ&password=test" \
                   -c 100
```

## Next Steps

1. Start the test server: `python test_server.py`
2. Run the test cases above
3. Try different configurations (concurrency, confidence thresholds)
4. Create custom wordlists for your use case
5. Test against your own authorized targets

Remember: Only test systems you own or have explicit permission to test!
