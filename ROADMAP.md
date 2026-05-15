# GuessWho - Development Roadmap 🗺️

This roadmap outlines the evolution of GuessWho from a user enumeration tool into a next-generation offensive security platform.

## 🎯 Vision
Transform GuessWho into the most advanced, intelligent, and comprehensive user enumeration and authentication testing framework - combining the speed of ffuf, the intelligence of AI, and the sophistication of commercial tools.

---

## 📊 Current Status (v1.0.0) ✅

**Completed Features:**
- ✅ Async HTTP fuzzing engine (1000+ req/s)
- ✅ 11 detection techniques (status, timing, length, patterns, headers, redirects, cookies, similarity, JSON structure, advanced timing, rate limiting)
- ✅ Intelligent confidence scoring system
- ✅ Verbose analysis mode
- ✅ Color-coded CLI output
- ✅ Basic statistics and reporting
- ✅ Test server for validation

---

## 🚀 Phase 1: Core Enhancements (Q2-Q3 2026)
**Focus:** Make it production-ready and add essential offensive capabilities

### 1.1 Multi-Protocol Support 🌐
**Priority: HIGH | Difficulty: MEDIUM**
- [ ] GraphQL query fuzzing with introspection
- [ ] WebSocket connection enumeration
- [ ] gRPC service testing
- [ ] SOAP/XML-RPC support
- [ ] Server-Sent Events (SSE) testing
**Dependencies:** None  
**Estimate:** 2-3 weeks

### 1.2 Advanced Evasion Techniques 🥷 ✅ COMPLETED
**Priority: CRITICAL | Difficulty: MEDIUM**
**Status:** ✅ Released in v1.1.0 (May 15, 2026)
**Documentation:** [EVASION.md](EVASION.md)

Completed Features:
- [x] User-Agent rotation (30+ real browser signatures) ✅
- [x] Proxy chain support (HTTP/SOCKS4/SOCKS5) ✅
- [x] Random timing/jitter between requests ✅
- [x] Header randomization and fingerprint evasion ✅

Future Enhancements (v1.2.0):
- [ ] HTTP/2 and HTTP/3 support
- [ ] TLS fingerprint randomization
- [ ] IPv6 support
- [ ] Expand User-Agent database to 1000+ signatures

**Implementation:**
- `core/evasion.py`: Complete evasion framework (280+ lines)
- 7 new CLI options: `--user-agent-rotation`, `--user-agents-file`, `--random-headers`, `--proxy`, `--proxy-file`, `--proxy-rotation`, `--jitter`
- Integrated into requester and fuzzer modules
- Zero performance overhead when disabled
- Composable evasion techniques (combine multiple methods)

**Dependencies:** None  
**Estimate:** 2 weeks

### 1.3 Session & Authentication Management 🔐
**Priority: HIGH | Difficulty: MEDIUM**
- [ ] Automatic CSRF token extraction and refresh
- [ ] Session cookie lifecycle management
- [ ] JWT token handling and refresh
- [ ] Multi-step authentication flow support
- [ ] OAuth2/OIDC flow enumeration
- [ ] API key rotation support
**Dependencies:** None  
**Estimate:** 2-3 weeks

### 1.4 Multi-Endpoint Correlation 🔗
**Priority: HIGH | Difficulty: MEDIUM**
- [ ] YAML/JSON configuration for multiple endpoints
- [ ] Parallel testing of login/register/forgot-password
- [ ] Cross-endpoint result correlation
- [ ] Confidence boosting from multiple sources
- [ ] Automatic endpoint discovery
**Dependencies:** None  
**Estimate:** 2 weeks

### 1.5 Professional Reporting 📊
**Priority: HIGH | Difficulty: EASY-MEDIUM**
- [ ] HTML report generation with charts
- [ ] PDF export functionality
- [ ] JSON/CSV/XML export formats
- [ ] HAR file export (HTTP Archive)
- [ ] Response diff visualization
- [ ] Screenshot evidence capture
- [ ] Timeline visualization
- [ ] Executive summary + technical details
**Dependencies:** None  
**Estimate:** 1-2 weeks

### 1.6 Enhanced CLI Features ⚡
**Priority: MEDIUM | Difficulty: EASY**
- [ ] Interactive mode with progress pausing
- [ ] Resume from checkpoint
- [ ] Dry-run mode for testing configs
- [ ] Auto-tuning concurrency based on target
- [ ] Colorized output themes
- [ ] Progress export to file
**Dependencies:** None  
**Estimate:** 1 week

### 1.7 Rate Limiting & Safety 🛡️
**Priority: MEDIUM | Difficulty: EASY**
- [ ] Configurable rate limits (max req/sec, req/hour)
- [ ] Automatic backoff on rate limit detection
- [ ] Domain whitelist/blacklist
- [ ] Safety mode (max 100 req/min)
- [ ] Target health monitoring
- [ ] Legal disclaimer integration
**Dependencies:** None  
**Estimate:** 1 week

---

## 🧠 Phase 2: Intelligence Layer (Q4 2026)
**Focus:** Add AI/ML and OSINT capabilities

### 2.1 OSINT Integration 🕵️
**Priority: HIGH | Difficulty: MEDIUM**
- [ ] HaveIBeenPwned API integration
- [ ] LinkedIn employee enumeration (via API/scraping)
- [ ] GitHub user discovery
- [ ] Breach database correlation
- [ ] Domain WHOIS/DNS intelligence
- [ ] Certificate transparency log mining
- [ ] Google dork automation
- [ ] Company email pattern detection
**Dependencies:** None  
**Estimate:** 3 weeks

### 2.2 Browser Automation 🌐
**Priority: HIGH | Difficulty: HARD**
- [ ] Playwright/Puppeteer integration
- [ ] JavaScript-rendered content handling
- [ ] CAPTCHA detection and notification
- [ ] Screenshot capture for evidence
- [ ] DOM analysis for dynamic content
- [ ] Form auto-detection and submission
- [ ] Cookie/LocalStorage extraction
**Dependencies:** None  
**Estimate:** 3-4 weeks

### 2.3 Machine Learning Models 🤖
**Priority: MEDIUM | Difficulty: HARD**
- [ ] Train anomaly detection model on real data
- [ ] Unsupervised clustering for outlier detection
- [ ] NLP for error message semantic analysis
- [ ] Transformer models for response classification
- [ ] Predictive modeling for likely valid usernames
- [ ] Pre-trained models for common patterns
**Dependencies:** Large dataset collection  
**Estimate:** 4-6 weeks

### 2.4 Active Learning System 🎓
**Priority: MEDIUM | Difficulty: HARD**
- [ ] Learn from early responses
- [ ] Adaptive strategy adjustment
- [ ] Auto-detect best detection method
- [ ] Early stopping on no vulnerability
- [ ] Intelligent concurrency tuning
- [ ] Smart wordlist filtering
**Dependencies:** 2.3 (ML Models)  
**Estimate:** 2-3 weeks

### 2.5 Wordlist Intelligence 📚
**Priority: MEDIUM | Difficulty: MEDIUM**
- [ ] Smart wordlist generation from OSINT
- [ ] Company-specific pattern generation
- [ ] Name permutation engine
- [ ] Email format detection and generation
- [ ] Wordlist quality scoring
- [ ] Contextual wordlist recommendations
**Dependencies:** 2.1 (OSINT)  
**Estimate:** 2 weeks

### 2.6 Threat Intelligence 🎯
**Priority: LOW | Difficulty: MEDIUM**
- [ ] Integration with threat intel feeds
- [ ] Known vulnerable software detection
- [ ] CVE correlation for endpoints
- [ ] Attack surface mapping
- [ ] Vulnerability scoring
**Dependencies:** None  
**Estimate:** 2 weeks

---

## ☁️ Phase 3: Scale & Performance (Q1 2027)
**Focus:** Distributed architecture and high performance

### 3.1 Distributed Architecture 🏗️
**Priority: HIGH | Difficulty: HARD**
- [ ] Redis/RabbitMQ job queuing
- [ ] Multi-worker coordination
- [ ] Distributed IP rotation
- [ ] Master/worker architecture
- [ ] Result aggregation across workers
- [ ] Fault tolerance and failover
**Dependencies:** None  
**Estimate:** 4-5 weeks

### 3.2 Cloud Deployment ☁️
**Priority: MEDIUM | Difficulty: HARD**
- [ ] Docker containerization
- [ ] Kubernetes deployment manifests
- [ ] AWS Lambda serverless mode
- [ ] Google Cloud Run support
- [ ] Azure Functions support
- [ ] Terraform infrastructure as code
- [ ] Helm charts for K8s
**Dependencies:** 3.1 (Distributed)  
**Estimate:** 3-4 weeks

### 3.3 Real-Time Dashboard 📈
**Priority: MEDIUM | Difficulty: HARD**
- [ ] React/Vue web interface
- [ ] WebSocket real-time updates
- [ ] Live progress visualization
- [ ] Result streaming
- [ ] Resource monitoring
- [ ] Queue management UI
- [ ] Remote control (pause/resume/kill)
**Dependencies:** None  
**Estimate:** 4-5 weeks

### 3.4 Performance Optimization ⚡
**Priority: MEDIUM | Difficulty: MEDIUM**
- [ ] Connection pooling optimization
- [ ] Memory usage profiling and reduction
- [ ] Response caching layer
- [ ] Batch processing optimization
- [ ] Async I/O improvements
- [ ] Multi-core utilization
**Dependencies:** None  
**Estimate:** 2 weeks

### 3.5 Database Backend 💾
**Priority: LOW | Difficulty: MEDIUM**
- [ ] PostgreSQL for result storage
- [ ] MongoDB for document storage
- [ ] Time-series database for metrics
- [ ] Full-text search for responses
- [ ] Historical result comparison
**Dependencies:** None  
**Estimate:** 2-3 weeks

---

## 🔌 Phase 4: Ecosystem & Integration (Q2 2027)
**Focus:** Extensibility and integration with existing tools

### 4.1 Plugin System 🧩
**Priority: HIGH | Difficulty: MEDIUM-HARD**
- [ ] Plugin API specification
- [ ] Custom analyzer plugins
- [ ] Wordlist generator plugins
- [ ] Response processor plugins
- [ ] Export format plugins
- [ ] Integration plugins
- [ ] Plugin marketplace/registry
**Dependencies:** None  
**Estimate:** 3-4 weeks

### 4.2 Security Tool Integration 🔧
**Priority: HIGH | Difficulty: MEDIUM**
- [ ] Burp Suite extension
- [ ] OWASP ZAP addon
- [ ] Metasploit module
- [ ] Nuclei template support
- [ ] Nmap script engine integration
- [ ] Import/export with other tools
**Dependencies:** None  
**Estimate:** 3 weeks

### 4.3 CI/CD Integration 🔄
**Priority: MEDIUM | Difficulty: EASY-MEDIUM**
- [ ] GitHub Actions workflow
- [ ] GitLab CI templates
- [ ] Jenkins plugin
- [ ] CircleCI orb
- [ ] Azure DevOps task
- [ ] Slack/Teams/Discord notifications
- [ ] Baseline comparison for regression testing
**Dependencies:** None  
**Estimate:** 2 weeks

### 4.4 REST API 🌐
**Priority: MEDIUM | Difficulty: MEDIUM**
- [ ] RESTful API for programmatic access
- [ ] API authentication (JWT/API keys)
- [ ] Job submission and management
- [ ] Result retrieval
- [ ] OpenAPI/Swagger documentation
- [ ] Rate limiting on API
- [ ] Webhook support for notifications
**Dependencies:** None  
**Estimate:** 2-3 weeks

### 4.5 Python SDK & CLI Improvements 📦
**Priority: LOW | Difficulty: EASY-MEDIUM**
- [ ] Python library/SDK
- [ ] Pip package distribution
- [ ] Homebrew formula
- [ ] Chocolatey package (Windows)
- [ ] Snap package (Linux)
- [ ] Auto-update mechanism
**Dependencies:** None  
**Estimate:** 1-2 weeks

### 4.6 Documentation & Community 📚
**Priority: HIGH | Difficulty: EASY-MEDIUM**
- [ ] Comprehensive documentation site (MkDocs/Docusaurus)
- [ ] Video tutorials
- [ ] Example configurations repository
- [ ] Community plugins repository
- [ ] Contributing guidelines
- [ ] Code of conduct
- [ ] Security disclosure policy
- [ ] Blog/case studies
**Dependencies:** None  
**Estimate:** 2-3 weeks

---

## 🎨 Phase 5: Advanced Features (Q3-Q4 2027)
**Focus:** Cutting-edge capabilities

### 5.1 Advanced Authentication Testing 🎭
**Priority: MEDIUM | Difficulty: HARD**
- [ ] Multi-step registration wizard handling
- [ ] Email verification bypass detection
- [ ] Social login enumeration (Google, FB, etc.)
- [ ] SSO/SAML enumeration
- [ ] LDAP/Active Directory testing
- [ ] Biometric authentication analysis
- [ ] MFA/2FA testing
**Dependencies:** 2.2 (Browser Automation)  
**Estimate:** 4-5 weeks

### 5.2 Automated Exploitation 💥
**Priority: LOW | Difficulty: HARD**
- [ ] Auto-exploit confirmed enumerations
- [ ] Password spraying automation
- [ ] Credential stuffing mode
- [ ] Account takeover chains
- [ ] Privilege escalation testing
- [ ] Session hijacking detection
**Dependencies:** Multiple  
**Estimate:** 3-4 weeks

### 5.3 AI-Powered Testing 🤖
**Priority: LOW | Difficulty: HARD**
- [ ] GPT integration for response analysis
- [ ] Automated test case generation
- [ ] Natural language query interface
- [ ] Smart report generation with insights
- [ ] Anomaly explanation via LLM
**Dependencies:** 2.3 (ML Models)  
**Estimate:** 3-4 weeks

### 5.4 Compliance & Audit 📋
**Priority: MEDIUM | Difficulty: MEDIUM**
- [ ] OWASP Top 10 mapping
- [ ] CWE/CVE references
- [ ] Compliance framework mapping (PCI-DSS, HIPAA, etc.)
- [ ] Audit trail and logging
- [ ] Evidence chain of custody
- [ ] Legal report templates
**Dependencies:** None  
**Estimate:** 2 weeks

---

## 📈 Success Metrics

### Phase 1 Success Criteria
- [ ] 5000+ req/sec throughput
- [ ] <1% false positive rate
- [ ] Support 10+ protocols
- [ ] Professional reports rated 9/10+

### Phase 2 Success Criteria
- [ ] 95%+ detection accuracy with ML
- [ ] OSINT reduces testing time by 50%
- [ ] JavaScript apps fully supported

### Phase 3 Success Criteria
- [ ] Linear scaling to 100+ workers
- [ ] Cloud deployment < 5 minutes
- [ ] Real-time dashboard sub-second updates

### Phase 4 Success Criteria
- [ ] 50+ community plugins
- [ ] Integration with top 5 security tools
- [ ] 10,000+ PyPI downloads/month

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

1. **Pick an issue** from the roadmap
2. **Comment** to claim it
3. **Fork and develop**
4. **Submit PR** with tests
5. **Get reviewed** and merged

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## 📞 Support & Discussion

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and community chat
- **Discord**: Real-time chat (coming soon)
- **Twitter**: Updates and announcements

---

## 📅 Release Schedule

- **v1.1.0** (Aug 2026): Phase 1 Complete
- **v2.0.0** (Jan 2027): Phase 2 Complete
- **v3.0.0** (Jun 2027): Phase 3 Complete
- **v4.0.0** (Nov 2027): Phase 4 Complete
- **v5.0.0** (Q4 2027): Phase 5 Complete

---

**Last Updated:** May 15, 2026  
**Current Version:** 1.0.0  
**Stars:** ⭐ Help us reach 1000 stars!
