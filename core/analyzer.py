"""
Response Analyzer Module
Analyzes HTTP responses to detect user enumeration vulnerabilities
"""

from typing import List, Dict, Set, Tuple
from collections import defaultdict, Counter
import statistics
import json
import Levenshtein
from sklearn.cluster import DBSCAN
import numpy as np
from .requester import Response


class ResponseAnalyzer:
    """Analyzes responses to detect valid usernames"""
    
    def __init__(self, verbose: bool = False):
        """
        Initialize the analyzer
        
        Args:
            verbose: Enable verbose output
        """
        self.verbose = verbose
        self.responses: List[Response] = []
        
    def add_response(self, response: Response):
        """Add a response to analyze"""
        self.responses.append(response)
        
    def analyze(self, min_confidence: float = 0.6) -> List[Tuple[str, float, str]]:
        """
        Analyze all responses and identify potential valid usernames
        
        Args:
            min_confidence: Minimum confidence score (0.0-1.0) to report
            
        Returns:
            List of tuples (username, confidence_score, reason)
        """
        if len(self.responses) < 2:
            return []
            
        if self.verbose:
            print("\n" + "="*70)
            print("[VERBOSE] Starting Response Analysis")
            print("="*70)
            
        results = []
        
        # Analyze by different techniques
        if self.verbose:
            print("\n[1/11] Analyzing status codes...")
        status_outliers = self._analyze_status_codes()
        if self.verbose:
            print(f"      Found {len(status_outliers)} outliers: {status_outliers if status_outliers else 'None'}")
            
        if self.verbose:
            print("\n[2/11] Analyzing response timing...")
        timing_outliers = self._analyze_timing()
        if self.verbose:
            print(f"      Found {len(timing_outliers)} outliers: {timing_outliers if timing_outliers else 'None'}")
            
        if self.verbose:
            print("\n[3/11] Analyzing content lengths...")
        length_outliers = self._analyze_content_length()
        if self.verbose:
            print(f"      Found {len(length_outliers)} outliers: {length_outliers if length_outliers else 'None'}")
            
        if self.verbose:
            print("\n[4/11] Analyzing body patterns...")
        pattern_matches = self._analyze_body_patterns()
        if self.verbose:
            print(f"      Found {len(pattern_matches)} matches: {[u for u, _ in pattern_matches] if pattern_matches else 'None'}")
            
        if self.verbose:
            print("\n[5/11] Analyzing HTTP headers...")
        header_outliers = self._analyze_headers()
        if self.verbose:
            print(f"      Found {len(header_outliers)} outliers: {[u for u, _ in header_outliers] if header_outliers else 'None'}")
            
        if self.verbose:
            print("\n[6/11] Analyzing redirect chains...")
        redirect_outliers = self._analyze_redirects()
        if self.verbose:
            print(f"      Found {len(redirect_outliers)} outliers: {[u for u, _ in redirect_outliers] if redirect_outliers else 'None'}")
            
        if self.verbose:
            print("\n[7/11] Analyzing cookies...")
        cookie_outliers = self._analyze_cookies()
        if self.verbose:
            print(f"      Found {len(cookie_outliers)} outliers: {[u for u, _ in cookie_outliers] if cookie_outliers else 'None'}")
            
        if self.verbose:
            print("\n[8/11] Analyzing response similarity...")
        similarity_outliers = self._analyze_response_similarity()
        if self.verbose:
            print(f"      Found {len(similarity_outliers)} outliers: {similarity_outliers if similarity_outliers else 'None'}")
            
        if self.verbose:
            print("\n[9/11] Analyzing JSON/XML structure...")
        structure_outliers = self._analyze_json_structure()
        if self.verbose:
            print(f"      Found {len(structure_outliers)} outliers: {[u for u, _ in structure_outliers] if structure_outliers else 'None'}")
            
        if self.verbose:
            print("\n[10/11] Analyzing advanced timing patterns...")
        timing_histogram_outliers = self._analyze_timing_histogram()
        if self.verbose:
            print(f"      Found {len(timing_histogram_outliers)} outliers: {timing_histogram_outliers if timing_histogram_outliers else 'None'}")
            
        if self.verbose:
            print("\n[11/11] Detecting rate limiting...")
        rate_limit_indicators = self._detect_rate_limiting()
        if self.verbose:
            print(f"      Found {len(rate_limit_indicators)} indicators: {[u for u, _ in rate_limit_indicators] if rate_limit_indicators else 'None'}")
        
        # Combine results with confidence scoring
        all_findings = defaultdict(list)
        
        for username in status_outliers:
            all_findings[username].append(("Different status code", 0.8))
            
        for username in timing_outliers:
            all_findings[username].append(("Response timing anomaly", 0.6))
            
        for username in length_outliers:
            all_findings[username].append(("Different content length", 0.7))
            
        for username, pattern in pattern_matches:
            all_findings[username].append((f"Pattern match: {pattern}", 0.9))
            
        for username, reason in header_outliers:
            all_findings[username].append((f"Header difference: {reason}", 0.75))
            
        for username, reason in redirect_outliers:
            all_findings[username].append((f"Redirect pattern: {reason}", 0.85))
            
        for username, reason in cookie_outliers:
            all_findings[username].append((f"Cookie difference: {reason}", 0.70))
            
        for username in similarity_outliers:
            all_findings[username].append(("Response content differs significantly", 0.75))
            
        for username, reason in structure_outliers:
            all_findings[username].append((f"JSON/XML structure: {reason}", 0.80))
            
        for username in timing_histogram_outliers:
            all_findings[username].append(("Advanced timing analysis outlier", 0.65))
            
        for username, reason in rate_limit_indicators:
            all_findings[username].append((f"Rate limiting: {reason}", 0.60))
            
        # Calculate confidence scores
        if self.verbose:
            print("\n" + "="*70)
            print("[VERBOSE] Confidence Scoring")
            print("="*70)
            
        for username, findings in all_findings.items():
            # Combine confidence scores with sophisticated scoring
            # Use weighted average of top 3 scores + bonus for multiple indicators
            scores = sorted([score for _, score in findings], reverse=True)
            
            if len(scores) == 1:
                base_score = scores[0]
                bonus = 0
            elif len(scores) == 2:
                base_score = scores[0] * 0.7 + scores[1] * 0.3
                bonus = 0.10  # 10% bonus for 2 indicators
            else:
                # Weight top 3 scores
                base_score = scores[0] * 0.5 + scores[1] * 0.3 + scores[2] * 0.2
                bonus = min(0.10 + 0.05 * (len(scores) - 2), 0.25)  # Up to 25% bonus
            
            confidence = min(base_score + bonus, 1.0)
            
            if self.verbose:
                print(f"\n{username}:")
                print(f"  Indicators: {len(findings)}")
                for reason, score in findings:
                    print(f"    - {reason}: {score:.0%}")
                scores = sorted([score for _, score in findings], reverse=True)
                print(f"  Top scores: {', '.join(f'{s:.0%}' for s in scores[:3])}")
                if len(scores) == 1:
                    print(f"  Base score: {scores[0]:.0%}")
                    print(f"  Bonus: +0% (single indicator)")
                elif len(scores) == 2:
                    base = scores[0] * 0.7 + scores[1] * 0.3
                    print(f"  Base score: {base:.0%} (weighted average)")
                    print(f"  Bonus: +10% (2 indicators)")
                else:
                    base = scores[0] * 0.5 + scores[1] * 0.3 + scores[2] * 0.2
                    bonus_calc = min(0.10 + 0.05 * (len(scores) - 2), 0.25)
                    print(f"  Base score: {base:.0%} (weighted top 3)")
                    print(f"  Bonus: +{bonus_calc:.0%} ({len(scores)} indicators)")
                print(f"  Final confidence: {confidence:.0%}")
                if confidence >= min_confidence:
                    print(f"  ✓ REPORTED (threshold: {min_confidence:.0%})")
                else:
                    print(f"  ✗ FILTERED OUT (below threshold: {min_confidence:.0%})")
            
            if confidence >= min_confidence:
                reasons = " | ".join(f"{reason} ({score:.0%})" for reason, score in findings)
                results.append((username, confidence, reasons))
                
        # Sort by confidence
        results.sort(key=lambda x: x[1], reverse=True)
        
        return results
        
    def _analyze_status_codes(self) -> Set[str]:
        """Find usernames with different status codes.
        5xx responses (server errors) are treated as unreliable noise and excluded
        from the baseline calculation — only 2xx/3xx/4xx are used.
        """
        status_counts = Counter(r.status_code for r in self.responses)

        if self.verbose:
            print(f"      Status code distribution: {dict(status_counts)}")

        # Warn if server is overwhelmed (lots of 5xx)
        total = len(self.responses)
        server_errors = sum(1 for r in self.responses if 500 <= r.status_code < 600)
        if server_errors > total * 0.3:
            if self.verbose:
                print(f"      [!] WARNING: {server_errors}/{total} responses are 5xx server errors")
                print(f"      [!] Server may be overloaded — try reducing concurrency (-c 5 or -c 1)")
                print(f"      [!] Retries attempted automatically, but some may still be 5xx")

        # Use only reliable responses (non-5xx, non-format-error 400s) for baseline
        reliable = [r for r in self.responses if self._reliable(r)]
        if not reliable:
            # All responses were noise — fall back to full set
            reliable = [r for r in self.responses if r.status_code > 0]

        reliable_counts = Counter(r.status_code for r in reliable)
        most_common_status = reliable_counts.most_common(1)[0][0] if reliable_counts else 0

        if self.verbose:
            print(f"      Reliable status baseline: {most_common_status} ({reliable_counts.get(most_common_status, 0)} occurrences, noise excluded)")

        outliers = set()
        for response in self.responses:
            if not self._reliable(response):
                continue  # noise (5xx or format-error 400) — never a valid-user signal
            if response.status_code != most_common_status:
                outliers.add(response.username)
                if self.verbose:
                    print(f"      → {response.username}: status {response.status_code} (differs from baseline {most_common_status})")

        return outliers
        
    def _analyze_timing(self) -> Set[str]:
        """Find usernames with unusual response times"""
        valid_times = [r.response_time for r in self.responses if self._reliable(r)]
        
        if len(valid_times) < 3:
            if self.verbose:
                print(f"      Skipped: Need at least 3 valid responses (got {len(valid_times)})")
            return set()
            
        mean_time = statistics.mean(valid_times)
        
        try:
            stdev_time = statistics.stdev(valid_times)
        except statistics.StatisticsError:
            if self.verbose:
                print("      Skipped: Cannot calculate standard deviation")
            return set()
            
        if stdev_time == 0:
            if self.verbose:
                print("      Skipped: No timing variance detected (all responses identical)")
            return set()
            
        if self.verbose:
            print(f"      Mean response time: {mean_time:.3f}s")
            print(f"      Standard deviation: {stdev_time:.3f}s")
            print(f"      Z-score threshold: 2.5 (outliers beyond ±2.5 std devs)")
            
        outliers = set()
        threshold = 2.5  # Z-score threshold
        
        for response in self.responses:
            if self._reliable(response):
                z_score = abs((response.response_time - mean_time) / stdev_time)
                if z_score > threshold:
                    outliers.add(response.username)
                    if self.verbose:
                        print(f"      → {response.username}: {response.response_time:.3f}s (z-score: {z_score:.2f})")
                    
        return outliers
        
    def _analyze_content_length(self) -> Set[str]:
        """Find usernames with different content lengths (5xx excluded)"""
        # Exclude noise (5xx and format-error 400s) — their body sizes are not user-validity signals
        reliable = [r for r in self.responses if self._reliable(r)]
        if not reliable:
            reliable = [r for r in self.responses if r.status_code > 0]

        length_counts = Counter(r.content_length for r in reliable)
        
        if not length_counts:
            if self.verbose:
                print("      Skipped: No valid responses to analyze")
            return set()
            
        most_common_length = length_counts.most_common(1)[0][0]
        
        if self.verbose:
            print(f"      Length distribution: {dict(length_counts)}")
            print(f"      Most common length: {most_common_length} bytes ({length_counts[most_common_length]} occurrences)")
            print(f"      Detection threshold: >5% or >50 bytes difference")
        
        outliers = set()
        for response in reliable:
            length_diff = abs(response.content_length - most_common_length)
            threshold = max(most_common_length * 0.05, 50)
            if length_diff > threshold:
                outliers.add(response.username)
                if self.verbose:
                    print(f"      → {response.username}: {response.content_length} bytes (diff: {length_diff}, threshold: {threshold:.0f})")
                    
        return outliers
        
    def _analyze_body_patterns(self) -> List[Tuple[str, str]]:
        """Deep analysis of response bodies.

        For JSON APIs: flattens every response to dot-notation paths and
        compares field presence, values, types and array lengths across all
        responses so even a single differing boolean or extra nested key is
        caught.

        For plain-text APIs: broad keyword matching covering success,
        existence, and error messages.
        """

        matches: List[Tuple[str, str]] = []

        # ── 1. Parse every JSON response ──────────────────────────────────
        json_data: Dict[str, any] = {}
        for response in self.responses:
            if response.status_code > 0:
                try:
                    json_data[response.username] = json.loads(response.body)
                except (json.JSONDecodeError, ValueError):
                    pass

        if self.verbose:
            print(f"      Parsed {len(json_data)}/{len(self.responses)} responses as JSON")

        # Exclude 5xx responses from JSON comparison baseline — they're server crashes, not user signals
        reliable_usernames = {r.username for r in self.responses if self._reliable(r)}
        json_data_reliable = {u: d for u, d in json_data.items() if u in reliable_usernames}

        # Use reliable responses as the comparison base; fall back to all if nothing reliable
        json_data_for_compare = json_data_reliable if json_data_reliable else json_data

        # ── 2. Flatten JSON to dot-notation {path: value} ─────────────────
        def _flatten(obj, prefix: str = '') -> Dict[str, any]:
            out: Dict[str, any] = {}
            if isinstance(obj, dict):
                for k, v in obj.items():
                    path = f"{prefix}.{k}" if prefix else k
                    out.update(_flatten(v, path))
            elif isinstance(obj, list):
                # Record array length as a comparable scalar
                out[prefix + '.__len__'] = len(obj)
                for i, item in enumerate(obj[:5]):   # inspect first 5 elements
                    out.update(_flatten(item, f"{prefix}[{i}]"))
            else:
                out[prefix] = obj
            return out

        flat: Dict[str, Dict[str, any]] = {
            u: _flatten(d) for u, d in json_data_for_compare.items()
        }

        if flat:
            # ── 3. Union of all paths seen across responses ────────────────
            all_paths: Set[str] = set()
            for f in flat.values():
                all_paths.update(f.keys())

            if self.verbose:
                print(f"      Found {len(all_paths)} unique JSON paths across all responses")

            for path in sorted(all_paths):
                values_by_user = {u: f.get(path) for u, f in flat.items()}

                present   = {u: v for u, v in values_by_user.items() if v is not None}
                absent    = {u for u, v in values_by_user.items() if v is None}

                # ── 3a. Field presence differs across responses ────────────
                if absent and present:
                    minority_threshold = len(flat) / 2
                    if len(present) < minority_threshold:
                        # Only a few users have this field — they are the outliers
                        for u in present:
                            reason = f"JSON '{path}' only present for this user (value: {str(present[u])[:40]!r})"
                            matches.append((u, reason))
                            if self.verbose:
                                print(f"      → {u}: {reason}")
                    elif len(absent) < minority_threshold:
                        # Only a few users are MISSING this field — they are the outliers
                        for u in absent:
                            reason = f"JSON '{path}' missing (present for all others)"
                            matches.append((u, reason))
                            if self.verbose:
                                print(f"      → {u}: {reason}")

                # ── 3b. Field value differs from the majority ──────────────
                if len(present) >= 2:
                    value_counts: Counter = Counter(str(v) for v in present.values())
                    if len(value_counts) > 1:
                        majority_str = value_counts.most_common(1)[0][0]
                        for u, v in present.items():
                            if str(v) != majority_str:
                                reason = f"JSON '{path}': {str(v)[:50]!r} (majority: {majority_str[:50]!r})"
                                matches.append((u, reason))
                                if self.verbose:
                                    print(f"      → {u}: {reason}")

                # ── 3c. Field type differs ────────────────────────────────
                if len(present) >= 2:
                    type_counts: Counter = Counter(type(v).__name__ for v in present.values())
                    if len(type_counts) > 1:
                        majority_type = type_counts.most_common(1)[0][0]
                        for u, v in present.items():
                            if type(v).__name__ != majority_type:
                                reason = f"JSON '{path}' type {type(v).__name__!r} (majority: {majority_type!r})"
                                matches.append((u, reason))
                                if self.verbose:
                                    print(f"      → {u}: {reason}")

        # ── 4. Plain-text patterns (non-JSON or fallback) ──────────────────
        text_patterns = [
            # Success / confirmation indicators
            ("password reset",       "Password reset mentioned"),
            ("check your email",     "Check email prompt"),
            ("email sent",           "Email sent confirmation"),
            ("verification link",    "Verification link sent"),
            ("reset link",           "Reset link sent"),
            ("link has been sent",   "Link sent confirmation"),
            ("email has been sent",  "Email sent confirmation"),
            # Account-existence indicators
            ("user exists",          "User exists"),
            ("account found",        "Account found"),
            ("already registered",   "Already registered"),
            ("already exists",       "Already exists"),
            ("username taken",       "Username taken"),
            ("email already",        "Email already in use"),
            ("account already",      "Account already exists"),
            # Error messages that imply the account IS real
            ("invalid credentials",  "Invalid credentials (user exists)"),
            ("wrong password",       "Wrong password (user exists)"),
            ("incorrect password",   "Incorrect password (user exists)"),
            ("account locked",       "Account locked (user exists)"),
            ("account disabled",     "Account disabled (user exists)"),
            ("account suspended",    "Account suspended (user exists)"),
            ("too many attempts",    "Brute-force protection (user exists)"),
            ("rate limit",           "Rate limit hit (user may exist)"),
        ]

        for response in self.responses:
            if response.status_code > 0 and response.username not in json_data:
                body_lower = response.body.lower()
                for pattern, description in text_patterns:
                    if pattern in body_lower:
                        matches.append((response.username, description))
                        if self.verbose:
                            print(f"      → {response.username}: Found '{pattern}' → {description}")

        # ── 5. Deduplicate ────────────────────────────────────────────────
        seen: Set[tuple] = set()
        deduped: List[Tuple[str, str]] = []
        for item in matches:
            key = (item[0], item[1])
            if key not in seen:
                seen.add(key)
                deduped.append(item)

        if self.verbose:
            print(f"      Total unique signals: {len(deduped)}")

        return deduped
    
    def _analyze_headers(self) -> List[Tuple[str, str]]:
        """Analyze HTTP headers for differences"""
        # Headers to ignore (vary per request, not per user validity)
        IGNORED_HEADERS = {
            'Date', 'date',
            'Set-Cookie', 'set-cookie',
            'Age', 'age',
            'ETag', 'Etag', 'etag',       # Content hash - unique per response body
            'Last-Modified', 'last-modified',
            'X-Request-ID', 'x-request-id',
            'X-Trace-Id', 'x-trace-id',
            'Request-Id', 'request-id',
            'CF-Ray',  # Cloudflare
            'X-Amzn-RequestId',  # AWS
            'X-Amzn-Trace-Id',
            'X-B3-TraceId',  # Zipkin
            'X-B3-SpanId',
        }
        
        header_patterns = defaultdict(lambda: defaultdict(int))
        
        # Count occurrences of each header value for each header name
        # Exclude 5xx responses — their headers reflect server crash state, not user validity
        for response in self.responses:
            if self._reliable(response):
                for header_name, header_value in response.headers.items():
                    # Skip noisy headers that change per request
                    if header_name not in IGNORED_HEADERS:
                        header_patterns[header_name][header_value] += 1
        
        outliers = []
        
        # Look for headers that have different values
        for header_name, value_counts in header_patterns.items():
            if len(value_counts) > 1:
                most_common_value = max(value_counts, key=value_counts.get)
                
                # Find responses with different header values (only non-5xx)
                for response in self.responses:
                    if self._reliable(response):
                        header_value = response.headers.get(header_name)
                        if header_value and header_value != most_common_value:
                            outliers.append((response.username, f"{header_name}: {header_value[:50]}"))
                            if self.verbose:
                                print(f"      → {response.username}: {header_name} = {header_value[:50]}")
        
        return outliers
    
    def _analyze_redirects(self) -> List[Tuple[str, str]]:
        """Analyze redirect chains for patterns"""
        redirect_patterns = defaultdict(int)
        
        # Count redirect patterns
        for response in self.responses:
            if response.status_code > 0:
                redirect_signature = f"{len(response.redirect_chain)}:{response.final_url}"
                redirect_patterns[redirect_signature] += 1
        
        if not redirect_patterns:
            return []
        
        most_common = max(redirect_patterns, key=redirect_patterns.get)
        
        outliers = []
        for response in self.responses:
            if response.status_code > 0:
                redirect_signature = f"{len(response.redirect_chain)}:{response.final_url}"
                if redirect_signature != most_common:
                    reason = f"{len(response.redirect_chain)} redirects to {response.final_url[:50]}"
                    outliers.append((response.username, reason))
                    if self.verbose:
                        print(f"      → {response.username}: {reason}")
        
        return outliers
    
    def _analyze_cookies(self) -> List[Tuple[str, str]]:
        """Analyze cookie differences"""
        cookie_patterns = defaultdict(int)
        
        # Count cookie patterns
        for response in self.responses:
            if response.status_code > 0:
                cookie_keys = tuple(sorted(response.cookies.keys()))
                cookie_patterns[cookie_keys] += 1
        
        if not cookie_patterns:
            return []
        
        most_common = max(cookie_patterns, key=cookie_patterns.get)
        
        outliers = []
        for response in self.responses:
            if response.status_code > 0:
                cookie_keys = tuple(sorted(response.cookies.keys()))
                if cookie_keys != most_common:
                    reason = f"Cookies: {', '.join(cookie_keys) if cookie_keys else 'none'}"
                    outliers.append((response.username, reason))
                    if self.verbose:
                        print(f"      → {response.username}: {reason}")
        
        return outliers
    
    def _analyze_response_similarity(self) -> Set[str]:
        """Use Levenshtein distance to find responses with different content"""
        if len(self.responses) < 3:
            return set()
        
        # Only use reliable (non-5xx) responses for similarity clustering
        # 5xx responses have different bodies due to crash messages — not user validity signals
        valid_responses = [r for r in self.responses if self._reliable(r)]
        if len(valid_responses) < 3:
            if self.verbose:
                print("      Skipped: Need at least 3 reliable responses")
            return set()
        
        if self.verbose:
            print(f"      Analyzing response similarity for {len(valid_responses)} responses")
        
        # Use DBSCAN clustering to group similar responses
        from sklearn.cluster import DBSCAN
        import numpy as np
        
        # Build similarity matrix
        n = len(valid_responses)
        distance_matrix = np.zeros((n, n))
        
        for i in range(n):
            for j in range(i + 1, n):
                # Levenshtein ratio: 1.0 = identical, 0.0 = completely different
                ratio = Levenshtein.ratio(valid_responses[i].body, valid_responses[j].body)
                # Convert to distance: 0.0 = identical, 1.0 = completely different
                distance = 1.0 - ratio
                distance_matrix[i][j] = distance
                distance_matrix[j][i] = distance
        
        # Cluster responses by similarity (eps=0.15 means 85% similarity threshold)
        clustering = DBSCAN(eps=0.15, min_samples=2, metric='precomputed').fit(distance_matrix)
        labels = clustering.labels_
        
        if self.verbose:
            unique_labels = set(labels)
            print(f"      Found {len(unique_labels)} clusters: {dict(zip(*np.unique(labels, return_counts=True)))}")
        
        # Find the largest cluster (baseline/invalid user responses)
        label_counts = {}
        for label in labels:
            if label != -1:  # -1 means noise/outlier in DBSCAN
                label_counts[label] = label_counts.get(label, 0) + 1
        
        if not label_counts:
            # All responses are outliers? Fallback to old logic
            return set()
        
        largest_cluster = max(label_counts, key=label_counts.get)
        largest_cluster_size = label_counts[largest_cluster]
        
        if self.verbose:
            print(f"      Largest cluster: {largest_cluster} with {largest_cluster_size} responses (baseline)")
        
        # Report responses NOT in the largest cluster
        outliers = set()
        for i, label in enumerate(labels):
            if label != largest_cluster:
                outliers.add(valid_responses[i].username)
                cluster_desc = f"outlier" if label == -1 else f"cluster {label}"
                if self.verbose:
                    print(f"      → {valid_responses[i].username}: In {cluster_desc} (differs from baseline)")
        
        return outliers
    
    def _analyze_json_structure(self) -> List[Tuple[str, str]]:
        """Analyze JSON/XML structure differences (deep recursive comparison)"""
        structures = defaultdict(int)
        json_responses = {}

        # Try to parse JSON responses (5xx excluded — crash messages skew structure)
        for response in self.responses:
            if self._reliable(response):
                try:
                    data = json.loads(response.body)
                    structure = self._get_json_structure(data)
                    structures[structure] += 1
                    json_responses[response.username] = structure
                except (json.JSONDecodeError, ValueError):
                    pass  # Not JSON

        if len(structures) <= 1:
            return []

        most_common = max(structures, key=structures.get)

        outliers = []
        for username, structure in json_responses.items():
            if structure != most_common:
                outliers.append((username, "Different JSON structure"))
                if self.verbose:
                    print(f"      → {username}: Different JSON structure")
                    print(f"         Structure: {structure}")
                    print(f"         Baseline:  {most_common}")

        return outliers

    def _get_json_structure(self, obj, depth: int = 0) -> str:
        """Recursively build a signature of JSON structure (keys + types at every level)"""
        if depth > 5:  # Prevent runaway recursion
            return "..."
        if isinstance(obj, dict):
            parts = []
            for key in sorted(obj.keys()):
                child_sig = self._get_json_structure(obj[key], depth + 1)
                parts.append(f"{key}:{child_sig}")
            return "{" + ",".join(parts) + "}"
        elif isinstance(obj, list):
            if not obj:
                return "[]"
            child_sig = self._get_json_structure(obj[0], depth + 1)
            return f"[{child_sig}]"
        else:
            return type(obj).__name__
    
    def _analyze_timing_histogram(self) -> Set[str]:
        """Advanced timing analysis using percentiles"""
        valid_times = [(r.username, r.response_time) for r in self.responses if self._reliable(r)]
        
        if len(valid_times) < 10:
            return set()
        
        times = [t for _, t in valid_times]
        p25 = np.percentile(times, 25)
        p75 = np.percentile(times, 75)
        iqr = p75 - p25
        
        # Outliers are beyond 1.5 * IQR from quartiles
        lower_bound = p25 - 1.5 * iqr
        upper_bound = p75 + 1.5 * iqr
        
        outliers = set()
        for username, time in valid_times:
            if time < lower_bound or time > upper_bound:
                outliers.add(username)
                if self.verbose:
                    print(f"      → {username}: {time:.3f}s (bounds: {lower_bound:.3f}-{upper_bound:.3f}s)")
        
        return outliers
    
    def _detect_rate_limiting(self) -> List[Tuple[str, str]]:
        """Detect rate limiting indicators"""
        indicators = []
        
        for response in self.responses:
            # Check status code
            if response.status_code == 429:
                indicators.append((response.username, "429 Too Many Requests"))
                if self.verbose:
                    print(f"      → {response.username}: 429 Too Many Requests")
            
            # Check rate limit headers
            if response.status_code > 0:
                for header_name in response.headers:
                    if 'ratelimit' in header_name.lower() or 'rate-limit' in header_name.lower():
                        indicators.append((response.username, f"Header: {header_name}"))
                        if self.verbose:
                            print(f"      → {response.username}: Rate limit header: {header_name}")
        
        return indicators

    def _is_format_error_400(self, response) -> bool:
        """Return True when a 400 response signals a format/validation failure
        (e.g. syntactically invalid email address such as 'anne marie@host') rather
        than user-existence information.  Treated as noise — excluded from all
        analysis the same way 5xx server errors are excluded."""
        if response.status_code != 400:
            return False
        try:
            body = json.loads(response.body)
            msg = ''
            for field in ('message', 'error', 'msg', 'detail', 'description'):
                val = body.get(field)
                if val:
                    msg = str(val).lower()
                    break
            if 'invalid' in msg and ('email' in msg or 'format' in msg or 'address' in msg):
                return True
            if any(kw in msg for kw in ('validation', 'malformed', 'bad request')):
                return True
        except (json.JSONDecodeError, ValueError, AttributeError):
            body_lower = response.body.lower()
            if 'invalid' in body_lower and 'email' in body_lower:
                return True
        return False

    def _reliable(self, response) -> bool:
        """Return True if this response is a reliable user-validity signal.

        Excludes:
          - status 0        : request failed entirely (network error / timeout)
          - 5xx             : server crash / overload — not user-specific
          - 400 format error: syntactically invalid input (e.g. email with a
                              space or apostrophe) rejected before the server
                              even looks up the user
        """
        if response.status_code <= 0 or response.status_code >= 500:
            return False
        return not self._is_format_error_400(response)

    def get_statistics(self) -> Dict:
        """Get statistics about the responses"""
        if not self.responses:
            return {}
            
        valid_responses = [r for r in self.responses if r.status_code > 0]
        
        if not valid_responses:
            return {"total": len(self.responses), "failed": len(self.responses)}
            
        status_counts = Counter(r.status_code for r in valid_responses)
        lengths = [r.content_length for r in valid_responses]
        times = [r.response_time for r in valid_responses]

        # Timing outlier flags (z-score > 2.5) for histogram colouring
        timing_outliers: Set[str] = set()
        if len(times) >= 3:
            try:
                mean_t = statistics.mean(times)
                stdev_t = statistics.stdev(times)
                if stdev_t > 0:
                    timing_outliers = {
                        r.username for r in valid_responses
                        if abs((r.response_time - mean_t) / stdev_t) > 2.5
                    }
            except statistics.StatisticsError:
                pass

        # Content-length distribution (cap at 20 unique lengths to keep graph readable)
        length_counter = Counter(lengths)
        if len(length_counter) <= 20:
            length_distribution = dict(sorted(length_counter.items()))
        else:
            length_distribution = {}

        return {
            "total": len(self.responses),
            "successful": len(valid_responses),
            "failed": len(self.responses) - len(valid_responses),
            "status_codes": dict(status_counts),
            "avg_response_time": statistics.mean(times) if times else 0,
            "min_response_time": min(times) if times else 0,
            "max_response_time": max(times) if times else 0,
            "avg_content_length": statistics.mean(lengths) if lengths else 0,
            "unique_lengths": len(set(lengths)) if lengths else 0,
            "length_distribution": length_distribution,
            # List of (response_time, is_outlier) for the timing histogram
            "timing_data": [
                (r.response_time, r.username in timing_outliers)
                for r in valid_responses
            ],
        }
