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
        """Find usernames with different status codes"""
        status_counts = Counter(r.status_code for r in self.responses)
        most_common_status = status_counts.most_common(1)[0][0]
        
        if self.verbose:
            print(f"      Status code distribution: {dict(status_counts)}")
            print(f"      Most common status: {most_common_status} ({status_counts[most_common_status]} occurrences)")
        
        outliers = set()
        for response in self.responses:
            if response.status_code != most_common_status and response.status_code > 0:
                outliers.add(response.username)
                if self.verbose:
                    print(f"      → {response.username}: status {response.status_code} (differs from {most_common_status})")
                
        return outliers
        
    def _analyze_timing(self) -> Set[str]:
        """Find usernames with unusual response times"""
        valid_times = [r.response_time for r in self.responses if r.status_code > 0]
        
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
            if response.status_code > 0:
                z_score = abs((response.response_time - mean_time) / stdev_time)
                if z_score > threshold:
                    outliers.add(response.username)
                    if self.verbose:
                        print(f"      → {response.username}: {response.response_time:.3f}s (z-score: {z_score:.2f})")
                    
        return outliers
        
    def _analyze_content_length(self) -> Set[str]:
        """Find usernames with different content lengths"""
        length_counts = Counter(r.content_length for r in self.responses if r.status_code > 0)
        
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
        for response in self.responses:
            if response.status_code > 0:
                length_diff = abs(response.content_length - most_common_length)
                threshold = max(most_common_length * 0.05, 50)
                # If difference is more than 5% or more than 50 bytes
                if length_diff > threshold:
                    outliers.add(response.username)
                    if self.verbose:
                        print(f"      → {response.username}: {response.content_length} bytes (diff: {length_diff}, threshold: {threshold:.0f})")
                    
        return outliers
        
    def _analyze_body_patterns(self) -> List[Tuple[str, str]]:
        """Find specific patterns in response bodies that indicate valid users"""
        patterns = [
            ("user exists", "User exists message"),
            ("account found", "Account found message"),
            ("email sent", "Email sent confirmation"),
            ("password reset", "Password reset message"),
            ("check your email", "Email check prompt"),
            ("verification link", "Verification message"),
            ("already registered", "Already registered message"),
            ("username taken", "Username taken message"),
            ("email already", "Email already used"),
        ]
        
        if self.verbose:
            print(f"      Searching for {len(patterns)} patterns in response bodies")
        
        matches = []
        
        for response in self.responses:
            if response.status_code > 0:
                body_lower = response.body.lower()
                for pattern, description in patterns:
                    if pattern in body_lower:
                        matches.append((response.username, description))
                        if self.verbose:
                            print(f"      → {response.username}: Found '{pattern}' → {description}")
                        
        return matches
    
    def _analyze_headers(self) -> List[Tuple[str, str]]:
        """Analyze HTTP headers for differences"""
        header_patterns = defaultdict(lambda: defaultdict(int))
        
        # Count occurrences of each header value for each header name
        for response in self.responses:
            if response.status_code > 0:
                for header_name, header_value in response.headers.items():
                    header_patterns[header_name][header_value] += 1
        
        outliers = []
        
        # Look for headers that have different values
        for header_name, value_counts in header_patterns.items():
            if len(value_counts) > 1:
                most_common_value = max(value_counts, key=value_counts.get)
                most_common_count = value_counts[most_common_value]
                
                # Find responses with different header values
                for response in self.responses:
                    if response.status_code > 0:
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
        
        valid_responses = [r for r in self.responses if r.status_code > 0]
        if len(valid_responses) < 3:
            return set()
        
        # Calculate similarity matrix
        similarities = []
        for i, resp1 in enumerate(valid_responses):
            for j, resp2 in enumerate(valid_responses):
                if i < j:
                    # Use Levenshtein ratio (0-1, higher = more similar)
                    ratio = Levenshtein.ratio(resp1.body, resp2.body)
                    similarities.append(ratio)
        
        if not similarities:
            return set()
        
        # Find responses that are significantly different from the majority
        mean_similarity = statistics.mean(similarities)
        threshold = 0.85  # 85% similarity threshold
        
        outliers = set()
        for response in valid_responses:
            # Compare this response to all others
            ratios = []
            for other in valid_responses:
                if response.username != other.username:
                    ratio = Levenshtein.ratio(response.body, other.body)
                    ratios.append(ratio)
            
            if ratios:
                avg_ratio = statistics.mean(ratios)
                if avg_ratio < threshold:
                    outliers.add(response.username)
                    if self.verbose:
                        print(f"      → {response.username}: Avg similarity {avg_ratio:.2%} (threshold: {threshold:.0%})")
        
        return outliers
    
    def _analyze_json_structure(self) -> List[Tuple[str, str]]:
        """Analyze JSON/XML structure differences"""
        structures = defaultdict(int)
        json_responses = {}
        
        # Try to parse JSON responses
        for response in self.responses:
            if response.status_code > 0:
                try:
                    data = json.loads(response.body)
                    # Get structure signature (keys and types)
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
                reason = f"Different JSON structure"
                outliers.append((username, reason))
                if self.verbose:
                    print(f"      → {username}: {reason}")
        
        return outliers
    
    def _get_json_structure(self, obj, prefix="") -> str:
        """Get a signature of JSON structure"""
        if isinstance(obj, dict):
            keys = sorted(obj.keys())
            return f"dict:{','.join(keys)}"
        elif isinstance(obj, list):
            if obj:
                return f"list[{self._get_json_structure(obj[0])}]"
            return "list[]"
        else:
            return type(obj).__name__
    
    def _analyze_timing_histogram(self) -> Set[str]:
        """Advanced timing analysis using percentiles"""
        valid_times = [(r.username, r.response_time) for r in self.responses if r.status_code > 0]
        
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
        }
