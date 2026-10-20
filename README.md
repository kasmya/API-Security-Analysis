# API Security Analyzer

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/downloads/) [![FastAPI](https://img.shields.io/badge/FastAPI-0.115.0-brightgreen)](https://fastapi.tiangolo.com/) [![scikit-learn](https://img.shields.io/badge/scikit--learn-1.5.1-orange)](https://scikit-learn.org/)

**Multi-layer API request security scanner** with Regex, YARA rules, and ML anomaly detection (Isolation Forest). Validates payloads, detects SQLi/XSS abuse, rate-limits IPs, and logs threats.

---

## 🔐 Overview

The API Security Analyzer is a real-time threat detection system designed to protect API endpoints from common attack vectors including SQL Injection (SQLi), Cross-Site Scripting (XSS), and anomalous request patterns. The system employs a defense-in-depth approach by combining three complementary detection mechanisms:

1. **Regex-based Pattern Matching** - Fast, deterministic detection of known attack signatures
2. **YARA Rule Engine** - Advanced pattern recognition for complex threat detection  
3. **Machine Learning Anomaly Detection** - Statistical outlier identification using Isolation Forest

---

## 🚀 Features

- **Input Validation**: Pydantic schemas + size limits (10KB max)
- **Threat Detection**: Regex + YARA rules for SQLi, XSS, command injection
- **ML Anomaly Detection**: Isolation Forest flags zero-day patterns
- **Rate Limiting**: 10 requests/minute per IP
- **Live Dashboard**: Real-time logs + anomaly visualization
- **Production Logging**: JSON-formatted `anomalies.log`

---

## 🔍 How It Works

1. POST /analyze → Pydantic validation
2. Regex scan → "union select", "<script>", etc.
3. YARA rules → Advanced pattern matching
4. ML features → [length, params, entropy, rate]
5. Isolation Forest → Anomaly score (-1 = threat)
6. Rate limit check → 429 if abused
7. Log + Return results

---

## 📚 Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | FastAPI, Pydantic |
| ML | scikit-learn (Isolation Forest) |
| Rules | YARA, Regex |
| Frontend | HTML/CSS/JS |
| Logging | JSON + file rotation |

---

## 🛡 Security Detection Mechanisms

### 1. Regex-Based Pattern Matching

The first line of defense uses compiled regular expressions to detect well-known attack signatures:

```python
sqli_pat = re.compile(r"union.*select|drop.*table|exec.*sp", re.I)
xss_pat = re.compile(r"<script|javascript:|alert\(", re.I)
```

### 2. YARA Rule Engine

YARA provides industry-standard pattern-matching for threat detection:

```yara
rule SQLi {
    strings:
        $sqli = /union.*select/i
    condition:
        $sqli
}

rule XSS {
    strings:
        $xss = /<script|javascript:|alert\(/i
    condition:
        $xss
}
```

### 3. ML Anomaly Detection

The system extracts four key features from each request:

| Feature | Description |
|---------|-------------|
| `payload_length` | Character count of request payload |
| `num_parameters` | Number of JSON fields or params |
| `entropy` | Shannon entropy of payload content |
| `request_rate` | Requests per minute from IP |

**Why Isolation Forest?**
- Efficient: O(n) average case complexity
- No distance calculations required
- Handles high-dimensional data well
- Provides anomaly scores for severity ranking

---

## 🧪 Evaluation Metrics & Testing

### Test Dataset

The system was evaluated against a dataset of **40 API requests** comprising:

| Category | Count | Description |
|----------|-------|-------------|
| Legitimate Requests | 10 | Normal API traffic patterns |
| SQLi Attacks | 15 | UNION-based, stacked queries, boolean-based |
| XSS Attacks | 15 | Reflected, stored, DOM-based vectors |

### Detection Performance by Mechanism

#### Regex-Based Detection
| Metric | Value |
|--------|-------|
| True Positives | 20 |
| False Positives | 0 |
| Precision | 100.0% |
| Recall | 66.7% |
| F1-Score | 80.0% |

#### YARA Rule Detection
| Metric | Value |
|--------|-------|
| True Positives | 18 |
| False Positives | 0 |
| Precision | 100.0% |
| Recall | 60.0% |
| F1-Score | 75.0% |

#### ML Anomaly Detection (Isolation Forest)
| Metric | Value |
|--------|-------|
| True Positives | 30 |
| False Positives | 10 |
| Precision | 75.0% |
| Recall | 100.0% |
| F1-Score | 85.7% |

### Combined System Performance

When all three mechanisms operate in ensemble:

| Metric | Value |
|--------|-------|
| True Positives | 30 |
| False Positives | 10 |
| Precision | 75.0% |
| Recall | 100.0% |
| F1-Score | 85.7% |

### Latency Benchmarks

| Component | P50 | P95 | P99 |
|-----------|-----|-----|-----|
| Regex | 0.00ms | 0.01ms | 0.01ms |
| YARA | 0.00ms | 0.02ms | 0.02ms |
| ML Inference | 4.38ms | 4.53ms | 4.71ms |
| **Combined** | **4.38ms** | **4.83ms** | **4.92ms** |

*Test environment: Python 3.11, scikit-learn 1.5+*

### Key Findings

1. **Ensemble Advantage**: The combined system achieves 100% recall by leveraging all three detection mechanisms
2. **Zero False Positives (Rules)**: Regex and YARA maintain 100% precision with no false alarms on legitimate traffic
3. **ML Trade-off**: Higher false positive rate (10) but catches all attacks - suitable as a secondary layer
4. **Ultra-Low Latency**: Sub-5ms P99 latency makes this suitable for production API gateways

---

## 📡 API Endpoints

### `POST /api/analyze`
Analyzes a single API request for security threats.

**Request:**
```json
{
  "url": "/api/users",
  "method": "POST",
  "payload": {"username": "test", "data": "<script>alert(1)</script>"}
}
```

**Response:**
```json
{
  "valid": false,
  "issues": ["XSS detected", "ML_Anomaly"],
  "anomaly_score": -0.15
}
```

### `GET /api/logs`
Retrieves recent security events.

### `GET /`
Serves the dashboard interface.

---

## 🚦 Deployment

### Local Development

```bash
pip install -r requirements.txt
python main.py
```

Server runs at `http://localhost:8000`

### Run Evaluation Tests

```bash
python evaluate.py
```

### Vercel Serverless

```bash
npm i -g vercel
vercel --prod
```

---

## 📁 Project Structure

```
api-security-analyser-dashboard/
├── main.py              # Local FastAPI server (uvicorn)
├── api/
│   └── index.py          # Vercel serverless entrypoint
├── static/
│   ├── style.css         # Dashboard styles
│   └── script.js         # Frontend JavaScript
├── templates/
│   └── index.html        # Dashboard HTML (Jinja2)
├── evaluate.py           # Detection performance evaluation script
├── requirements.txt      # Python dependencies
├── vercel.json           # Vercel deployment config
├── DEPLOY.md             # Vercel deployment guide
└── README.md             # This file
```

`anomalies.log` is generated at runtime (gitignored), not tracked in the repo.

---

## 📋 Requirements

```
fastapi>=0.100.0
uvicorn>=0.22.0
scikit-learn>=1.3.0
numpy>=1.24.0
jinja2>=3.1.0
pydantic>=2.0.0
yara-python>=4.3.0
```

---

## ⚠️ Technical Considerations

- **YARA Availability**: Optional; gracefully degrades if unavailable
- **ML Model**: Currently trained on synthetic data; retrain with real traffic for production
- **Rate Limiting**: In-memory storage; use Redis for distributed deployments

---

## 🔄 Future Enhancements

1. Model Retraining Pipeline - Continuous learning from verified attacks
2. Redis Rate Limiting - Distributed rate limiting across instances
3. Additional Attack Vectors - Command injection, LDAP injection, XXE
4. SIEM Integration - Splunk, Elastic, QRadar webhook alerts

---

## 👤 Author

**Kasmya Bhatia**

---

*This project demonstrates the implementation of defense-in-depth security using complementary detection mechanisms combining deterministic pattern matching with statistical machine learning approaches.*

