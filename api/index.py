import json
import re
import time
import logging
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from collections import defaultdict, deque
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Union

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# YARA rules for abuse (SQLi, XSS) - compile only if yara is available
try:
    import yara
    yara_available = True
except Exception:
    yara = None
    yara_available = False
    logger.warning("yara not available; YARA scanning disabled")

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

# ML Model (train on normal requests; retrain as needed)
scaler = StandardScaler()
model = IsolationForest(contamination=0.1, random_state=42)
normal_requests = np.random.rand(100, 4)
normal_requests[:, 0] = np.random.normal(50, 20, 100)
normal_requests[:, 1] = np.random.normal(4, 1, 100)
normal_requests[:, 2] = np.random.normal(3.5, 0.5, 100)
normal_requests[:, 3] = np.random.poisson(5, 100)
scaler.fit(normal_requests)
model.fit(scaler.transform(normal_requests))

# Rate limiting (in-memory, resets on cold start)
ratelimit = defaultdict(lambda: deque(maxlen=60))

class ApiRequest(BaseModel):
    url: str
    method: str
    headers: dict = {}
    payload: Optional[Union[dict, str]] = None

@app.get("/")
def dashboard(request: Request):
    """Serve the dashboard HTML"""
    with open('../templates/index.html', 'r') as f:
        html_content = f.read()
    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=html_content)

@app.get("/api/logs")
def get_logs():
    """Get recent logs for dashboard"""
    try:
        with open('../anomalies.log', 'r') as f:
            logs = f.readlines()[-20:]
        return {"logs": logs}
    except:
        return {"logs": []}

@app.post("/api/analyze")
async def analyze(req: ApiRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    
    # Rate limit
    ratelimit[client_ip].append(now)
    if len(ratelimit[client_ip]) > 10:
        logger.warning(f"Rate limit abuse: {client_ip}")
        raise HTTPException(429, "Rate limited")
    
    # Normalize payload
    if req.payload is None:
        payload_obj = {}
        payload_str = ""
    else:
        payload_obj = req.payload if isinstance(req.payload, dict) else {}
        payload_str = json.dumps(req.payload) if isinstance(req.payload, dict) else str(req.payload)
    
    # Input validation
    if not isinstance(req.payload, (dict, str)) or len(payload_str) > 10000:
        raise HTTPException(400, "Invalid input")
    
    issues = []
    
    # Regex abuse detection
    sqli_pat = re.compile(r"union.*select|drop.*table|exec.*sp", re.I)
    xss_pat = re.compile(r"<script|javascript:|alert\(", re.I)
    if sqli_pat.search(payload_str):
        issues.append("SQLi detected")
    if xss_pat.search(payload_str):
        issues.append("XSS detected")
    
    # YARA scan
    if rules is not None:
        matches = rules.match(data=payload_str)
        if matches:
            issues.extend([m.rule for m in matches])
    
    # ML Anomaly
    L = len(payload_str)
    if L == 0:
        entropy = 0.0
    else:
        counts = np.unique(list(payload_str), return_counts=True)[1]
        freqs = counts / L
        entropy = -np.sum([p * np.log(p + 1e-10) for p in freqs])

    num_params = len(payload_obj) if isinstance(payload_obj, dict) else 1

    features = np.array([[L, num_params, entropy, len(ratelimit[client_ip])]]).reshape(1, -1)
    features_scaled = scaler.transform(features)
    anomaly_score = model.decision_function(features_scaled)[0]
    is_anomaly = model.predict(features_scaled)[0] == -1
    if is_anomaly:
        issues.append(f"ML Anomaly (score: {anomaly_score:.2f})")
    
    # Log
    log_entry = {"ip": client_ip, "issues": issues, "timestamp": time.ctime(), "score": anomaly_score}
    logger.info(json.dumps(log_entry))
    
    return {"valid": not issues, "issues": issues, "anomaly_score": anomaly_score}

