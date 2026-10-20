from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional, Union
import uvicorn, json, re, time, logging, numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from collections import defaultdict, deque
import os

# Ensure directories exist for StaticFiles and templates at import time
os.makedirs("templates", exist_ok=True)
os.makedirs("static", exist_ok=True)

# Ensure logfile exists and configure logging early
open('anomalies.log', 'a').close()
logging.basicConfig(filename='anomalies.log', level=logging.INFO)

# Try to import yara if available; otherwise disable YARA scanning
try:
    import yara
    yara_available = True
except Exception:
    yara = None
    yara_available = False
    logging.warning("yara not available; YARA scanning disabled")

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# YARA rules for abuse (SQLi, XSS) - compile only if yara is available
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
normal_requests = np.random.rand(100, 4)  # Simulate; replace with real data
normal_requests[:, 0] = np.random.normal(50, 20, 100)  # payload_len
normal_requests[:, 1] = np.random.normal(4, 1, 100)    # num_params
normal_requests[:, 2] = np.random.normal(3.5, 0.5, 100) # entropy
normal_requests[:, 3] = np.random.poisson(5, 100)      # rate
scaler.fit(normal_requests)
model.fit(scaler.transform(normal_requests))

# Rate limiting
ratelimit = defaultdict(lambda: deque(maxlen=60))  # 1/min per IP

class ApiRequest(BaseModel):
    url: str
    method: str
    headers: dict = {}
    payload: Optional[Union[dict, str]] = None

@app.get("/")
def dashboard(request: Request):
    # open in a+ to ensure file exists and read last lines
    with open('anomalies.log', 'a+') as f:
        f.seek(0)
        logs = f.readlines()[-20:]
    return templates.TemplateResponse("index.html", {"request": request, "logs": logs})

@app.post("/api/analyze")
async def analyze(req: ApiRequest, request: Request):
    client_ip = request.client.host
    now = time.time()
    
    # Rate limit
    ratelimit[client_ip].append(now)
    if len(ratelimit[client_ip]) > 10:  # Abuse threshold
        logging.warning(f"Rate limit abuse: {client_ip}")
        raise HTTPException(429, "Rate limited")
    
    # Normalize payload and guard for None
    if req.payload is None:
        payload_obj = {}
        payload_str = ""
    else:
        payload_obj = req.payload if isinstance(req.payload, dict) else {}
        payload_str = json.dumps(req.payload) if isinstance(req.payload, dict) else str(req.payload)
    
    # Input validation (basic schema/Pydantic handles types)
    if not isinstance(req.payload, (dict, str)) or len(payload_str) > 10000:
        raise HTTPException(400, "Invalid input")
    
    issues = []
    
    # Regex abuse detection
    sqli_pat = re.compile(r"union.*select|drop.*table|exec.*sp", re.I)
    xss_pat = re.compile(r"<script|javascript:|alert\(", re.I)
    if sqli_pat.search(payload_str): issues.append("SQLi detected")
    if xss_pat.search(payload_str): issues.append("XSS detected")
    
    # YARA scan (skip if yara not available)
    if rules is not None:
        matches = rules.match(data=payload_str)
        if matches:
            issues.extend([m.rule for m in matches])
    
    # ML Anomaly (features: len, num_params, entropy, recent rate)
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
    if is_anomaly: issues.append(f"ML Anomaly (score: {anomaly_score:.2f})")
    
    # Log
    log_entry = {"ip": client_ip, "issues": issues, "timestamp": time.ctime(), "score": anomaly_score}
    logging.info(json.dumps(log_entry))
    
    return {"valid": not issues, "issues": issues, "anomaly_score": anomaly_score}

if __name__ == "__main__":
    os.makedirs("templates", exist_ok=True)
    os.makedirs("static", exist_ok=True)
    uvicorn.run(app, host="0.0.0.0", port=8000)
