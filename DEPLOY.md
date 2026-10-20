# Vercel Deployment Guide

This API Security Analyzer can be deployed to Vercel for serverless execution.

## Files Created for Vercel

- `vercel.json` - Vercel configuration
- `api/index.py` - Serverless API function
- `requirements.txt` - Python dependencies

## Deployment Steps

### 1. Install Vercel CLI
```bash
npm i -g vercel
```

### 2. Login to Vercel
```bash
vercel login
```

### 3. Deploy
```bash
cd api-security-analyser-dashboard
vercel
```

### 4. Set as Production
```bash
vercel --prod
```

## Project Structure
```
api-security-analyser-dashboard/
├── api/
│   └── index.py          # Serverless API function
├── static/
│   ├── style.css         # Dashboard styles
│   └── script.js         # Frontend JavaScript
├── templates/
│   └── index.html        # Dashboard HTML
├── vercel.json           # Vercel config
├── requirements.txt      # Python deps
├── main.py               # Local server
└── DEPLOY.md            # This file
```

## API Endpoints (Vercel)

- `GET /` - Dashboard
- `POST /api/analyze` - Analyze API request
- `GET /api/logs` - Get recent logs

## Features

- SQL Injection detection (regex + YARA)
- XSS detection (regex + YARA)
- ML-based anomaly detection (Isolation Forest)
- Rate limiting

## Notes

- YARA scanning may have limited support on Vercel's serverless functions
- Rate limiting resets on cold starts
- File-based logging not persistent on Vercel

