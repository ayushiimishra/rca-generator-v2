# AI RCA Generator

Automated Root Cause Analysis for security incidents.
Upload Windows Event Logs, Web Access Logs or DNS logs
and get a structured AI-powered incident report.

## Quick Start

### Step 1 — Clone
```
git clone https://github.com/crow18629-dev/rca-generator
cd rca-generator
```

### Step 2 — Setup
```
bash setup.sh
```

### Step 3 — Add API key
Edit .env and add your Gemini API key:
```
nano .env
```

Get a free key from:
https://aistudio.google.com/apikey

### Step 4 — Start
```
bash start.sh
```

### Step 5 — Open browser
http://localhost:8000

## Supported Log Formats
- Windows Event Logs (.evtx binary)
- Nginx/Apache web access logs (.log)
- DNS logs (Windows/Pihole/CoreDNS)
- CSV exports of Windows events

## Requirements
- Python 3.10 or higher
- Linux (Ubuntu, Fedora, Debian) or WSL2
- Internet connection for AI analysis
- Free Gemini API key

## Architecture
Three-layer detection pipeline:
1. Chainsaw + Sigma rules (2000+ community rules)
2. Custom YAML rules (context-aware conditions)
3. Behavioral state machine (attack chain correlation)

AI analysis via Gemini 2.5 Flash with xAI Grok fallback.

## Free API Keys
- Gemini: https://aistudio.google.com/apikey
- xAI: https://console.x.ai
- VirusTotal: https://www.virustotal.com/gui/sign-in
- AbuseIPDB: https://www.abuseipdb.com/register
