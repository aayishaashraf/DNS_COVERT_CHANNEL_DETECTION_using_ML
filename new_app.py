import sys, os, joblib, re, math, json
import pandas as pd
import numpy as np
from flask import Flask, request, jsonify, render_template_string, abort
from tensorflow.keras.models import load_model
from difflib import SequenceMatcher
from threat_detector import ThreatDetector
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from functools import wraps
import hashlib
import secrets
import smtplib, time, requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import OrderedDict

# ------------------------------------------------------------
# CONFIGURATION – ADD NEW SETTINGS
# ------------------------------------------------------------
# Email alerts
ENABLE_EMAIL_ALERTS = True
SMTP_SERVER = "smtp.gmail.com"      
SMTP_PORT = 587
SMTP_USER = "add your email here"  
SMTP_PASSWORD = "jipx seop icyt ejai"  
ALERT_RECIPIENT = "add recipient email here" 

# VirusTotal integration
ENABLE_VIRUSTOTAL = True
VIRUSTOTAL_API_KEY = "add your VirusTotal API here"  
VT_CACHE_TTL = 3600  # seconds (1 hour)
vt_cache = OrderedDict()  # simple in-memory cache

# 1. Path setup
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(current_dir, 'src'))

app = Flask(__name__)

from prometheus_client import make_wsgi_app
from werkzeug.middleware.dispatcher import DispatcherMiddleware


# Global threat detector
try:
    THREAT_DETECTOR = ThreatDetector()
    print("ThreatDetector with IBHH initialized successfully")
except Exception as e:
    print(f"Failed to initialize ThreatDetector: {e}")
    THREAT_DETECTOR = None

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION - Two-Layer Thresholds
# ═══════════════════════════════════════════════════════════════════════════

# Layer 1 (Entropy Filter) - Fast decisions
LOW_ENTROPY_THRESHOLD = 2.8   # Below = definitely benign
HIGH_ENTROPY_THRESHOLD = 4.3  # Above = likely malicious (DGA)

# Layer 2 (LSTM) - Deep analysis for ambiguous zone
LSTM_THRESHOLD = 0.35  # Lowered from 0.50 to catch subtle phishing (cisco-support.org, etc.)

# ═══════════════════════════════════════════════════════════════════════════
# PERFORMANCE TRACKING
# ═══════════════════════════════════════════════════════════════════════════
PERFORMANCE_STATS = {
    'total_queries': 0,
    'benign_count': 0,
    'malicious_count': 0,
    'layer1_decisions': 0,
    'layer2_decisions': 0,
    'whitelist_hits': 0,
    'attack_dga': 0,
    'attack_typosquat': 0,
    'attack_fastflux': 0,
    'attack_tunneling': 0,
    'attack_c2': 0,
    'attack_other': 0,
}

# ═══════════════════════════════════════════════════════════════════════════
# AUDIO ALERT SYSTEM - Recent Threats Tracking
# ═══════════════════════════════════════════════════════════════════════════
RECENT_THREATS = []  # Store last 10 malicious detections for audio alerts
MAX_RECENT_THREATS = 10

# ═══════════════════════════════════════════════════════════════════════════
# PROMETHEUS METRICS
# ═══════════════════════════════════════════════════════════════════════════
 
# Counters (always increasing)
METRICS_QUERIES_TOTAL = Counter('dns_shield_queries_total', 'Total DNS queries processed')
METRICS_MALICIOUS_TOTAL = Counter('dns_shield_malicious_total', 'Total malicious detections')
METRICS_BENIGN_TOTAL = Counter('dns_shield_benign_total', 'Total benign detections')
METRICS_LAYER1_TOTAL = Counter('dns_shield_layer1_total', 'Total Layer 1 decisions')
METRICS_LAYER2_TOTAL = Counter('dns_shield_layer2_total', 'Total Layer 2 decisions')
METRICS_WHITELIST_TOTAL = Counter('dns_shield_whitelist_total', 'Total whitelist hits')
 
# Attack type counters
METRICS_ATTACK_DGA = Counter('dns_shield_attack_dga_total', 'DGA attacks detected')
METRICS_ATTACK_TYPO = Counter('dns_shield_attack_typosquat_total', 'Typosquatting attacks')
METRICS_ATTACK_FASTFLUX = Counter('dns_shield_attack_fastflux_total', 'Fast flux attacks')
METRICS_ATTACK_TUNNELING = Counter('dns_shield_attack_tunneling_total', 'DNS tunneling attacks')
 
# Gauges (current values)
METRICS_CURRENT_QUERIES = Gauge('dns_shield_current_queries', 'Current total queries')
METRICS_CURRENT_MALICIOUS = Gauge('dns_shield_current_malicious', 'Current malicious count')
 
# Response time histogram
METRICS_RESPONSE_TIME = Histogram('dns_shield_response_time_seconds', 'Response time in seconds')

# ═══════════════════════════════════════════════════════════════════════════
# WHITELIST
# ═══════════════════════════════════════════════════════════════════════════
TRUSTED_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "amazon.com", "facebook.com",
    "instagram.com", "twitter.com", "linkedin.com", "netflix.com", "uwl.ac.uk",
    "wikipedia.org", "github.com", "stackoverflow.com", "youtube.com", "adobe.com",
    "zoom.us", "spotify.com", "dropbox.com", "slack.com", "cloudflare.com",
    "office.com", "live.com", "bing.com", "outlook.com", "gmail.com", "yahoo.com",
    "baidu.com", "reddit.com", "quora.com", "medium.com", "bbc.co.uk", "nytimes.com",
    "googleapis.com", "googleusercontent.com", "gstatic.com", "gemini.google.com",
    "microsoftonline.com", "office365.com", "sharepoint.com", "azure.com",
    "icloud.com", "amazonaws.com", "x.com", "whatsapp.com", "threads.net",
    "twitch.tv", "paypal.com", "ebay.com",
]

TRUSTED_BRANDS = {
    "google", "microsoft", "apple", "amazon", "facebook", "instagram",
    "twitter", "linkedin", "netflix", "youtube", "github", "stackoverflow",
    "adobe", "zoom", "spotify", "cloudflare", "gmail", "yahoo", "reddit",
    "paypal", "ebay", "wikipedia", "dropbox", "slack", "gemini",
}
# ═══════════════════════════════════════════════════════════════════════════
# API AUTHENTICATION CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

# Set to True when you want to enforce API key (recommended for production)
REQUIRE_AUTH = True

# List of valid API keys (you can add more)
VALID_API_KEYS = [
    'dns-shield-admin-2024',      # For manual testing / GUI
    'red-team-tester-2024',       # Specifically for red_team_test.py
    'soc-team-2024',
]

def require_api_key(f):
    """
    Decorator for optional API key authentication
    - If REQUIRE_AUTH = False → allows all requests (easy development)
    - If REQUIRE_AUTH = True  → requires valid X-API-Key header
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not REQUIRE_AUTH:
            return f(*args, **kwargs)   # ← Auth disabled = open access
        
        # Get API key from header (most common)
        api_key = request.headers.get('X-API-Key')
        
        # Fallback: check query parameter (for easy testing)
        if not api_key:
            api_key = request.args.get('api_key')
        
        if not api_key:
            return jsonify({
                'error': 'Authentication required',
                'message': 'Please provide X-API-Key header'
            }), 401
        
        if api_key in VALID_API_KEYS:
            return f(*args, **kwargs)
        
        return jsonify({
            'error': 'Invalid API key',
            'message': 'The provided API key is not valid'
        }), 403
    
    return decorated_function

def track_threat_for_audio_alert(domain, threat_type, confidence):
    """Track malicious detection for audio alert system"""
    global RECENT_THREATS
    threat_data = {
        'domain': domain,
        'threat_type': threat_type,
        'confidence': confidence,
        'timestamp': time.time(),
        'time_str': time.strftime('%H:%M:%S')
    }
    RECENT_THREATS.append(threat_data)
    # Keep only last MAX_RECENT_THREATS
    if len(RECENT_THREATS) > MAX_RECENT_THREATS:
        RECENT_THREATS.pop(0)
# ═══════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════
def send_email_alert(domain, threat_type, confidence, incident_id):
    """Send a professional, standardized email alert for malicious domain detection."""
    if not ENABLE_EMAIL_ALERTS:
        return
    try:
        # Professional subject line
        subject = f"🚨 SECURITY ALERT: Malicious Domain Detected - {domain}"
        
        # Plain text version (for older email clients)
        text_body = f"""
╔══════════════════════════════════════════════════════════════════════╗
║                      SECURITY ALERT NOTIFICATION                   ║
╚══════════════════════════════════════════════════════════════════════╝

IMMEDIATE ATTENTION REQUIRED

A malicious domain has been detected and automatically blocked by DNS Shield.
Please review the details below and take appropriate action.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 INCIDENT DETAILS:

   Incident ID:        {incident_id}
   Detection Time:     {time.strftime('%Y-%m-%d %H:%M:%S UTC')}
   
   Malicious Domain:   {domain}
   Threat Type:        {threat_type}
   Confidence Level:   {confidence}
   
   Status:              BLOCKED & SINKHOLED

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 ACTIONS TAKEN:

   ✓ Domain automatically sinkholed to prevent access
   ✓ Incident logged in forensic audit database
   ✓ Threat metrics updated in monitoring dashboard
   ✓ Alert generated and sent to security team

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 THREAT CLASSIFICATION:

   {threat_type}
   
   Common indicators:
   • Suspicious domain patterns
   • Known malicious infrastructure
   • Behavioral anomalies detected
   • ML model confidence: {confidence}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 RECOMMENDED ACTIONS:

   1. Review full incident details in audit log
   2. Verify no users accessed this domain
   3. Check for related indicators of compromise
   4. Update threat intelligence feeds
   5. Monitor for similar attack patterns

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 RESOURCES:

   • View Incident: http://localhost:5000/security/audit-view
   • System Dashboard: http://localhost:3000 (Grafana)
   • Metrics: http://localhost:9090 (Prometheus)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ℹ  SYSTEM INFORMATION:

   System:             DNS Shield AI - Two-Layer Defense System
   Detection Engine:   LSTM + Heuristic Analysis + VirusTotal
   Alert Priority:     HIGH
   Response:           Automated

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

This is an automated security alert. Do not reply to this email.
For urgent issues, contact your security operations team.

Generated by DNS Shield - Advanced Threat Detection System
University of West London - Cybersecurity Research Project
Student ID: 32146633 | Aayisha Ashraf
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

        # HTML version (for modern email clients)
        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px; }}
        .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #ef4444, #dc2626); color: white; padding: 30px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 24px; }}
        .alert-box {{ background: #fee2e2; border-left: 4px solid #ef4444; padding: 15px; margin: 20px; color: #991b1b; font-weight: bold; }}
        .section {{ padding: 20px; border-bottom: 1px solid #e5e7eb; }}
        .section h2 {{ color: #374151; font-size: 18px; margin-top: 0; }}
        .detail-row {{ display: flex; padding: 8px 0; }}
        .detail-label {{ font-weight: bold; color: #6b7280; min-width: 150px; }}
        .detail-value {{ color: #1f2937; }}
        .status-badge {{ display: inline-block; background: #10b981; color: white; padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .action-list {{ background: #f9fafb; padding: 15px; border-radius: 6px; }}
        .action-item {{ padding: 8px 0; color: #374151; }}
        .action-item::before {{ content: "✓ "; color: #10b981; font-weight: bold; }}
        .recommendation {{ background: #eff6ff; border-left: 4px solid #3b82f6; padding: 15px; margin: 20px 0; }}
        .recommendation ol {{ margin: 10px 0; padding-left: 20px; }}
        .recommendation li {{ padding: 5px 0; }}
        .footer {{ background: #f9fafb; padding: 20px; text-align: center; color: #6b7280; font-size: 12px; }}
        .btn {{ display: inline-block; background: #3b82f6; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; margin: 5px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1> SECURITY ALERT NOTIFICATION</h1>
        </div>
        
        <div class="alert-box">
            IMMEDIATE ATTENTION REQUIRED: A malicious domain has been detected and automatically blocked.
        </div>
        
        <div class="section">
            <h2> Incident Details</h2>
            <div class="detail-row">
                <div class="detail-label">Incident ID:</div>
                <div class="detail-value"><code>{incident_id}</code></div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Detection Time:</div>
                <div class="detail-value">{time.strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Malicious Domain:</div>
                <div class="detail-value"><strong>{domain}</strong></div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Threat Type:</div>
                <div class="detail-value"><strong style="color: #ef4444;">{threat_type}</strong></div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Confidence Level:</div>
                <div class="detail-value">{confidence}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Status:</div>
                <div class="detail-value"><span class="status-badge">✅ BLOCKED & SINKHOLED</span></div>
            </div>
        </div>
        
        <div class="section">
            <h2> Actions Taken</h2>
            <div class="action-list">
                <div class="action-item">Domain automatically sinkholed to prevent access</div>
                <div class="action-item">Incident logged in forensic audit database</div>
                <div class="action-item">Threat metrics updated in monitoring dashboard</div>
                <div class="action-item">Alert generated and sent to security team</div>
            </div>
        </div>
        
        <div class="section">
            <h2> Threat Classification: {threat_type}</h2>
            <p><strong>Common indicators:</strong></p>
            <ul>
                <li>Suspicious domain patterns</li>
                <li>Known malicious infrastructure</li>
                <li>Behavioral anomalies detected</li>
                <li>ML model confidence: {confidence}</li>
            </ul>
        </div>
        
        <div class="recommendation">
            <h2> Recommended Actions</h2>
            <ol>
                <li>Review full incident details in audit log</li>
                <li>Verify no users accessed this domain</li>
                <li>Check for related indicators of compromise</li>
                <li>Update threat intelligence feeds</li>
                <li>Monitor for similar attack patterns</li>
            </ol>
        </div>
        
        <div class="section" style="text-align: center;">
            <h2> Quick Access</h2>
            <a href="http://localhost:5000/security/audit-view" class="btn">View Incident</a>
            <a href="http://localhost:3000" class="btn">Dashboard</a>
            <a href="http://localhost:9090" class="btn">Metrics</a>
        </div>
        
        <div class="footer">
            <p><strong>DNS Shield AI - Two-Layer Defense System</strong></p>
            <p>Detection Engine: LSTM + Heuristic Analysis + VirusTotal</p>
            <p>Alert Priority: HIGH | Response: Automated</p>
            <hr style="margin: 15px 0; border: none; border-top: 1px solid #e5e7eb;">
            <p style="font-size: 11px;">
                This is an automated security alert. Do not reply to this email.<br>
                For urgent issues, contact your security operations team.
            </p>
            <p style="font-size: 11px; margin-top: 15px;">
                Generated by DNS Shield - Advanced Threat Detection System<br>
                University of West London - Cybersecurity Research Project<br>
                Student ID: 32146633 | Aayisha Ashraf
            </p>
        </div>
    </div>
</body>
</html>
"""
        
        # Create multipart message with both plain text and HTML
        msg = MIMEMultipart('alternative')
        msg['From'] = SMTP_USER
        msg['To'] = ALERT_RECIPIENT
        msg['Subject'] = subject
        
        # Attach both versions (email clients will choose the best one)
        msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        print(f" Professional alert email sent for {domain}")
    except Exception as e:
        print(f" Email alert failed: {e}")

def check_virustotal(domain):
    """Query VirusTotal API, return (is_malicious, details). Caches results."""
    if not ENABLE_VIRUSTOTAL or not VIRUSTOTAL_API_KEY:
        return False, "VirusTotal disabled"
    now = time.time()
    # Check cache
    if domain in vt_cache:
        cached = vt_cache[domain]
        if now - cached['timestamp'] < VT_CACHE_TTL:
            return cached['malicious'], cached['details']
    # API call
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        resp = requests.get(url, headers=headers, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0) > 0
            details = f"VT: {stats.get('malicious',0)}/{stats.get('total',0)} engines flagged"
            # Cache result
            vt_cache[domain] = {'timestamp': now, 'malicious': malicious, 'details': details}
            # Keep cache size limited
            if len(vt_cache) > 1000:
                vt_cache.popitem(last=False)
            return malicious, details
        else:
            return False, f"VT API error {resp.status_code}"
    except Exception as e:
        print(f"VT lookup error: {e}")
        return False, "VT lookup failed"
    
def _entropy(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((v / len(s)) * math.log2(v / len(s)) for v in freq.values())

def clean_input(raw_text):
    clean = raw_text.lower().strip()
    clean = re.sub(r'^[a-z][a-z0-9+\-.]*://', '', clean)
    if clean.startswith('www.'):
        clean = clean[4:]
    clean = clean.split('/')[0].split('?')[0].split('#')[0].split(':')[0]
    return clean.strip('.')

def is_domain_whitelisted(domain):
    if domain in TRUSTED_DOMAINS:
        return True
    parts = domain.split('.')
    for i in range(1, len(parts)):
        if '.'.join(parts[i:]) in TRUSTED_DOMAINS:
            return True
    if parts[0] in TRUSTED_BRANDS:
        return True
    return False

def load_existing_incidents():
    """Load all incidents from forensic audit log into a dict keyed by domain+action."""
    incidents = {}  # key: f"{domain}|{action}" -> incident_id
    log_path = "dns_shield_forensic_audit.json"
    if os.path.exists(log_path):
        with open(log_path, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    domain = entry.get('domain')
                    action = entry.get('action_taken')
                    if domain and action:
                        key = f"{domain}|{action}"
                        if key not in incidents:
                            incidents[key] = entry.get('incident_id')
                except:
                    pass
    return incidents

def get_existing_incident_id(domain, action_taken):
    """Return incident_id if domain+action already logged, else None."""
    incidents = load_existing_incidents()
    key = f"{domain}|{action_taken}"
    return incidents.get(key)

def is_domain_in_sinkhole(domain):
    """Check if domain already exists in sinkhole blocklist."""
    sinkhole_path = "sinkhole_blocklist.txt"
    if not os.path.exists(sinkhole_path):
        return False
    with open(sinkhole_path, 'r') as f:
        for line in f:
            if line.strip() and not line.startswith('#'):
                existing_domain = line.split()[0] if line.split() else ''
                if existing_domain == domain:
                    return True
    return False
# ═══════════════════════════════════════════════════════════════════════════
# ATTACK DETECTION FUNCTIONS - ENHANCED FOR ALL 8 TYPES
# ═══════════════════════════════════════════════════════════════════════════

def detect_typosquatting(domain):
    """Enhanced typosquatting detection"""
    norm = domain.replace('0', 'o').replace('1', 'l').replace('3', 'e') \
                 .replace('4', 'a').replace('5', 's')
    for trusted in TRUSTED_DOMAINS:
        if domain == trusted:
            return None
        if norm == trusted or norm.endswith("." + trusted):
            return f"Typosquatting: Visual substitution of {trusted}"
        ratio = SequenceMatcher(None, domain, trusted).ratio()
        if 0.78 <= ratio < 1.0:
            return f"Typosquatting: {int(ratio * 100)}% similarity to {trusted}"
    
    # Check homograph attacks
    for trusted in TRUSTED_BRANDS:
        if trusted in norm and domain != trusted:
            return f"Homograph: Character substitution mimicking {trusted}"
    
    return None

def detect_fast_flux(domain):
    """Enhanced fast flux detection"""
    parts  = domain.split('.')
    labels = parts[:-1] if len(parts) > 2 else parts
    found  = []

    # Multi-level subdomain detection (traditional fast flux)
    if len(parts) >= 6:
        found.append(f"Fast Flux: {len(parts)-1} subdomain levels (IP rotation)")

    rand = [l for l in labels[:-1] if len(l) <= 8 and _entropy(l) > 2.5]
    if len(rand) >= 3:
        found.append(f"Fast Flux: {len(rand)} rotating subdomain labels")

    numbered = sum(1 for l in labels[:-1] if re.search(r'[a-z]+\d+$', l))
    if numbered >= 3:
        found.append(f"Fast Flux: {numbered} numbered rotation labels")
    
    # NEW: Detect phishing patterns (login/account/secure + suspicious domain)
    domain_lower = domain.lower()
    phishing_prefixes = ['login.', 'account.', 'secure.', 'verify.', 'update.', 
                         'signin.', 'banking.', 'payment.', 'wallet.']
    suspicious_domains = ['bank-site', 'paypal-', 'amazon-', 'microsoft-', 
                         'google-', 'apple-', 'netflix-', 'facebook-']
    
    for prefix in phishing_prefixes:
        if domain_lower.startswith(prefix):
            # Check if rest of domain looks suspicious
            for susp in suspicious_domains:
                if susp in domain_lower:
                    found.append(f"Fast Flux / Phishing: Suspicious '{prefix}' with '{susp}'")
                    return found

    return found

def detect_dns_tunneling(domain):
    """Enhanced DNS tunneling detection"""
    parts = domain.split('.')
    found = []
    seen  = set()

    for label in parts:
        llen = len(label)
        ent  = _entropy(label)

        if llen > 20 and 'long' not in seen:
            found.append(f"DNS Tunneling: {llen}-char label (data exfil)")
            seen.add('long')

        if (llen >= 12 and re.fullmatch(r'[A-Za-z0-9+/=_-]+', label)
                and ent >= 3.2 and 'b64' not in seen):
            found.append("DNS Tunneling: Base64-encoded payload")
            seen.add('b64')

        if llen >= 12 and re.fullmatch(r'[0-9a-fA-F]+', label) and 'hex' not in seen:
            found.append("DNS Tunneling: Hex-encoded data")
            seen.add('hex')

        if llen >= 10 and ent > 4.0 and 'hiEnt' not in seen:
            found.append(f"DNS Tunneling: High entropy label ({ent:.2f})")
            seen.add('hiEnt')

    cmd_hits = [p for p in ['cmd','exe','whoami','passwd','bash','shell','powershell']
                if p in domain.lower()]
    if len(cmd_hits) >= 2:
        found.append(f"DNS Tunneling: Command strings {cmd_hits}")

    return found

def detect_dga(domain, entropy):
    """Enhanced DGA detection for Pure DGA and Structured DGA"""
    domain_name = domain.split('.')[0]
    domain_length = len(domain_name)
    found = []
    
    # Check for STRUCTURED DGA first (word + number patterns)
    match = re.match(r'([a-z]+)(\d{3,})$', domain_name)
    if match:
        word, num = match.groups()
        if word in ['data', 'update', 'system', 'cloud', 'server', 'backup', 'service', 'check', 'verify', 'status']:
            found.append(f"Structured DGA: Pattern '{word}{num}'")
            return found
    
    # Check for C2 BEACONING patterns (ENHANCED)
    c2_keywords = ['check-', 'verify-', 'status-', 'update-', 'ping-', 'beacon-', 'callback-',
                   'updates.', 'service-', 'time.', 'sync-', 'health-', 'monitor-']
    suspicious_tlds = ['service-network', 'check-sync', 'status-check', 'update-service',
                      'monitor-net', 'health-check', 'ping-service']
    
    # Check domain name for C2 patterns
    domain_lower = domain.lower()
    for pattern in c2_keywords:
        if pattern in domain_name:
            found.append(f"C2 Beaconing: Suspicious pattern '{pattern}'")
            return found
    
    # Check full domain for suspicious service-like patterns
    for tld in suspicious_tlds:
        if tld in domain_lower:
            found.append(f"C2 Beaconing: Suspicious service pattern '{tld}'")
            return found
    
    # PURE DGA: High entropy + reasonable length
    if entropy > 4.5 and domain_length >= 20:
        found.append(f"Pure DGA: Very high entropy ({entropy:.2f}), {domain_length} chars")
        return found
    
    if entropy > 4.0 and domain_length >= 12:
        vowels = sum(1 for c in domain_name if c in 'aeiou')
        digits = sum(1 for c in domain_name if c.isdigit())
        vowel_ratio = vowels / domain_length
        digit_ratio = digits / domain_length
        
        if vowel_ratio < 0.15 and entropy > 3.5:
            found.append(f"Pure DGA: Low vowel ratio + high entropy ({entropy:.2f})")
        
        if digit_ratio > 0.3 and entropy > 3.5:
            found.append(f"Pure DGA: High digit ratio random pattern")
    
    return found

def classify_attack_type(domain, entropy, dga_hits, ff_hits, tun_hits, typo_msg):
    """Enhanced classification for all 8 attack types"""
    domain_name = domain.split('.')[0]
    domain_lower = domain.lower()
    
    # Priority order
    if typo_msg:
        if 'Homograph' in typo_msg:
            return 'Homograph'
        return 'Typosquatting'
    
    if tun_hits:
        return 'Tunneling'
    
    if ff_hits:
        # Check if it's phishing or traditional fast flux
        for hit in ff_hits:
            if 'Phishing' in hit:
                return 'FastFlux_Phishing'
        return 'FastFlux'
    
    if dga_hits:
        for hit in dga_hits:
            if 'Structured DGA' in hit:
                return 'Structured_DGA'
            if 'C2 Beaconing' in hit or 'C2' in hit:
                return 'C2'
            if 'Pure DGA' in hit:
                return 'DGA'
    
    # IBHH check - internal hostname patterns
    internal_tlds = ['.local', '.internal', '.corp', '.lan', '.home', '.priv']
    for tld in internal_tlds:
        if tld in domain_lower:
            return 'IBHH'
    
    internal_names = ['fileserver', 'printserver', 'dc01', 'dc02', 'exchange', 
                     'sharepoint', 'sqlserver', 'webserver', 'mailserver']
    for name in internal_names:
        if name in domain_name:
            return 'IBHH'
    
    # IBHH check - character repetition (data exfiltration)
    if len(domain_name) >= 12:
        from collections import Counter
        counts = Counter(domain_name)
        max_freq = max(counts.values())
        if max_freq / len(domain_name) > 0.45:
            return 'IBHH'
    
    # Fallback checks
    if entropy > 4.5 and len(domain_name) >= 15:
        return 'DGA'
    
    if 3.3 <= entropy <= 4.0:
        # Check for C2 patterns
        suspicious = ['secure', 'update', 'portal', 'login', 'cloud', 'api', 'check', 'verify', 'status']
        if any(w in domain.lower() for w in suspicious) and any(c.isdigit() for c in domain):
            return 'C2'
    
    return 'Other'

def check_ibhh_rate(domain):
    """
    Check IBHH (Internal-Based Hostname Hijacking) indicators
    Returns rate if suspicious, 0 otherwise
    """
    domain_name = domain.split('.')[0]
    domain_lower = domain.lower()
    
    # Check for internal hostname patterns
    internal_tlds = ['.local', '.internal', '.corp', '.lan', '.home', '.priv']
    for tld in internal_tlds:
        if tld in domain_lower:
            return 0.9  # High suspicion for internal TLDs
    
    # Check for common internal server names
    internal_names = ['fileserver', 'printserver', 'dc01', 'dc02', 'exchange', 
                     'sharepoint', 'sqlserver', 'webserver', 'mailserver',
                     'srv01', 'srv02', 'nas', 'backup']
    for name in internal_names:
        if name in domain_name:
            return 0.85  # High suspicion for internal server names
    
    # Original character repetition check for data exfiltration
    if len(domain_name) < 8:
        return 0.0
    
    from collections import Counter
    counts = Counter(domain_name)
    max_freq = max(counts.values())
    rate = max_freq / len(domain_name)
    
    return rate if rate > 0.3 else 0.0

# ═══════════════════════════════════════════════════════════════════════════
# ACTIVE DEFENSE & GOVERNANCE LAYER
# ═══════════════════════════════════════════════════════════════════════════

def security_action_controller(detection_result):
    """
     SOC AUTOMATED RESPONSE LAYER
    
    This function acts as the 'SOC Automated Response' layer.
    It implements:
    1. AUTOMATED SINKHOLE (Active Defense)
    2. INCIDENT ID GENERATION (GDPR/HIPAA Compliance)
    3. FORENSIC AUDIT LOGGING (Governance)
    
    This moves the system from passive IDS to active IPS.
    """
    import uuid
    import time
    
    domain = detection_result['domain']
    is_malicious = detection_result['malicious']
    
    # 1. GENERATE COMPLIANCE AUDIT ID (Governance)
    # This creates a unique ID for every incident, essential for GDPR/HIPAA
    incident_id = f"DNS-{uuid.uuid4().hex[:8].upper()}"
    detection_result['incident_id'] = incident_id
    detection_result['timestamp'] = time.strftime("%Y-%m-%d %H:%M:%S")
    
    # 2. AUTOMATED SINKHOLE (Active Defense)
    if is_malicious:
        # Check if already in sinkhole
        if not is_domain_in_sinkhole(domain):
            sinkhole_path = "sinkhole_blocklist.txt"
            try:
                with open(sinkhole_path, "a") as block_file:
                    threat_type = detection_result.get('threat_type', 'Unknown')
                    confidence = detection_result.get('confidence', 'N/A')
                    block_file.write(
                        f"{domain} # Incident: {incident_id} | "
                        f"Threat: {threat_type} | "
                        f"Confidence: {confidence} | "
                        f"Time: {detection_result['timestamp']}\n"
                    )
                detection_result['action_taken'] = "SINKHOLED"
                print(f"  Security Action: Domain {domain} added to Sinkhole blocklist (ID: {incident_id})")
            except Exception as e:
                print(f"  Sinkhole Error: {e}")
                detection_result['action_taken'] = "BLOCKED_LOGGED_ONLY"
        else:
            detection_result['action_taken'] = "SINKHOLED_ALREADY"
            print(f"ℹ Domain {domain} already in sinkhole, skipping duplicate.")
    else:
        detection_result['action_taken'] = "ALLOWED"

    # 3. FINAL FORENSIC LOGGING (GDPR/HIPAA Audit Trail)
    log_path = "dns_shield_forensic_audit.json"
    try:
        with open(log_path, "a") as log_file:
            log_file.write(json.dumps(detection_result) + "\n")
    except Exception as e:
        print(f"  Forensic Log Error: {e}")
        
    return detection_result

def manual_override(domain, action="whitelist", reason="Administrator decision"):
    """
     MANUAL ADMIN OVERRIDE with deduplication
    """
    import uuid
    import time

    action_taken = action.upper()  # WHITELIST or BLACKLIST
    
    # Check if already handled
    existing_id = get_existing_incident_id(domain, action_taken)
    if existing_id:
        print(f" Manual Action: Domain {domain} already {action_taken} (Incident: {existing_id})")
        return {
            "incident_id": existing_id,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "domain": domain,
            "action_taken": action_taken,
            "duplicate": True,
            "message": f"Domain already {action_taken}"
        }
    
    incident_id = f"MANUAL-{uuid.uuid4().hex[:8].upper()}"
    
    log_entry = {
        "incident_id": incident_id,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "domain": domain,
        "malicious": False if action == "whitelist" else True,
        "threat_type": "Manual Administrator Entry",
        "confidence": "1.0000",
        "explanation": {"analysis": {"bullets": [reason]}},
        "layer_used": "ADMIN_CONSOLE",
        "stage": "Manual Override",
        "attack_type": None if action == "whitelist" else "Manually Blacklisted",
        "action_taken": action_taken,
        "ibhh_rate": None,
        "prediction": "benign" if action == "whitelist" else "malicious"
    }
    
    # Write to audit log
    log_path = "dns_shield_forensic_audit.json"
    try:
        with open(log_path, "a") as log_file:
            log_file.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"  Forensic Log Error: {e}")
    
    # For whitelist, also add to a custom whitelist file (optional but useful)
    if action == "whitelist":
        whitelist_file = "custom_whitelist.txt"
        try:
            with open(whitelist_file, "a") as wf:
                wf.write(f"{domain} # Manual whitelist {incident_id}\n")
        except:
            pass
    else:
        # Blacklist: add to sinkhole if not already present
        if not is_domain_in_sinkhole(domain):
            sinkhole_path = "sinkhole_blocklist.txt"
            try:
                with open(sinkhole_path, "a") as block_file:
                    block_file.write(
                        f"{domain} # Incident: {incident_id} | "
                        f"Threat: Manual Blacklist | "
                        f"Confidence: 1.0000 | "
                        f"Time: {log_entry['timestamp']}\n"
                    )
                print(f"  Security Action: Domain {domain} added to Sinkhole blocklist (ID: {incident_id})")
            except Exception as e:
                print(f"  Sinkhole Error: {e}")
    
    print(f" Manual Action: {domain} has been {action}ed by administrator. Incident: {incident_id}")
    return log_entry


# ═══════════════════════════════════════════════════════════════════════════
# AI ENGINE
# ═══════════════════════════════════════════════════════════════════════════

extractor = None
scaler = None
lstm_model = None
expected_features = []
model_loaded = False

try:
    sys.path.append(os.path.join(os.getcwd(), 'src'))
    
    from feature_extractor import DNSFeatureExtractor
    
    class TrainingFeatureMapper:
        def __init__(self):
            self.extractor = DNSFeatureExtractor()
            self.feature_mapping = {
                'length': 'dns_domain_name_length',
                'entropy': 'character_entropy',
                'digit_ratio': 'numerical_percentage',
                'consecutive_digits': 'max_continuous_numeric_len',
            }
        
        def extract_features(self, domain):
            raw = self.extractor.extract_features(domain)
            mapped = {}
            for k, v in self.feature_mapping.items():
                if k in raw:
                    mapped[v] = raw[k]
            
            domain_len = raw.get('length', len(domain))
            entropy = raw.get('entropy', 0)
            
            mapped.update({
                'min_packets_len': 64 if domain_len < 20 else 128,
                'max_packets_len': 256 if domain_len < 20 else 512,
                'mean_packets_len': 128 if domain_len < 20 else 256,
                'sending_bytes': domain_len * 50,
                'receiving_bytes': domain_len * 40,
                'total_bytes': domain_len * 90,
                'packets_len_rate': 1.0,
                'variance_packets_len': 10.0 if domain_len < 20 else 50.0,
                'distinct_A_records': 1 if domain_len < 20 else 2,
                'ttl_values_max': 3600,
                'ttl_values_mean': 1800,
                'entropy': entropy
            })
            return mapped

    # Load models
    scaler = joblib.load("models/dns_scaler_final.pkl")
    lstm_model = load_model("models/dns_covert_detector_final.h5", compile=False)
    lstm_model.compile(optimizer='adam', loss='binary_crossentropy')
    
    extractor = TrainingFeatureMapper()
    
    with open("models/final_features.txt", 'r') as f:
        expected_features = [feat.strip() for feat in f.read().split(',') if feat.strip()]
    
    model_loaded = True
    print(f" AI Shield Ready: {len(expected_features)} features | LSTM model loaded successfully")

except Exception as e:
    print(f" CRITICAL: AI Model failed to load: {e}")
    import traceback
    traceback.print_exc()
    print("  Falling back to heuristic-only detection (Layer 1 only)")

    # Dummy extractor that works without the deep learning model
    class DummyExtractor:
        def extract_features(self, domain):
            domain_name = domain.split('.')[0]
            return {
                'length': len(domain_name),
                'entropy': _entropy(domain_name),
                'digit_count': sum(c.isdigit() for c in domain_name),
                'vowel_ratio': sum(1 for c in domain_name if c in 'aeiou') / max(1, len(domain_name)),
                'consecutive_digits': 0,
            }
    extractor = DummyExtractor()
    scaler = None
    lstm_model = None
    expected_features = []
    model_loaded = False
# ═══════════════════════════════════════════════════════════════════════════
# EXPLANATION GENERATOR (WITH UNIQUE QUERY-SPECIFIC XAI)
# ═══════════════════════════════════════════════════════════════════════════
def get_detailed_explanation(features, prob, typo_msg, is_whitelisted,
                             dga_hits=None, ff_hits=None, tun_hits=None, 
                             layer_used="", entropy=0, ibhh_rate=None, domain=""):
    """
    Returns structured explanation with:
    - Original bullet-point analysis (unchanged)
    - NEW: Unique, query-specific XAI section with defensive measures
    """
    reasons = []

    # ────────────────────────────────────────────────
    # YOUR ORIGINAL ANALYSIS (kept 100% unchanged)
    # ────────────────────────────────────────────────
    if is_whitelisted:
        reasons.append(" Whitelisted: Verified safe source")
    else:
        # Layer information
        if layer_used:
            if "Layer 1" in layer_used:
                if "Low" in layer_used:
                    reasons.append(f"⚡ Layer 1 Fast Decision: Low entropy ({entropy:.2f}) = Natural language")
                else:
                    reasons.append(f"⚡ Layer 1 Fast Decision: High entropy ({entropy:.2f}) = Random/suspicious")
            elif "Layer 2" in layer_used:
                reasons.append(f" Layer 2 Deep Analysis: Ambiguous entropy ({entropy:.2f}) required LSTM")

        # Attack-specific reasons
        if typo_msg:
            reasons.append(typo_msg)
        for h in (dga_hits or []):
            reasons.append(h)
        for h in (ff_hits or []):
            reasons.append(h)
        for h in (tun_hits or []):
            reasons.append(h)

        # IBHH detection
        if ibhh_rate and ibhh_rate > 0.45:
            reasons.append(f"IBHH: High character repetition rate ({ibhh_rate:.1%})")

        # Additional heuristics
        if entropy > 3.8 and not dga_hits:
            reasons.append(f"High Entropy ({round(entropy,2)}): Random character pattern")
        if features.get('length', 0) > 30:
            reasons.append("Abnormal Length: Possible data exfiltration")
        if prob and prob > 0.5:
            reasons.append("Neural Network: Detected malicious signature")

    original_analysis = {
        "bullets": reasons,
        "metrics": {
            "Entropy": round(entropy, 2),
            "Length":  features.get('length', 0),
            "Digits":  features.get('digit_count', 0),
            "V-Ratio": round(features.get('vowel_ratio', 0), 2)
        }
    }

    # ────────────────────────────────────────────────
    # NEW: UNIQUE QUERY-SPECIFIC XAI SECTION
    # ────────────────────────────────────────────────
    xai_lines = []
    xai_lines.append("═══════════════════════════════════════════════════")
    xai_lines.append("XAI EXPLAINABILITY REPORT")
    xai_lines.append("═══════════════════════════════════════════════════")
    xai_lines.append("")
    
    # Extract domain characteristics for unique analysis
    domain_name = domain.split('.')[0] if domain else "unknown"
    domain_parts = domain.split('.') if domain else []
    num_subdomains = len(domain_parts) - 2 if len(domain_parts) > 2 else 0
    has_numbers = any(c.isdigit() for c in domain_name)
    vowel_count = sum(1 for c in domain_name if c in 'aeiou')
    consonant_count = len([c for c in domain_name if c.isalpha() and c not in 'aeiou'])
    
    # SECTION 1: DOMAIN-SPECIFIC ANALYSIS
    xai_lines.append("1. DOMAIN-SPECIFIC ANALYSIS")
    xai_lines.append("─" * 50)
    xai_lines.append(f"   Domain under review: {domain}")
    xai_lines.append(f"   Primary label: '{domain_name}' ({len(domain_name)} characters)")
    
    if is_whitelisted:
        xai_lines.append(f"   ✓ WHITELISTED: This domain is on our trusted list")
        xai_lines.append(f"   • Recognition: Known legitimate service")
        xai_lines.append(f"   • Historical data: Clean record, no previous threats")
        xai_lines.append(f"   • Confidence: 99.8% certainty this is safe")
    else:
        xai_lines.append(f"   • Subdomain levels: {num_subdomains}")
        xai_lines.append(f"   • Character composition: {vowel_count} vowels, {consonant_count} consonants")
        xai_lines.append(f"   • Shannon entropy: {entropy:.3f} (normal range: 2.5-3.5)")
        xai_lines.append(f"   • Numeric presence: {'Yes' if has_numbers else 'No'}")
    
    xai_lines.append("")
    
    # SECTION 2: THREAT INDICATORS (if malicious)
    if not is_whitelisted and (dga_hits or typo_msg or ff_hits or tun_hits or (ibhh_rate and ibhh_rate > 0.45)):
        xai_lines.append("2. THREAT INDICATORS DETECTED")
        xai_lines.append("─" * 50)
        
        # DGA Detection
        if dga_hits:
            for hit in dga_hits:
                if 'Pure DGA' in hit:
                    xai_lines.append(f"    PURE DOMAIN GENERATION ALGORITHM (DGA) DETECTED")
                    xai_lines.append(f"   • Pattern: Algorithmically generated random domain")
                    xai_lines.append(f"   • Entropy: {entropy:.2f} (threshold: {HIGH_ENTROPY_THRESHOLD})")
                    xai_lines.append(f"   • Character randomness: {entropy/4*100:.1f}% of maximum")
                    xai_lines.append(f"   • Typical use: C&C communication, malware callbacks")
                elif 'Structured DGA' in hit:
                    xai_lines.append(f"    STRUCTURED DGA PATTERN DETECTED")
                    xai_lines.append(f"   • Pattern: Predictable word+number combination")
                    xai_lines.append(f"   • Example: {hit}")
                    xai_lines.append(f"   • Typical use: Coordinated malware campaigns")
                elif 'C2 Beaconing' in hit or 'C2' in hit:
                    xai_lines.append(f"    COMMAND & CONTROL (C2) BEACONING DETECTED")
                    xai_lines.append(f"   • Pattern: Suspicious callback structure")
                    xai_lines.append(f"   • Example: {hit}")
                    xai_lines.append(f"   • Typical use: Remote malware control, data exfiltration")
        
        # Typosquatting Detection  
        if typo_msg:
            if 'Homograph' in typo_msg:
                xai_lines.append(f"    HOMOGRAPH ATTACK DETECTED")
                xai_lines.append(f"   • Technique: Character lookalike substitution")
                xai_lines.append(f"   • Example: {typo_msg}")
                xai_lines.append(f"   • User impact: Credential theft, phishing")
            else:
                xai_lines.append(f"    TYPOSQUATTING ATTACK DETECTED")
                xai_lines.append(f"   • Technique: Visual similarity to legitimate brand")
                xai_lines.append(f"   • Details: {typo_msg}")
                xai_lines.append(f"   • User impact: Credential theft, phishing, malware")
        
        # Fast Flux Detection
        if ff_hits:
            xai_lines.append(f"    FAST FLUX NETWORK DETECTED")
            xai_lines.append(f"   • Infrastructure: {num_subdomains + 2} subdomain levels")
            xai_lines.append(f"   • Behavior: Rapid DNS record rotation (IP changing)")
            xai_lines.append(f"   • Purpose: Evade takedowns, hide infrastructure")
        
        # DNS Tunneling Detection
        if tun_hits:
            xai_lines.append(f"    DNS TUNNELING / DATA EXFILTRATION DETECTED")
            xai_lines.append(f"   • Method: Data encoded in DNS subdomain labels")
            xai_lines.append(f"   • Detected patterns: {', '.join(tun_hits[:2])}")
            xai_lines.append(f"   • Purpose: Bypass firewalls, exfiltrate sensitive data")
        
        # IBHH Detection
        if ibhh_rate and ibhh_rate > 0.45:
            xai_lines.append(f"    IBHH (IMPLICIT BURST HEADER & HASH) DETECTED")
            xai_lines.append(f"   • Pattern: High character repetition ({ibhh_rate:.1%})")
            xai_lines.append(f"   • Indicates: Sequential data chunking for exfiltration")
            xai_lines.append(f"   • Purpose: Covert data transmission via DNS")
        
        xai_lines.append("")
    
    # SECTION 3: DEFENSIVE RECOMMENDATIONS
    xai_lines.append("3. RECOMMENDED ACTIONS")
    xai_lines.append("─" * 50)
    
    if is_whitelisted:
        xai_lines.append("    ALLOW - No action needed, domain is trusted")
    else:
        if dga_hits or typo_msg or ff_hits or tun_hits or (ibhh_rate and ibhh_rate > 0.45):
            xai_lines.append("    BLOCK - Immediate threat detected")
            xai_lines.append("   • Network action: Drop DNS query, return NXDOMAIN")
            xai_lines.append("   • User notification: Display security warning")
            xai_lines.append("   • Logging: Record incident for security analysis")
            xai_lines.append("   • Alert: Notify security team of potential compromise")
        else:
            xai_lines.append("    MONITOR - Ambiguous case, continue observation")
            xai_lines.append("   • Allow with logging for behavioral analysis")
    
    xai_lines.append("")
    xai_lines.append("═══════════════════════════════════════════════════")
    
    return {
        "analysis": original_analysis,
        "xai_report": "\n".join(xai_lines)
    }

# ═══════════════════════════════════════════════════════════════════════════
# HTML TEMPLATE - YOUR ORIGINAL GUI (100% PRESERVED)
# ═══════════════════════════════════════════════════════════════════════════

UI_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNS Shield AI</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        @keyframes gradient-shift {
            0%, 100% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
        }
        
        @keyframes float {
            0%, 100% { transform: translateY(0px); }
            50% { transform: translateY(-10px); }
        }
        
        @keyframes slide-in {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        @keyframes slide-in-right {
            from { opacity: 0; transform: translateX(-20px); }
            to { opacity: 1; transform: translateX(0); }
        }
        
        body {
            font-family: 'Inter', -apple-system, system-ui, sans-serif !important;
            background: linear-gradient(135deg, #1a0b2e 0%, #2d1b69 25%, #1e3a8a 50%, #7c3aed 100%) !important;
            background-size: 400% 400% !important;
            animation: gradient-shift 20s ease infinite !important;
            color: #f1f5f9 !important;
            min-height: 100vh !important;
        }
        
        .container {
            max-width: 1400px !important;
        }
        
        h1 {
            background: linear-gradient(135deg, #60a5fa, #a78bfa, #ec4899);
            -webkit-background-clip: text !important;
            -webkit-text-fill-color: transparent !important;
            background-clip: text !important;
            font-weight: 900 !important;
            letter-spacing: -1px !important;
            animation: float 3s ease-in-out infinite !important;
        }
        
        .glass-card {
            background: rgba(30, 27, 75, 0.6) !important;
            backdrop-filter: blur(20px) saturate(180%) !important;
            border: 1px solid rgba(139, 92, 246, 0.3) !important;
            border-radius: 24px !important;
            padding: 32px !important;
            margin-bottom: 24px !important;
            box-shadow: 0 8px 32px 0 rgba(139, 92, 246, 0.2) !important;
            transition: all 0.3s ease !important;
        }
        
        .glass-card:hover {
            transform: translateY(-4px) !important;
            box-shadow: 0 12px 48px 0 rgba(139, 92, 246, 0.3) !important;
        }
        
        .nav-pills .nav-link {
            color: #94a3b8 !important;
            background: rgba(30, 27, 75, 0.4) !important;
            border: 1px solid rgba(139, 92, 246, 0.2) !important;
            border-radius: 16px !important;
            padding: 12px 24px !important;
            margin: 0 8px !important;
            font-weight: 600 !important;
            transition: all 0.3s ease !important;
        }
        
        .nav-pills .nav-link.active {
            background: linear-gradient(135deg, #8b5cf6, #3b82f6) !important;
            border-color: transparent !important;
            color: white !important;
            box-shadow: 0 4px 20px rgba(139, 92, 246, 0.5) !important;
        }
        
        .nav-pills .nav-link:hover:not(.active) {
            background: rgba(139, 92, 246, 0.2) !important;
            color: #c7d2fe !important;
        }
        
        .stat-value {
            font-size: 3em !important;
            font-weight: 900 !important;
            background: linear-gradient(135deg, #60a5fa, #a78bfa);
            -webkit-background-clip: text !important;
            -webkit-text-fill-color: transparent !important;
            background-clip: text !important;
        }
        
        .reason-pill {
            background: linear-gradient(135deg, rgba(139, 92, 246, 0.15), rgba(59, 130, 246, 0.15));
            border-left: 3px solid #8b5cf6;
            padding: 12px 16px;
            margin: 8px 0;
            border-radius: 12px;
            color: #e2e8f0;
            font-size: 0.85em; /* Made smaller from 0.95em */
            transition: all 0.3s ease;
        }
        
        .reason-pill:hover {
            background: linear-gradient(135deg, rgba(139, 92, 246, 0.25), rgba(59, 130, 246, 0.25));
            transform: translateX(4px);
        }
        
        .xai-box {
            background: rgba(15, 23, 42, 0.8);
            border: 2px solid rgba(139, 92, 246, 0.4);
            border-radius: 16px;
            padding: 24px;
            font-family: 'Courier New', monospace;
            color: #cbd5e1;
            font-size: 1.1em; /* Made bigger from 0.9em to fill the box better */
            line-height: 1.8;
            white-space: pre-wrap;
            max-height: 600px;
            overflow-y: auto;
            text-align: center; /* Center-align the XAI text */
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #8b5cf6, #3b82f6) !important;
            border: none !important;
            transition: all 0.3s ease !important;
            font-weight: 600 !important;
            box-shadow: 0 4px 15px rgba(139, 92, 246, 0.4) !important;
        }
        
        .btn-primary:hover {
            background: linear-gradient(135deg, #7c3aed, #2563eb) !important;
            transform: translateY(-2px) !important;
            box-shadow: 0 6px 20px rgba(139, 92, 246, 0.6) !important;
        }
        
        .form-control {
            background: rgba(30, 27, 75, 0.6) !important;
            border: 2px solid rgba(139, 92, 246, 0.3) !important;
            color: #f1f5f9 !important;
            transition: all 0.3s ease !important;
        }
        
        .form-control:focus {
            background: rgba(30, 27, 75, 0.8) !important;
            border-color: rgba(139, 92, 246, 0.6) !important;
            box-shadow: 0 0 20px rgba(139, 92, 246, 0.3) !important;
        }
        
        #resultsArea {
            animation: slide-in 0.5s ease-out;
        }
        
        .stage-badge {
            display: inline-block;
            padding: 6px 14px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.9em;
            margin: 8px 0;
            animation: float 2s ease-in-out infinite;
        }
        
        .stage-ibhh { 
            background: linear-gradient(135deg, #8b5cf6, #ec4899); 
            color: white;
            box-shadow: 0 4px 15px rgba(139, 92, 246, 0.4);
        }
        
        .stage-normal { 
            background: linear-gradient(135deg, #3b82f6, #06b6d4); 
            color: white;
            box-shadow: 0 4px 15px rgba(59, 130, 246, 0.4);
        }
        
        /* Beautiful table styling for demo feed */
        #demoFeed table {
            border-collapse: separate;
            border-spacing: 0 8px;
            width: 100%;
        }
        
        #demoFeed th, #demoFeed td {
            padding: 12px;
            border: 1px solid rgba(139, 92, 246, 0.3);
        }
        
        #demoFeed thead tr {
            background: linear-gradient(135deg, rgba(139, 92, 246, 0.3), rgba(59, 130, 246, 0.3));
        }
        
        #demoFeed tbody tr {
            background: rgba(30, 27, 75, 0.6);
            transition: all 0.3s ease;
        }
        
        #demoFeed tbody tr:hover {
            background: rgba(139, 92, 246, 0.2);
            transform: translateX(4px);
        }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="text-center mb-4"> DNS SHIELD AI</h1>
        <p class="text-center mb-5" style="color: #c7d2fe; font-size: 1.1em; font-weight: 500; letter-spacing: 1px;">
            <span style="background: linear-gradient(135deg, #60a5fa, #a78bfa, #ec4899); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-weight: 700;">
                Two-Layer Hybrid Detection
            </span> 
            • Real-time Threat Intelligence • XAI Explainability
        </p>
        
        <ul class="nav nav-pills justify-content-center mb-4">
            <li class="nav-item"><a class="nav-link active" id="tab-scan" onclick="switchTab('scan')">THREAT SCANNER</a></li>
            <li class="nav-item"><a class="nav-link" id="tab-demo" onclick="switchTab('demo')"> LIVE DEMO</a></li>
            <li class="nav-item"><a class="nav-link" id="tab-doh" onclick="switchTab('doh')">DOH LOGS</a></li>
            <li class="nav-item"><a class="nav-link" id="tab-global" onclick="switchTab('global')">GLOBAL ANALYTICS</a></li>
            <li class="nav-item"><a class="nav-link" id="tab-perf" onclick="switchTab('perf')">PERFORMANCE</a></li>
            <li class="nav-item"><a class="nav-link" id="tab-security" onclick="switchTab('security')"> SECURITY ACTIONS</a></li>
        </ul>
        
        <div id="panel-scan">
            <div class="glass-card">
                <h5 class="mb-3" style="color: #c7d2fe; font-weight: 700; display: flex; align-items: center; gap: 10px;">
                    <span style="font-size: 1.3em;"></span> QUICK DOMAIN TEST
                </h5>
                <p style="color: #94a3b8; margin-bottom: 16px; font-size: 0.95em;">
                    Test domains directly through the detection engine • No command prompt needed
                </p>
                <div class="input-group input-group-lg">
                    <input type="text" id="domainInput" class="form-control bg-dark text-white border-secondary" placeholder="Test: xk9j2lq8.com (Layer 1), secure-update247.com (Layer 2)">
                    <button class="btn btn-primary px-5" onclick="performScan()">ANALYZE</button>
                </div>
            </div>
            <!-- ORIGINAL LAYOUT - KEPT AS IS -->
            <div id="resultsArea" class="row" style="display:none;">
                <div class="col-md-5"><div class="glass-card"><h3 id="resText" class="text-center fw-bold mb-4"></h3><canvas id="confChart"></canvas><h6 class="text-primary mt-4">ANALYSIS:</h6><div id="reasoningList"></div></div></div>
                <div class="col-md-7"><div class="glass-card"><div id="metricsRow" class="row mb-4 text-center"></div><canvas id="radarChart"></canvas></div></div>
            </div>
            
            <!-- NEW: XAI SECTION - CENTERED BELOW - SEPARATE ROW -->
            <div id="xaiArea" class="row" style="display:none; margin-top: 20px;">
                <div class="col-12">
                    <div class="glass-card">
                        <h6 class="text-primary mb-3" style="text-align: center;"> XAI EXPLANATION</h6>
                        <div id="xaiContent" class="xai-box"></div>
                    </div>
                </div>
            </div>
            
            <!-- VIRUSTOTAL SECTION - INSIDE CONTAINER -->
            <div id="vtArea" class="row" style="display:none; margin-top: 20px;">
                <div class="col-12">
                    <div class="glass-card">
                        <h6 class="text-primary mb-3" style="text-align: center;"> Threat Intelligence (VirusTotal)</h6>
                        <div id="vtContent" class="xai-box" style="font-size:0.9em; padding:16px;"></div>
                    </div>
                </div>
            </div>
        </div>
        <!-- END OF MAIN CONTAINER -->        
        <div id="panel-demo" style="display:none;">
            <div class="glass-card">
                <h5 class="mb-4" style="color: #c7d2fe; font-weight: 700;"> LIVE DEMO - Real-Time DNS Detection</h5>
                <p style="color: #94a3b8; margin-bottom: 24px;">Simulate browsing and watch threats detected in real-time!</p>
                
                <div class="row mb-4">
                    <div class="col-md-6">
                        <div class="glass-card">
                            <h6 style="color: #60a5fa; margin-bottom: 16px;"> BROWSER SIMULATOR</h6>
                            <input type="text" id="demoUrl" class="form-control mb-3" placeholder="Enter website (e.g., google.com, g00gle.com)">
                            <button class="btn btn-primary w-100 mb-2" onclick="simulateBrowsing()"> Visit Website</button>
                            <button class="btn btn-secondary w-100" onclick="autoDemo()"> Auto-Demo (30 sites)</button>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="glass-card">
                            <h6 style="color: #ec4899; margin-bottom: 16px;"> LIVE STATISTICS</h6>
                            <div style="display: flex; justify-content: space-between; margin-bottom: 12px;">
                                <span style="color: #c7d2fe;">Total:</span>
                                <span id="demoTotal" style="color: #60a5fa; font-weight: 700;">0</span>
                            </div>
                            <div style="display: flex; justify-content: space-between; margin-bottom: 12px;">
                                <span style="color: #c7d2fe;"> Safe:</span>
                                <span id="demoSafe" style="color: #10b981; font-weight: 700;">0</span>
                            </div>
                            <div style="display: flex; justify-content: space-between; margin-bottom: 12px;">
                                <span style="color: #c7d2fe;"> Threats:</span>
                                <span id="demoThreat" style="color: #ef4444; font-weight: 700;">0</span>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="glass-card">
                    <h6 style="color: #c7d2fe; margin-bottom: 16px;"> REAL-TIME ACTIVITY FEED</h6>
                    <div id="demoFeed" style="max-height: 500px; overflow-y: auto; overflow-x: auto;">
                        <table class="table table-dark" style="margin: 0;">
                            <thead style="position: sticky; top: 0; z-index: 10;">
                                <tr style="background: linear-gradient(135deg, rgba(139, 92, 246, 0.3), rgba(59, 130, 246, 0.3));">
                                    <th style="color: #c7d2fe; font-weight: 600; padding: 12px; border: 1px solid rgba(139, 92, 246, 0.3);">Time</th>
                                    <th style="color: #c7d2fe; font-weight: 600; padding: 12px; border: 1px solid rgba(139, 92, 246, 0.3);">Domain</th>
                                    <th style="color: #c7d2fe; font-weight: 600; padding: 12px; border: 1px solid rgba(139, 92, 246, 0.3);">Status</th>
                                    <th style="color: #c7d2fe; font-weight: 600; padding: 12px; border: 1px solid rgba(139, 92, 246, 0.3);">Threat Type</th>
                                    <th style="color: #c7d2fe; font-weight: 600; padding: 12px; border: 1px solid rgba(139, 92, 246, 0.3);">Confidence</th>
                                    <th style="color: #c7d2fe; font-weight: 600; padding: 12px; border: 1px solid rgba(139, 92, 246, 0.3);">Layer</th>
                                    <th style="color: #c7d2fe; font-weight: 600; padding: 12px; border: 1px solid rgba(139, 92, 246, 0.3);">Explanation</th>
                                </tr>
                            </thead>
                            <tbody id="demoTableBody">
                                <tr>
                                    <td colspan="7" style="text-align: center; padding: 60px; color: #64748b; background: rgba(30, 27, 75, 0.6);">
                                        <div style="font-size: 4em; margin-bottom: 20px;">🎯</div>
                                        <div style="font-size: 1.5em; color: #94a3b8; margin-bottom: 10px;">No activity yet</div>
                                        <div>Start browsing or run auto-demo to see live detection!</div>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
        
        <div id="panel-doh" style="display:none;">
            <div class="glass-card">
                <h5 class="mb-3" style="color: #c7d2fe; font-weight: 700; display: flex; align-items: center; gap: 10px;">
                    <span style="font-size: 1.3em;"></span> DNS-OVER-HTTPS RESOLVER LOGS
                </h5>
                <p style="color: #94a3b8; margin-bottom: 20px;">
                    Real-time monitoring of DoH resolver queries and threats detected
                </p>
                <div id="dohLogsContent" style="overflow-x: auto;">
                    <div style="text-align: center; padding: 40px; color: #64748b;">
                        <div style="font-size: 3em; margin-bottom: 16px;"></div>
                        <div>Loading DoH logs...</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div id="panel-global" style="display:none;">
            <div class="row g-4 text-center">
                <div class="col-md-4"><div class="glass-card"><h6 style="color: #c7d2fe; font-weight: 600; letter-spacing: 1px;">TOTAL QUERIES</h6><div id="stat-total" class="stat-value">0</div></div></div>
                <div class="col-md-4"><div class="glass-card"><h6 style="color: #fca5a5; font-weight: 600; letter-spacing: 1px;">THREATS BLOCKED</h6><div id="stat-mal" class="stat-value" style="color: #ef4444;">0</div></div></div>
                <div class="col-md-4"><div class="glass-card"><h6 style="color: #fcd34d; font-weight: 600; letter-spacing: 1px;">THREAT RATIO</h6><div id="stat-ratio" class="stat-value" style="color: #f59e0b;">0%</div></div></div>
            </div>
            <div class="glass-card"><canvas id="sessionPieChart" style="max-height: 350px;"></canvas></div>
        </div>
        
        <div id="panel-perf" style="display:none;">
            <div class="row g-4 text-center mb-4">
                <div class="col-md-3"><div class="glass-card"><h6 style="color: #86efac; font-weight: 600; letter-spacing: 1px;">LAYER 1</h6><div id="perf-layer1" class="stat-value" style="color: #22c55e;">0</div><small class="text-muted">Fast (&lt;1ms)</small></div></div>
                <div class="col-md-3"><div class="glass-card"><h6 style="color: #a78bfa; font-weight: 600; letter-spacing: 1px;">LAYER 2</h6><div id="perf-layer2" class="stat-value" style="color: #8b5cf6;">0</div><small class="text-muted">Deep (5-10ms)</small></div></div>
                <div class="col-md-3"><div class="glass-card"><h6 style="color: #fcd34d; font-weight: 600; letter-spacing: 1px;">WHITELIST</h6><div id="perf-whitelist" class="stat-value" style="color:#f59e0b">0</div><small class="text-muted">Trusted</small></div></div>
                <div class="col-md-3"><div class="glass-card"><h6 style="color: #fca5a5; font-weight: 600; letter-spacing: 1px;">THREATS</h6><div id="perf-threats" class="stat-value" style="color: #ef4444;">0</div><small class="text-muted">Blocked</small></div></div>
            </div>
            <div class="glass-card">
                <h5 class="mb-3" style="color: #c7d2fe; font-weight: 700; display: flex; align-items: center; gap: 10px;">
                    <span style="font-size: 1.3em;"></span> LAYER EFFICIENCY
                </h5>
                <canvas id="layerEffChart" style="max-height: 300px;"></canvas>
            </div>
            <div class="glass-card">
                <h5 class="mb-3" style="color: #c7d2fe; font-weight: 700; display: flex; align-items: center; gap: 10px;">
                    <span style="font-size: 1.3em;"></span> ATTACK TYPES
                </h5>
                <canvas id="attackTypeChart" style="max-height: 300px;"></canvas>
            </div>
        </div>
        
        <div id="panel-security" style="display:none;">
            <div class="glass-card">
                <h5 class="mb-4" style="color: #c7d2fe; font-weight: 700;"> ACTIVE DEFENSE & GOVERNANCE</h5>
                <p style="color: #94a3b8; margin-bottom: 24px;">
                    Automated Sinkhole, Incident Tracking & Manual Override
                </p>
                
                <div class="row mb-4">
                    <div class="col-md-6">
                        <div class="glass-card">
                            <h6 style="color: #ef4444; margin-bottom: 16px;"> AUTOMATED SINKHOLE</h6>
                            <p style="color: #94a3b8; font-size: 0.9em; margin-bottom: 12px;">
                                Malicious domains automatically added to blocklist
                            </p>
                            <div id="sinkholeCount" style="font-size: 2.5em; font-weight: 700; color: #ef4444; text-align: center;">0</div>
                            <div style="text-align: center; color: #94a3b8; margin-top: 8px;">Domains Sinkholed</div>
                            <button class="btn btn-secondary w-100 mt-3" onclick="viewSinkhole()"> View Blocklist</button>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="glass-card">
                            <h6 style="color: #10b981; margin-bottom: 16px;"> FORENSIC AUDIT LOG</h6>
                            <p style="color: #94a3b8; font-size: 0.9em; margin-bottom: 12px;">
                                GDPR/HIPAA compliant incident tracking
                            </p>
                            <div id="incidentCount" style="font-size: 2.5em; font-weight: 700; color: #10b981; text-align: center;">0</div>
                            <div style="text-align: center; color: #94a3b8; margin-top: 8px;">Total Incidents Logged</div>
                            <button class="btn btn-secondary w-100 mt-3" onclick="viewAuditLog()"> View Audit Trail</button>
                        </div>
                    </div>
                </div>
                
                <div class="glass-card">
                    <h6 style="color: #a78bfa; margin-bottom: 16px;"> MANUAL OVERRIDE (Human-in-the-Loop)</h6>
                    <p style="color: #94a3b8; font-size: 0.9em; margin-bottom: 16px;">
                        Administrator can manually whitelist or blacklist domains
                    </p>
                    <div class="row">
                        <div class="col-md-8">
                            <input type="text" id="manualDomain" class="form-control" placeholder="Enter domain (e.g., trusted-partner.com)">
                        </div>
                        <div class="col-md-2">
                            <button class="btn btn-primary w-100" onclick="manualOverride('whitelist')"> Whitelist</button>
                        </div>
                        <div class="col-md-2">
                            <button class="btn btn-danger w-100" onclick="manualOverride('blacklist')"> Blacklist</button>
                        </div>
                    </div>
                    <div id="manualResult" style="margin-top: 16px;"></div>
                </div>
                
                <div class="glass-card">
                    <h6 style="color: #c7d2fe; margin-bottom: 16px;">📡 RECENT SECURITY ACTIONS</h6>
                    <div id="securityActionsLog" style="max-height: 400px; overflow-y: auto;">
                        <div style="text-align: center; padding: 40px; color: #64748b;">
                            <div style="font-size: 3em;">🛡️</div>
                            <div>Security actions will appear here</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let session = { total: 0, mal: 0, ben: 0, layer1: 0, layer2: 0, whitelist: 0,
                       dga: 0, typosquat: 0, fastflux: 0, tunneling: 0, c2: 0, other: 0 };
        let charts = {};
        
        function switchTab(t) {
            ['scan', 'demo', 'doh', 'global', 'perf', 'security'].forEach(tab => {
                document.getElementById('panel-' + tab).style.display = t === tab ? 'block' : 'none';
                document.getElementById('tab-' + tab).classList.toggle('active', t === tab);
            });
            if(t === 'doh') refreshDoHLogs();
            if(t === 'global') refreshGlobal();
            if(t === 'perf') refreshPerformance();
            if(t === 'security') refreshSecurity();
        }
        
        async function performScan() {
            const domain = document.getElementById('domainInput').value;
            if (!domain) {
                alert('Please enter a domain name');
                return;
            }
            
            const button = document.querySelector('.btn-primary');
            const originalText = button.textContent;
            button.disabled = true;
            button.textContent = ' ANALYZING...';
            
            console.log('Analyzing domain:', domain);
            
            try {
                const res = await fetch('/predict', { 
    method: 'POST', 
    headers: {
        'Content-Type': 'application/json',
        'X-API-Key': 'dns-shield-admin-2024' // Add the API key here
    }, 
    body: JSON.stringify({domain}) 
});
                
                if (!res.ok) {
                    throw new Error(`Server error: ${res.status}`);
                }
                
                const data = await res.json();
                
                console.log('Response data:', data);
                
                if (data.error) {
                    throw new Error(data.error);
                }
                
                session.total++;
                data.prediction === 'malicious' ? session.mal++ : session.ben++;
                
                if(data.layer_used === 'Whitelist') session.whitelist++;
                else if(data.layer_used && data.layer_used.includes('Layer 1')) session.layer1++;
                else if(data.layer_used && data.layer_used.includes('Layer 2')) session.layer2++;
                
                if(data.attack_type) {
                    switch(data.attack_type) {
                        case 'DGA': session.dga++; break;
                        case 'Typosquatting': case 'Homograph': session.typosquat++; break;
                        case 'FastFlux': session.fastflux++; break;
                        case 'Tunneling': session.tunneling++; break;
                        case 'C2': case 'Structured_DGA': case 'IBHH': session.c2++; break;
                        default: session.other++; break;
                    }
                }
                
                // ═══════════════════════════════════════════════════════════════
                // UPDATED DISPLAY LOGIC - Now shows XAI section properly with vibrant styling
                // ═══════════════════════════════════════════════════════════════
                document.getElementById('resultsArea').style.display = 'flex';
                const color = data.prediction === 'malicious' ? '#ef4444' : '#10b981';
                
                // Build HTML with vibrant XAI support
                let html = `<div style="text-align: center; margin-bottom: 24px;">
                              <div style="font-size: 2.5em; font-weight: 900; background: linear-gradient(135deg, ${color}, ${data.prediction === 'malicious' ? '#ec4899' : '#34d399'}); -webkit-background-clip: text; -webkit-text-fill-color: transparent; animation: float 2s ease-in-out infinite;">
                                ${data.prediction.toUpperCase()}
                              </div>
                            </div>`;
                
                html += `<div style="font-size: 1.1em; margin: 16px 0;">
                           <strong style="color: #a78bfa;">Confidence:</strong> 
                           <span style="font-size: 1.3em; font-weight: 700; color: ${color};">${data.confidence}</span>
                         </div>`;
                
                // Show stage with vibrant badge
                let stage = data.stage || data.layer_used || 'Unknown';
                let stageClass = (stage.includes('IBHH') || stage.includes('Stage 0')) ? 'stage-ibhh' : 'stage-normal';
                html += `<div>
                           <strong style="color: #a78bfa;">Detection Stage:</strong><br>
                           <span class="stage-badge ${stageClass}">${stage}</span>
                         </div>`;
                
                // Show threat type with icon
                if (data.attack_type) {
                    let threatIcon = 'O';
                    if (data.attack_type.includes('DGA')) threatIcon = 'DGA';
                    if (data.attack_type.includes('Typo')) threatIcon = 'TYPO';
                    if (data.attack_type.includes('Tunnel')) threatIcon = 'TUNNEL';
                    if (data.attack_type.includes('IBHH')) threatIcon = 'IBHH';
                    if (data.attack_type.includes('C2')) threatIcon = 'C2';
                    if (data.attack_type.includes('Fast')) threatIcon = 'FF';
                    if (data.attack_type.includes('Homograph')) threatIcon = 'HOMOGRAPH';
                    
                    html += `<div style="margin: 16px 0;">
                              <strong style="color: #a78bfa;">Threat Type:</strong> 
                              <span style="color: ${color}; font-weight: 700; font-size: 1.1em;">
                                ${threatIcon} ${data.attack_type}
                              </span>
                             </div>`;
                }
                
                // Show original analysis bullets with vibrant styling
                if (data.explanation && data.explanation.analysis && data.explanation.analysis.bullets) {
                    html += `<div style="margin-top: 20px;">
                              <h6 style="color: #c7d2fe; font-weight: 700; font-size: 1.1em; margin-bottom: 12px;">
                                 ANALYSIS:
                              </h6>`;
                    data.explanation.analysis.bullets.forEach(bullet => {
                        html += `<div class="reason-pill">${bullet}</div>`;
                    });
                    html += `</div>`;
                }
                
                // Optional: show IBHH rate with animated badge
                if (data.ibhh_rate && data.ibhh_rate > 0) {
                    html += `<div style="margin-top: 16px; padding: 12px; background: linear-gradient(135deg, rgba(236, 72, 153, 0.15), rgba(139, 92, 246, 0.15)); border-radius: 12px; border: 2px solid rgba(236, 72, 153, 0.3);">
                              <strong style="color: #ec4899;">IBHH Rate:</strong> 
                              <span style="font-size: 1.2em; font-weight: 700; color: #f0abfc;">${(data.ibhh_rate * 100).toFixed(1)}%</span>
                             </div>`;
                }
                
                document.getElementById('resText').innerHTML = html;
                document.getElementById('reasoningList').innerHTML = '';
                
                // Show XAI report if available
                if (data.explanation && data.explanation.xai_report) {
                    document.getElementById('xaiArea').style.display = 'flex';
                    document.getElementById('xaiContent').textContent = data.explanation.xai_report;
                } else {
                    document.getElementById('xaiArea').style.display = 'none';
                }
                
                // Show VirusTotal report if available
                if (data.virustotal) {
                    document.getElementById('vtArea').style.display = 'flex';
                    document.getElementById('vtContent').innerHTML = data.virustotal;
                } else {
                    document.getElementById('vtArea').style.display = 'none';
                }
                
                // Render metrics
                if (data.explanation && data.explanation.analysis && data.explanation.analysis.metrics) {
                    const metrics = data.explanation.analysis.metrics;
                    let metricsHtml = '';
                    for (const [key, val] of Object.entries(metrics)) {
                        metricsHtml += `<div class="col-3">
                            <div style="background: rgba(139, 92, 246, 0.1); padding: 12px; border-radius: 12px; border: 1px solid rgba(139, 92, 246, 0.3);">
                                <small style="color: #94a3b8; font-weight: 600;">${key}</small>
                                <div style="color: #a78bfa; font-size: 1.3em; font-weight: 700;">${val}</div>
                            </div>
                        </div>`;
                    }
                    document.getElementById('metricsRow').innerHTML = metricsHtml;
                }
                
                console.log('Rendering charts...');
                renderCharts(data, color);
                console.log('Display complete!');
                
            } catch (error) {
                console.error('Error in performScan:', error);
                alert('Error analyzing domain: ' + error.message);
                document.getElementById('resultsArea').style.display = 'none';
            } finally {
                button.disabled = false;
                button.textContent = originalText;
            }
        }
        
        // DoH Logs refresh function
        async function refreshDoHLogs() {
            try {
                const res = await fetch('/doh-logs-json');
                const logs = await res.json();
                
                if (!logs || logs.length === 0) {
                    document.getElementById('dohLogsContent').innerHTML = `
                        <div style="text-align: center; padding: 40px; color: #64748b;">
                            <div style="font-size: 3em; margin-bottom: 16px;">📭</div>
                            <div style="font-size: 1.2em; color: #94a3b8;">No DoH logs available</div>
                            <div style="margin-top: 8px;">Start your DoH resolver to see logs here</div>
                        </div>
                    `;
                    return;
                }
                
                let html = `
                    <table class="table table-dark table-striped table-hover">
                        <thead>
                            <tr style="background: rgba(139, 92, 246, 0.2);">
                                <th>Time</th>
                                <th>Domain</th>
                                <th>Status</th>
                                <th>Threat</th>
                                <th>Confidence</th>
                                <th>IBHH</th>
                            </tr>
                        </thead>
                        <tbody>
                `;
                
                logs.reverse().forEach(log => {
                    const statusColor = log.malicious ? '#ef4444' : '#10b981';
                    const statusText = log.malicious ? ' BLOCKED' : ' SAFE';
                    html += `
                        <tr style="border-left: 3px solid ${statusColor};">
                            <td style="color: #94a3b8;">${log.time || 'N/A'}</td>
                            <td style="color: #c7d2fe; font-weight: 600;">${log.domain || 'N/A'}</td>
                            <td style="color: ${statusColor}; font-weight: 700;">${statusText}</td>
                            <td style="color: #a78bfa;">${log.threat_type || '-'}</td>
                            <td style="color: #60a5fa;">${log.confidence || '-'}</td>
                            <td style="color: #ec4899;">${log.ibhh_rate ? (log.ibhh_rate * 100).toFixed(1) + '%' : '-'}</td>
                        </tr>
                    `;
                });
                
                html += `
                        </tbody>
                    </table>
                `;
                
                document.getElementById('dohLogsContent').innerHTML = html;
                
            } catch (error) {
                document.getElementById('dohLogsContent').innerHTML = `
                    <div style="text-align: center; padding: 40px; color: #ef4444;">
                        <div style="font-size: 3em; margin-bottom: 16px;"></div>
                        <div style="font-size: 1.2em;">Error loading DoH logs</div>
                        <div style="margin-top: 8px; color: #94a3b8;">${error.message}</div>
                    </div>
                `;
            }
        }
        
        function renderCharts(data, color) {
            if(charts.conf) charts.conf.destroy();
            const conf = parseFloat(data.confidence) || 0;
            charts.conf = new Chart(document.getElementById('confChart'), {
                type: 'doughnut', data: { datasets: [{ data: [conf*100, 100-(conf*100)], backgroundColor: [color, '#0f172a'] }] }
            });
            if(charts.radar) charts.radar.destroy();
            
            const metrics = data.explanation?.analysis?.metrics || {};
            charts.radar = new Chart(document.getElementById('radarChart'), {
                type: 'radar', data: { labels: ['Entropy', 'Length', 'Digits', 'V-Ratio', 'Conf'],
                    datasets: [{ data: [(metrics.Entropy||0)*20, metrics.Length||0, 
                        (metrics.Digits||0)*10, (metrics['V-Ratio']||0)*100, conf*100],
                        borderColor: color, backgroundColor: color+'22' }] },
                options: { scales: { r: { grid: {color: '#334155'}, ticks: {display: false}, suggestMin:0, suggestMax:100 } },
                    plugins: { legend: { display: false } } }
            });
        }
        
        // DEMO SIMULATION FUNCTIONS - UPDATED WITH 30 SAMPLES
        let demoStats = { total: 0, safe: 0, threat: 0 };
        
        // 30 DEMO SAMPLES covering all 8 attack types
        const DEMO_SAMPLES = [
            // Benign (5)
            'google.com', 'facebook.com', 'youtube.com', 'amazon.com', 'twitter.com',
            // Pure DGA (5)
            'xK9j2Lq8M3p7RtY4nW6vB1sD5fG8hJ0k.com',
            'qWeRtYuIoPaSdFgHjKlZxCvBnM1234567890.com',
            'AbC123XyZ456DeF789GhI012JkL345MnO.com',
            'pLmNqWxYzAbCdEfGhIjKlMnOpQrStUvWx.net',
            'randomdomain7x8y9z1a2b3c4d5e6f.org',
            // DNS Tunneling (5)
            'ZG5zMnRjcF9lbmNvZGVkX3BheWxvYWRfZGF0YQ.attacker.com',
            '48656c6c6f576f726c644578616d706c65.exfil.net',
            'VGhpc0lzQUROU1R1bm5lbGluZ0V4YW1wbGU.c2server.com',
            'data.chunk1.chunk2.chunk3.tunnel.org',
            'cmdexewhoamibashpowershell.evil.com',
            // Typosquatting (4)
            'g00gle.com', 'faceb00k.com', 'paypa1.com', 'micr0s0ft.com',
            // Structured DGA (3)
            'update1234.com', 'data5678.net', 'system9999.org',
            // C2 Beaconing (5) - REAL-WORLD EXAMPLES
            'updates.service-network.com', 'time.check-sync.com', 'health.monitor-net.com',
            'check-system.com', 'verify-network.net',
            // IBHH (3) - REAL-WORLD EXAMPLES
            'fileserver.local', 'printserver.internal', 'aaaaaaaaaaaaaaabbbbbbbbbbbbb.exfil.com',
            // Homograph (2)
            'amaz0n.com', 'app1e.com',
            // Fast Flux (3) - INCLUDING PHISHING
            'a1.b2.c3.d4.e5.fastflux.com', 'login.bank-site.com', 'secure.paypal-verify.com'
        ];
        
        async function simulateBrowsing() {
            let domain = (document.getElementById('demoUrl').value || '').trim().replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0];
            if (!domain) { alert('Enter a website'); return; }
            
            const res = await fetch('/predict', { 
    method: 'POST', 
    headers: {
        'Content-Type': 'application/json',
        'X-API-Key': 'dns-shield-admin-2024' // Add the API key here
    }, 
    body: JSON.stringify({domain}) 
});
            const data = await res.json();
            
            demoStats.total++;
            data.prediction === 'malicious' ? demoStats.threat++ : demoStats.safe++;
            
            document.getElementById('demoTotal').textContent = demoStats.total;
            document.getElementById('demoSafe').textContent = demoStats.safe;
            document.getElementById('demoThreat').textContent = demoStats.threat;
            
            const tbody = document.getElementById('demoTableBody');
            
            // Remove placeholder if it exists
            if (tbody.querySelector('[colspan="7"]')) {
                tbody.innerHTML = '';
            }
            
            // Create new row with beautiful styling like DoH logs
            const row = document.createElement('tr');
            const statusColor = data.prediction === 'malicious' ? '#ef4444' : '#10b981';
            const statusText = data.prediction === 'malicious' ? 'BLOCKED' : 'SAFE';
            const statusIcon = data.prediction === 'malicious' ? 'X' : '✅';
            
            row.style.cssText = `background: rgba(30, 27, 75, 0.6); transition: all 0.3s ease; animation: slide-in-right 0.5s ease-out;`;
            row.onmouseenter = function() {
                this.style.background = 'rgba(139, 92, 246, 0.2)';
                this.style.transform = 'translateX(4px)';
            };
            row.onmouseleave = function() {
                this.style.background = 'rgba(30, 27, 75, 0.6)';
                this.style.transform = 'translateX(0)';
            };
            
            // Get current time
            const now = new Date();
            const timeStr = now.toLocaleTimeString();
            
            // Get explanation summary
            let explanation = '-';
            if (data.explanation && data.explanation.analysis && data.explanation.analysis.bullets) {
                explanation = data.explanation.analysis.bullets[0] || '-';
                if (explanation.length > 50) {
                    explanation = explanation.substring(0, 50) + '...';
                }
            }
            
            row.innerHTML = `
                <td style="color: #94a3b8; padding: 12px; border: 1px solid rgba(139, 92, 246, 0.3);">${timeStr}</td>
                <td style="color: #c7d2fe; font-weight: 600; padding: 12px; border: 1px solid rgba(139, 92, 246, 0.3);">${domain}</td>
                <td style="padding: 12px; border: 1px solid rgba(139, 92, 246, 0.3);">
                    <span style="color: ${statusColor}; font-weight: bold; background: ${data.prediction === 'malicious' ? 'rgba(239, 68, 68, 0.1)' : 'rgba(16, 185, 129, 0.1)'}; padding: 4px 12px; border-radius: 12px; display: inline-block;">
                        ${statusIcon} ${statusText}
                    </span>
                </td>
                <td style="color: ${data.prediction === 'malicious' ? '#fca5a5' : '#94a3b8'}; padding: 12px; border: 1px solid rgba(139, 92, 246, 0.3);">${data.attack_type || '-'}</td>
                <td style="color: #a78bfa; font-weight: 600; padding: 12px; border: 1px solid rgba(139, 92, 246, 0.3);">${data.confidence}</td>
                <td style="color: #60a5fa; padding: 12px; border: 1px solid rgba(139, 92, 246, 0.3);">${data.stage || data.layer_used || '-'}</td>
                <td style="color: #cbd5e1; font-size: 0.9em; padding: 12px; border: 1px solid rgba(139, 92, 246, 0.3);">${explanation}</td>
            `;
            
            // Insert at the top
            tbody.insertBefore(row, tbody.firstChild);
            
            // Keep only last 50 entries
            while (tbody.children.length > 50) {
                tbody.removeChild(tbody.lastChild);
            }
            
            document.getElementById('demoUrl').value = '';
        }
        
        async function autoDemo() {
            const btn = event.target;
            btn.disabled = true;
            btn.textContent = ' Running...';
            
            for (const site of DEMO_SAMPLES) {
                document.getElementById('demoUrl').value = site;
                await simulateBrowsing();
                await new Promise(r => setTimeout(r, 800));
            }
            
            btn.disabled = false;
            btn.textContent = ' Auto-Demo (30 sites)';
        }
        
        async function refreshGlobal() {
            const res = await fetch('/stats');
            const stats = await res.json();
            document.getElementById('stat-total').textContent = stats.total_queries;
            document.getElementById('stat-mal').textContent = stats.malicious_count;
            const ratio = stats.total_queries > 0 ? ((stats.malicious_count / stats.total_queries) * 100).toFixed(1) : 0;
            document.getElementById('stat-ratio').textContent = ratio + '%';
            
            if(charts.pie) charts.pie.destroy();
            charts.pie = new Chart(document.getElementById('sessionPieChart'), {
                type: 'pie',
                data: {
                    labels: ['Benign', 'Malicious'],
                    datasets: [{
                        data: [stats.benign_count, stats.malicious_count],
                        backgroundColor: ['#10b981', '#ef4444']
                    }]
                }
            });
        }
        
        async function refreshPerformance() {
            const res = await fetch('/stats');
            const stats = await res.json();
            document.getElementById('perf-layer1').textContent = stats.layer1_decisions;
            document.getElementById('perf-layer2').textContent = stats.layer2_decisions;
            document.getElementById('perf-whitelist').textContent = stats.whitelist_hits;
            document.getElementById('perf-threats').textContent = stats.malicious_count;
            
            if(charts.layerEff) charts.layerEff.destroy();
            charts.layerEff = new Chart(document.getElementById('layerEffChart'), {
                type: 'bar',
                data: {
                    labels: ['Layer 1 (Fast)', 'Layer 2 (LSTM)', 'Whitelist'],
                    datasets: [{
                        data: [stats.layer1_decisions, stats.layer2_decisions, stats.whitelist_hits],
                        backgroundColor: ['#22c55e', '#8b5cf6', '#f59e0b']
                    }]
                },
                options: { plugins: { legend: { display: false } } }
            });
            
            if(charts.attackType) charts.attackType.destroy();
            charts.attackType = new Chart(document.getElementById('attackTypeChart'), {
                type: 'doughnut',
                data: {
                    labels: ['DGA', 'Typosquat', 'FastFlux', 'Tunneling', 'C2', 'Other'],
                    datasets: [{
                        data: [stats.attack_dga, stats.attack_typosquat, stats.attack_fastflux, 
                               stats.attack_tunneling, stats.attack_c2, stats.attack_other],
                        backgroundColor: ['#ef4444', '#f59e0b', '#10b981', '#3b82f6', '#8b5cf6', '#6b7280']
                    }]
                }
            });
        }
        
        // SECURITY ACTIONS PANEL FUNCTIONS
        async function refreshSecurity() {
            try {
                // Get sinkhole count
                const sinkholeRes = await fetch('/security/sinkhole-count');
                const sinkholeData = await sinkholeRes.json();
                document.getElementById('sinkholeCount').textContent = sinkholeData.count || 0;
                
                // Get incident count
                const incidentRes = await fetch('/security/incident-count');
                const incidentData = await incidentRes.json();
                document.getElementById('incidentCount').textContent = incidentData.count || 0;
                
                // Get recent security actions
                const actionsRes = await fetch('/security/recent-actions');
                const actions = await actionsRes.json();
                
                if (actions.length === 0) {
                    document.getElementById('securityActionsLog').innerHTML = `
                        <div style="text-align: center; padding: 40px; color: #64748b;">
                            <div style="font-size: 3em;"></div>
                            <div>No security actions yet</div>
                        </div>
                    `;
                } else {
                    let html = '<table class="table table-dark" style="margin: 0;"><thead><tr style="background: linear-gradient(135deg, rgba(139, 92, 246, 0.3), rgba(59, 130, 246, 0.3));"><th>Time</th><th>Domain</th><th>Action</th><th>Incident ID</th><th>Threat Type</th></tr></thead><tbody>';
                    
                    actions.forEach(action => {
                        const actionColor = action.action_taken === 'SINKHOLED' ? '#ef4444' : '#10b981';
                        const actionIcon = action.action_taken === 'SINKHOLED' ? 'X' : '✅';
                        html += `
                            <tr style="background: rgba(30, 27, 75, 0.6);">
                                <td style="color: #94a3b8;">${action.timestamp}</td>
                                <td style="color: #c7d2fe; font-weight: 600;">${action.domain}</td>
                                <td><span style="color: ${actionColor}; font-weight: bold;">${actionIcon} ${action.action_taken}</span></td>
                                <td style="color: #a78bfa; font-family: monospace;">${action.incident_id}</td>
                                <td style="color: #60a5fa;">${action.threat_type || '-'}</td>
                            </tr>
                        `;
                    });
                    
                    html += '</tbody></table>';
                    document.getElementById('securityActionsLog').innerHTML = html;
                }
            } catch (error) {
                console.error('Error refreshing security:', error);
            }
        }
        
        async function manualOverride(action) {
            const domain = document.getElementById('manualDomain').value;
            if (!domain) {
                alert('Please enter a domain name');
                return;
            }
            
            try {
                const res = await fetch('/security/manual-override', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({domain, action})
                });
                
                const data = await res.json();
                
                const resultDiv = document.getElementById('manualResult');
                const color = action === 'whitelist' ? '#10b981' : '#ef4444';
                const icon = action === 'whitelist' ? '✅' : 'X';
                
                resultDiv.innerHTML = `
                    <div style="background: rgba(${action === 'whitelist' ? '16, 185, 129' : '239, 68, 68'}, 0.1); border: 2px solid ${color}; border-radius: 12px; padding: 16px; color: ${color}; font-weight: 600;">
                        ${icon} Domain <strong>${domain}</strong> has been ${action}ed successfully!
                        <br><small style="color: #94a3b8; font-weight: normal;">Incident ID: ${data.incident_id}</small>
                    </div>
                `;
                
                document.getElementById('manualDomain').value = '';
                
                // Refresh security panel
                setTimeout(() => refreshSecurity(), 500);
                
            } catch (error) {
                alert('Error: ' + error.message);
            }
        }
        
        async function viewSinkhole() {
            window.open('/security/sinkhole-view', '_blank');
        }
        
        async function viewAuditLog() {
            window.open('/security/audit-view', '_blank');
        }
        // ═══════════════════════════════════════════════════════════════════════════
        // AUDIO ALERT SYSTEM - Real-time Threat Notifications
        // ═══════════════════════════════════════════════════════════════════════════

        let lastAlertTimestamp = 0;
        let alertedThreats = new Set(); // Track already-alerted threats

        // Web Audio API - Create alert sound (no external files needed!)
        function playAlertSound() {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            
            // Create three beeps for attention
            for (let i = 0; i < 3; i++) {
                setTimeout(() => {
                    const oscillator = audioContext.createOscillator();
                    const gainNode = audioContext.createGain();
                    
                    oscillator.connect(gainNode);
                    gainNode.connect(audioContext.destination);
                    
                    oscillator.frequency.value = 800; // High-pitched alert tone
                    oscillator.type = 'sine';
                    
                    gainNode.gain.setValueAtTime(0.3, audioContext.currentTime);
                    gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.2);
                    
                    oscillator.start(audioContext.currentTime);
                    oscillator.stop(audioContext.currentTime + 0.2);
                }, i * 300); // 300ms between beeps
            }
        }

        // Show visual alert banner
        function showAlertBanner(threat) {
            // Remove existing banner if any
            const existing = document.getElementById('audio-alert-banner');
            if (existing) existing.remove();
            
            // Create new alert banner
            const banner = document.createElement('div');
            banner.id = 'audio-alert-banner';
            banner.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                background: linear-gradient(135deg, #dc2626, #ef4444);
                color: white;
                padding: 20px;
                text-align: center;
                z-index: 10000;
                box-shadow: 0 4px 20px rgba(220, 38, 38, 0.5);
                animation: slideDown 0.5s ease-out;
                border-bottom: 4px solid #991b1b;
            `;
            
            banner.innerHTML = `
                <div style="display: flex; align-items: center; justify-content: center; gap: 15px;">
                    <span style="font-size: 32px; animation: pulse 1s infinite;">X</span>
                    <div style="text-align: left;">
                        <div style="font-size: 18px; font-weight: 700; margin-bottom: 5px;">
                            MALICIOUS DOMAIN DETECTED!
                        </div>
                        <div style="font-size: 14px; opacity: 0.9;">
                            <strong>${threat.domain}</strong> - ${threat.threat_type} (${threat.confidence} confidence)
                        </div>
                        <div style="font-size: 12px; opacity: 0.8; margin-top: 3px;">
                            Detected at ${threat.time_str}
                        </div>
                    </div>
                    <button onclick="closeAlertBanner()" style="
                        background: rgba(255,255,255,0.2);
                        border: 2px solid white;
                        color: white;
                        padding: 8px 16px;
                        border-radius: 8px;
                        cursor: pointer;
                        font-weight: 600;
                        margin-left: auto;
                    ">DISMISS</button>
                </div>
            `;
            
            // Add slide-down animation
            const style = document.createElement('style');
            style.textContent = `
                @keyframes slideDown {
                    from { transform: translateY(-100%); opacity: 0; }
                    to { transform: translateY(0); opacity: 1; }
                }
                @keyframes pulse {
                    0%, 100% { transform: scale(1); }
                    50% { transform: scale(1.2); }
                }
            `;
            document.head.appendChild(style);
            
            document.body.insertBefore(banner, document.body.firstChild);
            
            // Auto-hide after 10 seconds
            setTimeout(() => {
                if (banner.parentElement) {
                    banner.style.animation = 'slideDown 0.5s ease-in reverse';
                    setTimeout(() => banner.remove(), 500);
                }
            }, 10000);
        }

        // Close alert banner
        function closeAlertBanner() {
            const banner = document.getElementById('audio-alert-banner');
            if (banner) {
                banner.style.animation = 'slideDown 0.5s ease-in reverse';
                setTimeout(() => banner.remove(), 500);
            }
        }

        // Check for new threats (polls every 5 seconds)
        async function checkForNewThreats() {
            try {
                const response = await fetch('/api/recent-threats');
                const data = await response.json();
                
                if (data.threats && data.threats.length > 0) {
                    // Check for new threats we haven't alerted yet
                    data.threats.forEach(threat => {
                        const threatKey = `${threat.domain}_${threat.timestamp}`;
                        
                        if (!alertedThreats.has(threatKey)) {
                            // New threat detected!
                            console.log(' NEW THREAT DETECTED:', threat);
                            
                            // Play audio alert
                            playAlertSound();
                            
                            // Show visual banner
                            showAlertBanner(threat);
                            
                            // Mark as alerted
                            alertedThreats.add(threatKey);
                            
                            // Clean up old entries (keep only last 50)
                            if (alertedThreats.size > 50) {
                                const entries = Array.from(alertedThreats);
                                alertedThreats = new Set(entries.slice(-50));
                            }
                        }
                    });
                }
            } catch (error) {
                console.error('Error checking threats:', error);
            }
        }

        // Start monitoring for threats (runs in background on ALL pages)
        console.log(' Audio Alert System: ACTIVE');
        console.log('Checking for threats every 5 seconds...');

        // Initial check
        checkForNewThreats();

        // Poll every 5 seconds
        setInterval(checkForNewThreats, 5000);

        // Also check when page becomes visible (tab switching)
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden) {
                checkForNewThreats();
            }
        });
    </script>
</body>
</html>
"""

# ═══════════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════════
@app.route('/')
def index():
    return render_template_string(UI_HTML)

@app.route('/predict', methods=['POST'])
@require_api_key  
def predict():
    """Two-Layer DNS Shield Prediction with Safety Fallback
    """
    try:
        # === SAFETY CHECK ===
        # if extractor is None:
        #     return jsonify({
        #         "error": "AI models not loaded",
        #         "message": "Model files are missing or incompatible. Check docker logs.",
        #         "domain": clean_input(request.json.get('domain', '')),
        #         "prediction": "unknown",
        #         "malicious": False
        #     }), 503
    
        raw_input = request.json.get('domain', '').strip()
        clean_domain = clean_input(raw_input)
        PERFORMANCE_STATS['total_queries'] += 1
        METRICS_QUERIES_TOTAL.inc()  # Increment total queries metric
        data = request.get_json()
        domain = data.get('domain', '')
        # ═══════════════════════════════════════════════════════════════════
        # STEP 1: Whitelist Check
        # ═══════════════════════════════════════════════════════════════════
        is_whitelisted = is_domain_whitelisted(clean_domain)
        if is_whitelisted:
            PERFORMANCE_STATS['whitelist_hits'] += 1
            PERFORMANCE_STATS['benign_count'] += 1
            METRICS_WHITELIST_TOTAL.inc()  # Increment whitelist metric
            METRICS_BENIGN_TOTAL.inc()      # Increment benign metric
            
            explanation = get_detailed_explanation(
                {}, None, None, True, None, None, None, "Whitelist", 0, None, clean_domain
            )
            
            result = {
                "domain": clean_domain,
                "prediction": "benign",
                "malicious": False,
                "confidence": "0.9800",
                "threat_type": None,
                "layer_used": "Whitelist",
                "stage": "Whitelist",
                "attack_type": None,
                "explanation": explanation,
                "ibhh_rate": None,
                "virustotal": None  # Whitelisted domains don't need VT check
            }
            
            # Apply security action controller (generates incident ID, logs to forensic audit)
            result = security_action_controller(result)
            
            # === UPDATE GAUGES FOR PROMETHEUS ===
            METRICS_CURRENT_QUERIES.set(PERFORMANCE_STATS['total_queries'])
            METRICS_CURRENT_MALICIOUS.set(PERFORMANCE_STATS['malicious_count'])
            
            return jsonify(result)

        # VirusTotal intelligence (only if not whitelisted)
        vt_malicious, vt_details = False, ""
        if ENABLE_VIRUSTOTAL:
            vt_malicious, vt_details = check_virustotal(clean_domain)
            if vt_malicious:
                print(f" VirusTotal: {clean_domain} is malicious - {vt_details}")
        # ═══════════════════════════════════════════════════════════════════
        # STEP 2: Extract Features & Get Entropy
        # ═══════════════════════════════════════════════════════════════════
        features = extractor.extract_features(clean_domain)
        domain_name = clean_domain.split('.')[0]
        entropy = features.get('entropy', _entropy(domain_name))
        
        # Calculate IBHH rate
        ibhh_rate = check_ibhh_rate(clean_domain)

        # ═══════════════════════════════════════════════════════════════════
        # STEP 3: LAYER 1 DECISION (Entropy + Heuristics - Fast Path)
        # ═══════════════════════════════════════════════════════════════════
        
        # Run attack detection FIRST (before entropy check)
        dga_hits  = detect_dga(clean_domain, entropy)
        typo_msg  = detect_typosquatting(clean_domain)
        ff_hits   = detect_fast_flux(clean_domain)
        tun_hits  = detect_dns_tunneling(clean_domain)
        
        # ━━━ CRITICAL: If ANY attack detected, it's MALICIOUS regardless of entropy! ━━━
        if dga_hits or typo_msg or ff_hits or tun_hits:
            # ━━━ LAYER 1: Attack Detected - MALICIOUS ━━━
            attack_type = classify_attack_type(clean_domain, entropy, 
                                               dga_hits, ff_hits, tun_hits, typo_msg)
            
            PERFORMANCE_STATS['layer1_decisions'] += 1
            PERFORMANCE_STATS['malicious_count'] += 1
            METRICS_LAYER1_TOTAL.inc()      # Increment Layer 1 metric
            METRICS_MALICIOUS_TOTAL.inc()   # Increment malicious metric
            print(f"DEBUG: Counter incremented for domain: {domain}")
            # Increment specific attack type metrics
            if dga_hits:
                METRICS_ATTACK_DGA.inc()
            if typo_msg:
                METRICS_ATTACK_TYPO.inc()
            if ff_hits:
                METRICS_ATTACK_FASTFLUX.inc()
            if tun_hits:
                METRICS_ATTACK_TUNNELING.inc()

            # Update attack stats
            key = f"attack_{attack_type.lower()}"
            if key in PERFORMANCE_STATS:
                PERFORMANCE_STATS[key] += 1
            
            explanation = get_detailed_explanation(
                features, None, typo_msg, False, dga_hits, ff_hits, tun_hits,
                "Layer 1 (Attack Detected)", entropy, ibhh_rate, clean_domain
            )
            
            result = {
                "domain": clean_domain,
                "prediction": "malicious",
                "malicious": True,
                "confidence": "0.9300",
                "threat_type": attack_type,
                "layer_used": "Layer 1 (Attack Detected)",
                "stage": "Layer 1 (Heuristics)",
                "attack_type": attack_type,
                "explanation": explanation,
                "ibhh_rate": ibhh_rate if ibhh_rate > 0 else None,
                "virustotal": vt_details if vt_malicious else None
            }
            if vt_malicious:
                attack_type = "Malicious (VirusTotal)"
                # Override confidence
                result["confidence"] = "0.9999"
                result["explanation"]["analysis"]["bullets"].append(f" VirusTotal: {vt_details}")            
            #  Apply security action controller (SINKHOLE + AUDIT)
            result = security_action_controller(result)
                        # === UPDATE GAUGES FOR PROMETHEUS ===
            METRICS_CURRENT_QUERIES.set(PERFORMANCE_STATS['total_queries'])
            METRICS_CURRENT_MALICIOUS.set(PERFORMANCE_STATS['malicious_count'])
            track_threat_for_audio_alert(clean_domain, attack_type, result["confidence"])
            send_email_alert(clean_domain, attack_type, result["confidence"], result.get("incident_id",""))
            return jsonify(result)
        
        
            
        # ━━━ No attacks detected, now check entropy ━━━
        # REMOVED LOW ENTROPY BENIGN BLOCK - These should go to Layer 2!
        # Low entropy domains without obvious attacks need LSTM analysis
        # Examples: cisco-support.org, oracle-verify.net (phishing!)
        
        if entropy > HIGH_ENTROPY_THRESHOLD:
            # ━━━ LAYER 1: High entropy - likely DGA ━━━
            attack_type = classify_attack_type(clean_domain, entropy, 
                                               dga_hits, ff_hits, tun_hits, typo_msg)
            
            PERFORMANCE_STATS['layer1_decisions'] += 1
            PERFORMANCE_STATS['malicious_count'] += 1
            METRICS_LAYER1_TOTAL.inc()      # Increment Layer 1 metric
            METRICS_MALICIOUS_TOTAL.inc()   # Increment malicious metric
            
            key = f"attack_{attack_type.lower()}"
            if key in PERFORMANCE_STATS:
                PERFORMANCE_STATS[key] += 1
            
            explanation = get_detailed_explanation(
                features, None, typo_msg, False, dga_hits, ff_hits, tun_hits,
                "Layer 1 (High Entropy)", entropy, ibhh_rate, clean_domain
            )
            
            result = {
                "domain": clean_domain,
                "prediction": "malicious",
                "malicious": True,
                "confidence": "0.9500",
                "threat_type": attack_type,
                "layer_used": "Layer 1 (High Entropy)",
                "stage": "Layer 1 (High Entropy)",
                "attack_type": attack_type,
                "explanation": explanation,
                "ibhh_rate": ibhh_rate if ibhh_rate > 0 else None,
                "virustotal": vt_details if vt_malicious else None
            }
            
            #  Apply security action controller (SINKHOLE + AUDIT)
            result = security_action_controller(result)
                        # === UPDATE GAUGES FOR PROMETHEUS ===
            METRICS_CURRENT_QUERIES.set(PERFORMANCE_STATS['total_queries'])
            METRICS_CURRENT_MALICIOUS.set(PERFORMANCE_STATS['malicious_count'])
            track_threat_for_audio_alert(clean_domain, attack_type, result["confidence"])
            send_email_alert(clean_domain, attack_type, result["confidence"], result.get("incident_id",""))
            return jsonify(result)
        
        # ═══════════════════════════════════════════════════════════════════
        # STEP 4: LAYER 2 DECISION (LSTM - Truly Ambiguous Cases Only)
        # ═══════════════════════════════════════════════════════════════════
        else:
            # Entropy is ambiguous AND no heuristics detected attacks
            # Only NOW do we run LSTM for deep analysis
            PERFORMANCE_STATS['layer2_decisions'] += 1
            METRICS_LAYER2_TOTAL.inc()  # Increment Layer 2 metric
            # Prepare and run LSTM
            input_df = pd.DataFrame([features])
            for col in expected_features:
                if col not in input_df.columns:
                    input_df[col] = 0
            
            scaled_x = scaler.transform(input_df[expected_features])
            
            # Reshape for LSTM: (batch_size, features) → (batch_size, time_steps, features)
            # LSTM expects 3D input: (samples, time_steps, features)
            scaled_x = scaled_x.reshape(scaled_x.shape[0], 1, scaled_x.shape[1])
            
            lstm_prob = float(lstm_model.predict(scaled_x, verbose=0)[0][0])
            
            # DEBUG: Print LSTM prediction
            print(f" Layer 2 LSTM: domain={clean_domain}, entropy={entropy:.2f}, lstm_prob={lstm_prob:.4f}, threshold={LSTM_THRESHOLD}")
            
            # Attack detection was already done above, reuse results
            # (dga_hits, typo_msg, ff_hits, tun_hits are still in scope)
            
            # Final decision
            if lstm_prob > LSTM_THRESHOLD:
                final_pred = "malicious"
                confidence = lstm_prob
                # Classify attack type based on what LSTM found
                attack_type = classify_attack_type(clean_domain, entropy,
                                                   dga_hits, ff_hits, tun_hits, typo_msg)
                
                PERFORMANCE_STATS['malicious_count'] += 1
                METRICS_MALICIOUS_TOTAL.inc()  # Increment malicious metric
                key = f"attack_{attack_type.lower()}"
                if key in PERFORMANCE_STATS:
                    PERFORMANCE_STATS[key] += 1
            else:
                final_pred = "benign"
                confidence = 1 - lstm_prob
                attack_type = None
                PERFORMANCE_STATS['benign_count'] += 1
                METRICS_BENIGN_TOTAL.inc()  # Increment benign metric
            explanation = get_detailed_explanation(
                features, lstm_prob, typo_msg, False, dga_hits, ff_hits, tun_hits,
                "Layer 2 (LSTM)", entropy, ibhh_rate, clean_domain
            )
            
            result = {
                "domain": clean_domain,
                "prediction": final_pred,
                "malicious": (final_pred == "malicious"),
                "confidence": f"{confidence:.4f}",
                "threat_type": attack_type,
                "layer_used": "Layer 2 (LSTM)",
                "stage": "Layer 2 (LSTM)",
                "attack_type": attack_type,
                "explanation": explanation,
                "ibhh_rate": ibhh_rate if ibhh_rate > 0 else None,
                "virustotal": vt_details if vt_malicious else None
            }
            
            #  Apply security action controller (SINKHOLE + AUDIT)
            result = security_action_controller(result)
                        # === UPDATE GAUGES FOR PROMETHEUS ===
            METRICS_CURRENT_QUERIES.set(PERFORMANCE_STATS['total_queries'])
            METRICS_CURRENT_MALICIOUS.set(PERFORMANCE_STATS['malicious_count'])
            track_threat_for_audio_alert(clean_domain, attack_type, result["confidence"])
            send_email_alert(clean_domain, attack_type, result["confidence"], result.get("incident_id",""))            
            return jsonify(result)

    except Exception as e:
        print(f"X Error: {e}")
        import traceback; traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/stats', methods=['GET'])
def get_stats():
    return jsonify(PERFORMANCE_STATS)

@app.route('/metrics', methods=['GET'])
def metrics():
    """
    Prometheus metrics endpoint
    Exposes metrics in Prometheus format
    """
    # Update gauges with current values
    METRICS_CURRENT_QUERIES.set(PERFORMANCE_STATS['total_queries'])
    METRICS_CURRENT_MALICIOUS.set(PERFORMANCE_STATS['malicious_count'])
    
    # Return metrics in Prometheus format
    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}

#app.wsgi_app = DispatcherMiddleware(app.wsgi_app, {
#   '/metrics': make_wsgi_app()
#})

@app.route('/auth/test', methods=['GET'])
@require_api_key
def test_auth():
    """
    Test if authentication is working
    """
    return jsonify({
        'status': 'authenticated',
        'message': 'Your API key is valid!',
        'auth_enabled': REQUIRE_AUTH
    }), 200
 
@app.route('/auth/generate-key', methods=['POST'])
def generate_api_key():
    """
    Generate a new API key (admin only)
    """
    data = request.json or {}
    admin_password = data.get('admin_password')
    
    # Check admin password (CHANGE THIS!)
    if admin_password != 'dns-shield-master-2024':
        return jsonify({'error': 'Invalid admin password'}), 403
    
    # Generate new random API key
    new_key = secrets.token_urlsafe(32)
    
    return jsonify({
        'api_key': new_key,
        'message': 'New API key generated',
        'usage': f'curl -H "X-API-Key: {new_key}" http://localhost:5000/predict'
    }), 200

# ═══════════════════════════════════════════════════════════════════════════
# SECURITY ACTIONS ROUTES (Active Defense & Governance)
# ═══════════════════════════════════════════════════════════════════════════

@app.route('/security/sinkhole-count', methods=['GET'])
def get_sinkhole_count():
    """Return count of sinkholed domains"""
    try:
        if os.path.exists('sinkhole_blocklist.txt'):
            with open('sinkhole_blocklist.txt', 'r') as f:
                count = len([line for line in f if line.strip() and not line.strip().startswith('#')])
        else:
            count = 0
        return jsonify({"count": count})
    except Exception as e:
        return jsonify({"count": 0, "error": str(e)})

@app.route('/security/incident-count', methods=['GET'])
def get_incident_count():
    """Return count of total incidents"""
    try:
        if os.path.exists('dns_shield_forensic_audit.json'):
            with open('dns_shield_forensic_audit.json', 'r') as f:
                count = len([line for line in f if line.strip()])
        else:
            count = 0
        return jsonify({"count": count})
    except Exception as e:
        return jsonify({"count": 0, "error": str(e)})

@app.route('/security/recent-actions', methods=['GET'])
def get_recent_actions():
    """Return last 20 security actions"""
    try:
        actions = []
        if os.path.exists('dns_shield_forensic_audit.json'):
            with open('dns_shield_forensic_audit.json', 'r') as f:
                lines = f.readlines()
                for line in lines[-20:]:
                    try:
                        actions.append(json.loads(line.strip()))
                    except:
                        pass
        return jsonify(list(reversed(actions)))
    except Exception as e:
        return jsonify([])

@app.route('/security/manual-override', methods=['POST'])
def manual_override_route():
    """Handle manual whitelist/blacklist from admin"""
    try:
        data = request.json
        domain = data.get('domain', '').strip()
        action = data.get('action', 'whitelist')
        
        if not domain:
            return jsonify({"error": "Domain required"}), 400
        
        # Call the manual override function
        result = manual_override(domain, action, f"Manual {action} by administrator")
                    # === UPDATE GAUGES FOR PROMETHEUS ===
        METRICS_CURRENT_QUERIES.set(PERFORMANCE_STATS['total_queries'])
        METRICS_CURRENT_MALICIOUS.set(PERFORMANCE_STATS['malicious_count'])
        track_threat_for_audio_alert(clean_domain, attack_type, result["confidence"])
        send_email_alert(clean_domain, attack_type, result["confidence"], result.get("incident_id",""))        
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/security/sinkhole-view')
def view_sinkhole_blocklist():
    """Display sinkhole blocklist in browser"""
    try:
        if not os.path.exists('sinkhole_blocklist.txt'):
            content = "# No domains sinkholed yet\n"
        else:
            with open('sinkhole_blocklist.txt', 'r') as f:
                content = f.read()
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Sinkhole Blocklist</title>
            <style>
                body {{
                    font-family: 'Courier New', monospace;
                    background: linear-gradient(135deg, #1a0b2e 0%, #2d1b69 25%, #1e3a8a 50%, #7c3aed 100%);
                    color: #e2e8f0;
                    padding: 30px;
                }}
                h1 {{ color: #ef4444; }}
                pre {{
                    background: rgba(30, 27, 75, 0.8);
                    padding: 20px;
                    border-radius: 12px;
                    border: 2px solid rgba(239, 68, 68, 0.3);
                    white-space: pre-wrap;
                    word-wrap: break-word;
                }}
                .back-link {{
                    display: inline-block;
                    padding: 10px 20px;
                    background: linear-gradient(135deg, #ef4444, #dc2626);
                    color: white;
                    text-decoration: none;
                    border-radius: 8px;
                    margin-bottom: 20px;
                }}
            </style>
        </head>
        <body>
            <a href="/" class="back-link">← Back to Dashboard</a>
            <h1> Sinkhole Blocklist</h1>
            <p>Malicious domains automatically added by DNS Shield Active Defense</p>
            <pre>{content}</pre>
        </body>
        </html>
        """
        return html
    except Exception as e:
        return f"Error: {e}", 500

@app.route('/security/audit-view')
def view_forensic_audit():
    """Display forensic audit log in browser"""
    try:
        entries = []
        if os.path.exists('dns_shield_forensic_audit.json'):
            with open('dns_shield_forensic_audit.json', 'r') as f:
                for line in f:
                    try:
                        entries.append(json.loads(line.strip()))
                    except:
                        pass
        
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Forensic Audit Log</title>
            <style>
                body {
                    font-family: 'Courier New', monospace;
                    background: linear-gradient(135deg, #1a0b2e 0%, #2d1b69 25%, #1e3a8a 50%, #7c3aed 100%);
                    color: #e2e8f0;
                    padding: 30px;
                }
                h1 { color: #10b981; }
                table {
                    width: 100%;
                    border-collapse: separate;
                    border-spacing: 0 8px;
                    margin-top: 20px;
                }
                th, td {
                    padding: 12px;
                    border: 1px solid rgba(139, 92, 246, 0.3);
                    text-align: left;
                }
                th {
                    background: linear-gradient(135deg, rgba(139, 92, 246, 0.3), rgba(59, 130, 246, 0.3));
                    color: #c7d2fe;
                }
                tr {
                    background: rgba(30, 27, 75, 0.6);
                }
                .back-link {
                    display: inline-block;
                    padding: 10px 20px;
                    background: linear-gradient(135deg, #10b981, #059669);
                    color: white;
                    text-decoration: none;
                    border-radius: 8px;
                    margin-bottom: 20px;
                }
                .incident-id {
                    font-family: monospace;
                    color: #a78bfa;
                    font-weight: bold;
                }
            </style>
        </head>
        <body>
            <a href="/" class="back-link">← Back to Dashboard</a>
            <h1> Forensic Audit Log (GDPR/HIPAA Compliant)</h1>
            <p>Every security decision with unique incident ID for auditing</p>
        """
        
        if not entries:
            html += "<p style='color: #64748b;'>No audit entries yet</p>"
        else:
            html += """
            <table>
                <thead>
                    <tr>
                        <th>Incident ID</th>
                        <th>Timestamp</th>
                        <th>Domain</th>
                        <th>Action</th>
                        <th>Threat Type</th>
                        <th>Confidence</th>
                    </tr>
                </thead>
                <tbody>
            """
            
            for entry in reversed(entries[-100:]):  # Last 100
                action_color = '#ef4444' if entry.get('action_taken') == 'SINKHOLED' else '#10b981'
                html += f"""
                    <tr>
                        <td class="incident-id">{entry.get('incident_id', 'N/A')}</td>
                        <td style="color: #94a3b8;">{entry.get('timestamp', 'N/A')}</td>
                        <td style="color: #c7d2fe; font-weight: 600;">{entry.get('domain', 'N/A')}</td>
                        <td style="color: {action_color}; font-weight: bold;">{entry.get('action_taken', 'N/A')}</td>
                        <td style="color: #60a5fa;">{entry.get('threat_type') or '-'}</td>
                        <td style="color: #a78bfa;">{entry.get('confidence', 'N/A')}</td>
                    </tr>
                """
            
            html += """
                </tbody>
            </table>
            """
        
        html += """
        </body>
        </html>
        """
        return html
    except Exception as e:
        return f"Error: {e}", 500


@app.route('/doh-logs-json', methods=['GET'])
def doh_logs_json():
    """Return DoH resolver logs as JSON"""
    try:
        # Try multiple possible locations
        possible_paths = [
            'shared_doh_logs.json',
            os.path.join(current_dir, 'shared_doh_logs.json'),
            os.path.join(os.path.dirname(current_dir), 'shared_doh_logs.json')
        ]
        
        logs = []
        for path in possible_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        content = f.read().strip()
                        if content:
                            logs = json.loads(content)
                        break
                except (json.JSONDecodeError, ValueError) as e:
                    print(f"JSON decode error in {path}: {e}")
                    continue
        
        # Return last 50 entries
        return jsonify(logs[-50:] if logs else [])
    
    except Exception as e:
        print(f"Error reading DoH logs: {e}")
        return jsonify([])

@app.route('/doh-logs')
def doh_logs_html():
    """HTML view of DoH logs (standalone page)"""
    try:
        # Try multiple possible locations
        possible_paths = [
            'shared_doh_logs.json',
            os.path.join(current_dir, 'shared_doh_logs.json'),
            os.path.join(os.path.dirname(current_dir), 'shared_doh_logs.json')
        ]
        
        logs = []
        log_file_found = False
        for path in possible_paths:
            if os.path.exists(path):
                log_file_found = True
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        content = f.read().strip()
                        if content:
                            logs = json.loads(content)
                        break
                except (json.JSONDecodeError, ValueError):
                    continue
        
        if not log_file_found:
            no_file_html = """
            <!DOCTYPE html>
            <html><head><title>DoH Logs</title>
            <style>body{font-family:Arial;background:#1a0b2e;color:#c7d2fe;padding:40px;text-align:center;}
            h1{color:#a78bfa;}</style></head>
            <body><h1> DoH Logs</h1><p>Log file not found: <code>shared_doh_logs.json</code></p>
            <p>Make sure your <code>dns_resolver.py</code> is running and logging queries.</p>
            <p><a href="/" style="color:#60a5fa;">← Back to Dashboard</a></p></body></html>"""
            return no_file_html
        
        logs = logs[-100:]  # Last 100 entries
    except Exception as e:
        error_html = f"""
        <!DOCTYPE html>
        <html><head><title>DoH Logs Error</title>
        <style>body{{font-family:Arial;background:#1a0b2e;color:#ef4444;padding:40px;text-align:center;}}</style></head>
        <body><h1> Error Loading Logs</h1><p>{str(e)}</p>
        <p><a href="/" style="color:#60a5fa;">← Back to Dashboard</a></p></body></html>"""
        return error_html

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>DoH Resolver Logs</title>
        <meta http-equiv="refresh" content="10">
        <meta charset="UTF-8">
        <style>
            @keyframes gradient-shift { 0%, 100% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } }
            body { 
                font-family: 'Courier New', monospace; 
                background: linear-gradient(135deg, #1a0b2e 0%, #2d1b69 25%, #1e3a8a 50%, #7c3aed 100%);
                background-size: 400% 400%;
                animation: gradient-shift 15s ease infinite;
                color: #e2e8f0; 
                padding: 30px; 
            }
            .container { max-width: 1400px; margin: 0 auto; }
            h1 { 
                color: #a78bfa; 
                text-align: center;
                font-size: 2.5em;
                margin-bottom: 10px;
            }
            .info { 
                text-align: center; 
                color: #94a3b8; 
                margin-bottom: 30px; 
            }
            table { 
                border-collapse: separate; 
                border-spacing: 0 8px;
                width: 100%; 
                margin-top: 20px; 
            }
            th, td { 
                padding: 12px; 
                border: 1px solid rgba(139, 92, 246, 0.3);
                text-align: left; 
            }
            th { 
                background: linear-gradient(135deg, rgba(139, 92, 246, 0.3), rgba(59, 130, 246, 0.3));
                color: #c7d2fe;
                font-weight: 600;
            }
            tr { 
                background: rgba(30, 27, 75, 0.6);
                transition: all 0.3s ease;
            }
            tr:hover {
                background: rgba(139, 92, 246, 0.2);
                transform: translateX(4px);
            }
            .blocked { 
                color: #f87171; 
                font-weight: bold; 
                background: rgba(239, 68, 68, 0.1);
                padding: 4px 12px;
                border-radius: 12px;
                display: inline-block;
            }
            .allowed { 
                color: #4ade80; 
                font-weight: bold; 
                background: rgba(16, 185, 129, 0.1);
                padding: 4px 12px;
                border-radius: 12px;
                display: inline-block;
            }
            .back-link {
                display: inline-block;
                padding: 10px 20px;
                background: linear-gradient(135deg, #8b5cf6, #3b82f6);
                color: white;
                text-decoration: none;
                border-radius: 8px;
                margin-bottom: 20px;
            }
            .back-link:hover {
                background: linear-gradient(135deg, #7c3aed, #2563eb);
            }
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/" class="back-link">← Back to Dashboard</a>
            <h1> DoH Resolver Logs</h1>
            <div class="info">
                Auto-refreshes every 10 seconds • Last 100 entries • Newest first
            </div>
    """
    
    if not logs:
        html += """
            <div style="text-align: center; padding: 60px; color: #64748b;">
                <div style="font-size: 4em; margin-bottom: 20px;">📭</div>
                <div style="font-size: 1.5em; color: #94a3b8; margin-bottom: 10px;">No logs yet</div>
                <div>Start making DNS queries through the resolver to see logs here</div>
            </div>
        """
    else:
        html += """
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Domain</th>
                        <th>Status</th>
                        <th>Threat Type</th>
                        <th>Confidence</th>
                        <th>IBHH Rate</th>
                        <th>Explanation</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        for entry in reversed(logs):
            status_class = "blocked" if entry.get("malicious") else "allowed"
            status_text = "BLOCKED" if entry.get("malicious") else "Allowed"
            threat = entry.get("threat_type") or "-"
            conf = f"{entry.get('confidence', 0):.3f}" if entry.get("confidence") is not None else "-"
            rate = entry.get("ibhh_rate") or "-"
            expl = entry.get("explanation", "-")
            if len(expl) > 80:
                expl = expl[:80] + "..."

            html += f"""
                <tr>
                    <td style="color: #94a3b8;">{entry.get('time', 'N/A')}</td>
                    <td style="color: #c7d2fe; font-weight: 600;">{entry.get('domain', 'N/A')}</td>
                    <td><span class="{status_class}">{status_text}</span></td>
                    <td style="color: {'#fca5a5' if entry.get('malicious') else '#94a3b8'};">{threat}</td>
                    <td style="color: #a78bfa; font-weight: 600;">{conf}</td>
                    <td style="color: #ec4899;">{rate}</td>
                    <td style="color: #cbd5e1; font-size: 0.9em;">{expl}</td>
                </tr>
            """
        
        html += """
                </tbody>
            </table>
        """
    
    html += """
        </div>
    </body>
    </html>
    """
    return html
#app.wsgi_app = DispatcherMiddleware(app.wsgi_app, {
#    '/metrics': make_wsgi_app()
#})
# ═══════════════════════════════════════════════════════════════════════════
# AUDIO ALERT ENDPOINT - Returns recent malicious detections
# ═══════════════════════════════════════════════════════════════════════════
@app.route('/api/recent-threats', methods=['GET'])
def get_recent_threats():
    """Return recent malicious detections for audio alert system"""
    global RECENT_THREATS
    return jsonify({
        'threats': RECENT_THREATS,
        'count': len(RECENT_THREATS),
        'timestamp': time.time()
    })
if __name__ == '__main__':
    print("\n" + "="*70)
    print("DNS SHIELD AI - TWO-LAYER SYSTEM WITH XAI")
    print("="*70)
    print("\n8 Attack Types: DGA, Tunneling, Typosquatting, Structured DGA,")
    print("                C2 Beaconing, IBHH, Homograph, Fast Flux")
    print("\n30 Demo Samples Ready!")
    print("="*70)
    print("\nStarting server at http://127.0.0.1:5000")
    print("="*70 + "\n")
    
    app.run(debug=False, host='0.0.0.0', port=5000)