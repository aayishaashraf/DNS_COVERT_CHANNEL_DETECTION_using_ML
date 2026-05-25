"""
DNS-over-HTTPS (DoH) and DoT Resolver with FULL XAI Threat Detection + Shared Logging
ISSUE 3 & 5 FIX: Now includes complete XAI explanation in logs for malicious queries
Now supports both DoH (port 8053) and DoT (port 853) with shared logic and logging.
"""

import sys
import os
import base64
import time
import json
from flask import Flask, request, Response, jsonify
import requests
import socket
import ssl
import threading
from werkzeug.serving import make_ssl_devcert

# ─── PATH SETUP ──────────────────────────────────────────────────────────────

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, '..'))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, 'src'))

# Import threat detector and feature extractor
try:
    from threat_detector import ThreatDetector
    print("[STARTUP] ThreatDetector imported successfully")
except ImportError as e:
    print(f"ERROR: Cannot import ThreatDetector → {e}")
    ThreatDetector = None

# Import dependencies for XAI generation
try:
    import joblib
    import re
    import math
    from difflib import SequenceMatcher
    print("[STARTUP] XAI dependencies imported successfully")
except ImportError as e:
    print(f"WARNING: Some XAI dependencies missing → {e}")

app = Flask(__name__)

# Use absolute path
LOG_FILE = r"C:\Users\aayis\OneDrive\Desktop\UWL\PROJECT\DNS_Covert_Channel_Detection\shared_doh_logs.json"

print(f"[STARTUP] Logs will be written to: {LOG_FILE}")

# Global threat detector
THREAT_DETECTOR = None
try:
    THREAT_DETECTOR = ThreatDetector()
    print("[STARTUP] ThreatDetector initialized successfully")
except Exception as e:
    print(f"[STARTUP] Failed to initialize ThreatDetector: {e}")

# Upstream DoH providers (used for forwarding both DoH and DoT queries)
UPSTREAM_DOH = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
    "https://dns.quad9.net/dns-query"
]

# Stats (shared between DoH and DoT)
STATS = {
    'total_queries': 0,
    'blocked': 0,
    'forwarded': 0,
    'ibhh_blocked': 0,
    'last_block_time': None,
    'last_block_domain': None
}

def extract_domain_from_dns(dns_wire):
    """
    Extract domain from DNS wire format - PRODUCTION READY VERSION.
    Handles all edge cases including extra null bytes, malformed queries, etc.
    """
    try:
        if len(dns_wire) < 13:
            return 'unknown'
        
        # Start at position 12 (after DNS header)
        position = 12
        
        # CRITICAL FIX: Skip any leading null bytes (sometimes queries have extra padding)
        while position < len(dns_wire) and dns_wire[position] == 0:
            position += 1
            if position >= len(dns_wire):
                print(f"[DEBUG] Only null bytes after header")
                return 'unknown'
        
        print(f"[DEBUG] Starting domain extraction at position {position}")
        
        domain_parts = []
        max_iterations = 20
        iteration = 0
        
        while position < len(dns_wire) and iteration < max_iterations:
            iteration += 1
            
            length = dns_wire[position]
            print(f"[DEBUG] Position {position}: length byte = 0x{length:02x} ({length})")
            
            # End of domain
            if length == 0:
                print(f"[DEBUG] End of domain at position {position}")
                break
            
            # Compression pointer (0xC0+)
            if length >= 0xC0:
                print(f"[DEBUG] Compression pointer 0x{length:02x}, stopping")
                break
            
            # Validate length (DNS labels must be 1-63 bytes)
            if length > 63:
                print(f"[DEBUG] Invalid length {length} > 63, trying to recover")
                # Skip this byte and try next
                position += 1
                continue
            
            # Check bounds
            if position + 1 + length > len(dns_wire):
                print(f"[DEBUG] Label would extend beyond packet, stopping")
                break
            
            # Extract label
            label_bytes = dns_wire[position + 1 : position + 1 + length]
            label = label_bytes.decode('ascii', errors='replace')
            
            print(f"[DEBUG]   Label bytes: {' '.join(f'{b:02x}' for b in label_bytes[:10])}")
            print(f"[DEBUG]   Label text: '{label}'")
            
            # Validate characters - be lenient but clean
            # Accept alphanumeric, hyphen, underscore
            valid_chars = ''.join(c if (c.isalnum() or c in '-_') else '' for c in label)
            
            if valid_chars:
                domain_parts.append(valid_chars.lower())
                print(f"[DEBUG]   Added label: '{valid_chars}'")
            else:
                print(f"[DEBUG]   Label has no valid characters, skipping")
            
            position += length + 1
        
        # Build domain from parts
        if len(domain_parts) >= 2:
            domain = '.'.join(domain_parts)
            print(f"[DEBUG] ✓ Extracted domain: '{domain}' from {len(domain_parts)} labels")
            return domain
        elif len(domain_parts) == 1:
            # Single label - might be incomplete
            domain = domain_parts[0]
            print(f"[DEBUG] ⚠ Only one label extracted: '{domain}' (may be incomplete)")
            return domain
        else:
            print(f"[DEBUG] ✗ No valid labels extracted")
            return 'unknown'
        
    except Exception as e:
        print(f"[ERROR] Domain extraction exception: {e}")
        import traceback
        traceback.print_exc()
        return 'unknown'

def process_dns_query(dns_wire, protocol="DoH"):
    """Shared logic for processing DNS queries (used by both DoH and DoT)."""
    STATS['total_queries'] += 1

    if not dns_wire or len(dns_wire) < 12:
        return None  # Invalid

    domain = extract_domain_from_dns(dns_wire)
    print(f"[{protocol} QUERY] Received for: {domain}")

    log_entry = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "domain": domain,
        "malicious": False,
        "threat_type": None,
        "confidence": None,
        "explanation": None,
        "ibhh_rate": None,
        "status": "allowed",
        "protocol": protocol
    }

    is_malicious = False
    threat_type = None
    confidence = None
    explanation = None

    if THREAT_DETECTOR and domain != "unknown":
        try:
            is_malicious, threat_type, confidence, explanation = THREAT_DETECTOR.check_domain(domain)
            
            # Extract IBHH rate - try multiple methods
            ibhh_rate = None
            
            # Method 1: Parse from explanation string if it contains rate info
            if explanation and "rate:" in str(explanation):
                import re
                rate_match = re.search(r'rate:\s*([\d.]+)\s*B/s', str(explanation))
                if rate_match:
                    try:
                        ibhh_rate = float(rate_match.group(1))
                        print(f"[DEBUG] Extracted IBHH rate from explanation: {ibhh_rate} B/s")
                    except:
                        pass
            
            # Method 2: Access IBHH detector directly
            if ibhh_rate is None and hasattr(THREAT_DETECTOR, 'ibhh'):
                try:
                    # The IBHH detector might store the last rate
                    if hasattr(THREAT_DETECTOR.ibhh, 'last_rate'):
                        ibhh_rate = THREAT_DETECTOR.ibhh.last_rate
                        print(f"[DEBUG] Got IBHH rate from detector.last_rate: {ibhh_rate}")
                    elif hasattr(THREAT_DETECTOR.ibhh, 'current_rate'):
                        ibhh_rate = THREAT_DETECTOR.ibhh.current_rate
                        print(f"[DEBUG] Got IBHH rate from detector.current_rate: {ibhh_rate}")
                except Exception as e:
                    print(f"[DEBUG] Could not extract IBHH rate: {e}")
            
            log_entry.update({
                "malicious": is_malicious,
                "threat_type": threat_type,
                "confidence": confidence,
                "explanation": explanation,
                "ibhh_rate": ibhh_rate,
                "status": "blocked" if is_malicious else "allowed"
            })
            
            print(f"[DETECTION] {domain} → malicious={is_malicious}, type={threat_type}, conf={confidence}, ibhh={ibhh_rate}")
        except Exception as e:
            print(f"[ERROR] Detection failed for {domain}: {e}")
            import traceback
            traceback.print_exc()
            log_entry["explanation"] = f"Detection error: {str(e)}"

    # Append to shared log file
    try:
        logs = []
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                logs = json.load(f)
        logs.append(log_entry)
        with open(LOG_FILE, 'w') as f:
            json.dump(logs, f, indent=2)
        print(f"[LOGGED] {domain} → {log_entry['status']} ({protocol})")
    except Exception as e:
        print(f"[ERROR] Log write failed: {e}")

    if is_malicious:
        STATS['blocked'] += 1
        STATS['last_block_time'] = time.strftime("%H:%M:%S")
        STATS['last_block_domain'] = domain
        if "IBHH" in str(threat_type):
            STATS['ibhh_blocked'] += 1

        # Create REFUSED response - FIX: Convert to bytes for Flask
        response_wire = bytearray(dns_wire[:2]) + b'\x81\x85' + dns_wire[4:]
        return bytes(response_wire)  # Must return bytes, not bytearray

    else:
        STATS['forwarded'] += 1
        # Forward to upstream DoH (shared for both protocols)
        headers = {
            'Content-Type': 'application/dns-message',
            'Accept': 'application/dns-message'
        }
        for upstream in UPSTREAM_DOH:
            try:
                r = requests.post(upstream, headers=headers, data=dns_wire, timeout=4)
                if r.status_code == 200:
                    return r.content
            except Exception as e:
                print(f"[ERROR] Upstream {upstream} failed: {e}")
                continue
        return None  # Upstream failed

@app.route('/dns-query', methods=['GET', 'POST'])
def doh_query():
    dns_wire = None

    if request.method == 'GET':
        dns_b64 = request.args.get('dns')
        if dns_b64:
            try:
                # Add proper padding for base64
                dns_b64 += '=' * ((4 - len(dns_b64) % 4) % 4)
                dns_wire = base64.urlsafe_b64decode(dns_b64)
                print(f"[DoH GET] Received {len(dns_wire)} bytes")
            except Exception as e:
                print(f"[DoH ERROR] Invalid base64: {e}")
                return Response("Invalid base64", status=400)

    elif request.method == 'POST':
        if request.content_type == 'application/dns-message':
            dns_wire = request.data
            print(f"[DoH POST] Received {len(dns_wire)} bytes")

    response_wire = process_dns_query(dns_wire, protocol="DoH")
    if response_wire is None:
        return Response("Upstream failed", status=502)
    return Response(response_wire, mimetype='application/dns-message')

@app.route('/stats')
def get_stats():
    return jsonify(STATS)

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "detector_loaded": THREAT_DETECTOR is not None})

def dot_server(cert_path, key_path):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('0.0.0.0', 853))
    sock.listen(5)
    print("[STARTUP] DoT server listening on port 853")

    while True:
        client, addr = sock.accept()
        try:
            with context.wrap_socket(client, server_side=True) as tls_client:
                length_bytes = tls_client.recv(2)
                if len(length_bytes) != 2:
                    continue
                length = int.from_bytes(length_bytes, 'big')
                dns_wire = tls_client.recv(length)
                if len(dns_wire) != length:
                    continue

                response_wire = process_dns_query(dns_wire, protocol="DoT")
                if response_wire is not None:
                    resp_length = len(response_wire)
                    tls_client.sendall(resp_length.to_bytes(2, 'big') + response_wire)
        except Exception as e:
            print(f"[DoT ERROR] {e}")
        finally:
            client.close()

if __name__ == '__main__':
    print("="*70)
    print(" DNS-over-HTTPS and DoT Resolver with FULL XAI Logging")
    print(f" Log file: {LOG_FILE}")
    print(" DoH Endpoint: https://localhost:8053/dns-query")
    print(" DoT Endpoint: tls://localhost:853")
    print(" Home:     https://localhost:8053/")
    print(" Stats:    https://localhost:8053/stats")
    print(" Dashboard: http://127.0.0.1:5000")
    print("="*70)
    print("\n✅ All malicious queries will now include full XAI explanation")
    print("✅ Click any log entry in dashboard to view XAI details\n")
    print("✅ Now supports both DoH and DoT with shared detection and logging")

    # Generate self-signed cert for both DoH and DoT
    cert_path, key_path = make_ssl_devcert(os.path.join(os.path.dirname(__file__), 'adhoc_ssl'))

    # Start DoT server in background thread
    threading.Thread(target=dot_server, args=(cert_path, key_path), daemon=True).start()

    # Start DoH server
    app.run(host='0.0.0.0', port=8053, debug=False, ssl_context=(cert_path, key_path))