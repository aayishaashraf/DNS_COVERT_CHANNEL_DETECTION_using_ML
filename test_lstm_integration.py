#!/usr/bin/env python3
"""
LSTM Integration Test - Fixed Stage Detection
Tests all attack types with correct stage reporting
"""

import sys
import os
import json
import time

# Add paths
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src'))

print("="*70)
print("LSTM INTEGRATION TEST")
print("="*70)

# Initialize detector
print("\n Initializing ThreatDetector...\n")
from threat_detector import ThreatDetector
detector = ThreatDetector()

# CORRECTED: Changed detector.lstm_loaded to detector.loaded to match your class
if not detector.loaded:
    print("\n❌ ERROR: ThreatDetector not loaded properly!")
    print("   Please ensure models/dns_covert_detector_final.h5 and models/dns_scaler_final.pkl exist.")
    sys.exit(1)

print("\n" + "="*70)
print("✅ THREAT DETECTOR & LSTM LOADED SUCCESSFULLY!")
print("="*70)

# Test cases including your proposal's identified threats [cite: 32, 39]
test_cases = [
    {
        'domain': 'google.com',
        'expected': 'benign',
        'description': 'Standard benign domain'
    },
    {
        'domain': 'g00gle.com',
        'expected': 'malicious',
        'description': 'Typosquatting attack'
    },
    {
        'domain': 'xk9j2lq8m3p7.com',
        'expected': 'malicious',
        'description': 'Domain Generation Algorithm (DGA)'
    },
    {
        'domain': 'dgvzdgrhdgexmjm0nty3odkw.attacker.com',
        'expected': 'malicious',
        'description': 'DNS Tunneling exfiltration'
    },
    {
        'domain': 'system-update.net',
        'expected': 'malicious',
        'description': 'Low entropy stealthy C2'
    }
]

print("\n Running 2-Stage Analysis (Entropy + LSTM)...\n")

passed = 0
failed = 0
stage_counts = {
    "Whitelist": 0,
    "Stage 1 (Entropy - Low)": 0,
    "Stage 1 (Entropy - High)": 0,
    "Stage 2 (LSTM)": 0,
    "Unknown": 0
}

for test in test_cases:
    domain = test['domain']
    expected = test['expected']
    description = test['description']
    
    # Run detection through your hybrid logic
    is_malicious, threat_type, confidence, explanation = detector.check_domain(domain)
    actual = 'malicious' if is_malicious else 'benign'
    
    # Map the explanation to the correct architectural stage
    if "Whitelisted" in explanation or "whitelisted" in explanation.lower():
        stage = "Whitelist"
    elif "LSTM" in explanation:
        stage = "Stage 2 (LSTM)"
    elif "Low entropy" in explanation:
        stage = "Stage 1 (Entropy - Low)"
    elif "High entropy" in explanation:
        stage = "Stage 1 (Entropy - High)"
    else:
        stage = "Unknown"
    
    stage_counts[stage] += 1
    
    if actual == expected:
        print(f"✅ {domain}")
        passed += 1
    else:
        print(f"❌ {domain}")
        failed += 1
    
    print(f"   Description: {description}")
    print(f"   Stage Used : {stage}")
    print(f"   Result     : {actual.upper()}")
    print(f"   Confidence : {confidence*100:.2f}%")
    print(f"   Reason     : {explanation}")
    print("-" * 30)

# Final Summary for Dissertation Evidence
print("\n" + "="*70)
print("FINAL TEST SUMMARY")
print("="*70)
print(f"Overall Accuracy: {(passed/len(test_cases))*100:.2f}% ({passed}/{len(test_cases)})")

print(f"\nArchitectural Distribution:")
for stage, count in stage_counts.items():
    if count > 0:
        print(f"   - {stage}: {count} queries")

print("="*70)
if failed == 0:
    print(" ALL SYSTEMS OPERATIONAL - READY FOR DEMONSTRATION")
else:
    print(f"⚠️  {failed} TEST(S) FAILED - CHECK MODEL CALIBRATION")
print("="*70)