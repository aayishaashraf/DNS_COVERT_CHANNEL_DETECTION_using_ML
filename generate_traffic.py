import requests
import time
import random

domains = [
    # Benign
    "google.com", "microsoft.com", "apple.com", "amazon.com", "facebook.com",
    # Malicious (these should be detected)
    "g00gle.com", "paypa1.com", "update1234.com", "xK9j2Lq8M3p7RtY4nW6vB1sD5fG8hJ0k.com",
    "ZG5zMnRjcF9lbmNvZGVkX3BheWxvYWRfZGF0YQ.attacker.com", "fileserver.local"
]

url = "http://localhost:5000/predict"
headers = {"Content-Type": "application/json", "X-API-Key": "dns-shield-admin-2024"}

for i in range(200):   # 200 total requests
    domain = random.choice(domains)
    try:
        resp = requests.post(url, json={"domain": domain}, headers=headers, timeout=2)
        print(f"{i+1:3d}: {domain:40s} -> {resp.json().get('prediction', 'error')}")
    except Exception as e:
        print(f"{i+1:3d}: {domain:40s} -> ERROR: {e}")
    time.sleep(0.05)   # 50ms delay to avoid overwhelming