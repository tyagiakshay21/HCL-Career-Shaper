"""Sends a fake credential over plain HTTP to the detector (Day 2/3 attack).
Usage:  python attack.py            (default http://localhost:5000)
        python attack.py http://localhost:5000
"""
import sys
import urllib.parse
import urllib.request

base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
data = urllib.parse.urlencode({"password": "Fake123", "api_key": "FAKE-KEY"}).encode()
with urllib.request.urlopen(urllib.request.Request(base + "/login", data=data)) as r:
    print(r.status, r.read().decode())
