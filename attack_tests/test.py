#!/usr/bin/env python3
"""Inject all attack types into NetworkSnifferr via /api/alerts/inject"""

import json, urllib.request, sys, time

BASE = "http://localhost:5000"
USER, PASS = "attacktest", "TestPass123!"

def api(method, path, data=None, token=None):
    url = f"{BASE}{path}"
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        err = e.read().decode()
        print(f"  HTTP {e.code}: {err}")
        return None

def inject(token, packets):
    result = api("POST", "/api/alerts/inject", {"packets": packets}, token)
    n = result.get("alerts_generated", 0) if result else 0
    print(f"  => {n} alerts")
    return n

# --- Login ---
print("Logging in...")
r = api("POST", "/api/auth/login", {"username": USER, "password": PASS})
if not r or "token" not in r:
    print("Login failed"); sys.exit(1)
token = r["token"]
print(f"Token: {token[:20]}...")

# --- Enable test mode ---
api("POST", "/api/test-mode", {
    "enabled": True, "port_scan_count": 5, "syn_flood_rate": 10,
    "brute_force_attempts": 4, "dns_query_length": 50, "alert_cooldown": 10
}, token)
print("Test mode enabled\n")

ATTACKS = [
    ("Port Scan", [
        {"src_ip": "1.2.3.4", "dst_ip": "10.0.0.1", "src_port": 54321, "dst_port": p, "protocol": "TCP", "tcp_flags": 2}
        for p in range(1, 20)
    ]),
    ("SYN Flood", [
        {"src_ip": "8.8.8.8", "dst_ip": "10.0.0.1", "src_port": 54000 + i, "dst_port": 80, "protocol": "TCP", "tcp_flags": 2}
        for i in range(25)
    ]),
    ("Brute Force", [
        {"src_ip": "8.8.4.4", "dst_ip": "10.0.0.1", "src_port": 50000 + i, "dst_port": 22, "protocol": "TCP", "tcp_flags": 2}
        for i in range(10)
    ]),
    ("SQL Injection", [
        {"src_ip": "1.2.3.5", "dst_ip": "10.0.0.1", "src_port": 45678, "dst_port": 80, "protocol": "HTTP",
         "payload": "GET /login?user=' OR '1'='1 HTTP/1.1"}
    ]),
    ("XSS", [
        {"src_ip": "1.2.3.6", "dst_ip": "10.0.0.1", "src_port": 45679, "dst_port": 80, "protocol": "HTTP",
         "payload": "GET /search?q=<script>alert(1)</script> HTTP/1.1"}
    ]),
    ("Command Injection", [
        {"src_ip": "1.2.3.7", "dst_ip": "10.0.0.1", "src_port": 45680, "dst_port": 80, "protocol": "HTTP",
         "payload": "GET /ping?host=127.0.0.1;cat /etc/passwd HTTP/1.1"}
    ]),
    ("Path Traversal", [
        {"src_ip": "1.2.3.10", "dst_ip": "10.0.0.1", "src_port": 45681, "dst_port": 80, "protocol": "HTTP",
         "payload": "GET /download?file=../../../etc/passwd HTTP/1.1"}
    ]),
    ("DNS Tunneling", [
        {"src_ip": "1.2.3.8", "dst_ip": "8.8.8.8", "src_port": 50000 + i, "dst_port": 53, "protocol": "DNS",
         "payload": f"base64data.sub{i}.a.b.c.evil.com"}
        for i in range(30)
    ]),
    ("LAND Attack", [
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.1", "src_port": 80, "dst_port": 80, "protocol": "TCP", "tcp_flags": 2}
    ]),
    ("IP Spoofing", [
        {"src_ip": "255.255.255.255", "dst_ip": "10.0.0.1", "src_port": 12345, "dst_port": 80, "protocol": "TCP", "tcp_flags": 2}
    ]),
    ("XMAS Scan", [
        {"src_ip": "1.2.3.9", "dst_ip": "10.0.0.1", "src_port": 54321, "dst_port": p, "protocol": "TCP", "tcp_flags": 41}
        for p in [21, 22, 23, 25, 80]
    ]),
    ("DDoS / Flood (multi-source)", [
        {"src_ip": f"10.0.{i}.{j}", "dst_ip": "10.0.0.1", "src_port": 80, "dst_port": 80, "protocol": "TCP", "tcp_flags": 2}
        for i in range(5) for j in range(5)
    ]),
]

total = 0
for name, packets in ATTACKS:
    print(f"=== {name} ===")
    n = inject(token, packets)
    total += n
    time.sleep(1)

print(f"\nDone. Total alerts generated: {total}")
