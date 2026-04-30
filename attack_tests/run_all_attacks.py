#!/usr/bin/env python3
"""
Master Attack Runner - Runs all attack simulations for comprehensive testing
For EDUCATIONAL and AUTHORIZED TESTING purposes only!
"""

import argparse
import time
import sys
import os
import subprocess
from typing import List, Tuple

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_banner():
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║     ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗       ║
    ║     ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝       ║
    ║     ██████╔╝███████║██║     █████╔╝ █████╗     ██║          ║
    ║     ██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║          ║
    ║     ██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║          ║
    ║     ╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝          ║
    ║                                                              ║
    ║     ████████╗███████╗███████╗████████╗███████╗██████╗       ║
    ║     ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗      ║
    ║        ██║   █████╗  ███████╗   ██║   █████╗  ██████╔╝      ║
    ║        ██║   ██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗      ║
    ║        ██║   ███████╗███████║   ██║   ███████╗██║  ██║      ║
    ║        ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝      ║
    ║                                                              ║
    ║            Network Attack Simulation Toolkit                 ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(f"{Colors.CYAN}{banner}{Colors.ENDC}")


def print_warning():
    warning = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                      ⚠️  WARNING ⚠️                            ║
    ╠══════════════════════════════════════════════════════════════╣
    ║                                                              ║
    ║  This toolkit is for EDUCATIONAL and AUTHORIZED TESTING     ║
    ║  purposes ONLY!                                              ║
    ║                                                              ║
    ║  • Only use on networks you OWN or have EXPLICIT written    ║
    ║    permission to test                                        ║
    ║  • Unauthorized use is ILLEGAL and may result in criminal   ║
    ║    prosecution                                               ║
    ║  • The authors assume NO responsibility for misuse          ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(f"{Colors.WARNING}{warning}{Colors.ENDC}")


def check_dependencies() -> Tuple[bool, List[str]]:
    """Check if required dependencies are installed"""
    missing = []
    
    try:
        import scapy
    except ImportError:
        missing.append("scapy")
    
    try:
        import requests
    except ImportError:
        missing.append("requests")
    
    return len(missing) == 0, missing


def run_attack_module(module: str, target: str, args: List[str] = None) -> bool:
    """Run a specific attack module"""
    args = args or []
    script_dir = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(script_dir, f"{module}.py")
    
    if not os.path.exists(script_path):
        print(f"{Colors.FAIL}[!] Module not found: {module}{Colors.ENDC}")
        return False
    
    cmd = [sys.executable, script_path, "--target", target] + args
    
    try:
        result = subprocess.run(cmd, capture_output=False, text=True)
        return result.returncode == 0
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error running {module}: {e}{Colors.ENDC}")
        return False


def run_comprehensive_test(target: str, port: int = 80, quick: bool = False) -> None:
    """Run comprehensive attack test suite"""
    
    print(f"\n{Colors.BOLD}{'='*60}{Colors.ENDC}")
    print(f"{Colors.HEADER}  Starting Comprehensive Security Test{Colors.ENDC}")
    print(f"  Target: {target}:{port}")
    print(f"  Mode: {'Quick' if quick else 'Full'}")
    print(f"{Colors.BOLD}{'='*60}{Colors.ENDC}\n")
    
    # Define test categories
    tests = [
        {
            "name": "Port Scanning Detection",
            "module": "port_scanner",
            "args": ["--type", "all" if not quick else "syn", "--ports", "1-50"],
            "expected_detections": ["PORT_SCAN", "STEALTH_SCAN", "XMAS_SCAN"]
        },
        {
            "name": "DoS Attack Detection",
            "module": "dos_attacks",
            "args": ["--type", "synflood", "--duration", "5" if quick else "15", "--port", str(port)],
            "expected_detections": ["SYN_FLOOD", "DDOS_ATTACK"]
        },
        {
            "name": "Spoofing Attack Detection",
            "module": "spoofing_attacks",
            "args": ["--type", "ip"],
            "expected_detections": ["IP_SPOOFING", "ARP_SPOOFING"]
        },
        {
            "name": "Application Layer Attacks",
            "module": "application_attacks",
            "args": ["--type", "all" if not quick else "sqli", "--port", str(port), "--count", "20" if quick else "50"],
            "expected_detections": ["SQL_INJECTION", "XSS_ATTACK", "BRUTE_FORCE"]
        },
        {
            "name": "Advanced Attack Patterns",
            "module": "advanced_attacks",
            "args": ["--type", "all" if not quick else "dns", "--count", "20" if quick else "50"],
            "expected_detections": ["DNS_TUNNELING", "COVERT_CHANNEL", "MALFORMED_PACKET"]
        }
    ]
    
    results = []
    
    for i, test in enumerate(tests, 1):
        print(f"\n{Colors.BLUE}{'─'*60}{Colors.ENDC}")
        print(f"{Colors.BOLD}[{i}/{len(tests)}] {test['name']}{Colors.ENDC}")
        print(f"{Colors.BLUE}{'─'*60}{Colors.ENDC}")
        print(f"Expected Detections: {', '.join(test['expected_detections'])}")
        
        success = run_attack_module(test["module"], target, test["args"])
        results.append((test["name"], success, test["expected_detections"]))
        
        if i < len(tests):
            print(f"\n{Colors.CYAN}[*] Waiting 3 seconds before next test...{Colors.ENDC}")
            time.sleep(3)
    
    # Print summary
    print(f"\n\n{Colors.BOLD}{'='*60}{Colors.ENDC}")
    print(f"{Colors.HEADER}  TEST SUMMARY{Colors.ENDC}")
    print(f"{Colors.BOLD}{'='*60}{Colors.ENDC}\n")
    
    for name, success, detections in results:
        status = f"{Colors.GREEN}✓ COMPLETED{Colors.ENDC}" if success else f"{Colors.FAIL}✗ FAILED{Colors.ENDC}"
        print(f"  {status} - {name}")
        print(f"           Expected: {', '.join(detections)}")
    
    print(f"\n{Colors.BOLD}{'='*60}{Colors.ENDC}")
    print(f"{Colors.CYAN}  Check PacketPeeper for detection alerts!{Colors.ENDC}")
    print(f"{Colors.BOLD}{'='*60}{Colors.ENDC}\n")


def interactive_menu(target: str, port: int) -> None:
    """Interactive menu for selecting attacks"""
    
    while True:
        print(f"\n{Colors.BOLD}{'='*50}{Colors.ENDC}")
        print(f"{Colors.HEADER}  Attack Selection Menu{Colors.ENDC}")
        print(f"{Colors.BOLD}{'='*50}{Colors.ENDC}")
        print(f"  Target: {target}:{port}")
        print(f"{Colors.BOLD}{'─'*50}{Colors.ENDC}")
        print("""
  [1] Port Scanning (SYN, FIN, XMAS, NULL, ACK)
  [2] DoS Attacks (SYN Flood, UDP Flood, Slowloris)
  [3] Spoofing Attacks (ARP, DNS, IP, MAC)
  [4] Application Attacks (SQLi, XSS, Command Injection)
  [5] Advanced Attacks (Covert Channel, DNS Tunneling)
  [6] Run ALL Tests (Comprehensive)
  [7] Quick Test (Subset of attacks)
  [0] Exit
        """)
        
        choice = input(f"{Colors.CYAN}  Select option: {Colors.ENDC}").strip()
        
        if choice == "0":
            print(f"\n{Colors.GREEN}[*] Exiting. Stay safe!{Colors.ENDC}\n")
            break
        elif choice == "1":
            scan_type = input("  Scan type (syn/fin/xmas/null/ack/udp/all) [syn]: ").strip() or "syn"
            run_attack_module("port_scanner", target, ["--type", scan_type])
        elif choice == "2":
            attack_type = input("  Attack type (synflood/udpflood/icmpflood/slowloris/all) [synflood]: ").strip() or "synflood"
            duration = input("  Duration in seconds [10]: ").strip() or "10"
            run_attack_module("dos_attacks", target, ["--type", attack_type, "--duration", duration, "--port", str(port)])
        elif choice == "3":
            spoof_type = input("  Spoof type (arp/dns/ip/mac/dhcp/all) [ip]: ").strip() or "ip"
            run_attack_module("spoofing_attacks", target, ["--type", spoof_type])
        elif choice == "4":
            attack_type = input("  Attack type (sqli/xss/cmd/lfi/brute/enum/all) [sqli]: ").strip() or "sqli"
            run_attack_module("application_attacks", target, ["--type", attack_type, "--port", str(port)])
        elif choice == "5":
            attack_type = input("  Attack type (covert/dns/beacon/exfil/hijack/malformed/all) [dns]: ").strip() or "dns"
            run_attack_module("advanced_attacks", target, ["--type", attack_type])
        elif choice == "6":
            run_comprehensive_test(target, port, quick=False)
        elif choice == "7":
            run_comprehensive_test(target, port, quick=True)
        else:
            print(f"{Colors.WARNING}[!] Invalid option{Colors.ENDC}")


def main():
    parser = argparse.ArgumentParser(
        description="Master Attack Runner - Comprehensive Security Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_all_attacks.py --target 192.168.1.1 --quick   (your router)
  python run_all_attacks.py --target 10.0.0.1 --full       (another device)
  
NOTE: Do NOT use 127.0.0.1! Loopback traffic won't be captured by PacketPeeper!
      Use your router IP (find with: ipconfig | findstr Gateway)
        """
    )
    parser.add_argument("--target", "-t", default=None, help="Target IP address (NOT 127.0.0.1! Use your router IP)")
    parser.add_argument("--port", "-p", type=int, default=80, help="Target port (for HTTP attacks)")
    parser.add_argument("--quick", "-q", action="store_true", help="Run quick test (shorter duration)")
    parser.add_argument("--full", "-f", action="store_true", help="Run full comprehensive test")
    parser.add_argument("--interactive", "-i", action="store_true", help="Interactive menu mode")
    parser.add_argument("--no-warning", action="store_true", help="Skip warning prompt")
    
    args = parser.parse_args()
    
    # Check if target is specified
    if args.target is None:
        print(f"\n{Colors.FAIL}" + "=" * 60)
        print("  ⚠️  ERROR: You must specify a target!")
        print("=" * 60 + f"{Colors.ENDC}")
        print(f"\n{Colors.WARNING}  DO NOT use 127.0.0.1 - loopback traffic won't be captured!{Colors.ENDC}")
        print(f"\n  Use your router IP or another device on your network:")
        print(f"    python run_all_attacks.py --target 192.168.1.1 --quick")
        print(f"\n  To find your router IP, run:")
        print(f"    ipconfig | findstr Gateway\n")
        sys.exit(1)
    
    if args.target == "127.0.0.1" or args.target == "localhost":
        print(f"\n{Colors.FAIL}" + "=" * 60)
        print("  ⚠️  WARNING: Using localhost/127.0.0.1!")
        print("=" * 60 + f"{Colors.ENDC}")
        print(f"\n{Colors.WARNING}  Loopback traffic doesn't go through your network interface,")
        print(f"  so PacketPeeper will NOT capture these packets!{Colors.ENDC}")
        print(f"\n  Use your router IP instead (check: ipconfig | findstr Gateway)")
        proceed = input(f"\n{Colors.WARNING}  Continue anyway? (y/N): {Colors.ENDC}")
        if proceed.lower() != 'y':
            sys.exit(0)
    
    print_banner()
    
    if not args.no_warning:
        print_warning()
        confirm = input(f"{Colors.WARNING}  Do you accept responsibility and have authorization? (yes/no): {Colors.ENDC}").strip().lower()
        if confirm != "yes":
            print(f"\n{Colors.FAIL}[!] You must accept responsibility to continue.{Colors.ENDC}\n")
            sys.exit(1)
    
    # Check dependencies
    deps_ok, missing = check_dependencies()
    if not deps_ok:
        print(f"\n{Colors.WARNING}[!] Missing dependencies: {', '.join(missing)}{Colors.ENDC}")
        print(f"[*] Install with: pip install {' '.join(missing)}")
        print(f"[*] Some attacks may not work without these dependencies.\n")
    
    if args.interactive:
        interactive_menu(args.target, args.port)
    elif args.full:
        run_comprehensive_test(args.target, args.port, quick=False)
    elif args.quick:
        run_comprehensive_test(args.target, args.port, quick=True)
    else:
        # Default to interactive
        interactive_menu(args.target, args.port)


if __name__ == "__main__":
    main()
