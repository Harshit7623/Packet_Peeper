#!/usr/bin/env python3
"""
Backend Verification Script for Packet Peeper
Checks all dependencies, configurations, and routing before startup
"""

import sys
import os
from pathlib import Path

def check_python_version():
    """Verify Python version >= 3.8"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("❌ Python 3.8+ required")
        return False
    print(f"✅ Python {version.major}.{version.minor}.{version.micro}")
    return True

def check_required_files():
    """Verify all required files exist"""
    required_files = [
        "app.py",
        "packet_sniffer.py",
        "network_security_monitor.py",
        "requirements.txt",
        "config/config.py",
        "services/database_services.py",
        "services/packet_processor.py",
        "services/report_generator.py",
    ]
    
    all_exist = True
    for file_path in required_files:
        full_path = Path(file_path)
        if full_path.exists():
            print(f"✅ {file_path}")
        else:
            print(f"❌ {file_path} NOT FOUND")
            all_exist = False

    # .env can live in backend/.env or project-root .env
    if Path(".env").exists() or Path("../.env").exists():
        print("✅ .env")
    else:
        print("❌ .env NOT FOUND")
        all_exist = False
    
    return all_exist

def check_dependencies():
    """Verify all required Python packages are installed"""
    required_packages = [
        'flask',
        'flask_socketio',
        'flask_cors',
        'scapy',
        'psutil',
        'sqlalchemy',
        'eventlet',
        'tldextract',
        'requests',
        'dotenv',
    ]
    
    all_installed = True
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
            print(f"✅ {package}")
        except ImportError:
            print(f"❌ {package} NOT INSTALLED")
            all_installed = False
    
    return all_installed

def check_config():
    """Verify configuration loads correctly"""
    try:
        from config.config import (
            FLASK_ENV, FLASK_DEBUG, SECRET_KEY, HOST, PORT,
            DATABASE_URL, LOG_LEVEL, FEATURES
        )
        print(f"✅ Config loaded")
        print(f"   - Environment: {FLASK_ENV}")
        print(f"   - Database: {DATABASE_URL.split('://')[0]}")
        print(f"   - Host: {HOST}:{PORT}")
        print(f"   - Log Level: {LOG_LEVEL}")
        print(f"   - Features: {FEATURES}")
        return True
    except Exception as e:
        print(f"❌ Config failed: {str(e)}")
        return False

def check_services():
    """Verify all service imports work"""
    try:
        from services.database_services import get_database_service
        print("✅ Database service")
    except Exception as e:
        print(f"❌ Database service: {str(e)}")
        return False
    
    try:
        from services.packet_processor import init_packet_processor
        print("✅ Packet processor")
    except Exception as e:
        print(f"❌ Packet processor: {str(e)}")
        return False
    
    try:
        from services.report_generator import get_report_generator
        print("✅ Report generator")
    except Exception as e:
        print(f"❌ Report generator: {str(e)}")
        return False
    
    return True

def check_directories():
    """Verify all required directories exist and are writable"""
    directories = [
        'logs',
        'data',
        'data/reports',
        'templates',
    ]
    
    all_ok = True
    for dir_path in directories:
        path = Path(dir_path)
        if path.exists():
            if os.access(path, os.W_OK):
                print(f"✅ {dir_path}")
            else:
                print(f"⚠️  {dir_path} (not writable)")
                all_ok = False
        else:
            try:
                path.mkdir(parents=True, exist_ok=True)
                print(f"✅ {dir_path} (created)")
            except Exception as e:
                print(f"❌ {dir_path}: {str(e)}")
                all_ok = False
    
    return all_ok

def check_routes():
    """Verify Flask app can initialize"""
    try:
        from app import app, socketio
        print("✅ Flask app initialized")
        print(f"✅ SocketIO configured")
        return True
    except Exception as e:
        print(f"❌ Flask app initialization failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all verification checks"""
    print("\n" + "="*50)
    print("🔍 PACKET PEEPER BACKEND VERIFICATION")
    print("="*50 + "\n")
    
    checks = [
        ("Python Version", check_python_version),
        ("Required Files", check_required_files),
        ("Dependencies", check_dependencies),
        ("Configuration", check_config),
        ("Directories", check_directories),
        ("Services", check_services),
        ("Flask Routes", check_routes),
    ]
    
    results = {}
    for check_name, check_func in checks:
        print(f"\n📋 {check_name}:")
        try:
            results[check_name] = check_func()
        except Exception as e:
            print(f"❌ Exception: {str(e)}")
            import traceback
            traceback.print_exc()
            results[check_name] = False
    
    print("\n" + "="*50)
    print("📊 VERIFICATION SUMMARY")
    print("="*50)
    
    all_passed = True
    for check_name, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status}: {check_name}")
        if not passed:
            all_passed = False
    
    print("="*50 + "\n")
    
    if all_passed:
        print("✅ ALL CHECKS PASSED - Backend is ready to launch!")
        print("\nTo start the backend, run:")
        print("  python app.py auto\n")
        return 0
    else:
        print("❌ SOME CHECKS FAILED - Please fix issues above\n")
        return 1

if __name__ == "__main__":
    sys.exit(main())
