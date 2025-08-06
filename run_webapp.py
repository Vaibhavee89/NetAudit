#!/usr/bin/env python3
"""
NetAudit Web Application Launcher
A simple launcher script for the NetAudit network auditing tool.
"""

import sys
import os
import subprocess
import webbrowser
import time
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 7):
        print("❌ Error: Python 3.7 or higher is required.")
        print(f"   Current version: {sys.version}")
        return False
    print(f"✅ Python version: {sys.version.split()[0]}")
    return True

def check_nmap():
    """Check if Nmap is installed and accessible."""
    try:
        result = subprocess.run(['nmap', '--version'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            version_line = result.stdout.split('\n')[0]
            print(f"✅ Nmap found: {version_line}")
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    
    print("❌ Error: Nmap not found or not accessible.")
    print("   Please install Nmap and ensure it's in your system PATH.")
    print("   Download from: https://nmap.org/download.html")
    return False

def check_dependencies():
    """Check if required Python packages are installed."""
    required_packages = [
        'flask', 'python-nmap', 'psutil', 'dnspython', 
        'fpdf', 'pandas', 'networkx', 'pyvis', 'scapy'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"❌ Missing packages: {', '.join(missing_packages)}")
        print("   Please install with: pip install -r requirements_webapp.txt")
        return False
    
    print("✅ All required packages are installed")
    return True

def create_directories():
    """Create necessary directories."""
    directories = ['reports', 'static', 'templates']
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
    print("✅ Required directories created/verified")

def check_admin_privileges():
    """Check if running with administrative privileges."""
    try:
        if os.name == 'nt':  # Windows
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        else:  # Unix/Linux/macOS
            is_admin = os.geteuid() == 0
        
        if is_admin:
            print("✅ Running with administrative privileges")
        else:
            print("⚠️  Warning: Not running with administrative privileges")
            print("   Some features (packet capture, OS detection) may not work properly")
        
        return is_admin
    except Exception:
        print("⚠️  Warning: Could not determine privilege level")
        return False

def main():
    """Main launcher function."""
    print("🛡️  NetAudit - Network Auditing Web Application")
    print("=" * 50)
    
    # System checks
    print("\n🔍 System Checks:")
    
    if not check_python_version():
        sys.exit(1)
    
    if not check_nmap():
        print("\n⚠️  Nmap is required for network scanning functionality.")
        response = input("Continue anyway? (y/N): ").lower().strip()
        if response != 'y':
            sys.exit(1)
    
    if not check_dependencies():
        sys.exit(1)
    
    create_directories()
    check_admin_privileges()
    
    # Launch application
    print("\n🚀 Starting NetAudit Web Application...")
    print("   Access the application at: http://localhost:5000")
    print("   Press Ctrl+C to stop the application")
    print("\n" + "=" * 50)
    
    # Auto-open browser after a short delay
    def open_browser():
        time.sleep(2)
        try:
            webbrowser.open('http://localhost:5000')
        except Exception:
            pass
    
    import threading
    browser_thread = threading.Thread(target=open_browser, daemon=True)
    browser_thread.start()
    
    # Import and run the Flask app
    try:
        from webapp import app
        app.run(debug=False, host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        print("\n\n👋 NetAudit application stopped.")
    except ImportError:
        print("❌ Error: Could not import webapp.py")
        print("   Make sure you're running this script from the correct directory.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error starting application: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 