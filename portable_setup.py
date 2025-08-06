#!/usr/bin/env python3
"""
NetAudit Portable Setup
Creates a portable version that can run from USB or any directory
"""

import os
import sys
import shutil
import subprocess
import zipfile
from pathlib import Path

def create_portable_package():
    """Create a portable NetAudit package."""
    print("🛡️  Creating NetAudit Portable Package")
    print("=" * 40)
    
    # Create portable directory
    portable_dir = Path("NetAudit-Portable")
    if portable_dir.exists():
        shutil.rmtree(portable_dir)
    portable_dir.mkdir()
    
    print("📁 Creating portable directory structure...")
    
    # Copy essential files
    files_to_copy = [
        'webapp.py',
        'run_webapp.py', 
        'requirements_webapp.txt',
        'README_webapp.md',
        'vuln_db.json'
    ]
    
    dirs_to_copy = [
        'templates',
        'lib'
    ]
    
    # Copy files
    for file in files_to_copy:
        if Path(file).exists():
            shutil.copy2(file, portable_dir / file)
            print(f"✅ Copied {file}")
    
    # Copy directories
    for directory in dirs_to_copy:
        if Path(directory).exists():
            shutil.copytree(directory, portable_dir / directory)
            print(f"✅ Copied {directory}/")
    
    # Create batch files for Windows
    create_windows_launcher(portable_dir)
    
    # Create shell scripts for Linux/Mac
    create_unix_launcher(portable_dir)
    
    # Create portable Python installer
    create_python_installer(portable_dir)
    
    # Create README for portable version
    create_portable_readme(portable_dir)
    
    print(f"\n✅ Portable package created in: {portable_dir.absolute()}")
    print("📦 Package contents:")
    for item in sorted(portable_dir.rglob("*")):
        if item.is_file():
            print(f"   {item.relative_to(portable_dir)}")

def create_windows_launcher(portable_dir):
    """Create Windows batch launcher."""
    batch_content = """@echo off
echo NetAudit - Network Auditing Tool
echo ================================

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Python is not installed or not in PATH
    echo Please install Python 3.7+ from python.org
    pause
    exit /b 1
)

REM Check if pip is available
pip --version >nul 2>&1
if errorlevel 1 (
    echo pip is not available
    pause
    exit /b 1
)

REM Install requirements if not already installed
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
)

echo Activating virtual environment...
call venv\\Scripts\\activate.bat

echo Installing/updating requirements...
pip install -r requirements_webapp.txt

echo Starting NetAudit...
python run_webapp.py

pause
"""
    
    with open(portable_dir / "start_netaudit.bat", "w") as f:
        f.write(batch_content)
    print("✅ Created Windows launcher (start_netaudit.bat)")

def create_unix_launcher(portable_dir):
    """Create Unix shell launcher."""
    shell_content = """#!/bin/bash
echo "NetAudit - Network Auditing Tool"
echo "================================"

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is not installed"
    echo "Please install Python 3.7+ using your package manager"
    exit 1
fi

# Check if pip is available
if ! command -v pip3 &> /dev/null; then
    echo "pip3 is not available"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

echo "Activating virtual environment..."
source venv/bin/activate

echo "Installing/updating requirements..."
pip install -r requirements_webapp.txt

echo "Starting NetAudit..."
python run_webapp.py
"""
    
    launcher_path = portable_dir / "start_netaudit.sh"
    with open(launcher_path, "w") as f:
        f.write(shell_content)
    
    # Make executable
    launcher_path.chmod(0o755)
    print("✅ Created Unix launcher (start_netaudit.sh)")

def create_python_installer(portable_dir):
    """Create Python requirements installer."""
    installer_content = """#!/usr/bin/env python3
import subprocess
import sys
import os

def install_requirements():
    print("Installing NetAudit requirements...")
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", 
            "-r", "requirements_webapp.txt"
        ])
        print("✅ Requirements installed successfully!")
        return True
    except subprocess.CalledProcessError:
        print("❌ Failed to install requirements")
        return False

def main():
    print("NetAudit Portable - Requirements Installer")
    print("=" * 40)
    
    if install_requirements():
        print("\\n🚀 Ready to run NetAudit!")
        print("Run: python run_webapp.py")
    else:
        print("\\n❌ Installation failed")
        print("Please install requirements manually:")
        print("pip install -r requirements_webapp.txt")

if __name__ == "__main__":
    main()
"""
    
    with open(portable_dir / "install_requirements.py", "w") as f:
        f.write(installer_content)
    print("✅ Created Python installer")

def create_portable_readme(portable_dir):
    """Create README for portable version."""
    readme_content = """# NetAudit Portable

This is a portable version of NetAudit that can run from any directory or USB drive.

## Quick Start

### Windows:
1. Double-click `start_netaudit.bat`
2. Wait for setup to complete
3. Browser will open automatically

### Linux/Mac:
1. Open terminal in this directory
2. Run: `./start_netaudit.sh`
3. Open browser to http://localhost:5000

### Manual Setup:
1. Install Python 3.7+ if not already installed
2. Run: `python install_requirements.py`
3. Run: `python run_webapp.py`

## Requirements

- Python 3.7 or higher
- Internet connection (for initial setup)
- Administrative privileges (for some scanning features)
- Nmap installed (download from nmap.org)

## Features

All features from the full NetAudit application:
- Network scanning and discovery
- Port and service enumeration
- Vulnerability assessment
- Traffic analysis
- DNS auditing
- Report generation

## Legal Notice

Only use this tool on networks you own or have permission to audit.
Unauthorized network scanning may be illegal in your jurisdiction.

## Support

For issues or questions, refer to README_webapp.md for full documentation.
"""
    
    with open(portable_dir / "README_PORTABLE.md", "w") as f:
        f.write(readme_content)
    print("✅ Created portable README")

def create_zip_package():
    """Create a ZIP package of the portable version."""
    portable_dir = Path("NetAudit-Portable")
    if not portable_dir.exists():
        print("❌ Portable directory not found. Run create_portable_package() first.")
        return
    
    zip_name = "NetAudit-Portable.zip"
    print(f"📦 Creating ZIP package: {zip_name}")
    
    with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for file_path in portable_dir.rglob("*"):
            if file_path.is_file():
                arcname = file_path.relative_to(portable_dir.parent)
                zipf.write(file_path, arcname)
    
    print(f"✅ ZIP package created: {Path(zip_name).absolute()}")
    print(f"📏 Package size: {Path(zip_name).stat().st_size / 1024 / 1024:.2f} MB")

if __name__ == "__main__":
    create_portable_package()
    
    # Ask if user wants to create ZIP
    response = input("\n📦 Create ZIP package? (y/N): ").lower().strip()
    if response == 'y':
        create_zip_package()
    
    print("\n🎉 Portable package creation complete!")
    print("📋 Next steps:")
    print("   1. Copy NetAudit-Portable folder to target device")
    print("   2. Run the appropriate launcher script")
    print("   3. Ensure Nmap is installed on target system") 