#!/bin/bash
# NetAudit launcher for macOS. Double-click this file to start NetAudit.
cd "$(dirname "$0")" || exit 1
# Double-clicked files get a minimal PATH; include the usual Homebrew locations.
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

finish() {
  echo ""
  read -r -p "Press Enter to close this window..." _
  exit "${1:-1}"
}

echo "NetAudit - starting up"
echo "======================"

# 1. Python 3
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is not installed."
  echo "Install it from https://www.python.org/downloads/ then double-click this file again."
  finish 1
fi

# 2. Nmap (the scanning engine)
if ! command -v nmap >/dev/null 2>&1; then
  if command -v brew >/dev/null 2>&1; then
    echo "Installing Nmap with Homebrew (this can take a few minutes)..."
    brew install nmap || { echo "Nmap installation failed."; finish 1; }
  else
    echo "Nmap is not installed, and Homebrew was not found to install it."
    echo "Install Nmap from https://nmap.org/download.html then double-click this file again."
    finish 1
  fi
fi

# 3. Python packages (first run, or after requirements.txt changes)
VENV=".venv"
STAMP="$VENV/requirements_installed.txt"
if [ ! -x "$VENV/bin/python" ]; then
  echo "Setting up the Python environment (first run only)..."
  python3 -m venv "$VENV" || finish 1
fi
if ! cmp -s requirements.txt "$STAMP" 2>/dev/null; then
  echo "Installing required packages (first run only, may take a few minutes)..."
  "$VENV/bin/python" -m pip install --quiet --upgrade pip
  "$VENV/bin/python" -m pip install --quiet -r requirements.txt || { echo "Package installation failed."; finish 1; }
  cp requirements.txt "$STAMP"
fi

# 4. Start NetAudit (run_webapp.py checks the setup, opens the browser and starts the server)
echo ""
echo "Starting NetAudit. Your browser will open shortly."
echo "Close this window to stop NetAudit."
echo ""
"$VENV/bin/python" run_webapp.py
finish $?
