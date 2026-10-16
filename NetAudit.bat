@echo off
REM NetAudit launcher for Windows. Double-click this file to start NetAudit.
setlocal
cd /d "%~dp0"
title NetAudit

echo NetAudit - starting up
echo ======================

REM 1. Python 3
where python >nul 2>nul
if errorlevel 1 (
  echo Python is not installed.
  echo Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH",
  echo then double-click this file again.
  goto :fail
)

REM 2. Nmap (the scanning engine). Add the default install folders to PATH for this window.
set "PATH=%PATH%;%ProgramFiles(x86)%\Nmap;%ProgramFiles%\Nmap"
where nmap >nul 2>nul
if errorlevel 1 goto :install_nmap
goto :nmap_ready

:install_nmap
where winget >nul 2>nul
if errorlevel 1 goto :nmap_manual
echo Nmap is not installed. Installing it with Windows Package Manager...
echo Approve any prompts that appear.
winget install -e --id Insecure.Nmap --accept-package-agreements --accept-source-agreements
set "PATH=%PATH%;%ProgramFiles(x86)%\Nmap;%ProgramFiles%\Nmap"
where nmap >nul 2>nul
if errorlevel 1 goto :nmap_manual
goto :nmap_ready

:nmap_manual
echo Nmap is not installed, and it could not be installed automatically.
echo Install it from https://nmap.org/download.html then double-click this file again.
goto :fail

:nmap_ready

REM 3. Python packages (first run, or after requirements.txt changes)
set "VENV=.venv"
set "STAMP=%VENV%\requirements_installed.txt"
if not exist "%VENV%\Scripts\python.exe" (
  echo Setting up the Python environment ^(first run only^)...
  python -m venv "%VENV%" || goto :fail
)
fc /b requirements.txt "%STAMP%" >nul 2>nul
if not errorlevel 1 goto :packages_ready
echo Installing required packages ^(first run only, may take a few minutes^)...
"%VENV%\Scripts\python.exe" -m pip install --quiet --upgrade pip
"%VENV%\Scripts\python.exe" -m pip install --quiet -r requirements.txt || goto :fail
copy /y requirements.txt "%STAMP%" >nul

:packages_ready

REM 4. Start NetAudit (run_webapp.py checks the setup, opens the browser and starts the server)
echo.
echo Starting NetAudit. Your browser will open shortly.
echo Close this window to stop NetAudit.
echo.
"%VENV%\Scripts\python.exe" run_webapp.py
goto :end

:fail
echo.
echo NetAudit could not start. Read the messages above, then double-click this file again.

:end
echo.
pause
