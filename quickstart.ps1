# PurpleForge Quick Start Script for Windows 11
# This script automates the initial setup process

Write-Host "=== PurpleForge Quick Start ===" -ForegroundColor Cyan
Write-Host ""

# Check Python version
Write-Host "Checking Python version..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "Found: $pythonVersion" -ForegroundColor Green

    # Check if Python 3.11+
    if ($pythonVersion -match "Python 3\.(\d+)") {
        $minorVersion = [int]$matches[1]
        if ($minorVersion -lt 11) {
            Write-Host "ERROR: Python 3.11 or later required" -ForegroundColor Red
            Write-Host "Download from: https://www.python.org/downloads/" -ForegroundColor Yellow
            exit 1
        }
    }
} catch {
    Write-Host "ERROR: Python not found" -ForegroundColor Red
    Write-Host "Install Python 3.11+ from: https://www.python.org/downloads/" -ForegroundColor Yellow
    exit 1
}

# Check if virtual environment exists
Write-Host ""
Write-Host "Setting up virtual environment..." -ForegroundColor Yellow
if (Test-Path ".venv") {
    Write-Host "Virtual environment already exists" -ForegroundColor Green
} else {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv .venv
    Write-Host "Virtual environment created" -ForegroundColor Green
}

# Activate virtual environment
Write-Host ""
Write-Host "Activating virtual environment..." -ForegroundColor Yellow
& .\.venv\Scripts\Activate.ps1

# Upgrade pip
Write-Host ""
Write-Host "Upgrading pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip --quiet

# Install dependencies
Write-Host ""
Write-Host "Installing dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt --quiet
Write-Host "Dependencies installed" -ForegroundColor Green

# Install PurpleForge in development mode
Write-Host ""
Write-Host "Installing PurpleForge..." -ForegroundColor Yellow
pip install -e . --quiet
Write-Host "PurpleForge installed" -ForegroundColor Green

# Initialize PurpleForge
Write-Host ""
Write-Host "Initializing PurpleForge..." -ForegroundColor Yellow
purpleforge init

# Success message
Write-Host ""
Write-Host "=== Setup Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Validate sample scenario:" -ForegroundColor White
Write-Host "   purpleforge validate scenarios\sample-web-assess.yml" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Start a test server (in another terminal):" -ForegroundColor White
Write-Host "   python -m http.server 3000" -ForegroundColor Gray
Write-Host ""
Write-Host "3. Verify target:" -ForegroundColor White
Write-Host "   purpleforge verify --base-url http://127.0.0.1:3000" -ForegroundColor Gray
Write-Host ""
Write-Host "4. Run scenario:" -ForegroundColor White
Write-Host "   purpleforge run scenarios\sample-web-assess.yml --target http://127.0.0.1:3000" -ForegroundColor Gray
Write-Host ""
Write-Host "For detailed instructions, see SETUP_GUIDE.md" -ForegroundColor Yellow
Write-Host ""
