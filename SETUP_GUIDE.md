# PurpleForge Setup Guide for Windows 11

This guide walks through complete installation and verification on Windows 11.

## Prerequisites

1. **Python 3.11 or later**
   - Download from: https://www.python.org/downloads/
   - During installation, check "Add Python to PATH"
   - Verify: `python --version`

2. **Git** (optional, for version control)
   - Download from: https://git-scm.com/download/win
   - Or use GitHub Desktop

3. **Text Editor**
   - VS Code (recommended): https://code.visualstudio.com/
   - Or any text editor

## Installation Steps

### Step 1: Navigate to Project Directory

```powershell
# Open PowerShell
cd D:\PurpleForge
```

### Step 2: Create Virtual Environment

```powershell
# Create virtual environment
python -m venv .venv

# Activate virtual environment
.venv\Scripts\activate

# You should see (.venv) prefix in your prompt
```

### Step 3: Install Dependencies

```powershell
# Upgrade pip
python -m pip install --upgrade pip

# Install requirements
pip install -r requirements.txt

# Install PurpleForge in development mode
pip install -e .
```

### Step 4: Verify Installation

```powershell
# Check purpleforge command is available
purpleforge --help

# You should see the help menu with available commands
```

### Step 5: Initialize PurpleForge

```powershell
purpleforge init
```

This creates:
- `%USERPROFILE%\.purpleforge\config.yml` - Configuration file
- `%USERPROFILE%\.purpleforge\targets.yml` - Target allowlist
- `D:\PurpleForge\runs` - Workspace for run data
- `D:\PurpleForge\scenarios` - Directory for scenarios (sample already included)

## Quick Test

### Test 1: Validate Sample Scenario

```powershell
purpleforge validate scenarios\sample-web-assess.yml
```

Expected output: Validation success with scenario summary

### Test 2: Create a Simple Test Target

For testing, we'll create a simple Python HTTP server:

```powershell
# Create a test directory
mkdir test-target
cd test-target

# Create .well-known directory for verification
mkdir .well-known

# Start Python HTTP server in a new PowerShell window
# Open new terminal and run:
cd D:\PurpleForge\test-target
python -m http.server 3000
```

### Test 3: Verify Target

Back in your original PowerShell window:

```powershell
cd D:\PurpleForge

# Start verification process
purpleforge verify --base-url http://127.0.0.1:3000 --description "Local test server"
```

PurpleForge will display a verification token. Copy it.

In another PowerShell window:

```powershell
cd D:\PurpleForge\test-target

# Create verification file with the token
# Replace TOKEN_HERE with your actual token
Set-Content -Path ".well-known\purpleforge-verify.txt" -Value "TOKEN_HERE" -NoNewline
```

Back in the verification window, press Enter when ready.

### Test 4: Run Scenario

```powershell
purpleforge run scenarios\sample-web-assess.yml --target http://127.0.0.1:3000
```

This will:
1. Verify target is in allowlist
2. Execute all scenario steps
3. Collect telemetry
4. Generate reports

Expected: Run completes successfully with run ID displayed

### Test 5: View Report

```powershell
# List runs
purpleforge list-runs

# View report (replace RUN_ID with actual ID)
Get-Content runs\RUN_ID\reports\incident_report.md | more
```

## Troubleshooting

### Issue: "purpleforge: command not found"

**Solution:**
```powershell
# Ensure virtual environment is activated
.venv\Scripts\activate

# Reinstall in editable mode
pip install -e .
```

### Issue: "Python not found"

**Solution:**
- Install Python 3.11+ from python.org
- During installation, check "Add Python to PATH"
- Restart PowerShell after installation

### Issue: "Module not found"

**Solution:**
```powershell
# Reinstall dependencies
pip install -r requirements.txt
pip install -e .
```

### Issue: Verification timeout

**Solution:**
- Ensure test server is running: `python -m http.server 3000`
- Check firewall settings
- Verify `.well-known\purpleforge-verify.txt` exists
- Check file contains only the token (no extra spaces)

### Issue: Permission denied creating config

**Solution:**
```powershell
# Check path exists
$env:USERPROFILE

# Create directory manually if needed
New-Item -Path "$env:USERPROFILE\.purpleforge" -ItemType Directory -Force
```

## Configuration

### Default Configuration Location

`%USERPROFILE%\.purpleforge\config.yml`

Example:
```yaml
workspace_dir: D:\PurpleForge\runs
scenarios_dir: D:\PurpleForge\scenarios
log_level: INFO
default_timeout: 30
max_response_log_size: 200
```

### Customizing Configuration

Edit the config file directly or specify paths during init:

```powershell
purpleforge init --workspace D:\MyWorkspace --scenarios D:\MyScenarios
```

## Running Tests

### Install Development Dependencies

```powershell
pip install pytest pytest-mock
```

### Run Test Suite

```powershell
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests\test_scenarios.py

# Run with coverage
pip install pytest-cov
pytest --cov=purpleforge --cov-report=html
```

## Next Steps

1. **Create Custom Scenarios**
   - Copy `scenarios\sample-web-assess.yml`
   - Modify for your use case
   - Validate with `purpleforge validate`

2. **Setup Test Targets**
   - Deploy test web applications
   - Create verification files
   - Add to allowlist with `purpleforge verify`

3. **Generate Reports**
   - Run scenarios
   - Review generated reports
   - Share with team

4. **Install Pandoc (Optional)**
   - For PDF report generation
   - Download: https://pandoc.org/installing.html
   - Or use Chocolatey: `choco install pandoc`

## Support

For issues or questions:
1. Check this guide first
2. Review README.md
3. Check source code comments
4. Review test files for examples

## Uninstallation

```powershell
# Deactivate virtual environment
deactivate

# Remove virtual environment
Remove-Item -Recurse -Force .venv

# Remove configuration (optional)
Remove-Item -Recurse -Force "$env:USERPROFILE\.purpleforge"

# Remove runs (optional)
Remove-Item -Recurse -Force runs
```

---

**You're ready to use PurpleForge!**
