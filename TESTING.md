# PurpleForge Testing Guide

This document describes how to test PurpleForge end-to-end.

## Automated Test Suite

### Running Tests

```powershell
# Activate virtual environment
.venv\Scripts\activate

# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests\test_scenarios.py

# Run with coverage
pytest --cov=purpleforge --cov-report=html

# View coverage report
start htmlcov\index.html
```

### Test Structure

```
tests/
├── test_scenarios.py      # Scenario validation tests
├── test_verification.py   # Target verification tests (mocked)
├── test_workspace.py      # Workspace management tests
└── test_reporting.py      # Report generation tests
```

## Manual Testing Checklist

### 1. Installation Validation

```powershell
# Run validation script
python validate_install.py
```

Expected: All checks pass

### 2. Initialization

```powershell
# Initialize PurpleForge
purpleforge init
```

Expected:
- Configuration created at `%USERPROFILE%\.purpleforge\config.yml`
- Targets file created at `%USERPROFILE%\.purpleforge\targets.yml`
- `./runs` directory created
- `./scenarios` directory created
- Success message with next steps

Verify:
```powershell
Test-Path "$env:USERPROFILE\.purpleforge\config.yml"
Test-Path "$env:USERPROFILE\.purpleforge\targets.yml"
Test-Path ".\runs"
Test-Path ".\scenarios"
```

### 3. Scenario Validation

```powershell
# Validate sample scenario
purpleforge validate scenarios\sample-web-assess.yml
```

Expected:
- "Scenario is valid!" message
- Scenario summary table
- Steps table with 5 steps

### 4. Target Verification (Manual)

#### Setup Test Server

Terminal 1:
```powershell
# Create test directory
mkdir test-target
cd test-target
mkdir .well-known

# Start HTTP server
python -m http.server 3000
```

#### Run Verification

Terminal 2:
```powershell
cd D:\PurpleForge

# Start verification
purpleforge verify --base-url http://127.0.0.1:3000 --description "Test server"
```

Expected:
- Token displayed
- Instructions for file placement
- Prompt asking if file is placed

#### Place Verification File

Terminal 3:
```powershell
cd D:\PurpleForge\test-target

# Create verification file (replace TOKEN with actual token)
Set-Content -Path ".well-known\purpleforge-verify.txt" -Value "YOUR_TOKEN_HERE" -NoNewline
```

#### Complete Verification

Back in Terminal 2:
- Press Enter when ready

Expected:
- "Verification successful!" message
- "Target added to allowlist" message

Verify:
```powershell
Get-Content "$env:USERPROFILE\.purpleforge\targets.yml"
```

Should contain entry for `http://127.0.0.1:3000`

### 5. Scenario Execution

```powershell
# Run scenario
purpleforge run scenarios\sample-web-assess.yml --target http://127.0.0.1:3000
```

Expected:
- Verification check passes
- Run ID and directory displayed
- Progress spinner
- 5/5 steps successful (or most successful depending on test server)
- Coverage percentage displayed
- Report generated message
- Next steps displayed

Verify workspace created:
```powershell
# List runs
purpleforge list-runs

# Check run directory structure
$runId = "<run_id_from_output>"
Get-ChildItem "runs\$runId" -Recurse
```

Expected files:
- `meta.json`
- `scenario.yaml`
- `target.json`
- `ground_truth/expected_evidence.jsonl`
- `telemetry/web_requests.jsonl`
- `telemetry/normalized_events.jsonl`
- `correlation/timeline.json`
- `correlation/coverage.json`
- `reports/incident_report.md`

### 6. Report Generation

```powershell
# Generate report
$runId = "<run_id>"
purpleforge report $runId
```

Expected:
- Report generated message
- Markdown file created
- PDF attempt message (may fail if pandoc not installed)

Verify:
```powershell
# View report
Get-Content "runs\$runId\reports\incident_report.md"
```

Report should contain:
- Run ID
- Timestamp
- Scenario name and description
- Target information
- Coverage analysis
- Timeline
- Detection recommendations
- Platform information

### 7. List Runs

```powershell
purpleforge list-runs
```

Expected:
- Table with recent runs
- Run IDs (truncated)
- Started timestamps
- Status
- Tool version

### 8. Help Commands

```powershell
# Main help
purpleforge --help

# Command-specific help
purpleforge init --help
purpleforge validate --help
purpleforge verify --help
purpleforge run --help
purpleforge report --help
purpleforge list-runs --help
```

Expected: Well-formatted help text for each command

### 9. Version Command

```powershell
purpleforge version
```

Expected: Version panel with tool name and version

## Integration Test Scenarios

### Test Case 1: Invalid Scenario

Create `test-invalid.yml`:
```yaml
name: "Invalid Scenario"
description: "Missing required fields"
# Missing category, target, steps
```

Run:
```powershell
purpleforge validate test-invalid.yml
```

Expected: Validation error with specific field errors

### Test Case 2: Unverified Target

```powershell
# Try to run without verification
purpleforge run scenarios\sample-web-assess.yml --target http://unverified-target.example.com
```

Expected: Error message stating target not verified

### Test Case 3: Non-existent Scenario

```powershell
purpleforge validate nonexistent.yml
```

Expected: "Scenario file not found" error

### Test Case 4: Non-existent Run

```powershell
purpleforge report nonexistent-run-id
```

Expected: "Run directory not found" error

### Test Case 5: Controlled Mode

Create `test-controlled.yml`:
```yaml
name: "Controlled Test"
description: "Test controlled mode"
category: web
mode: controlled
ownership_verification: true
target:
  type: web
  base_url: "http://127.0.0.1:3000"
steps:
  - id: "test_001"
    type: "http_get_baseline"
    description: "Test step"
    parameters:
      path: "/"
    expected_evidence:
      - "http_request_log"
```

Run without acknowledgement:
```powershell
purpleforge run test-controlled.yml --target http://127.0.0.1:3000
```

Expected: Error requiring `--acknowledge-controlled` flag

Run with acknowledgement:
```powershell
purpleforge run test-controlled.yml --target http://127.0.0.1:3000 --acknowledge-controlled
```

Expected: Confirmation prompt (unless `--yes` flag used)

## Performance Testing

### Large Scenario

Create scenario with 20+ steps and measure:
- Validation time: < 1 second
- Execution time: depends on steps and timeouts
- Report generation: < 5 seconds

### Multiple Runs

Execute 10 scenarios back-to-back:
```powershell
for ($i=1; $i -le 10; $i++) {
    purpleforge run scenarios\sample-web-assess.yml --target http://127.0.0.1:3000
}
```

Verify:
- All runs complete successfully
- Each has unique run ID
- No workspace conflicts
- Memory usage stable

## Error Handling Tests

### Test Network Errors

Stop test server and try to run:
```powershell
# Stop http.server in Terminal 1

# Try to run
purpleforge run scenarios\sample-web-assess.yml --target http://127.0.0.1:3000
```

Expected: Connection errors logged, run marked as failed

### Test Timeout

Create scenario with very short timeout:
```yaml
steps:
  - id: "timeout_test"
    type: "http_get_baseline"
    description: "Timeout test"
    parameters:
      path: "/"
    timeout_seconds: 1  # Very short
```

Expected: Timeout errors handled gracefully

### Test Invalid Configuration

Edit `%USERPROFILE%\.purpleforge\config.yml` with invalid YAML:
```yaml
invalid yaml syntax [[[
```

Run any command:
```powershell
purpleforge list-runs
```

Expected: Clear error message about invalid config

## Windows-Specific Tests

### Long Paths

Create scenario in deeply nested directory:
```powershell
mkdir -p "a\b\c\d\e\f\g\h\i\j\k\l\m\n\o\p\scenarios"
Copy-Item scenarios\sample-web-assess.yml "a\b\c\d\e\f\g\h\i\j\k\l\m\n\o\p\scenarios\"
purpleforge validate "a\b\c\d\e\f\g\h\i\j\k\l\m\n\o\p\scenarios\sample-web-assess.yml"
```

Expected: Works without issues (Python 3.11+ supports long paths)

### Unicode Paths

Create directory with Unicode characters:
```powershell
mkdir "测试目录"
Copy-Item scenarios\sample-web-assess.yml "测试目录\"
purpleforge validate "测试目录\sample-web-assess.yml"
```

Expected: Works correctly with Unicode

### Spaces in Paths

Create directory with spaces:
```powershell
mkdir "My Test Directory"
Copy-Item scenarios\sample-web-assess.yml "My Test Directory\"
purpleforge validate "My Test Directory\sample-web-assess.yml"
```

Expected: Works correctly with spaces

## Security Tests

### Verify Allowlist Enforcement

1. Verify target A
2. Try to run scenario against target B (not verified)

Expected: Execution refused

### Verify Token Security

Check that tokens are:
- Cryptographically random (32 hex chars)
- Hashed before storage (SHA-256)
- Not logged in plaintext

Verify:
```powershell
Get-Content "$env:USERPROFILE\.purpleforge\targets.yml"
```

Should contain `token_hash`, not plain token

### Verify Fail-Closed Design

Simulate verification server errors:
1. Stop test server
2. Try to run scenario

Expected: Execution refused, not bypassed

## Regression Test Checklist

Run this checklist before each release:

- [ ] All pytest tests pass
- [ ] Installation validation passes
- [ ] `purpleforge init` creates all files
- [ ] Sample scenario validates successfully
- [ ] Target verification works end-to-end
- [ ] Scenario execution completes
- [ ] Telemetry files created correctly
- [ ] Correlation analysis produces results
- [ ] Report generation succeeds
- [ ] All CLI commands show help
- [ ] Version command works
- [ ] List runs shows runs
- [ ] Controlled mode requires acknowledgement
- [ ] Unverified targets are rejected
- [ ] Invalid scenarios show clear errors
- [ ] Non-existent files show clear errors
- [ ] Windows paths work (backslashes and forward slashes)
- [ ] Unicode paths work
- [ ] Spaces in paths work
- [ ] Long paths work
- [ ] Error messages are clear and helpful

## Continuous Integration

For CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
name: Test PurpleForge

on: [push, pull_request]

jobs:
  test:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: pip install -e .
      - run: pytest
      - run: python validate_install.py
```

## Reporting Issues

When reporting issues, include:

1. **Environment**:
   - OS version: `(Get-ComputerInfo).WindowsVersion`
   - Python version: `python --version`
   - PurpleForge version: `purpleforge version`

2. **Steps to Reproduce**:
   - Exact commands run
   - Input files used
   - Expected vs actual behavior

3. **Logs**:
   - Console output
   - Contents of `meta.json` if run-related
   - Relevant JSONL logs

4. **Configuration**:
   - Contents of config.yml (redact sensitive data)
   - Directory structure

## Test Data

Sample test data for manual testing available in:
- `scenarios/sample-web-assess.yml` - Complete web scenario
- `tests/` - Unit test fixtures and mocks

---

**Happy Testing!**

For questions about testing, see SETUP_GUIDE.md or README.md.
