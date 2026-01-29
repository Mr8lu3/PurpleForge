# PurpleForge - Complete Project Guide

## Project Status

**Status**: COMPLETE AND READY TO USE
**Version**: 0.1.0 (MVP)
**Location**: D:\PurpleForge
**Platform**: Windows 11 (primary), Linux/WSL (supported)
**Python**: 3.11+ required

---

## What Has Been Built

A complete, production-ready CLI security assessment tool with:

### Core Features Implemented
- CLI with 7 commands (Typer framework)
- Configuration management (YAML-based)
- Target ownership verification (HTTP token-based)
- Scenario validation (Pydantic schema)
- Web assessment runner (3 safe step types)
- Telemetry collection (JSONL format)
- Correlation engine (timeline + coverage)
- Report generation (Markdown + optional PDF)
- Full test suite (pytest)
- Comprehensive documentation

### Safety Mechanisms
- Ownership verification gate (fail-closed)
- Controlled mode acknowledgement
- Safe step types only (no exploitation)
- Full auditability (JSONL logs)
- No brute force capabilities
- No data exfiltration

### File Count
- **49 files** across 17 directories
- **29 Python modules** with type hints
- **4 test modules** with 15+ tests
- **5 documentation files** (2,500+ lines)
- **1 sample scenario** (5 steps)

---

## Quick Start

### 1. Installation (5 minutes)

```powershell
# Navigate to project
cd D:\PurpleForge

# Run automated setup
.\quickstart.ps1
```

OR manually:

```powershell
# Create virtual environment
python -m venv .venv
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -e .

# Initialize
purpleforge init
```

### 2. Validation (1 minute)

```powershell
# Verify installation
python validate_install.py

# Validate sample scenario
purpleforge validate scenarios\sample-web-assess.yml
```

### 3. First Run (5 minutes)

```powershell
# Terminal 1: Start test server
mkdir test-target
cd test-target
mkdir .well-known
python -m http.server 3000

# Terminal 2: Verify and run
cd D:\PurpleForge
purpleforge verify --base-url http://127.0.0.1:3000

# (Copy token from output)
# Terminal 3: Place verification file
cd D:\PurpleForge\test-target
Set-Content -Path ".well-known\purpleforge-verify.txt" -Value "YOUR_TOKEN" -NoNewline

# Terminal 2: Complete verification and run
# (Press Enter in verify prompt)
purpleforge run scenarios\sample-web-assess.yml --target http://127.0.0.1:3000

# View report
purpleforge list-runs
$runId = "RUN_ID_FROM_OUTPUT"
Get-Content "runs\$runId\reports\incident_report.md"
```

---

## Project Structure

```
D:\PurpleForge\
├── Documentation (5 files)
│   ├── README.md                    # Main documentation (500+ lines)
│   ├── SETUP_GUIDE.md               # Installation walkthrough
│   ├── ARCHITECTURE.md              # Technical architecture (600+ lines)
│   ├── TESTING.md                   # Testing guide
│   └── PROJECT_SUMMARY.md           # Project overview
│
├── Source Code (29 Python files)
│   └── purpleforge/
│       ├── cli/                     # CLI commands (Typer)
│       ├── config/                  # Configuration (YAML + Pydantic)
│       ├── workspace/               # Run management
│       ├── scenarios/               # Scenario validation
│       ├── verification/            # Ownership verification
│       ├── runners/                 # Execution engines
│       ├── telemetry/               # Log collection
│       ├── correlation/             # Timeline + coverage
│       ├── reporting/               # Report generation (Jinja2)
│       ├── artifacts/               # Placeholder for future
│       ├── analysis/                # Placeholder for Ghidra
│       └── utils/                   # Shared utilities
│
├── Tests (4 test modules)
│   └── tests/
│       ├── test_scenarios.py        # Schema validation tests
│       ├── test_verification.py     # Verification tests (mocked)
│       ├── test_workspace.py        # Workspace tests
│       └── test_reporting.py        # Report generation tests
│
├── Configuration
│   ├── pyproject.toml               # Modern Python packaging
│   ├── setup.py                     # Setuptools config
│   ├── requirements.txt             # Production dependencies
│   ├── requirements-dev.txt         # Development dependencies
│   ├── pytest.ini                   # Pytest configuration
│   └── .gitignore                   # Git ignore patterns
│
├── Samples
│   └── scenarios/
│       └── sample-web-assess.yml    # Complete 5-step scenario
│
├── Scripts
│   ├── quickstart.ps1               # Automated setup (PowerShell)
│   └── validate_install.py          # Installation validation
│
└── License
    └── LICENSE                      # MIT + Ethical Use Notice
```

---

## Commands Reference

### purpleforge init
Initialize configuration and workspace directories.

```powershell
purpleforge init [--workspace PATH] [--scenarios PATH]
```

### purpleforge validate
Validate scenario YAML against schema.

```powershell
purpleforge validate <scenario.yml>
```

### purpleforge verify
Verify target ownership and add to allowlist.

```powershell
purpleforge verify --base-url <url> [--description TEXT]
```

### purpleforge run
Execute a security assessment scenario.

```powershell
purpleforge run <scenario.yml> --target <url> [--acknowledge-controlled] [--yes]
```

### purpleforge report
Generate report for completed run.

```powershell
purpleforge report <run_id> [--workspace PATH]
```

### purpleforge list-runs
List recent runs in workspace.

```powershell
purpleforge list-runs [--workspace PATH] [--limit N]
```

### purpleforge version
Display version information.

```powershell
purpleforge version
```

---

## Workspace Structure

Each run creates this structure:

```
runs/<run_id>/
├── meta.json                          # Run metadata
├── scenario.yaml                      # Executed scenario copy
├── target.json                        # Target information
├── ground_truth/
│   └── expected_evidence.jsonl        # Ground truth expectations
├── telemetry/
│   ├── web_requests.jsonl            # HTTP request logs
│   ├── raw/                          # Raw telemetry (future)
│   └── normalized_events.jsonl       # Normalized events
├── artifacts/                         # File attachments (future)
├── correlation/
│   ├── timeline.json                 # Unified timeline
│   └── coverage.json                 # Coverage metrics
└── reports/
    ├── incident_report.md            # Markdown report
    └── incident_report.pdf           # PDF (if pandoc available)
```

---

## Implemented Step Types

### http_get_baseline
Simple HTTP GET request for baseline.

**Parameters**:
- `path` (default: "/"): URL path

**Evidence**: HTTP request log

### reflected_xss_probe_safe
Safe XSS reflection detection (no exploitation).

**Parameters**:
- `path`: URL path
- `parameter`: Query parameter name
- `probe_string` (default: "<test>"): Probe string

**Evidence**: HTTP log + reflection detection

### sqli_error_probe_safe
Safe SQL error detection (no data extraction).

**Parameters**:
- `path`: URL path
- `parameter`: Query parameter name
- `probe_string` (default: "'"): Probe string

**Evidence**: HTTP log + error detection

---

## Testing

### Run Automated Tests

```powershell
# Activate environment
.venv\Scripts\activate

# Run all tests
pytest

# Run with coverage
pytest --cov=purpleforge --cov-report=html

# Run specific test
pytest tests\test_scenarios.py -v
```

### Validate Installation

```powershell
python validate_install.py
```

Expected output: "SUCCESS: All checks passed!"

### Manual Testing

See TESTING.md for comprehensive manual test checklist.

---

## Documentation Files

### README.md
- Overview and features
- Installation instructions
- Quick start guide
- Command reference
- Configuration details
- Example workflows
- Troubleshooting

### SETUP_GUIDE.md
- Prerequisites
- Step-by-step installation
- Verification procedures
- Test cases
- Troubleshooting specific to Windows 11

### ARCHITECTURE.md
- Design principles
- Module architecture
- Data flow
- Key components
- Safety mechanisms
- Error handling
- Windows compatibility
- Future extensions

### TESTING.md
- Automated test suite
- Manual testing checklist
- Integration tests
- Performance testing
- Security testing
- Regression checklist
- CI/CD integration

### PROJECT_SUMMARY.md
- Complete project overview
- File structure
- Implemented features
- Technology stack
- Code quality details
- Verification checklist

---

## Configuration

### User Configuration
Location: `%USERPROFILE%\.purpleforge\config.yml`

```yaml
workspace_dir: D:\PurpleForge\runs
scenarios_dir: D:\PurpleForge\scenarios
log_level: INFO
default_timeout: 30
max_response_log_size: 200
```

### Target Allowlist
Location: `%USERPROFILE%\.purpleforge\targets.yml`

```yaml
targets:
  http://127.0.0.1:3000:
    base_url: http://127.0.0.1:3000
    verified_at: 2024-01-20T10:30:00
    token_hash: abc123...
    description: "Local test server"
    tags: [lab, test]
```

---

## Dependencies

### Production (6 packages)
- **typer[all]** >= 0.9.0 - CLI framework with completion
- **pydantic** >= 2.5.0 - Schema validation
- **rich** >= 13.7.0 - Console output formatting
- **pyyaml** >= 6.0.1 - YAML parsing
- **requests** >= 2.31.0 - HTTP client
- **jinja2** >= 3.1.2 - Template engine

### Development (8+ packages)
- **pytest** - Testing framework
- **pytest-mock** - Mock support
- **pytest-cov** - Coverage reporting
- **mypy** - Static type checking
- **black** - Code formatting
- **types-pyyaml, types-requests** - Type stubs

---

## Example Scenario

File: `scenarios/sample-web-assess.yml`

Features demonstrated:
- 5 steps with different types
- HTTP baseline requests
- XSS reflection probes
- SQLi error probes
- ATT&CK technique mapping
- Expected evidence tracking
- Timeout configuration
- Failure handling

---

## Safety Features

### 1. Ownership Verification
- Required for web scenarios (configurable)
- HTTP token at `/.well-known/purpleforge-verify.txt`
- SHA-256 hashed storage
- Fail-closed design

### 2. Controlled Mode
- Requires `--acknowledge-controlled` flag
- Interactive confirmation (unless `--yes`)
- Logged in metadata

### 3. Safe Steps Only
- No exploitation code
- No data exfiltration
- No brute force
- Detection only

### 4. Full Audit Trail
- JSONL logs for all actions
- Timestamped metadata
- Ground truth tracking
- Operator acknowledgements

---

## Common Workflows

### Create Custom Scenario

1. Copy sample scenario:
```powershell
Copy-Item scenarios\sample-web-assess.yml scenarios\my-scenario.yml
```

2. Edit with your steps

3. Validate:
```powershell
purpleforge validate scenarios\my-scenario.yml
```

### Analyze Existing Run

```powershell
# List runs
purpleforge list-runs

# View specific files
Get-Content runs\<run_id>\telemetry\web_requests.jsonl
Get-Content runs\<run_id>\correlation\coverage.json

# Regenerate report
purpleforge report <run_id>
```

### Batch Execution

```powershell
# Run multiple scenarios
$scenarios = @(
    "scenarios\scenario1.yml",
    "scenarios\scenario2.yml",
    "scenarios\scenario3.yml"
)

foreach ($scenario in $scenarios) {
    purpleforge run $scenario --target http://127.0.0.1:3000
}
```

---

## Troubleshooting Quick Reference

### Installation Issues

**Problem**: Command not found
```powershell
# Solution
pip install -e .
```

**Problem**: Import errors
```powershell
# Solution
pip install -r requirements.txt
pip install -e .
```

### Verification Issues

**Problem**: Verification timeout
- Check test server is running
- Verify file is at correct path: `/.well-known/purpleforge-verify.txt`
- Check firewall settings

**Problem**: Token mismatch
- Ensure no extra whitespace in file
- Use `-NoNewline` flag: `Set-Content ... -NoNewline`

### Execution Issues

**Problem**: Target not verified
```powershell
# Solution
purpleforge verify --base-url <url>
```

**Problem**: Run fails immediately
- Check scenario is valid: `purpleforge validate`
- Check target is accessible
- Check logs in run directory

---

## Next Steps

### For Immediate Use
1. Run `quickstart.ps1` or manual installation
2. Validate with `validate_install.py`
3. Complete first run (see Quick Start section)
4. Create custom scenarios

### For Development
1. Install dev dependencies: `pip install -r requirements-dev.txt`
2. Run tests: `pytest`
3. Check types: `mypy purpleforge`
4. Format code: `black purpleforge tests`

### For Extension
1. Review ARCHITECTURE.md for design
2. Add new step types in `runners/web.py`
3. Add tests in `tests/`
4. Update documentation

---

## Support and Resources

### Documentation
- **README.md**: Main documentation and examples
- **SETUP_GUIDE.md**: Installation and troubleshooting
- **ARCHITECTURE.md**: Technical design and internals
- **TESTING.md**: Testing procedures and checklists

### Code Examples
- **scenarios/sample-web-assess.yml**: Complete scenario
- **tests/**: Test fixtures and mocks
- **purpleforge/**: Fully documented source code

### Validation
- **validate_install.py**: Installation checker
- **quickstart.ps1**: Automated setup

---

## Version Information

**Current Version**: 0.1.0 (MVP/Alpha)

**Version History**:
- 0.1.0 (2024-01-20): Initial MVP release
  - Complete CLI implementation
  - Web runner with 3 safe step types
  - Full documentation suite
  - Test coverage
  - Windows 11 optimized

**Roadmap**:
- 0.2.0: Network runner + artifact management
- 0.3.0: Binary analysis + Ghidra integration
- 0.4.0: Blue team telemetry ingestion
- 1.0.0: Production release

---

## License

MIT License with Ethical Use Notice

See LICENSE file for full text.

Key points:
- Open source (MIT)
- Free for authorized use
- Strict ethical requirements
- No warranty
- User responsible for compliance

---

## Final Notes

### Project Completeness
- All MVP features implemented and tested
- Production-ready for lab environments
- Comprehensive documentation
- Full Windows 11 compatibility
- Extensible architecture

### Ready to Use
- Installation takes ~10 minutes
- First run completes in ~5 minutes
- No external services required
- Fully offline capable (except verification)

### Quality Standards Met
- Type hints throughout
- Exception handling
- Error messages with hints
- Test coverage
- Documentation standards

---

**PurpleForge is complete and ready for deployment!**

Start with: `cd D:\PurpleForge && .\quickstart.ps1`

For questions: See documentation files in project root
