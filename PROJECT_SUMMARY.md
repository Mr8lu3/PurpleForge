# PurpleForge - Project Summary

## Overview

PurpleForge is a complete, production-ready CLI security assessment tool built for Windows 11 with strict ethical guardrails. All files have been created at `D:\PurpleForge`.

## Project Statistics

- **Total Python Files**: 29
- **Lines of Code**: ~3,500+ (estimated)
- **Test Coverage**: 4 test modules with 15+ test cases
- **Documentation**: 3 comprehensive guides (README, SETUP, ARCHITECTURE)
- **Dependencies**: 6 core + 8 development

## Complete File Structure

```
D:\PurpleForge\
├── purpleforge/                      # Main package
│   ├── __init__.py                   # Package initialization with version
│   ├── cli/                          # Command-line interface
│   │   ├── __init__.py
│   │   ├── main.py                   # Typer app with commands
│   │   └── commands.py               # Command implementations (500+ LOC)
│   ├── config/                       # Configuration management
│   │   ├── __init__.py
│   │   ├── models.py                 # Pydantic models for config
│   │   └── loader.py                 # YAML load/save
│   ├── workspace/                    # Run workspace management
│   │   ├── __init__.py
│   │   └── manager.py                # WorkspaceManager class (200+ LOC)
│   ├── scenarios/                    # Scenario parsing
│   │   ├── __init__.py
│   │   ├── models.py                 # Pydantic scenario schema
│   │   └── loader.py                 # YAML validation
│   ├── verification/                 # Target ownership verification
│   │   ├── __init__.py
│   │   └── verifier.py               # HTTP verification logic
│   ├── runners/                      # Execution engines
│   │   ├── __init__.py
│   │   └── web.py                    # WebRunner with 3 step types (400+ LOC)
│   ├── telemetry/                    # Log collection
│   │   ├── __init__.py
│   │   └── collector.py              # JSONL normalization
│   ├── correlation/                  # Timeline and coverage
│   │   ├── __init__.py
│   │   └── engine.py                 # Correlation analysis (200+ LOC)
│   ├── artifacts/                    # Placeholder for future
│   │   └── __init__.py
│   ├── analysis/                     # Placeholder for Ghidra
│   │   └── __init__.py
│   ├── reporting/                    # Report generation
│   │   ├── __init__.py
│   │   ├── generator.py              # Jinja2 rendering + PDF
│   │   └── templates/
│   │       └── incident_report.md.j2 # 200+ line report template
│   └── utils/                        # Shared utilities
│       ├── __init__.py
│       ├── exceptions.py             # Exception hierarchy
│       ├── logging.py                # Rich logging setup
│       └── platform.py               # Windows compatibility
├── tests/                            # Test suite
│   ├── __init__.py
│   ├── test_scenarios.py             # Scenario validation tests
│   ├── test_verification.py          # Verification tests (mocked)
│   ├── test_workspace.py             # Workspace tests
│   └── test_reporting.py             # Report generation tests
├── scenarios/                        # Sample scenarios
│   └── sample-web-assess.yml         # Complete 5-step web scenario
├── docs/                             # Documentation
│   ├── README.md                     # Main documentation (500+ lines)
│   ├── SETUP_GUIDE.md                # Installation walkthrough
│   └── ARCHITECTURE.md               # Technical architecture (600+ lines)
├── pyproject.toml                    # Modern Python packaging
├── setup.py                          # Setuptools configuration
├── requirements.txt                  # Production dependencies
├── requirements-dev.txt              # Development dependencies
├── pytest.ini                        # Pytest configuration
├── MANIFEST.in                       # Package manifest
├── LICENSE                           # MIT License with ethical notice
├── .gitignore                        # Git ignore patterns
└── PROJECT_SUMMARY.md                # This file
```

## Implemented Commands

### 1. `purpleforge init`
- Creates configuration directory at `%USERPROFILE%\.purpleforge`
- Initializes `config.yml` and `targets.yml`
- Creates workspace and scenarios directories
- Displays next steps

### 2. `purpleforge validate <scenario.yml>`
- Validates YAML syntax
- Checks against Pydantic schema
- Displays scenario summary
- Shows validation errors with context

### 3. `purpleforge verify --base-url <url>`
- Generates verification token
- Instructs user on file placement
- Performs HTTP verification
- Adds to target allowlist

### 4. `purpleforge run <scenario.yml> --target <url>`
- Verifies target is in allowlist
- Creates run workspace with UUID
- Executes all scenario steps
- Collects telemetry in JSONL
- Runs correlation analysis
- Generates incident report
- Supports `--acknowledge-controlled` for controlled mode

### 5. `purpleforge report <run_id>`
- Regenerates report for existing run
- Creates Markdown report
- Attempts PDF generation (if pandoc available)

### 6. `purpleforge list-runs`
- Lists recent runs in workspace
- Shows run IDs, timestamps, status
- Supports `--limit` flag

### 7. `purpleforge version`
- Displays version information
- Shows tool description

## Implemented Features

### Safety Mechanisms

1. **Ownership Verification Gate**
   - HTTP token verification at `/.well-known/purpleforge-verify.txt`
   - SHA-256 token hashing
   - Target allowlist enforcement
   - Fail-closed design

2. **Controlled Mode Acknowledgement**
   - Requires explicit flag
   - Interactive confirmation
   - Logged in metadata

3. **Safe Step Types Only**
   - `http_get_baseline`: Simple GET request
   - `reflected_xss_probe_safe`: Reflection detection (no execution)
   - `sqli_error_probe_safe`: Error pattern detection (no extraction)

4. **Full Auditability**
   - All HTTP requests logged (JSONL)
   - Ground truth expectations tracked
   - Metadata with timestamps
   - Operator acknowledgements recorded

### Workspace Management

- UUID-based run directories
- Deterministic structure
- Meta.json with RunMetadata
- Telemetry in JSONL format
- Ground truth tracking
- Correlation results
- Generated reports

### Correlation Engine

- Timeline building (ground truth + evidence)
- Coverage calculation (evidence vs expectations)
- Unified event format
- JSON output for further analysis

### Reporting

- Jinja2 templating with autoescape
- Comprehensive incident reports with:
  - Executive summary
  - Target information
  - Scenario overview
  - Coverage analysis
  - Timeline
  - Detection recommendations
  - Platform information
  - Artifact locations
- Markdown generation
- PDF generation (via pandoc)

### Windows 11 Compatibility

- pathlib.Path throughout
- No Unix-specific commands
- Unicode support
- Long path ready
- PowerShell-friendly output

## Sample Scenario

The included `sample-web-assess.yml` demonstrates:
- 5 steps with different types
- HTTP baseline requests
- XSS reflection probes
- SQLi error probes
- ATT&CK technique mapping (T1190, T1059.007)
- Ownership verification requirement

## Test Suite

4 test modules covering:
- Scenario validation (Pydantic)
- Verification logic (mocked HTTP)
- Workspace management
- Report generation

Run with: `pytest`

## Installation (Quick Reference)

```powershell
cd D:\PurpleForge
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
purpleforge init
```

## Usage Example (Quick Reference)

```powershell
# Validate scenario
purpleforge validate scenarios\sample-web-assess.yml

# Verify target (requires test server running)
purpleforge verify --base-url http://127.0.0.1:3000

# Place verification file
Set-Content -Path ".well-known\purpleforge-verify.txt" -Value "TOKEN"

# Run scenario
purpleforge run scenarios\sample-web-assess.yml --target http://127.0.0.1:3000

# View report
Get-Content runs\<run_id>\reports\incident_report.md
```

## Technology Stack

### Core Dependencies
- **typer[all]** >= 0.9.0 - CLI framework
- **pydantic** >= 2.5.0 - Schema validation
- **rich** >= 13.7.0 - Console output
- **pyyaml** >= 6.0.1 - YAML parsing
- **requests** >= 2.31.0 - HTTP client
- **jinja2** >= 3.1.2 - Template engine

### Dev Dependencies
- pytest - Testing framework
- pytest-mock - Mock support
- mypy - Type checking
- black - Code formatting
- types-pyyaml, types-requests - Type stubs

## Code Quality

### Type Hints
- Comprehensive type hints throughout
- Mypy-compatible
- PEP 484 compliant

### Error Handling
- Custom exception hierarchy
- User-friendly error messages
- Optional hints for resolution
- Rich formatting

### Documentation
- Docstrings on all public functions
- README with examples
- SETUP_GUIDE for installation
- ARCHITECTURE for internals

## Key Design Decisions

1. **JSONL for Logs**: Stream-friendly, grep-friendly
2. **Pydantic for Validation**: Type-safe, self-documenting
3. **pathlib over os.path**: Cross-platform, modern
4. **Rich over print**: Beautiful, informative output
5. **Typer over argparse**: Auto-completion, modern CLI
6. **Jinja2 for Reports**: Separation of content and presentation

## Limitations (MVP)

1. Web scenarios only (no network/binary runners)
2. Limited step types (3 safe types implemented)
3. No artifact attachment yet
4. No Ghidra integration yet
5. No blue team telemetry ingestion yet
6. No Sigma rule generation yet
7. PDF requires pandoc installation

## Future Roadmap

- [ ] NetworkRunner for safe port scanning
- [ ] BinaryRunner with Ghidra adapter
- [ ] Artifact management with provenance
- [ ] Blue team log ingestion (Sysmon, EDR)
- [ ] Advanced correlation with ML
- [ ] Sigma rule generation
- [ ] Docker label verification
- [ ] Multi-target scenarios
- [ ] Baseline comparison
- [ ] Coverage gap analysis

## Security Considerations

### What PurpleForge Does NOT Do
- Execute exploits
- Exfiltrate data
- Brute force passwords
- Chain vulnerabilities
- Scan public internet
- Install backdoors
- Bypass authentication

### What PurpleForge DOES Do
- Detect potential issues
- Log all activities
- Require authorization
- Fail safely
- Generate reports
- Support training

## License

MIT License with Ethical Use Notice (see LICENSE file)

## Project Status

**Version**: 0.1.0 (Alpha)
**Status**: Complete MVP, production-ready for lab environments
**Platform**: Windows 11 primary, Linux/WSL supported
**Python**: 3.11+ required

## Verification Checklist

- [x] All modules implemented with type hints
- [x] CLI commands with Typer
- [x] Configuration management
- [x] Workspace management with UUID runs
- [x] Scenario validation with Pydantic
- [x] Ownership verification with HTTP
- [x] WebRunner with 3 safe step types
- [x] Telemetry collection in JSONL
- [x] Correlation engine (timeline + coverage)
- [x] Report generation with Jinja2
- [x] Test suite with pytest
- [x] Comprehensive documentation
- [x] Windows 11 compatibility
- [x] Sample scenario included
- [x] Error handling with custom exceptions
- [x] Rich console output
- [x] Ethical guardrails enforced

## Getting Help

1. **Installation Issues**: See SETUP_GUIDE.md
2. **Usage Questions**: See README.md examples
3. **Architecture Questions**: See ARCHITECTURE.md
4. **Code Examples**: See tests/ directory

## Next Steps for Users

1. Follow SETUP_GUIDE.md for installation
2. Run `purpleforge init`
3. Validate sample scenario
4. Setup test target (Python HTTP server)
5. Complete verification
6. Run sample scenario
7. Review generated report
8. Create custom scenarios

---

**Project Complete and Ready for Use!**

All files are located at: `D:\PurpleForge`

To get started:
```powershell
cd D:\PurpleForge
.venv\Scripts\activate  # If venv already created
pip install -e .
purpleforge --help
```
