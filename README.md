# PurpleForge

A CLI-driven purple team training and evaluation platform with strict ethical guardrails, comprehensive auditability, and Windows 11 first-class support.

## Overview

PurpleForge is an academic security assessment tool designed for controlled lab environments. It enables security teams to:

- Execute safe, non-destructive security assessment scenarios
- Collect detailed telemetry and evidence
- Correlate red team activities with blue team observations
- Generate ATT&CK-aligned incident reports
- Build reproducible security training exercises

## Hard Guardrails

PurpleForge is built with safety as the primary concern:

- **Ownership Verification Required**: Web scenarios refuse to execute without explicit target verification
- **No Exploitation**: Only implements safe detection techniques (no weaponized exploits)
- **Assessment Mode Default**: Controlled mode requires explicit acknowledgement
- **Full Auditability**: All actions logged to disk with timestamps
- **No Brute Force**: No password attacks, credential stuffing, or DoS capabilities
- **Ethical Design**: Every feature designed to prevent misuse

## Technology Stack

- **Python 3.11+** with full type hints
- **Typer** for CLI with auto-completion
- **Pydantic v2** for schema validation
- **Rich** for beautiful console output
- **Jinja2** for report templating
- **JSONL** for streaming event logs

## Installation

### Windows 11 Quick Start

```powershell
# Clone the repository (use any drive/folder you like)
git clone https://github.com/Mr8lu3/PurpleForge.git
cd PurpleForge

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .

# Initialize PurpleForge
purpleforge init
```

### Linux/WSL

```bash
cd /mnt/d/PurpleForge

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
pip install -e .

purpleforge init
```

## Quick Start Guide

### 1. Initialize Configuration

```powershell
purpleforge init
```

This creates:
- Configuration at `%USERPROFILE%\.purpleforge\config.yml`
- Target allowlist at `%USERPROFILE%\.purpleforge\targets.yml`
- Local `./runs` directory for execution workspaces
- Local `./scenarios` directory for scenario files

### 2. Validate a Scenario

```powershell
purpleforge validate scenarios\sample-web-assess.yml
```

This validates:
- YAML syntax
- Schema compliance
- Step definitions
- Required fields

### 3. Verify Target Ownership

Before running web scenarios, you must verify ownership:

```powershell
purpleforge verify --base-url http://127.0.0.1:3000
```

PurpleForge will:
1. Generate a unique verification token
2. Instruct you where to place it: `{base_url}/.well-known/purpleforge-verify.txt`
3. Verify the token is accessible
4. Add the target to your allowlist

**Example verification file:**

Create `http://127.0.0.1:3000/.well-known/purpleforge-verify.txt` containing:
```
a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
```

### 4. Run a Scenario

```powershell
purpleforge run scenarios\sample-web-assess.yml --target http://127.0.0.1:3000
```

This will:
- Verify target is in allowlist
- Create a unique run workspace
- Execute all scenario steps
- Collect telemetry in JSONL format
- Perform correlation analysis
- Generate incident report

### 5. View Reports

```powershell
# List recent runs
purpleforge list-runs

# Generate report for specific run
purpleforge report <run_id>

# View the Markdown report
cat runs\<run_id>\reports\incident_report.md
```

## Workspace Structure

Each run creates a deterministic directory structure:

```
runs/<run_id>/
├── meta.json                          # Run metadata
├── scenario.yaml                      # Copy of executed scenario
├── target.json                        # Target information
├── ground_truth/
│   └── expected_evidence.jsonl        # Ground truth expectations
├── telemetry/
│   ├── web_requests.jsonl            # HTTP request logs
│   ├── raw/                          # Raw telemetry (future)
│   └── normalized_events.jsonl       # Normalized event stream
├── artifacts/                         # Collected files (future)
├── correlation/
│   ├── timeline.json                 # Unified timeline
│   └── coverage.json                 # Evidence coverage metrics
└── reports/
    ├── incident_report.md            # Generated Markdown report
    └── incident_report.pdf           # PDF report (if pandoc available)
```

## Scenario Schema

Scenarios are defined in YAML:

```yaml
name: "Scenario Name"
description: "Detailed description"
category: web  # web, network, binary, composite
mode: assess   # assess or controlled
ownership_verification: true

target:
  type: web
  base_url: "http://127.0.0.1:3000"

steps:
  - id: "step_001"
    type: "http_get_baseline"
    description: "Baseline HTTP request"
    parameters:
      path: "/"
    expected_evidence:
      - "http_request_log"
    timeout_seconds: 30
    continue_on_failure: false

att_ck_techniques:
  - "T1190"  # Exploit Public-Facing Application
```

## Supported Step Types (Assessment Mode)

### http_get_baseline

Performs a baseline HTTP GET request.

**Parameters:**
- `path` (default: "/"): URL path to request

**Evidence:** HTTP request log entry

### reflected_xss_probe_safe

Tests for reflected XSS without exploitation.

**Parameters:**
- `path`: URL path to test
- `parameter`: Query parameter name
- `probe_string` (default: "<test>"): Safe probe string

**Evidence:** HTTP request log, reflection detection

### sqli_error_probe_safe

Tests for SQL injection error messages without data extraction.

**Parameters:**
- `path`: URL path to test
- `parameter`: Query parameter name
- `probe_string` (default: "'"): Safe probe string

**Evidence:** HTTP request log, error pattern detection

## Configuration

Configuration is stored at `%USERPROFILE%\.purpleforge\config.yml`:

```yaml
workspace_dir: <path-to-your-clone>\runs
scenarios_dir: <path-to-your-clone>\scenarios
log_level: INFO
default_timeout: 30
max_response_log_size: 200
```

## Target Allowlist

Verified targets are stored at `%USERPROFILE%\.purpleforge\targets.yml`:

```yaml
targets:
  http://127.0.0.1:3000:
    base_url: http://127.0.0.1:3000
    verified_at: 2024-01-20T10:30:00
    token_hash: abc123...
    description: "Local test application"
    tags:
      - lab
      - test
```

## Development

### Running Tests

```powershell
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=purpleforge --cov-report=html

# Type checking
mypy purpleforge

# Code formatting
black purpleforge tests
```

### Project Structure

```
purpleforge/
├── cli/           # Typer commands and CLI interface
├── config/        # Configuration management
├── workspace/     # Run workspace management
├── scenarios/     # Scenario parsing and validation
├── verification/  # Target ownership verification
├── runners/       # Scenario execution (web, future: network, binary)
├── telemetry/     # Log collection and normalization
├── correlation/   # Timeline building and coverage analysis
├── artifacts/     # Artifact management (future)
├── analysis/      # Static analysis integration (future)
├── reporting/     # Report generation
└── utils/         # Shared utilities
```

## Windows 11 Compatibility

PurpleForge is designed for Windows 11 with:

- `pathlib.Path` for all file operations (handles forward/backslashes)
- No Unix-specific shell commands
- Unicode support in paths and content
- Long path support ready (via Python 3.11+)
- PowerShell-friendly output

## Example Workflow

```powershell
# Setup
purpleforge init

# Create a simple test web app (Python example)
# In another terminal:
# python -m http.server 3000

# Verify the target
purpleforge verify --base-url http://127.0.0.1:3000 --description "Local test server"

# Create verification file
New-Item -Path ".\\.well-known" -ItemType Directory -Force
Set-Content -Path ".\\.well-known\\purpleforge-verify.txt" -Value "<token_from_verify_command>"

# Complete verification
# Press Enter in the verify prompt

# Run scenario
purpleforge run scenarios\sample-web-assess.yml --target http://127.0.0.1:3000

# View results
purpleforge list-runs
$run_id = "<run_id_from_output>"
purpleforge report $run_id
Get-Content "runs\$run_id\reports\incident_report.md"
```

## Limitations and Future Work

### Current Limitations

- Web assessment only (no network/binary runners yet)
- Limited to safe detection techniques
- No artifact analysis or Ghidra integration
- No telemetry ingestion from external sources
- No comparison with baseline runs

### Roadmap

- [ ] Network runner for safe port scanning
- [ ] Binary analysis integration with Ghidra
- [ ] Artifact attachment and provenance tracking
- [ ] Blue team telemetry ingestion (Sysmon, EDR logs)
- [ ] Advanced correlation with ML anomaly detection
- [ ] Sigma rule generation from scenarios
- [ ] Docker target detection with label verification
- [ ] Multi-target scenario support

## Safety and Ethics

### What PurpleForge Does NOT Do

- Execute exploits or payloads
- Exfiltrate data
- Perform brute force attacks
- Bypass authentication
- Chain exploits
- Scan the public internet
- Crack passwords or encryption
- Install backdoors or webshells

### What PurpleForge DOES Do

- Detect potential vulnerabilities
- Log all activities
- Require explicit authorization
- Fail safely
- Generate educational reports
- Support defensive training

## Troubleshooting

### Verification Fails

**Problem:** Target verification returns 404 or timeout

**Solution:**
1. Ensure target is running and accessible
2. Check the verification file is at `/.well-known/purpleforge-verify.txt`
3. Verify file contains only the token (no extra whitespace)
4. Check firewall settings

### Import Errors

**Problem:** `ModuleNotFoundError` when running commands

**Solution:**
```powershell
# Reinstall in editable mode
pip install -e .
```

### PDF Generation Fails

**Problem:** PDF report not generated

**Solution:**
- Install pandoc: `choco install pandoc` (Windows)
- Or use Markdown report directly

### Permission Denied

**Problem:** Cannot create workspace or config directories

**Solution:**
- Check directory permissions
- Run terminal as administrator (if needed)
- Verify disk space available

## License

MIT License - See LICENSE file for details

## Contributing

This is an academic project. Contributions should maintain the ethical guardrails and safety-first design philosophy.

## Disclaimer

PurpleForge is designed exclusively for authorized security assessment in controlled lab environments. Users are responsible for ensuring they have explicit permission before running any scenarios. Unauthorized security testing is illegal.

## Support

For issues, questions, or feature requests, please review the documentation and source code comments.

---

**Built with safety, ethics, and education as the primary goals.**

---

## Reproducibility and CI

> PurpleForge is for authorized purple-team assessments, defensive evaluation, and educational use only.

![CI](https://github.com/purpleforge/purpleforge/actions/workflows/ci.yml/badge.svg)

PurpleForge ships a fully automated quality-gate pipeline and a Zenodo-ready
research artifact to support academic reproducibility requirements.

### CI Pipeline (GitHub Actions)

Every push and pull request to `main` triggers a matrix build on Python 3.11
and 3.12 that runs:

1. Lint — `ruff check` (non-blocking `--exit-zero` while codebase stabilises)
2. Security scan — `bandit -r purpleforge/ -ll` (medium+ severity fails build)
3. Dependency audit — `pip-audit --strict` (fail on any known CVE)
4. Test suite — 370 tests, deselecting one known-duplicate test
5. Coverage gate — `pytest --cov-fail-under=50` (measured baseline: 52%)
6. SBOM generation — CycloneDX JSON uploaded as a build artifact

See `.github/workflows/ci.yml` for the full workflow definition.

### Building the Research Artifact

```bash
make artifact
# Produces dist/purpleforge_artifact.zip containing:
#   purpleforge/  tests/  examples/  pyproject.toml  README.md
#   LICENSE  REPRODUCIBILITY.md  CITATION.cff
#   .github/workflows/ci.yml  requirements.lock
# Prints SHA-256 of the zip.
```

Other useful targets:

```bash
make test      # run the test suite
make lint      # ruff check
make security  # bandit + pip-audit
make sbom      # generate sbom.json
make all       # all of the above + artifact
```

For full reproduction instructions see [REPRODUCIBILITY.md](REPRODUCIBILITY.md).
For citation metadata see [CITATION.cff](CITATION.cff).
