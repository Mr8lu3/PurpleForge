# PurpleForge Architecture

This document describes the internal architecture and design decisions.

## Design Principles

1. **Safety First**: Every feature designed to prevent misuse
2. **Fail Closed**: Security checks fail safely
3. **Full Auditability**: Every action logged with timestamps
4. **Reproducibility**: Deterministic workspace structure
5. **Windows 11 Support**: First-class Windows compatibility

## Module Architecture

```
purpleforge/
├── cli/              # User-facing CLI commands
├── config/           # Configuration and persistence
├── workspace/        # Run lifecycle management
├── scenarios/        # Scenario definition and validation
├── verification/     # Target ownership verification
├── runners/          # Execution engines
├── telemetry/        # Event collection and normalization
├── correlation/      # Timeline and coverage analysis
├── artifacts/        # File attachment (future)
├── analysis/         # Static analysis (future)
├── reporting/        # Report generation
└── utils/            # Shared utilities
```

## Data Flow

```
User Input (CLI)
    ↓
Scenario Validation (Pydantic)
    ↓
Target Verification Gate (HTTP check)
    ↓
Workspace Creation (Directory + meta.json)
    ↓
Runner Execution (WebRunner, etc.)
    ↓
Telemetry Collection (JSONL logging)
    ↓
Correlation Engine (Timeline + Coverage)
    ↓
Report Generation (Jinja2 → Markdown → PDF)
```

## Key Components

### 1. CLI Layer (cli/)

**Purpose**: User interaction and command orchestration

**Components**:
- `main.py`: Typer app with command definitions
- `commands.py`: Command implementations

**Design**:
- Rich console output for user feedback
- Input validation before calling core modules
- Error handling with friendly messages

### 2. Configuration (config/)

**Purpose**: Persistent configuration and target allowlist

**Components**:
- `models.py`: Pydantic models for Config and TargetEntry
- `loader.py`: YAML serialization/deserialization

**Storage**:
- `%USERPROFILE%\.purpleforge\config.yml`
- `%USERPROFILE%\.purpleforge\targets.yml`

### 3. Workspace Management (workspace/)

**Purpose**: Run lifecycle and directory structure

**Components**:
- `manager.py`: WorkspaceManager class

**Workspace Structure**:
```
runs/<run_id>/
├── meta.json                 # RunMetadata (Pydantic)
├── scenario.yaml             # Frozen scenario copy
├── target.json               # Target info + verification
├── ground_truth/             # Expected evidence
├── telemetry/                # Collected logs (JSONL)
├── artifacts/                # File attachments
├── correlation/              # Analysis results
└── reports/                  # Generated reports
```

**Key Methods**:
- `create_run()`: Initialize new run directory
- `save_metadata()`: Persist run metadata
- `update_status()`: Update run status

### 4. Scenario System (scenarios/)

**Purpose**: Scenario definition, parsing, and validation

**Components**:
- `models.py`: Pydantic models (Scenario, ScenarioStep, Target)
- `loader.py`: YAML loading and validation

**Validation**:
- YAML syntax checking
- Schema validation via Pydantic
- Business rules (unique step IDs, required fields)

**Schema**:
```yaml
name: string
description: string
category: enum[web, network, binary, composite]
mode: enum[assess, controlled]
ownership_verification: bool
target: Target
steps: List[ScenarioStep]
att_ck_techniques: List[string]
```

### 5. Verification Gate (verification/)

**Purpose**: Enforce target ownership verification

**Components**:
- `verifier.py`: Token generation, HTTP verification

**Flow**:
1. Generate random 32-char hex token
2. User places at `{base_url}/.well-known/purpleforge-verify.txt`
3. HTTP GET with timeout
4. Token comparison
5. Store hash in allowlist

**Status**:
- VERIFIED: Token matched
- FAILED: Token mismatch or 404
- TIMEOUT: Request timed out
- ERROR: Network error

**Future**: Docker label inspection for local targets

### 6. Runners (runners/)

**Purpose**: Execute scenario steps

**Current Runners**:
- `WebRunner`: HTTP-based assessment

**WebRunner Design**:
- Context manager for log file handling
- Step handler dispatch pattern
- Telemetry logging per request
- Ground truth tracking

**Implemented Steps**:
- `http_get_baseline`: Simple GET request
- `reflected_xss_probe_safe`: Check for reflection (no execution)
- `sqli_error_probe_safe`: Check for SQL errors (no extraction)

**Future Runners**:
- NetworkRunner: Safe port scanning
- BinaryRunner: Static analysis orchestration

### 7. Telemetry (telemetry/)

**Purpose**: Log collection and normalization

**Components**:
- `collector.py`: TelemetryCollector class

**Log Formats**:
- `web_requests.jsonl`: Raw HTTP request logs
- `normalized_events.jsonl`: Common event format

**Event Schema**:
```json
{
  "timestamp": "ISO8601",
  "event_type": "http_request",
  "step_id": "step_001",
  "data": { ... }
}
```

### 8. Correlation Engine (correlation/)

**Purpose**: Timeline building and coverage analysis

**Components**:
- `engine.py`: CorrelationEngine class

**Outputs**:
- `timeline.json`: Unified event timeline
- `coverage.json`: Evidence coverage metrics

**Algorithm**:
1. Load ground truth expectations
2. Load normalized events
3. Merge into unified timeline (sorted by timestamp)
4. Calculate coverage: evidence present for each step?
5. Compute coverage percentage

### 9. Reporting (reporting/)

**Purpose**: Generate human-readable reports

**Components**:
- `generator.py`: ReportGenerator class
- `templates/incident_report.md.j2`: Jinja2 template

**Process**:
1. Load all run data (metadata, scenario, coverage, timeline)
2. Render Jinja2 template with context
3. Write Markdown report
4. Optionally convert to PDF via pandoc

**Report Sections**:
- Executive Summary
- Target Information
- Scenario Overview
- Coverage Analysis
- Timeline
- Detection Recommendations
- Platform Information
- Artifacts

### 10. Utilities (utils/)

**Purpose**: Shared functionality

**Components**:
- `exceptions.py`: Exception hierarchy
- `logging.py`: Rich logging setup
- `platform.py`: OS detection, path handling

## Safety Mechanisms

### 1. Ownership Verification Gate

**Requirement**: Web scenarios with `ownership_verification: true` MUST verify target ownership.

**Implementation**:
- Check allowlist before execution
- HTTP verification at `/.well-known/purpleforge-verify.txt`
- Fail closed: execution refuses if verification fails

**Bypass Prevention**:
- No command-line flag to skip
- No config option to disable
- Scenario must explicitly set `ownership_verification: false`

### 2. Controlled Mode Acknowledgement

**Requirement**: Scenarios with `mode: controlled` require explicit acknowledgement.

**Implementation**:
- Requires `--acknowledge-controlled` flag
- Interactive confirmation prompt (unless `--yes`)
- Logged in metadata with timestamp

### 3. Safe Step Types Only

**Restriction**: Runners only implement detection, not exploitation.

**Web Runner Examples**:
- GET/HEAD requests only (no POST with payloads)
- Reflection detection (no script execution)
- Error pattern detection (no data extraction)
- No credential enumeration
- No brute force

### 4. No Internet Scanning

**Restriction**: Local/lab targets only.

**Implementation**:
- Verification requirement forces explicit allowlisting
- No wildcard or CIDR range support
- No DNS enumeration or subdomain discovery

### 5. Full Auditability

**Requirement**: Every action logged with timestamps.

**Implementation**:
- meta.json with start/completion times
- JSONL logs for every HTTP request
- Ground truth expectations logged
- Operator acknowledgements recorded

## Error Handling

### Exception Hierarchy

```
PurpleForgeError (base)
├── VerificationError
├── ScenarioValidationError
├── WorkspaceError
├── ConfigurationError
├── RunnerError
└── ReportError
```

### Error Display

- Rich console formatting for errors
- User-friendly messages
- Optional hints for resolution
- Exit codes for scripting

## Windows 11 Compatibility

### Path Handling

- `pathlib.Path` throughout (handles forward/backslashes)
- Absolute paths in all operations
- Unicode support in paths

### Long Path Support

- Python 3.11+ has improved support
- No manual registry changes required
- Paths resolved with `.resolve()`

### Commands

- No Unix-specific commands (grep, find, etc.)
- Python stdlib for all file operations
- `shutil` for file manipulation

### Output

- Rich library handles Windows console
- PowerShell-friendly formatting
- No ANSI escape sequence issues

## Testing Strategy

### Unit Tests

- Pydantic model validation
- Verification logic (mocked HTTP)
- Workspace creation
- Report generation

### Integration Tests

- End-to-end scenario execution (requires test target)
- Correlation analysis
- Report generation with real data

### Test Fixtures

- Temporary workspace directories
- Mock HTTP responses
- Sample scenario YAML files

## Performance Considerations

### JSONL Logs

- Stream-friendly format
- No need to load entire log into memory
- Grep-friendly for analysis

### Correlation

- Single pass through events
- O(n) timeline building
- O(n) coverage calculation

### Reports

- Jinja2 template caching
- Markdown generation is fast
- PDF conversion optional (pandoc)

## Future Extensions

### 1. Network Runner

**Capabilities**:
- Safe port scanning (SYN, no full connect)
- Banner grabbing
- SSL/TLS certificate analysis
- No DOS or flooding

### 2. Binary Analysis

**Integration**:
- Ghidra adapter for static analysis
- Artifact attachment with provenance
- Hash tracking (SHA-256)
- No unpacking or decryption

### 3. Blue Team Telemetry

**Ingestion**:
- Sysmon logs (JSONL import)
- EDR telemetry
- SIEM exports
- Correlation with ground truth

### 4. Advanced Correlation

**Features**:
- ML anomaly detection
- Baseline comparison
- Coverage gap analysis
- Missing evidence alerts

### 5. Sigma Rule Generation

**Output**:
- Auto-generate Sigma rules from scenarios
- Map steps to detection rules
- Export in Sigma YAML format

## Security Considerations

### Threat Model

**In Scope**:
- Accidental misuse by legitimate users
- Confused deputy attacks (targeting wrong hosts)
- Log tampering (integrity checks)

**Out of Scope**:
- Malicious operator with root access
- Physical security of workstation
- Supply chain attacks on dependencies

### Secrets Management

**Current**:
- No secrets stored
- Verification tokens are one-time
- Token hashes in allowlist (SHA-256)

**Future**:
- API key management for integrations
- Encrypted credential storage
- Secrets redaction in logs

## Deployment

### Development Mode

```powershell
pip install -e .
```

Installs as editable package, changes reflected immediately.

### Production Mode

```powershell
pip install .
```

Installs as regular package.

### Distribution

```powershell
python -m build
pip install dist/purpleforge-0.1.0-py3-none-any.whl
```

## Versioning

**Scheme**: Semantic Versioning (MAJOR.MINOR.PATCH)

**Current**: 0.1.0 (alpha)

**Version stored**:
- `purpleforge/__init__.py`
- `pyproject.toml`
- Run metadata

## Logging

### Log Levels

- DEBUG: Detailed execution flow
- INFO: Normal operations (default)
- WARNING: Recoverable issues
- ERROR: Failures requiring attention
- CRITICAL: Unrecoverable errors

### Log Destinations

- Console: Rich handler with formatting
- File: Optional per-run log file

## Configuration Precedence

1. Command-line arguments (highest)
2. Configuration file
3. Default values (lowest)

Example:
```powershell
# Uses config file workspace
purpleforge run scenario.yml --target http://...

# Overrides with CLI argument
purpleforge report <run_id> --workspace D:\custom
```

---

**This architecture balances safety, usability, and extensibility.**
