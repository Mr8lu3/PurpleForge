# PurpleForge Reproducibility Checklist

ACM-style artifact reproducibility documentation for PurpleForge v0.1.0.
This document provides step-by-step instructions to reproduce all test results,
evaluation metrics, and assessment outputs reported in the accompanying coursework.

---

## 1. Software and Hardware Requirements

| Requirement        | Minimum                  | Tested with               |
|--------------------|--------------------------|---------------------------|
| Operating System   | Linux, macOS, Windows 11 | WSL2 (Ubuntu 22.04)       |
| Python             | 3.11                     | 3.11.x, 3.12.x            |
| RAM                | 512 MB                   | 8 GB                      |
| Disk               | 200 MB                   | 40 GB                     |
| Network            | None (offline tests)     | N/A                       |
| Make               | GNU make 4.x             | make 4.3 (WSL2)           |

No external services, databases, or Docker containers are required to reproduce
the test suite. The evaluation and campaign commands connect to `http://localhost`
and will produce partial output if no server is listening — this is expected and
documented in section 7.

---

## 2. Setup Steps

```bash
# Clone the repository (or unzip the artifact)
git clone https://github.com/purpleforge/purpleforge.git
cd purpleforge

# Create and activate a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate          # Linux / macOS / WSL
# .venv\Scripts\Activate.ps1       # PowerShell (Windows)

# Install the package with all development dependencies
pip install -e .[dev]

# Verify the CLI is available
purpleforge --help
```

Alternatively install quality-gate tools individually:

```bash
pip install ruff bandit pip-audit cyclonedx-bom
```

---

## 3. Reproducing the Test Suite

```bash
make test
# Equivalent:
python3 -m pytest tests/ \
    --deselect tests/test_scenarios.py::test_web_target_requires_base_url \
    -q
```

**Expected output:**
```
370 passed, 1 deselected, 223 warnings in ~10s
```

The deselected test (`test_web_target_requires_base_url`) covers a validation
path that is already exercised by `test_scenario_web_target_requires_base_url`
in the same file; the deselection prevents a duplicate-ID conflict introduced
during Phase 2 refactoring.

### Coverage gate

```bash
python3 -m pytest tests/ \
    --deselect tests/test_scenarios.py::test_web_target_requires_base_url \
    --cov=purpleforge --cov-report=term --cov-fail-under=50 -q
```

**Measured baseline (2026-04-08):** 52% total coverage across 4,957 statements.
CI gate is set at 50% to provide a 2-point buffer. Low-coverage modules are
stub implementations scheduled for Phase 10+: `purpleforge/detections/` (0%),
`purpleforge/reporting/exporters/` (0%), `purpleforge/runners/execute.py` (41%).

---

## 4. Reproducing the Evaluation Framework Results

The evaluation framework runs a labelled dataset of scenario/target pairs and
computes precision, recall, F1, and mean-time-to-detect metrics.

```bash
purpleforge evaluate examples/datasets/demo.yml --runs 3
```

**Expected behaviour:** PurpleForge loads the demo dataset (1 item, 1 detection
label), attempts to run the `http_get_baseline` step against `http://localhost`,
and prints a metrics table. If no server is listening at localhost the step
completes with a connection-error result; metrics still compute (precision=0.0
for that run). This is the documented offline behaviour.

To reproduce against a live server, start any HTTP server on port 80:

```bash
python3 -m http.server 80
purpleforge evaluate examples/datasets/demo.yml --runs 3
```

---

## 5. Reproducing a Sample Campaign

```bash
purpleforge campaign examples/campaigns/demo.yml
```

The demo campaign runs two stages (`stage_a_recon` → `stage_b_followup`), both
pointing at `http://localhost` with `continue_on_failure: true`. Each stage
creates a workspace run directory under `runs/`. The campaign respects the
dependency ordering enforced by topological sort.

```bash
# Inspect the generated run directories
ls runs/
```

---

## 6. Verifying Audit Integrity

Every workspace run writes a hash-chained JSONL audit log. To verify the chain
has not been tampered with:

```bash
# Substitute <run_id> with a real run directory name from runs/
purpleforge audit verify <run_id>
```

**Expected output:**
```
Audit chain verified: N events, all hashes consistent.
```

A broken chain (modified or deleted log entries) is reported with the index of
the first failing link.

---

## 7. Expected Output Snippets and Where to Find Them

| Output                  | Location                                      |
|-------------------------|-----------------------------------------------|
| Test results            | stdout (pytest -q)                            |
| Coverage report         | stdout (--cov-report=term)                    |
| Workspace metadata      | `runs/<run_id>/meta.json`                     |
| Telemetry events        | `runs/<run_id>/telemetry/events.jsonl`        |
| Correlation timeline    | `runs/<run_id>/correlation/timeline.json`     |
| Coverage metrics        | `runs/<run_id>/correlation/coverage.json`     |
| Markdown report         | `runs/<run_id>/reports/report.md`             |
| Audit log               | `runs/<run_id>/audit/audit.jsonl`             |
| SBOM                    | `sbom.json` (after `make sbom`)               |
| Artifact zip            | `dist/purpleforge_artifact.zip`               |

---

## 8. Artifact Hash

The SHA-256 of the canonical Zenodo artifact zip is printed by `make artifact`
and recorded here at build time.

```
SHA-256: <filled at build time by make artifact>
```

To recompute:

```bash
python3 -c "
import hashlib, pathlib
data = pathlib.Path('dist/purpleforge_artifact.zip').read_bytes()
print(hashlib.sha256(data).hexdigest())
"
```

---

## 9. Known Limitations and Deviations

1. **Ownership verification bypass for localhost.** The demo examples set
   `ownership_verification: false` because no well-known file can be placed
   at `http://localhost/.well-known/fypctl-verify.txt` in a generic lab
   environment. Production use must keep verification enabled.

2. **Detections module (0% test coverage).** `purpleforge/detections/` contains
   Sigma, YARA, Snort, Splunk, and Elastic rule-generation stubs introduced for
   future Phase 10 work. They are not exercised by the current suite.

3. **PDF export.** `purpleforge/reporting/exporters/pdf_exporter.py` requires
   `weasyprint`, which is an optional dependency not listed in `[dev]`. Install
   it separately if PDF output is needed.

4. **Binary analysis (Ghidra adapter).** `purpleforge/analysis/` provides an
   interface stub only. Ghidra must be installed separately; the adapter is
   not tested in CI.

5. **Windows native.** All paths use `pathlib.Path` for cross-platform
   compatibility. The Makefile requires WSL or Git Bash on Windows; the
   Python test suite runs natively on Windows via `python -m pytest`.

6. **`test_artifact_build.py` marks.** The artifact-build test is marked
   `@pytest.mark.slow` and is included in the default suite. It invokes
   `make artifact` via subprocess and will be skipped on Windows when `make`
   is not available.
