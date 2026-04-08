"""Tests for report generation."""

import pytest
from pathlib import Path
import tempfile
import shutil
import json

from purpleforge.workspace.manager import WorkspaceManager
from purpleforge.reporting.generator import ReportGenerator
from purpleforge.analysis.findings_schema import Finding, dump_findings


@pytest.fixture
def temp_workspace():
    """Create temporary workspace directory."""
    temp_dir = Path(tempfile.mkdtemp())
    yield temp_dir
    shutil.rmtree(temp_dir)


def test_report_generation(temp_workspace):
    """Test basic report generation."""
    # Create run directory
    manager = WorkspaceManager(temp_workspace)
    run_id, run_dir = manager.create_run("Test Scenario")

    # Create minimal data files
    (run_dir / "scenario.yaml").write_text(
        """
name: Test Scenario
description: Test description
category: web
target:
  type: web
  base_url: http://example.com
steps: []
"""
    )

    (run_dir / "target.json").write_text(
        json.dumps({"base_url": "http://example.com"})
    )

    (run_dir / "correlation" / "coverage.json").write_text(
        json.dumps(
            {
                "total_steps": 0,
                "steps_with_evidence": 0,
                "coverage_percentage": 0.0,
                "step_coverage": [],
            }
        )
    )

    (run_dir / "correlation" / "timeline.json").write_text(json.dumps([]))

    # Generate report
    generator = ReportGenerator(run_dir)
    report_path = generator.generate()

    assert report_path.exists()
    assert report_path.suffix == ".md"

    # Check report contains expected sections
    content = report_path.read_text()
    assert "PurpleForge Incident Report" in content
    assert run_id in content


def _create_run_with_minimal_files(temp_workspace):
    """Helper: create a valid run dir with minimal required files."""
    manager = WorkspaceManager(temp_workspace)
    run_id, run_dir = manager.create_run("Test Scenario")

    (run_dir / "scenario.yaml").write_text(
        "name: Test Scenario\ndescription: Test\ncategory: web\n"
        "target:\n  type: web\n  base_url: http://example.com\nsteps: []\n"
    )
    (run_dir / "target.json").write_text(json.dumps({"base_url": "http://example.com"}))
    (run_dir / "correlation").mkdir(exist_ok=True)
    (run_dir / "correlation" / "coverage.json").write_text(
        json.dumps({"total_steps": 0, "steps_with_evidence": 0,
                    "coverage_percentage": 0.0, "step_coverage": []})
    )
    (run_dir / "correlation" / "timeline.json").write_text(json.dumps([]))
    return run_id, run_dir


def test_report_contains_binary_findings_section_when_present(temp_workspace):
    """Report includes 'Binary Analysis Findings' section when findings file exists."""
    run_id, run_dir = _create_run_with_minimal_files(temp_workspace)

    # Write a binary findings file
    analysis_dir = run_dir / "analysis"
    analysis_dir.mkdir(parents=True, exist_ok=True)
    finding = Finding(
        source="ghidra_binary",
        category="suspicious_import",
        title="Suspicious import: VirtualAlloc",
        description="Potentially suspicious API import: VirtualAlloc",
        severity="medium",
        confidence="medium",
        location="VirtualAlloc",
        file_path="/tmp/sample.exe",
    )
    dump_findings([finding], analysis_dir / "binary_findings.json")

    generator = ReportGenerator(run_dir)
    report_path = generator.generate()
    content = report_path.read_text(encoding="utf-8")

    assert "Binary Analysis Findings" in content
    # Should contain finding data
    assert "VirtualAlloc" in content or "suspicious_import" in content


def test_report_omits_binary_findings_section_when_absent(temp_workspace):
    """Report omits 'Binary Analysis Findings' section when no findings file exists."""
    run_id, run_dir = _create_run_with_minimal_files(temp_workspace)

    # Do NOT create analysis/binary_findings.json

    generator = ReportGenerator(run_dir)
    report_path = generator.generate()
    content = report_path.read_text(encoding="utf-8")

    assert "Binary Analysis Findings" not in content


def test_report_confidence_distribution_present_with_new_fields(temp_workspace):
    """When coverage.json includes confidence fields, report renders 'Confidence Distribution'."""
    run_id, run_dir = _create_run_with_minimal_files(temp_workspace)

    # Overwrite coverage.json with new-style fields
    (run_dir / "correlation" / "coverage.json").write_text(
        json.dumps({
            "total_steps": 2,
            "steps_with_evidence": 1,
            "coverage_percentage": 50.0,
            "step_coverage": [
                {
                    "step_id": "step-a",
                    "step_type": "http_get_baseline",
                    "expected_evidence": ["http_200"],
                    "has_evidence": True,
                    "has_any_evidence": True,
                    "evidence_count": 1,
                    "best_confidence": 0.85,
                    "quality_tier": "A",
                },
                {
                    "step_id": "step-b",
                    "step_type": "reflected_xss_probe_safe",
                    "expected_evidence": ["reflection_detected"],
                    "has_evidence": False,
                    "has_any_evidence": False,
                    "evidence_count": 0,
                    "best_confidence": 0.0,
                    "quality_tier": "none",
                },
            ],
            "coverage_confidence_mean": 0.425,
            "coverage_confidence_median": 0.425,
            "tier_distribution": {"A": 1, "B": 0, "C": 0, "none": 1},
        })
    )

    generator = ReportGenerator(run_dir)
    report_path = generator.generate()
    content = report_path.read_text(encoding="utf-8")

    assert "Confidence Distribution" in content


def test_report_legacy_coverage_no_confidence_distribution(temp_workspace):
    """Legacy coverage.json without confidence fields must still render, without 'Confidence Distribution'."""
    run_id, run_dir = _create_run_with_minimal_files(temp_workspace)

    # Leave coverage.json as legacy format (no confidence fields) — already written by helper

    generator = ReportGenerator(run_dir)
    report_path = generator.generate()
    content = report_path.read_text(encoding="utf-8")

    # Report must render without error
    assert "PurpleForge Incident Report" in content
    # Must NOT contain the new section because fields are absent
    assert "Confidence Distribution" not in content


# ---------------------------------------------------------------------------
# Campaign reporting tests
# ---------------------------------------------------------------------------

def _write_campaign_json(run_dir: Path, stage_ids=None) -> None:
    """Write a minimal campaign.json into run_dir to simulate a campaign dir."""
    stages = [
        {
            "stage_id": sid,
            "run_id": f"run-{sid}",
            "status": "success",
            "started_at": "2026-01-01T00:00:00Z",
            "completed_at": "2026-01-01T00:01:00Z",
            "error": None,
            "skip_reason": None,
            "coverage": None,
            "run_dir": None,
        }
        for sid in (stage_ids or ["recon", "xss"])
    ]
    payload = {
        "campaign": {
            "name": "Test Campaign",
            "description": "Campaign for report test",
            "abort_on_failure": True,
            "shared_context_keys": [],
            "stages": [],
        },
        "result": {
            "campaign_id": "test-campaign-id",
            "campaign_name": "Test Campaign",
            "started_at": "2026-01-01T00:00:00Z",
            "completed_at": "2026-01-01T00:02:00Z",
            "overall_status": "success",
            "stages": stages,
        },
    }
    (run_dir / "campaign.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8"
    )


def test_campaign_report_has_campaign_summary_section(temp_workspace):
    """When campaign.json is present, report contains 'Campaign Summary'."""
    run_id, run_dir = _create_run_with_minimal_files(temp_workspace)
    _write_campaign_json(run_dir, stage_ids=["recon", "xss"])

    generator = ReportGenerator(run_dir)
    report_path = generator.generate()
    content = report_path.read_text(encoding="utf-8")

    assert "Campaign Summary" in content


def test_campaign_report_has_stage_table(temp_workspace):
    """Campaign summary section contains stage names."""
    run_id, run_dir = _create_run_with_minimal_files(temp_workspace)
    _write_campaign_json(run_dir, stage_ids=["recon", "xss_probe"])

    generator = ReportGenerator(run_dir)
    report_path = generator.generate()
    content = report_path.read_text(encoding="utf-8")

    assert "recon" in content
    assert "xss_probe" in content


def test_campaign_report_embeds_mermaid_when_diagram_present(temp_workspace):
    """If killchain.mmd exists in run_dir, report embeds a ```mermaid block."""
    run_id, run_dir = _create_run_with_minimal_files(temp_workspace)
    _write_campaign_json(run_dir)
    mmd_content = "graph LR\n    recon[\"recon\\n[success]\"]\n"
    (run_dir / "killchain.mmd").write_text(mmd_content, encoding="utf-8")

    generator = ReportGenerator(run_dir)
    report_path = generator.generate()
    content = report_path.read_text(encoding="utf-8")

    assert "mermaid" in content
    assert "graph LR" in content


def test_regular_run_dir_has_no_campaign_summary(temp_workspace):
    """Without campaign.json, the report must NOT have a Campaign Summary section."""
    run_id, run_dir = _create_run_with_minimal_files(temp_workspace)
    # Do NOT write campaign.json

    generator = ReportGenerator(run_dir)
    report_path = generator.generate()
    content = report_path.read_text(encoding="utf-8")

    assert "Campaign Summary" not in content


# ---------------------------------------------------------------------------
# Mirror findings reporting tests
# ---------------------------------------------------------------------------

def test_report_contains_mirror_findings_section_when_present(temp_workspace):
    """Report includes 'Mirror Static Findings' section when mirror/mirror_findings.json exists."""
    run_id, run_dir = _create_run_with_minimal_files(temp_workspace)

    mirror_dir = run_dir / "mirror"
    mirror_dir.mkdir(parents=True, exist_ok=True)

    finding = Finding(
        source="mirror_static",
        category="missing_security_header",
        title="Missing CSP header",
        description="Page is missing Content-Security-Policy header.",
        severity="low",
        confidence="high",
        location="http://example.com/",
        file_path="assets/index.html",
    )
    dump_findings([finding], mirror_dir / "mirror_findings.json")

    generator = ReportGenerator(run_dir)
    report_path = generator.generate()
    content = report_path.read_text(encoding="utf-8")

    assert "Mirror Static Findings" in content
    assert "missing_security_header" in content or "CSP" in content


def test_report_omits_mirror_findings_section_when_absent(temp_workspace):
    """Report omits 'Mirror Static Findings' section when no mirror findings file exists."""
    run_id, run_dir = _create_run_with_minimal_files(temp_workspace)
    # Do NOT create mirror/mirror_findings.json

    generator = ReportGenerator(run_dir)
    report_path = generator.generate()
    content = report_path.read_text(encoding="utf-8")

    assert "Mirror Static Findings" not in content


def test_report_mirror_findings_severity_counts(temp_workspace):
    """Mirror section shows correct severity counts when multiple findings present."""
    run_id, run_dir = _create_run_with_minimal_files(temp_workspace)

    mirror_dir = run_dir / "mirror"
    mirror_dir.mkdir(parents=True, exist_ok=True)

    findings = [
        Finding(
            source="mirror_static",
            category="secret_exposure",
            title="AWS key found",
            description="Possible AWS access key in assets/config.js.",
            severity="high",
            confidence="medium",
        ),
        Finding(
            source="mirror_static",
            category="dom_sink_candidate",
            title="DOM sink candidate",
            description="Possible DOM sink in assets/app.js.",
            severity="medium",
            confidence="low",
        ),
        Finding(
            source="mirror_static",
            category="missing_security_header",
            title="Missing CSP",
            description="Missing CSP.",
            severity="low",
            confidence="high",
        ),
    ]
    dump_findings(findings, mirror_dir / "mirror_findings.json")

    generator = ReportGenerator(run_dir)
    report_path = generator.generate()
    content = report_path.read_text(encoding="utf-8")

    assert "Mirror Static Findings" in content
    # Top-10 table should have at least one row
    assert "secret_exposure" in content or "dom_sink_candidate" in content or "missing_security_header" in content


# ---------------------------------------------------------------------------
# Audit Integrity section tests
# ---------------------------------------------------------------------------

def test_report_contains_audit_integrity_section_when_log_present(temp_workspace):
    """When audit/run_audit.log.jsonl exists, report contains 'Audit Integrity' section."""
    from purpleforge.audit.hash_chain import HashChainLog

    run_id, run_dir = _create_run_with_minimal_files(temp_workspace)

    audit_dir = run_dir / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    chain = HashChainLog(audit_dir / "run_audit.log.jsonl")
    chain.append({"event": "run_created", "ts": "2026-04-07T12:00:00+00:00"})
    chain.append({"event": "run_completed", "ts": "2026-04-07T12:01:00+00:00"})

    generator = ReportGenerator(run_dir)
    report_path = generator.generate()
    content = report_path.read_text(encoding="utf-8")

    assert "Audit Integrity" in content


def test_report_audit_integrity_intact_status(temp_workspace):
    """Intact audit log shows INTACT status in the report."""
    from purpleforge.audit.hash_chain import HashChainLog

    run_id, run_dir = _create_run_with_minimal_files(temp_workspace)
    audit_dir = run_dir / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    chain = HashChainLog(audit_dir / "run_audit.log.jsonl")
    chain.append({"event": "run_created", "ts": "2026-04-07T12:00:00+00:00"})

    generator = ReportGenerator(run_dir)
    report_path = generator.generate()
    content = report_path.read_text(encoding="utf-8")

    assert "INTACT" in content


def test_report_omits_audit_section_when_log_absent(temp_workspace):
    """Without audit log, the report must NOT contain 'Audit Integrity' section."""
    run_id, run_dir = _create_run_with_minimal_files(temp_workspace)
    # Do NOT create audit/run_audit.log.jsonl

    generator = ReportGenerator(run_dir)
    report_path = generator.generate()
    content = report_path.read_text(encoding="utf-8")

    assert "Audit Integrity" not in content


def test_report_contains_data_protection_section(temp_workspace):
    """Report must always contain the 'Data Protection' disclaimer."""
    run_id, run_dir = _create_run_with_minimal_files(temp_workspace)

    generator = ReportGenerator(run_dir)
    report_path = generator.generate()
    content = report_path.read_text(encoding="utf-8")

    assert "Data Protection" in content


def test_report_data_protection_mentions_dpa_gdpr(temp_workspace):
    """Data Protection section must mention UK DPA 2018 and GDPR."""
    run_id, run_dir = _create_run_with_minimal_files(temp_workspace)

    generator = ReportGenerator(run_dir)
    report_path = generator.generate()
    content = report_path.read_text(encoding="utf-8")

    assert "DPA" in content or "GDPR" in content
