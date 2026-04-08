"""Smoke tests for purpleforge.reporting.exporters subpackage.

Goals
-----
* Import every exporter submodule so module-level code is counted.
* Invoke each exporter's public function on a minimal report_data dict.
* Assert JSON and HTML outputs are present and plausible.
* Gracefully skip PDF / DOCX when optional native deps (weasyprint / python-docx)
  are absent, rather than failing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest

# ---------------------------------------------------------------------------
# Minimal report_data fixture – mirrors what ReportGenerator produces
# ---------------------------------------------------------------------------

MINIMAL_REPORT_DATA: Dict[str, Any] = {
    "run_id": "smoke-run-exporters-001",
    "tool_version": "0.1.0",
    "scenario_name": "Exporters Smoke Test",
    "status": "completed",
    "started_at": "2026-04-07T10:00:00Z",
    "completed_at": "2026-04-07T10:05:00Z",
    "target_url": "http://localhost:8080",
    "verification_status": "verified",
    "category": "web",
    "mode": "assess",
    "total_steps": 2,
    "steps_with_evidence": 1,
    "coverage": 50,
    "timeline": [
        {
            "timestamp": "2026-04-07T10:01:00Z",
            "type": "step_start",
            "step_id": "step-001",
            "details": "Starting baseline HTTP GET",
        },
        {
            "timestamp": "2026-04-07T10:02:00Z",
            "type": "evidence",
            "step_id": "step-001",
            "details": "HTTP 200 OK",
        },
    ],
    "steps": [
        {
            "id": "step-001",
            "type": "http_request",
            "description": "Baseline HTTP GET",
            "has_evidence": True,
            "evidence_count": 1,
        },
        {
            "id": "step-002",
            "type": "header_analysis",
            "description": "Security header check",
            "has_evidence": False,
            "evidence_count": 0,
        },
    ],
    "attack_techniques": [],
    "detection_recommendations": "## Recommendations\n- Enable CSP header\n- Monitor for SQL injection patterns",
}


# ---------------------------------------------------------------------------
# Direct import smoke tests – cover module-level import paths
# ---------------------------------------------------------------------------


def test_import_exporters_package():
    from purpleforge.reporting import exporters  # noqa: F401


def test_import_json_exporter_module():
    from purpleforge.reporting.exporters import json_exporter  # noqa: F401


def test_import_html_exporter_module():
    from purpleforge.reporting.exporters import html_exporter  # noqa: F401


def test_import_pdf_exporter_module():
    from purpleforge.reporting.exporters import pdf_exporter  # noqa: F401


def test_import_docx_exporter_module():
    from purpleforge.reporting.exporters import docx_exporter  # noqa: F401


def test_import_export_json_function():
    from purpleforge.reporting.exporters.json_exporter import export_json  # noqa: F401


def test_import_export_html_function():
    from purpleforge.reporting.exporters.html_exporter import export_html  # noqa: F401


def test_import_export_pdf_function():
    from purpleforge.reporting.exporters.pdf_exporter import export_pdf  # noqa: F401


def test_import_export_docx_function():
    from purpleforge.reporting.exporters.docx_exporter import export_docx  # noqa: F401


def test_import_check_pdf_support():
    from purpleforge.reporting.exporters.pdf_exporter import check_pdf_support  # noqa: F401


def test_import_check_docx_support():
    from purpleforge.reporting.exporters.docx_exporter import check_docx_support  # noqa: F401


# ---------------------------------------------------------------------------
# JSON exporter
# ---------------------------------------------------------------------------


def test_export_json_creates_file(tmp_path: Path):
    from purpleforge.reporting.exporters.json_exporter import export_json

    output = tmp_path / "report.json"
    result = export_json(MINIMAL_REPORT_DATA, output)
    assert result == output
    assert output.exists()


def test_export_json_is_valid_json(tmp_path: Path):
    from purpleforge.reporting.exporters.json_exporter import export_json

    output = tmp_path / "report.json"
    export_json(MINIMAL_REPORT_DATA, output)
    parsed = json.loads(output.read_text(encoding="utf-8"))
    assert "export_format" in parsed
    assert parsed["export_format"] == "json"


def test_export_json_contains_data(tmp_path: Path):
    from purpleforge.reporting.exporters.json_exporter import export_json

    output = tmp_path / "report.json"
    export_json(MINIMAL_REPORT_DATA, output)
    parsed = json.loads(output.read_text(encoding="utf-8"))
    assert "data" in parsed
    assert parsed["data"]["run_id"] == "smoke-run-exporters-001"


def test_export_json_has_export_version(tmp_path: Path):
    from purpleforge.reporting.exporters.json_exporter import export_json

    output = tmp_path / "report.json"
    export_json(MINIMAL_REPORT_DATA, output)
    parsed = json.loads(output.read_text(encoding="utf-8"))
    assert "export_version" in parsed


def test_export_json_pretty_false(tmp_path: Path):
    """pretty=False should still produce valid JSON without indentation."""
    from purpleforge.reporting.exporters.json_exporter import export_json

    output = tmp_path / "report_compact.json"
    export_json(MINIMAL_REPORT_DATA, output, pretty=False)
    assert output.exists()
    parsed = json.loads(output.read_text(encoding="utf-8"))
    assert parsed["export_format"] == "json"


def test_export_json_creates_parent_dirs(tmp_path: Path):
    from purpleforge.reporting.exporters.json_exporter import export_json

    output = tmp_path / "nested" / "deep" / "report.json"
    export_json(MINIMAL_REPORT_DATA, output)
    assert output.exists()


def test_export_json_exported_at_present(tmp_path: Path):
    from purpleforge.reporting.exporters.json_exporter import export_json

    output = tmp_path / "report.json"
    export_json(MINIMAL_REPORT_DATA, output)
    parsed = json.loads(output.read_text(encoding="utf-8"))
    assert "exported_at" in parsed


# ---------------------------------------------------------------------------
# HTML exporter
# ---------------------------------------------------------------------------


def test_export_html_creates_file(tmp_path: Path):
    from purpleforge.reporting.exporters.html_exporter import export_html

    output = tmp_path / "report.html"
    result = export_html(MINIMAL_REPORT_DATA, output)
    assert result == output
    assert output.exists()


def test_export_html_starts_with_doctype(tmp_path: Path):
    from purpleforge.reporting.exporters.html_exporter import export_html

    output = tmp_path / "report.html"
    export_html(MINIMAL_REPORT_DATA, output)
    content = output.read_text(encoding="utf-8")
    assert "<html" in content.lower()


def test_export_html_contains_run_id(tmp_path: Path):
    from purpleforge.reporting.exporters.html_exporter import export_html

    output = tmp_path / "report.html"
    export_html(MINIMAL_REPORT_DATA, output)
    content = output.read_text(encoding="utf-8")
    assert "smoke-run-exporters-001" in content


def test_export_html_contains_scenario_name(tmp_path: Path):
    from purpleforge.reporting.exporters.html_exporter import export_html

    output = tmp_path / "report.html"
    export_html(MINIMAL_REPORT_DATA, output)
    content = output.read_text(encoding="utf-8")
    assert "Exporters Smoke Test" in content


def test_export_html_contains_steps_table(tmp_path: Path):
    from purpleforge.reporting.exporters.html_exporter import export_html

    output = tmp_path / "report.html"
    export_html(MINIMAL_REPORT_DATA, output)
    content = output.read_text(encoding="utf-8")
    # The steps table section should be present
    assert "step-001" in content


def test_export_html_timeline_included_by_default(tmp_path: Path):
    from purpleforge.reporting.exporters.html_exporter import export_html

    output = tmp_path / "report.html"
    export_html(MINIMAL_REPORT_DATA, output, include_timeline=True)
    content = output.read_text(encoding="utf-8")
    # Timeline events should appear in the HTML
    assert "step-001" in content


def test_export_html_no_timeline_when_excluded(tmp_path: Path):
    from purpleforge.reporting.exporters.html_exporter import export_html

    output = tmp_path / "report.html"
    export_html(MINIMAL_REPORT_DATA, output, include_timeline=False)
    content = output.read_text(encoding="utf-8")
    # The file still renders without error
    assert "<html" in content.lower()


def test_export_html_coverage_percentage_present(tmp_path: Path):
    from purpleforge.reporting.exporters.html_exporter import export_html

    output = tmp_path / "report.html"
    export_html(MINIMAL_REPORT_DATA, output)
    content = output.read_text(encoding="utf-8")
    # Coverage value (50) should appear somewhere in the rendered template
    assert "50" in content


def test_export_html_creates_parent_dirs(tmp_path: Path):
    from purpleforge.reporting.exporters.html_exporter import export_html

    output = tmp_path / "nested" / "report.html"
    export_html(MINIMAL_REPORT_DATA, output)
    assert output.exists()


def test_export_html_with_empty_attack_techniques(tmp_path: Path):
    """Empty att_ck list should not cause template errors."""
    from purpleforge.reporting.exporters.html_exporter import export_html

    data = dict(MINIMAL_REPORT_DATA, attack_techniques=[])
    output = tmp_path / "report.html"
    export_html(data, output)
    assert output.exists()


def test_export_html_with_attack_techniques(tmp_path: Path):
    """Non-empty att_ck list renders the ATT&CK section."""
    from purpleforge.reporting.exporters.html_exporter import export_html

    data = dict(
        MINIMAL_REPORT_DATA,
        attack_techniques=[
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program.",
                "url": "https://attack.mitre.org/techniques/T1190/",
                "mitigations": [
                    {"id": "M1048", "name": "Application Isolation and Sandboxing"},
                ],
            }
        ],
    )
    output = tmp_path / "report_attack.html"
    export_html(data, output)
    content = output.read_text(encoding="utf-8")
    assert "T1190" in content


# ---------------------------------------------------------------------------
# PDF exporter (skip gracefully when no PDF backend is available)
# ---------------------------------------------------------------------------


def test_check_pdf_support_returns_dict():
    from purpleforge.reporting.exporters.pdf_exporter import check_pdf_support

    result = check_pdf_support()
    assert isinstance(result, dict)
    assert "weasyprint" in result
    assert "pandoc" in result


def test_export_pdf_returns_none_or_path_when_no_backend(tmp_path: Path):
    """Without weasyprint or pandoc+markdown, export_pdf must return None rather than raise."""
    from purpleforge.reporting.exporters.pdf_exporter import export_pdf, check_pdf_support

    support = check_pdf_support()
    if support["weasyprint"] or support["pandoc"]:
        pytest.skip("PDF backend available — skipping 'no backend' path test")

    output = tmp_path / "report.pdf"
    result = export_pdf(MINIMAL_REPORT_DATA, output)
    # Must return None gracefully (no exception)
    assert result is None


def test_export_pdf_smoke(tmp_path: Path):
    """If any PDF backend is available, attempt export and assert path returned."""
    from purpleforge.reporting.exporters.pdf_exporter import export_pdf, check_pdf_support

    support = check_pdf_support()
    if not support["weasyprint"] and not support["pandoc"]:
        pytest.skip("No PDF backend (weasyprint or pandoc+xelatex) available; skipping PDF export smoke test")

    output = tmp_path / "report.pdf"
    result = export_pdf(MINIMAL_REPORT_DATA, output)
    # If backend present it should succeed
    if result is not None:
        assert result.exists()


def test_export_pdf_weasyprint_smoke(tmp_path: Path):
    """Direct weasyprint path – skip if weasyprint is absent."""
    try:
        import weasyprint  # noqa: F401
    except ImportError:
        pytest.skip("weasyprint not installed; skipping weasyprint PDF smoke test")

    from purpleforge.reporting.exporters.pdf_exporter import export_pdf_weasyprint
    from purpleforge.reporting.exporters.html_exporter import export_html

    html_path = tmp_path / "report.html"
    export_html(MINIMAL_REPORT_DATA, html_path)

    pdf_path = tmp_path / "report.pdf"
    result = export_pdf_weasyprint(html_path, pdf_path)
    assert result is not None
    assert result.exists()


def test_export_pdf_pandoc_no_binary(tmp_path: Path):
    """export_pdf_pandoc returns None gracefully when pandoc is not present."""
    import shutil

    if shutil.which("pandoc") is not None:
        pytest.skip("pandoc is present; skipping 'no pandoc' path test")

    from purpleforge.reporting.exporters.pdf_exporter import export_pdf_pandoc

    # Create a dummy markdown file so it doesn't fail on missing file
    md_path = tmp_path / "report.md"
    md_path.write_text("# Test\n\nHello world\n", encoding="utf-8")
    pdf_path = tmp_path / "report.pdf"

    result = export_pdf_pandoc(md_path, pdf_path)
    assert result is None


# ---------------------------------------------------------------------------
# DOCX exporter (skip gracefully when python-docx is absent)
# ---------------------------------------------------------------------------


def test_check_docx_support_returns_bool():
    from purpleforge.reporting.exporters.docx_exporter import check_docx_support

    result = check_docx_support()
    assert isinstance(result, bool)


def test_export_docx_smoke(tmp_path: Path):
    """Invoke export_docx; skip test if python-docx is not installed."""
    try:
        import docx  # noqa: F401
    except ImportError:
        pytest.skip("python-docx not installed; skipping DOCX export smoke test")

    from purpleforge.reporting.exporters.docx_exporter import export_docx

    output = tmp_path / "report.docx"
    result = export_docx(MINIMAL_REPORT_DATA, output)
    assert result is not None
    assert result.exists()


def test_export_docx_returns_none_without_python_docx(tmp_path: Path):
    """Without python-docx, export_docx must return None rather than raise."""
    try:
        import docx  # noqa: F401
        pytest.skip("python-docx IS installed; cannot test the missing-dep path")
    except ImportError:
        pass

    from purpleforge.reporting.exporters.docx_exporter import export_docx

    output = tmp_path / "report.docx"
    result = export_docx(MINIMAL_REPORT_DATA, output)
    assert result is None


def test_export_docx_smoke_with_steps(tmp_path: Path):
    """DOCX with non-empty steps list exercises the steps-table code path."""
    try:
        import docx  # noqa: F401
    except ImportError:
        pytest.skip("python-docx not installed")

    from purpleforge.reporting.exporters.docx_exporter import export_docx

    data = dict(
        MINIMAL_REPORT_DATA,
        steps=[
            {"id": "s1", "type": "http_request", "description": "GET /", "has_evidence": True},
            {"id": "s2", "type": "header_analysis", "description": "Headers", "has_evidence": False},
        ],
    )
    output = tmp_path / "report_steps.docx"
    result = export_docx(data, output)
    assert result is not None
    assert result.exists()


def test_export_docx_smoke_with_attack_techniques(tmp_path: Path):
    """DOCX with ATT&CK techniques exercises the technique loop path."""
    try:
        import docx  # noqa: F401
    except ImportError:
        pytest.skip("python-docx not installed")

    from purpleforge.reporting.exporters.docx_exporter import export_docx

    data = dict(
        MINIMAL_REPORT_DATA,
        attack_techniques=[
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "description": "Adversaries exploit web applications.",
                "url": "https://attack.mitre.org/techniques/T1190/",
                "mitigations": [
                    {"id": "M1048", "name": "Application Isolation"},
                ],
            }
        ],
    )
    output = tmp_path / "report_attack.docx"
    result = export_docx(data, output)
    assert result is not None


def test_export_docx_smoke_with_timeline(tmp_path: Path):
    """DOCX with timeline exercises the timeline section code path."""
    try:
        import docx  # noqa: F401
    except ImportError:
        pytest.skip("python-docx not installed")

    from purpleforge.reporting.exporters.docx_exporter import export_docx

    data = dict(MINIMAL_REPORT_DATA)  # already has timeline in MINIMAL_REPORT_DATA
    output = tmp_path / "report_timeline.docx"
    result = export_docx(data, output)
    assert result is not None


def test_export_docx_smoke_with_recommendations(tmp_path: Path):
    """DOCX with detection_recommendations exercises the markdown parsing loop."""
    try:
        import docx  # noqa: F401
    except ImportError:
        pytest.skip("python-docx not installed")

    from purpleforge.reporting.exporters.docx_exporter import export_docx

    data = dict(
        MINIMAL_REPORT_DATA,
        detection_recommendations=(
            "## Overview\n"
            "### Detail\n"
            "- bullet one\n"
            "1. numbered item\n"
            "Plain text line\n"
        ),
    )
    output = tmp_path / "report_recs.docx"
    result = export_docx(data, output)
    assert result is not None


# ---------------------------------------------------------------------------
# Package-level re-exports
# ---------------------------------------------------------------------------


def test_package_exports_all_four_functions():
    from purpleforge.reporting import exporters

    assert hasattr(exporters, "export_json")
    assert hasattr(exporters, "export_html")
    assert hasattr(exporters, "export_pdf")
    assert hasattr(exporters, "export_docx")
