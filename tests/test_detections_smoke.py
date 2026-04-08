"""Smoke tests for purpleforge.detections subpackage.

Goals
-----
* Import every submodule so module-level code is counted.
* Invoke the happy path of each generator with a minimal scenario fixture.
* Assert text-rule formats (sigma, splunk, elastic) produce non-empty output.
* Wrap yara / snort calls so unexpected errors still give a clear failure.
"""

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

# ---------------------------------------------------------------------------
# Direct import smoke tests – cover module-level code
# ---------------------------------------------------------------------------


def test_import_detection_generator():
    from purpleforge.detections.generator import DetectionGenerator  # noqa: F401


def test_import_sigma_generator():
    from purpleforge.detections.sigma import SigmaGenerator  # noqa: F401


def test_import_splunk_generator():
    from purpleforge.detections.splunk import SplunkGenerator  # noqa: F401


def test_import_elastic_generator():
    from purpleforge.detections.elastic import ElasticGenerator  # noqa: F401


def test_import_yara_generator():
    from purpleforge.detections.yara import YaraGenerator  # noqa: F401


def test_import_snort_generator():
    from purpleforge.detections.snort import SnortGenerator  # noqa: F401


def test_import_detections_package():
    from purpleforge.detections import DetectionGenerator  # noqa: F401


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

MINIMAL_SCENARIO: Dict[str, Any] = {
    "name": "Smoke Test Scenario",
    "description": "Minimal scenario for smoke testing",
    "category": "web",
    "mode": "assess",
    "target": {
        "type": "web",
        "base_url": "http://localhost:8080",
    },
    "steps": [
        {
            "id": "step-http-baseline",
            "type": "http_request",
            "description": "Baseline HTTP GET",
            "parameters": {"method": "GET", "path": "/"},
            "expected_evidence": ["http_200"],
            "timeout_seconds": 30,
        },
        {
            "id": "step-sql-probe",
            "type": "sql_probe",
            "description": "Safe SQL injection probe",
            "parameters": {"path": "/login"},
            "expected_evidence": ["sqli_error_pattern"],
            "timeout_seconds": 30,
        },
        {
            "id": "step-xss-probe",
            "type": "xss_probe",
            "description": "Safe XSS probe",
            "parameters": {"path": "/search"},
            "expected_evidence": ["xss_reflection"],
            "timeout_seconds": 30,
        },
        {
            "id": "step-header-analysis",
            "type": "header_analysis",
            "description": "Analyse security headers",
            "parameters": {},
            "expected_evidence": [],
            "timeout_seconds": 30,
        },
    ],
    "att_ck_techniques": ["T1190", "T1059.001"],
}

EMPTY_TELEMETRY: List[Dict[str, Any]] = []
EMPTY_CORRELATION: Dict[str, Any] = {}


@pytest.fixture()
def run_dir(tmp_path: Path) -> Path:
    """Create a minimal run directory that DetectionGenerator expects."""
    run = tmp_path / "runs" / "smoke-run-001"
    run.mkdir(parents=True)

    # scenario.yaml
    (run / "scenario.yaml").write_text(
        yaml.dump(MINIMAL_SCENARIO), encoding="utf-8"
    )

    # telemetry/raw directory (empty is fine – no JSONL events)
    (run / "telemetry" / "raw").mkdir(parents=True)

    # correlation files (optional, but present so _load_correlation is exercised)
    corr = run / "correlation"
    corr.mkdir()
    (corr / "timeline.json").write_text(json.dumps([]), encoding="utf-8")
    (corr / "coverage.json").write_text(
        json.dumps({"total_steps": 1, "steps_with_evidence": 0, "coverage_percentage": 0.0}),
        encoding="utf-8",
    )

    return run


# ---------------------------------------------------------------------------
# Individual generator unit smoke tests
# ---------------------------------------------------------------------------


def test_sigma_generator_produces_output():
    from purpleforge.detections.sigma import SigmaGenerator

    gen = SigmaGenerator()
    result = gen.generate(MINIMAL_SCENARIO, EMPTY_TELEMETRY, EMPTY_CORRELATION)
    assert isinstance(result, str)
    assert len(result) > 0


def test_sigma_generator_contains_scenario_name():
    from purpleforge.detections.sigma import SigmaGenerator

    gen = SigmaGenerator()
    result = gen.generate(MINIMAL_SCENARIO, EMPTY_TELEMETRY, EMPTY_CORRELATION)
    assert "Smoke Test Scenario" in result


def test_sigma_generator_http_step_rule():
    """http_request step should produce a Sigma rule with the method."""
    from purpleforge.detections.sigma import SigmaGenerator

    gen = SigmaGenerator()
    result = gen.generate(MINIMAL_SCENARIO, EMPTY_TELEMETRY, EMPTY_CORRELATION)
    assert "GET" in result


def test_sigma_generator_sql_probe_rule():
    from purpleforge.detections.sigma import SigmaGenerator

    gen = SigmaGenerator()
    result = gen.generate(MINIMAL_SCENARIO, EMPTY_TELEMETRY, EMPTY_CORRELATION)
    assert "SQL" in result or "sqli" in result.lower() or "sql" in result.lower()


def test_sigma_generator_xss_probe_rule():
    from purpleforge.detections.sigma import SigmaGenerator

    gen = SigmaGenerator()
    result = gen.generate(MINIMAL_SCENARIO, EMPTY_TELEMETRY, EMPTY_CORRELATION)
    assert "XSS" in result or "script" in result.lower()


def test_sigma_generator_header_analysis_rule():
    from purpleforge.detections.sigma import SigmaGenerator

    gen = SigmaGenerator()
    result = gen.generate(MINIMAL_SCENARIO, EMPTY_TELEMETRY, EMPTY_CORRELATION)
    assert "OPTIONS" in result or "header" in result.lower()


def test_sigma_generator_attack_tags():
    from purpleforge.detections.sigma import SigmaGenerator

    gen = SigmaGenerator()
    result = gen.generate(MINIMAL_SCENARIO, EMPTY_TELEMETRY, EMPTY_CORRELATION)
    assert "t1190" in result.lower() or "attack." in result


def test_sigma_generator_web_category():
    """Exercise web-category YARA path via SigmaGenerator (smoke)."""
    from purpleforge.detections.sigma import SigmaGenerator

    gen = SigmaGenerator()
    web_scenario = dict(MINIMAL_SCENARIO, category="web")
    result = gen.generate(web_scenario, EMPTY_TELEMETRY, EMPTY_CORRELATION)
    assert isinstance(result, str)


def test_splunk_generator_produces_output():
    from purpleforge.detections.splunk import SplunkGenerator

    gen = SplunkGenerator()
    result = gen.generate(MINIMAL_SCENARIO, EMPTY_TELEMETRY, EMPTY_CORRELATION)
    assert isinstance(result, str)
    assert len(result) > 0


def test_splunk_generator_contains_spl_keywords():
    from purpleforge.detections.splunk import SplunkGenerator

    gen = SplunkGenerator()
    result = gen.generate(MINIMAL_SCENARIO, EMPTY_TELEMETRY, EMPTY_CORRELATION)
    assert "index=web" in result or "sourcetype" in result


def test_splunk_generator_http_step():
    from purpleforge.detections.splunk import SplunkGenerator

    gen = SplunkGenerator()
    result = gen.generate(MINIMAL_SCENARIO, EMPTY_TELEMETRY, EMPTY_CORRELATION)
    # http_request step should produce a query referencing method GET
    assert "GET" in result


def test_splunk_generator_sql_probe():
    from purpleforge.detections.splunk import SplunkGenerator

    gen = SplunkGenerator()
    result = gen.generate(MINIMAL_SCENARIO, EMPTY_TELEMETRY, EMPTY_CORRELATION)
    assert "UNION SELECT" in result or "OR 1=1" in result


def test_splunk_generator_xss_probe():
    from purpleforge.detections.splunk import SplunkGenerator

    gen = SplunkGenerator()
    result = gen.generate(MINIMAL_SCENARIO, EMPTY_TELEMETRY, EMPTY_CORRELATION)
    assert "<script>" in result or "javascript:" in result


def test_elastic_generator_produces_valid_json():
    from purpleforge.detections.elastic import ElasticGenerator

    gen = ElasticGenerator()
    result = gen.generate(MINIMAL_SCENARIO, EMPTY_TELEMETRY, EMPTY_CORRELATION)
    assert isinstance(result, str)
    parsed = json.loads(result)
    assert "queries" in parsed
    assert "metadata" in parsed


def test_elastic_generator_has_http_query():
    from purpleforge.detections.elastic import ElasticGenerator

    gen = ElasticGenerator()
    result = gen.generate(MINIMAL_SCENARIO, EMPTY_TELEMETRY, EMPTY_CORRELATION)
    parsed = json.loads(result)
    assert len(parsed["queries"]) > 0


def test_elastic_generator_sql_probe():
    from purpleforge.detections.elastic import ElasticGenerator

    gen = ElasticGenerator()
    result = gen.generate(MINIMAL_SCENARIO, EMPTY_TELEMETRY, EMPTY_CORRELATION)
    assert "UNION SELECT" in result or "OR 1=1" in result


def test_elastic_generator_xss_probe():
    from purpleforge.detections.elastic import ElasticGenerator

    gen = ElasticGenerator()
    result = gen.generate(MINIMAL_SCENARIO, EMPTY_TELEMETRY, EMPTY_CORRELATION)
    assert "<script>" in result or "javascript:" in result


def test_yara_generator_produces_output():
    from purpleforge.detections.yara import YaraGenerator

    gen = YaraGenerator()
    result = gen.generate(MINIMAL_SCENARIO, EMPTY_TELEMETRY, EMPTY_CORRELATION)
    assert isinstance(result, str)
    assert len(result) > 0


def test_yara_generator_contains_rule_keyword():
    from purpleforge.detections.yara import YaraGenerator

    gen = YaraGenerator()
    result = gen.generate(MINIMAL_SCENARIO, EMPTY_TELEMETRY, EMPTY_CORRELATION)
    assert "rule " in result


def test_yara_generator_web_category_rule():
    """web category should trigger the web-artifact rule path."""
    from purpleforge.detections.yara import YaraGenerator

    gen = YaraGenerator()
    web_scenario = dict(MINIMAL_SCENARIO, category="web")
    result = gen.generate(web_scenario, EMPTY_TELEMETRY, EMPTY_CORRELATION)
    assert "PurpleForge_Web_" in result


def test_yara_generator_binary_category_rule():
    """binary category should trigger the binary-artifact rule path."""
    from purpleforge.detections.yara import YaraGenerator

    gen = YaraGenerator()
    binary_scenario = dict(MINIMAL_SCENARIO, category="binary")
    result = gen.generate(binary_scenario, EMPTY_TELEMETRY, EMPTY_CORRELATION)
    assert "PurpleForge_Binary_" in result


def test_yara_generator_suspicious_patterns_always_present():
    from purpleforge.detections.yara import YaraGenerator

    gen = YaraGenerator()
    result = gen.generate(MINIMAL_SCENARIO, EMPTY_TELEMETRY, EMPTY_CORRELATION)
    assert "PurpleForge_Suspicious_Patterns" in result


def test_snort_generator_produces_output():
    from purpleforge.detections.snort import SnortGenerator

    gen = SnortGenerator()
    result = gen.generate(MINIMAL_SCENARIO, EMPTY_TELEMETRY, EMPTY_CORRELATION)
    assert isinstance(result, str)
    assert len(result) > 0


def test_snort_generator_contains_alert_rules():
    from purpleforge.detections.snort import SnortGenerator

    gen = SnortGenerator()
    result = gen.generate(MINIMAL_SCENARIO, EMPTY_TELEMETRY, EMPTY_CORRELATION)
    assert "alert tcp" in result


def test_snort_generator_generic_sqli_rule():
    from purpleforge.detections.snort import SnortGenerator

    gen = SnortGenerator()
    result = gen.generate(MINIMAL_SCENARIO, EMPTY_TELEMETRY, EMPTY_CORRELATION)
    assert "Generic SQL Injection" in result


def test_snort_generator_generic_xss_rule():
    from purpleforge.detections.snort import SnortGenerator

    gen = SnortGenerator()
    result = gen.generate(MINIMAL_SCENARIO, EMPTY_TELEMETRY, EMPTY_CORRELATION)
    assert "Generic XSS" in result


# ---------------------------------------------------------------------------
# DetectionGenerator integration – uses run_dir fixture
# ---------------------------------------------------------------------------


def test_detection_generator_init(run_dir: Path):
    from purpleforge.detections.generator import DetectionGenerator

    gen = DetectionGenerator(run_dir)
    assert gen.detections_dir.exists()


def test_detection_generator_sigma(run_dir: Path):
    from purpleforge.detections.generator import DetectionGenerator

    gen = DetectionGenerator(run_dir)
    results = gen.generate(format="sigma")
    assert "sigma" in results
    assert results["sigma"].exists()
    content = results["sigma"].read_text(encoding="utf-8")
    assert len(content) > 0


def test_detection_generator_splunk(run_dir: Path):
    from purpleforge.detections.generator import DetectionGenerator

    gen = DetectionGenerator(run_dir)
    results = gen.generate(format="splunk")
    assert "splunk" in results
    assert results["splunk"].exists()


def test_detection_generator_elastic(run_dir: Path):
    from purpleforge.detections.generator import DetectionGenerator

    gen = DetectionGenerator(run_dir)
    results = gen.generate(format="elastic")
    assert "elastic" in results
    content = results["elastic"].read_text(encoding="utf-8")
    parsed = json.loads(content)
    assert "queries" in parsed


def test_detection_generator_yara(run_dir: Path):
    from purpleforge.detections.generator import DetectionGenerator

    gen = DetectionGenerator(run_dir)
    try:
        results = gen.generate(format="yara")
        assert "yara" in results
        assert results["yara"].exists()
    except Exception as exc:
        pytest.fail(f"yara generation raised unexpectedly: {exc}")


def test_detection_generator_snort(run_dir: Path):
    from purpleforge.detections.generator import DetectionGenerator

    gen = DetectionGenerator(run_dir)
    try:
        results = gen.generate(format="snort")
        assert "snort" in results
        assert results["snort"].exists()
    except Exception as exc:
        pytest.fail(f"snort generation raised unexpectedly: {exc}")


def test_detection_generator_all_formats(run_dir: Path):
    """all_formats=True must produce all five outputs."""
    from purpleforge.detections.generator import DetectionGenerator

    gen = DetectionGenerator(run_dir)
    results = gen.generate(format="sigma", all_formats=True)
    assert set(results.keys()) == {"sigma", "splunk", "elastic", "yara", "snort"}
    for fmt, path in results.items():
        assert path.exists(), f"Output file missing for format {fmt}"


def test_detection_generator_unsupported_format(run_dir: Path):
    """Requesting an unknown format raises PurpleForgeError."""
    from purpleforge.detections.generator import DetectionGenerator
    from purpleforge.utils.exceptions import PurpleForgeError

    gen = DetectionGenerator(run_dir)
    with pytest.raises(PurpleForgeError):
        gen.generate(format="cobol")


def test_detection_generator_sigma_output_non_empty(run_dir: Path):
    from purpleforge.detections.generator import DetectionGenerator

    gen = DetectionGenerator(run_dir)
    results = gen.generate(format="sigma")
    content = results["sigma"].read_text(encoding="utf-8")
    assert "PurpleForge" in content


def test_detection_generator_splunk_output_contains_spl(run_dir: Path):
    from purpleforge.detections.generator import DetectionGenerator

    gen = DetectionGenerator(run_dir)
    results = gen.generate(format="splunk")
    content = results["splunk"].read_text(encoding="utf-8")
    assert "index=web" in content or "sourcetype" in content


def test_detection_generator_elastic_output_is_valid_json(run_dir: Path):
    from purpleforge.detections.generator import DetectionGenerator

    gen = DetectionGenerator(run_dir)
    results = gen.generate(format="elastic")
    content = results["elastic"].read_text(encoding="utf-8")
    data = json.loads(content)
    assert data["metadata"]["scenario"] == "Smoke Test Scenario"
