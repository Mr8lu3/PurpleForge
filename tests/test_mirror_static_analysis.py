"""
Tests for purpleforge.mirror.static_analysis.

All tests use local fixture files — no network calls are made.

Authorized, verified targets only; defensive static analysis; no exploitation;
manual review required.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from purpleforge.mirror.crawler import CrawlManifest, PageRecord
from purpleforge.mirror.static_analysis import run_static_analysis


# ---------------------------------------------------------------------------
# Fixtures: helper to build a CrawlManifest backed by real files in tmp_path
# ---------------------------------------------------------------------------

def _write_asset(assets_dir: Path, rel: str, content: str) -> Path:
    """Write a fixture file and return its path."""
    path = assets_dir / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _make_manifest(
    tmp_path: Path,
    pages: list[dict],
) -> tuple[Path, CrawlManifest]:
    """
    Build a CrawlManifest in tmp_path from a list of page dicts.
    Each dict: {rel_path, content, content_type, headers (optional)}.
    """
    assets_dir = tmp_path / "assets"
    records = []
    for p in pages:
        rel = p["rel_path"]
        _write_asset(assets_dir, rel, p["content"])
        records.append(
            PageRecord(
                url=f"http://example.com/{rel}",
                local_path=f"assets/{rel}",
                content_type=p.get("content_type", "text/html"),
                status=200,
                sha256="aabbcc",
                bytes=len(p["content"]),
                headers=p.get("headers", {}),
            )
        )

    manifest = CrawlManifest(
        base_url="http://example.com",
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:01:00+00:00",
        user_agent="PurpleForge-Mirror/0.1",
        robots_txt_sha256=None,
        pages=records,
    )
    return tmp_path, manifest


# ---------------------------------------------------------------------------
# Pass 1: Secret scan
# ---------------------------------------------------------------------------

class TestSecretScan:
    def test_aws_access_key_detected(self, tmp_path):
        content = "# config\nACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n"
        _, manifest = _make_manifest(tmp_path, [{"rel_path": "config.js", "content": content, "content_type": "application/javascript"}])
        findings = run_static_analysis(tmp_path, manifest)
        cats = [f.category for f in findings]
        assert "secret_exposure" in cats
        high = [f for f in findings if f.category == "secret_exposure" and f.severity == "high"]
        assert high, "AWS key should produce a high-severity finding"

    def test_private_key_detected_high(self, tmp_path):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n"
        _, manifest = _make_manifest(tmp_path, [{"rel_path": "key.pem", "content": content}])
        findings = run_static_analysis(tmp_path, manifest)
        secrets = [f for f in findings if f.category == "secret_exposure" and f.severity == "high"]
        assert secrets

    def test_generic_api_key_medium(self, tmp_path):
        content = 'api_key = "abcdef1234567890abcdef1234567890"\n'
        _, manifest = _make_manifest(tmp_path, [{"rel_path": "config.js", "content": content, "content_type": "application/javascript"}])
        findings = run_static_analysis(tmp_path, manifest)
        secrets = [f for f in findings if f.category == "secret_exposure"]
        assert secrets
        # Severity should be medium for generic api key
        assert any(f.severity == "medium" for f in secrets)

    def test_jwt_detected(self, tmp_path):
        # A properly formed JWT (three base64url parts)
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        content = f'const token = "{jwt}";\n'
        _, manifest = _make_manifest(tmp_path, [{"rel_path": "app.js", "content": content, "content_type": "application/javascript"}])
        findings = run_static_analysis(tmp_path, manifest)
        cats = [f.category for f in findings]
        assert "secret_exposure" in cats

    def test_no_false_positive_on_clean_file(self, tmp_path):
        content = "<html><body><h1>Welcome</h1></body></html>"
        _, manifest = _make_manifest(tmp_path, [{"rel_path": "index.html", "content": content}])
        findings = run_static_analysis(tmp_path, manifest)
        secrets = [f for f in findings if f.category == "secret_exposure"]
        assert not secrets


# ---------------------------------------------------------------------------
# Pass 2: Outdated JS library detection
# ---------------------------------------------------------------------------

class TestOutdatedJsLib:
    def test_old_jquery_via_script_src(self, tmp_path):
        content = '<html><head><script src="jquery-1.11.3.min.js"></script></head><body></body></html>'
        _, manifest = _make_manifest(tmp_path, [{"rel_path": "index.html", "content": content}])
        findings = run_static_analysis(tmp_path, manifest)
        outdated = [f for f in findings if f.category == "outdated_js_lib"]
        assert outdated
        assert outdated[0].severity == "medium"
        assert "jquery" in outdated[0].evidence.get("library", "").lower()

    def test_current_jquery_not_flagged(self, tmp_path):
        content = '<html><head><script src="jquery-3.7.1.min.js"></script></head><body></body></html>'
        _, manifest = _make_manifest(tmp_path, [{"rel_path": "index.html", "content": content}])
        findings = run_static_analysis(tmp_path, manifest)
        outdated = [f for f in findings if f.category == "outdated_js_lib"]
        assert not outdated

    def test_inline_banner_detected(self, tmp_path):
        content = "/*! jQuery v2.1.4 | (c) jQuery Foundation */\n(function(){})\n"
        _, manifest = _make_manifest(tmp_path, [{"rel_path": "jquery.js", "content": content, "content_type": "application/javascript"}])
        findings = run_static_analysis(tmp_path, manifest)
        outdated = [f for f in findings if f.category == "outdated_js_lib"]
        assert outdated

    def test_old_bootstrap_flagged(self, tmp_path):
        content = '<html><head><script src="bootstrap-4.0.0.min.js"></script></head></html>'
        _, manifest = _make_manifest(tmp_path, [{"rel_path": "index.html", "content": content}])
        findings = run_static_analysis(tmp_path, manifest)
        outdated = [f for f in findings if f.category == "outdated_js_lib"]
        assert outdated


# ---------------------------------------------------------------------------
# Pass 3: Security header audit
# ---------------------------------------------------------------------------

class TestSecurityHeaders:
    def test_missing_csp_produces_finding(self, tmp_path):
        # No CSP header in page record
        page = {
            "rel_path": "index.html",
            "content": "<html></html>",
            "headers": {
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "strict-transport-security": "max-age=31536000",
                "referrer-policy": "no-referrer",
            },
        }
        _, manifest = _make_manifest(tmp_path, [page])
        findings = run_static_analysis(tmp_path, manifest)
        header_findings = [f for f in findings if f.category == "missing_security_header"]
        missing = [f for f in header_findings if "content-security-policy" in f.evidence.get("missing_header", "")]
        assert missing

    def test_all_headers_present_no_finding(self, tmp_path):
        page = {
            "rel_path": "index.html",
            "content": "<html></html>",
            "headers": {
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "strict-transport-security": "max-age=31536000",
                "referrer-policy": "no-referrer",
            },
        }
        _, manifest = _make_manifest(tmp_path, [page])
        findings = run_static_analysis(tmp_path, manifest)
        header_findings = [f for f in findings if f.category == "missing_security_header"]
        assert not header_findings

    def test_severity_is_low(self, tmp_path):
        page = {"rel_path": "index.html", "content": "<html></html>", "headers": {}}
        _, manifest = _make_manifest(tmp_path, [page])
        findings = run_static_analysis(tmp_path, manifest)
        header_findings = [f for f in findings if f.category == "missing_security_header"]
        assert header_findings
        assert all(f.severity == "low" for f in header_findings)


# ---------------------------------------------------------------------------
# Pass 4: DOM sink detection
# ---------------------------------------------------------------------------

class TestDomSinkDetection:
    def test_sink_plus_url_input_produces_finding(self, tmp_path):
        content = (
            "var q = location.search;\n"
            "document.getElementById('out').innerHTML = q;\n"
        )
        _, manifest = _make_manifest(tmp_path, [{"rel_path": "app.js", "content": content, "content_type": "application/javascript"}])
        findings = run_static_analysis(tmp_path, manifest)
        dom = [f for f in findings if f.category == "dom_sink_candidate"]
        assert dom
        assert dom[0].severity == "medium"
        assert dom[0].confidence == "low"

    def test_sink_only_no_url_input_no_finding(self, tmp_path):
        content = "var x = 'hello';\ndocument.getElementById('out').innerHTML = x;\n"
        _, manifest = _make_manifest(tmp_path, [{"rel_path": "app.js", "content": content, "content_type": "application/javascript"}])
        findings = run_static_analysis(tmp_path, manifest)
        dom = [f for f in findings if f.category == "dom_sink_candidate"]
        assert not dom

    def test_url_input_only_no_sink_no_finding(self, tmp_path):
        content = "var q = location.search;\nconsole.log(q);\n"
        _, manifest = _make_manifest(tmp_path, [{"rel_path": "app.js", "content": content, "content_type": "application/javascript"}])
        findings = run_static_analysis(tmp_path, manifest)
        dom = [f for f in findings if f.category == "dom_sink_candidate"]
        assert not dom


# ---------------------------------------------------------------------------
# Output file
# ---------------------------------------------------------------------------

class TestOutputFile:
    def test_mirror_findings_json_written(self, tmp_path):
        page = {
            "rel_path": "index.html",
            "content": "<html></html>",
            "headers": {},
        }
        _, manifest = _make_manifest(tmp_path, [page])
        findings = run_static_analysis(tmp_path, manifest)

        out_file = tmp_path / "mirror_findings.json"
        assert out_file.exists()

        with open(out_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        assert isinstance(data, list)

    def test_all_findings_have_source_mirror_static(self, tmp_path):
        page = {
            "rel_path": "index.html",
            "content": 'api_key = "abcdef1234567890abcdef1234567890"\n',
            "headers": {},
        }
        _, manifest = _make_manifest(tmp_path, [page])
        findings = run_static_analysis(tmp_path, manifest)
        assert all(f.source == "mirror_static" for f in findings)
