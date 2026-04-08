"""
Tests for purpleforge.mirror.differential.MirrorDiff.

No network calls; purely operates on hand-built manifest dicts written to files.

Authorized, verified targets only; defensive static analysis; no exploitation;
manual review required.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from purpleforge.mirror.differential import MirrorDiff, DiffResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_manifest(path: Path, pages: list[dict], base_url: str = "http://example.com") -> Path:
    data = {
        "base_url": base_url,
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:01:00+00:00",
        "user_agent": "PurpleForge-Mirror/0.1",
        "robots_txt_sha256": None,
        "pages": pages,
    }
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _page(url: str, sha256: str = "aaaa", headers: dict | None = None, content_type: str = "text/html") -> dict:
    return {
        "url": url,
        "local_path": f"assets/{url.split('/')[-1] or 'index.html'}",
        "content_type": content_type,
        "status": 200,
        "sha256": sha256,
        "bytes": 100,
        "headers": headers or {},
    }


# ---------------------------------------------------------------------------
# DiffResult contents
# ---------------------------------------------------------------------------

class TestDiffResult:
    def test_added_pages(self, tmp_path):
        old_path = tmp_path / "old_manifest.json"
        new_path = tmp_path / "new_manifest.json"

        _write_manifest(old_path, [_page("http://example.com/a")])
        _write_manifest(new_path, [_page("http://example.com/a"), _page("http://example.com/b")])

        diff = MirrorDiff().diff(old_path, new_path)
        assert "http://example.com/b" in diff.added_pages
        assert diff.removed_pages == []

    def test_removed_pages(self, tmp_path):
        old_path = tmp_path / "old.json"
        new_path = tmp_path / "new.json"

        _write_manifest(old_path, [_page("http://example.com/a"), _page("http://example.com/b")])
        _write_manifest(new_path, [_page("http://example.com/a")])

        diff = MirrorDiff().diff(old_path, new_path)
        assert "http://example.com/b" in diff.removed_pages
        assert diff.added_pages == []

    def test_changed_pages(self, tmp_path):
        old_path = tmp_path / "old.json"
        new_path = tmp_path / "new.json"

        _write_manifest(old_path, [_page("http://example.com/a", sha256="hash1")])
        _write_manifest(new_path, [_page("http://example.com/a", sha256="hash2")])

        diff = MirrorDiff().diff(old_path, new_path)
        assert "http://example.com/a" in diff.changed_pages

    def test_unchanged_page_not_in_changed(self, tmp_path):
        old_path = tmp_path / "old.json"
        new_path = tmp_path / "new.json"

        _write_manifest(old_path, [_page("http://example.com/a", sha256="same")])
        _write_manifest(new_path, [_page("http://example.com/a", sha256="same")])

        diff = MirrorDiff().diff(old_path, new_path)
        assert diff.changed_pages == []
        assert diff.added_pages == []
        assert diff.removed_pages == []

    def test_header_changes_detected(self, tmp_path):
        old_path = tmp_path / "old.json"
        new_path = tmp_path / "new.json"

        _write_manifest(old_path, [_page("http://example.com/a", headers={"x-frame-options": "DENY"})])
        _write_manifest(new_path, [_page("http://example.com/a", headers={"content-security-policy": "default-src 'self'"})])

        diff = MirrorDiff().diff(old_path, new_path)
        assert "http://example.com/a" in diff.header_changes
        changes = diff.header_changes["http://example.com/a"]
        assert "content-security-policy" in changes["added"]
        assert "x-frame-options" in changes["removed"]

    def test_added_js_script_detected(self, tmp_path):
        old_path = tmp_path / "old.json"
        new_path = tmp_path / "new.json"

        _write_manifest(old_path, [_page("http://example.com/a")])
        _write_manifest(new_path, [
            _page("http://example.com/a"),
            _page("http://example.com/app.js", content_type="application/javascript"),
        ])

        diff = MirrorDiff().diff(old_path, new_path)
        assert "http://example.com/app.js" in diff.added_scripts


# ---------------------------------------------------------------------------
# to_findings
# ---------------------------------------------------------------------------

class TestToFindings:
    def test_added_page_produces_low_finding(self, tmp_path):
        old_path = tmp_path / "old.json"
        new_path = tmp_path / "new.json"

        _write_manifest(old_path, [])
        _write_manifest(new_path, [_page("http://example.com/new")])

        diff = MirrorDiff().diff(old_path, new_path)
        findings = MirrorDiff().to_findings(diff)

        added_findings = [f for f in findings if "new page" in f.title.lower() or "added_page" in f.evidence.get("change_type", "")]
        assert added_findings
        assert all(f.severity == "low" for f in added_findings)

    def test_cross_origin_script_produces_medium_finding(self, tmp_path):
        old_path = tmp_path / "old.json"
        new_path = tmp_path / "new.json"

        _write_manifest(old_path, [], base_url="http://example.com")
        _write_manifest(new_path, [
            _page("http://evil.com/tracker.js", content_type="application/javascript"),
        ], base_url="http://example.com")

        diff = MirrorDiff().diff(old_path, new_path)
        findings = MirrorDiff().to_findings(diff)

        cross_origin = [f for f in findings if f.evidence.get("cross_origin") is True]
        assert cross_origin
        assert all(f.severity == "medium" for f in cross_origin)

    def test_same_origin_script_produces_low_finding(self, tmp_path):
        old_path = tmp_path / "old.json"
        new_path = tmp_path / "new.json"

        _write_manifest(old_path, [], base_url="http://example.com")
        _write_manifest(new_path, [
            _page("http://example.com/app.js", content_type="application/javascript"),
        ], base_url="http://example.com")

        diff = MirrorDiff().diff(old_path, new_path)
        findings = MirrorDiff().to_findings(diff)

        script_findings = [f for f in findings if "script" in f.title.lower()]
        assert script_findings
        assert all(f.severity == "low" for f in script_findings)

    def test_findings_source_is_mirror_diff(self, tmp_path):
        old_path = tmp_path / "old.json"
        new_path = tmp_path / "new.json"

        _write_manifest(old_path, [_page("http://example.com/a")])
        _write_manifest(new_path, [_page("http://example.com/b")])

        diff = MirrorDiff().diff(old_path, new_path)
        findings = MirrorDiff().to_findings(diff)

        assert all(f.source == "mirror_diff" for f in findings)

    def test_removed_page_finding(self, tmp_path):
        old_path = tmp_path / "old.json"
        new_path = tmp_path / "new.json"

        _write_manifest(old_path, [_page("http://example.com/old")])
        _write_manifest(new_path, [])

        diff = MirrorDiff().diff(old_path, new_path)
        findings = MirrorDiff().to_findings(diff)

        removed = [f for f in findings if "removed" in f.title.lower()]
        assert removed

    def test_changed_page_finding(self, tmp_path):
        old_path = tmp_path / "old.json"
        new_path = tmp_path / "new.json"

        _write_manifest(old_path, [_page("http://example.com/a", sha256="v1")])
        _write_manifest(new_path, [_page("http://example.com/a", sha256="v2")])

        diff = MirrorDiff().diff(old_path, new_path)
        findings = MirrorDiff().to_findings(diff)

        changed = [f for f in findings if "changed" in f.title.lower()]
        assert changed


# ---------------------------------------------------------------------------
# write_diff
# ---------------------------------------------------------------------------

class TestWriteDiff:
    def test_write_diff_creates_json(self, tmp_path):
        old_path = tmp_path / "old.json"
        new_path = tmp_path / "new.json"

        _write_manifest(old_path, [_page("http://example.com/a")])
        _write_manifest(new_path, [_page("http://example.com/b")])

        diff = MirrorDiff().diff(old_path, new_path)
        out_path = MirrorDiff().write_diff(tmp_path, diff)

        assert out_path.exists()
        with open(out_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        assert "added_pages" in data
        assert "http://example.com/b" in data["added_pages"]
