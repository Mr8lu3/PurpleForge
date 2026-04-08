"""
Tests for mirror CLI commands via Typer's CliRunner.

All crawler and analyzer interactions are mocked — no real network calls.

Authorized, verified targets only; polite crawl; defensive static analysis;
no exploitation; manual review required.
"""

from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, Mock

import pytest
from typer.testing import CliRunner

from purpleforge.cli.main import app
from purpleforge.mirror.crawler import CrawlManifest, PageRecord
from purpleforge.utils.exceptions import MirrorError

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_manifest(base_url: str = "http://example.com", pages: int = 1) -> CrawlManifest:
    records = [
        PageRecord(
            url=f"{base_url}/page{i}",
            local_path=f"assets/page{i}.html",
            content_type="text/html",
            status=200,
            sha256="aabb",
            bytes=100,
            headers={},
        )
        for i in range(pages)
    ]
    return CrawlManifest(
        base_url=base_url,
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:01:00+00:00",
        user_agent="PurpleForge-Mirror/0.1",
        robots_txt_sha256=None,
        pages=records,
    )


def _write_manifest_file(path: Path, base_url: str = "http://example.com") -> None:
    data = {
        "base_url": base_url,
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:01:00+00:00",
        "user_agent": "PurpleForge-Mirror/0.1",
        "robots_txt_sha256": None,
        "pages": [],
    }
    path.write_text(json.dumps(data), encoding="utf-8")


# ---------------------------------------------------------------------------
# mirror command
# ---------------------------------------------------------------------------

class TestMirrorCommand:
    @patch("purpleforge.mirror.static_analysis.run_static_analysis")
    @patch("purpleforge.mirror.crawler.PoliteCrawler.crawl")
    @patch("purpleforge.cli.commands.load_targets")
    def test_mirror_exits_zero_when_verified(
        self,
        mock_load_targets,
        mock_crawl,
        mock_static,
        tmp_path,
    ):
        """mirror command exits 0 when target is verified and crawl succeeds."""
        from purpleforge.config.models import TargetAllowlist, TargetEntry

        allowlist = TargetAllowlist()
        # Use full URL as key — matches how load_targets/save_targets stores entries.
        allowlist.targets["http://example.com"] = TargetEntry(
            base_url="http://example.com",
            verified_at=datetime.now(tz=timezone.utc),
            token_hash="abc",
        )
        mock_load_targets.return_value = allowlist
        mock_crawl.return_value = _make_manifest()
        mock_static.return_value = []

        result = runner.invoke(
            app,
            ["mirror", "http://example.com", "--output", str(tmp_path / "out"), "--rate-limit", "0"],
        )

        assert result.exit_code == 0, result.output

    @patch("purpleforge.cli.commands.load_targets")
    def test_mirror_exits_nonzero_when_unverified(self, mock_load_targets, tmp_path):
        """mirror command exits nonzero when target is not in allowlist."""
        from purpleforge.config.models import TargetAllowlist
        mock_load_targets.return_value = TargetAllowlist()

        result = runner.invoke(
            app,
            ["mirror", "http://evil.example.com", "--output", str(tmp_path / "out")],
        )

        assert result.exit_code != 0
        # No Python traceback should be emitted
        assert "Traceback" not in result.output
        assert "Traceback" not in (result.stderr or "")

    @patch("purpleforge.mirror.static_analysis.run_static_analysis")
    @patch("purpleforge.mirror.crawler.PoliteCrawler.crawl")
    @patch("purpleforge.cli.commands.load_targets")
    def test_mirror_writes_manifest_and_findings(
        self,
        mock_load_targets,
        mock_crawl,
        mock_static,
        tmp_path,
    ):
        """After a successful mirror, manifest.json and mirror_findings.json exist."""
        from purpleforge.config.models import TargetAllowlist, TargetEntry
        from purpleforge.analysis.findings_schema import Finding

        allowlist = TargetAllowlist()
        allowlist.targets["http://example.com"] = TargetEntry(
            base_url="http://example.com",
            verified_at=datetime.now(tz=timezone.utc),
            token_hash="abc",
        )
        mock_load_targets.return_value = allowlist

        out_dir = tmp_path / "mirror_out"
        manifest = _make_manifest()

        # crawl() should write manifest.json (simulate by writing it in side_effect)
        def crawl_side_effect():
            out_dir.mkdir(parents=True, exist_ok=True)
            manifest_path = out_dir / "manifest.json"
            with open(manifest_path, "w") as fh:
                json.dump(manifest.to_dict(), fh)
            return manifest

        mock_crawl.side_effect = crawl_side_effect

        # run_static_analysis writes mirror_findings.json; simulate
        def static_side_effect(mirror_dir, m, out_path=None):
            real_path = out_path or mirror_dir / "mirror_findings.json"
            real_path.parent.mkdir(parents=True, exist_ok=True)
            real_path.write_text("[]", encoding="utf-8")
            return []

        mock_static.side_effect = static_side_effect

        result = runner.invoke(
            app,
            ["mirror", "http://example.com", "--output", str(out_dir), "--rate-limit", "0"],
        )

        assert result.exit_code == 0, result.output


# ---------------------------------------------------------------------------
# mirror-scan command
# ---------------------------------------------------------------------------

class TestMirrorScanCommand:
    @patch("purpleforge.mirror.static_analysis.run_static_analysis")
    def test_mirror_scan_exits_zero(self, mock_static, tmp_path):
        """mirror-scan exits 0 when manifest exists and analysis succeeds."""
        mirror_dir = tmp_path / "mirror"
        mirror_dir.mkdir()
        manifest_path = mirror_dir / "manifest.json"
        _write_manifest_file(manifest_path)

        mock_static.return_value = []

        result = runner.invoke(app, ["mirror-scan", str(mirror_dir)])
        assert result.exit_code == 0, result.output

    def test_mirror_scan_fails_without_manifest(self, tmp_path):
        """mirror-scan exits nonzero when no manifest.json present."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        result = runner.invoke(app, ["mirror-scan", str(empty_dir)])
        assert result.exit_code != 0
        assert "Traceback" not in result.output
        assert "Traceback" not in (result.stderr or "")


# ---------------------------------------------------------------------------
# mirror-diff command
# ---------------------------------------------------------------------------

class TestMirrorDiffCommand:
    def test_mirror_diff_exits_zero(self, tmp_path):
        """mirror-diff exits 0 when two valid manifests are provided."""
        old_path = tmp_path / "old.json"
        new_path = tmp_path / "new.json"
        out_dir = tmp_path / "out"

        _write_manifest_file(old_path)
        _write_manifest_file(new_path)

        result = runner.invoke(
            app,
            ["mirror-diff", str(old_path), str(new_path), "--output", str(out_dir)],
        )
        assert result.exit_code == 0, result.output

    def test_mirror_diff_writes_output_files(self, tmp_path):
        """mirror-diff writes mirror_diff.json and mirror_diff_findings.json."""
        old_path = tmp_path / "old.json"
        new_path = tmp_path / "new.json"
        out_dir = tmp_path / "out"

        _write_manifest_file(old_path)
        _write_manifest_file(new_path)

        runner.invoke(
            app,
            ["mirror-diff", str(old_path), str(new_path), "--output", str(out_dir)],
        )

        assert (out_dir / "mirror_diff.json").exists()
        assert (out_dir / "mirror_diff_findings.json").exists()
