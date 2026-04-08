"""
Tests for purpleforge.mirror.crawler.PoliteCrawler.

IMPORTANT: No real network calls are made.  All HTTP is mocked via
unittest.mock.patch on requests.get and urllib.robotparser.RobotFileParser.

Authorized, verified targets only; polite crawl; defensive static analysis;
no exploitation; manual review required.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from purpleforge.mirror.crawler import PoliteCrawler, CrawlManifest, _normalize_netloc
from purpleforge.utils.exceptions import MirrorError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(
    text: str = "<html><body>Hello</body></html>",
    status_code: int = 200,
    content_type: str = "text/html",
    headers: dict | None = None,
) -> Mock:
    resp = Mock()
    resp.status_code = status_code
    resp.text = text
    resp.content = text.encode()
    resp.headers = {"Content-Type": content_type, **(headers or {})}
    # iter_content yields the whole body as one chunk
    resp.iter_content = lambda chunk_size=8192: iter([text.encode()])
    return resp


def _robots_disallow_all() -> Mock:
    resp = Mock()
    resp.status_code = 200
    resp.text = "User-agent: *\nDisallow: /"
    resp.content = b"User-agent: *\nDisallow: /"
    resp.headers = {"Content-Type": "text/plain"}
    resp.iter_content = lambda chunk_size=8192: iter([b"User-agent: *\nDisallow: /"])
    return resp


def _robots_allow_all() -> Mock:
    resp = Mock()
    resp.status_code = 200
    resp.text = "User-agent: *\nAllow: /"
    resp.content = b"User-agent: *\nAllow: /"
    resp.headers = {"Content-Type": "text/plain"}
    resp.iter_content = lambda chunk_size=8192: iter([b"User-agent: *\nAllow: /"])
    return resp


def _robots_404() -> Mock:
    resp = Mock()
    resp.status_code = 404
    resp.text = "Not Found"
    resp.content = b"Not Found"
    resp.headers = {}
    resp.iter_content = lambda chunk_size=8192: iter([b""])
    return resp


# ---------------------------------------------------------------------------
# Ownership gate
# ---------------------------------------------------------------------------

class TestOwnershipGate:
    def test_unverified_target_raises_mirror_error(self, tmp_path):
        """Crawling an unverified target raises MirrorError before any network call."""
        with pytest.raises(MirrorError) as exc_info:
            PoliteCrawler(
                base_url="http://evil.example.com",
                out_dir=tmp_path,
                verified_targets=["example.com"],
            )
        assert "not in the verified allowlist" in str(exc_info.value)
        assert exc_info.value.hint is not None

    def test_verified_target_is_accepted(self, tmp_path):
        """Crawler does not raise when netloc matches a verified entry."""
        crawler = PoliteCrawler(
            base_url="http://example.com",
            out_dir=tmp_path,
            verified_targets=["example.com"],
        )
        assert crawler.base_url == "http://example.com"

    def test_www_same_as_apex(self, tmp_path):
        """www.example.com is accepted when example.com is in the allowlist."""
        crawler = PoliteCrawler(
            base_url="http://www.example.com",
            out_dir=tmp_path,
            verified_targets=["example.com"],
        )
        assert crawler is not None

    def test_no_verified_targets_list_skips_gate(self, tmp_path):
        """Passing verified_targets=None (unit-test mode) skips the ownership gate."""
        crawler = PoliteCrawler(
            base_url="http://anything.example.com",
            out_dir=tmp_path,
            verified_targets=None,
        )
        assert crawler is not None


# ---------------------------------------------------------------------------
# robots.txt enforcement
# ---------------------------------------------------------------------------

class TestRobotsTxt:
    @patch("requests.get")
    def test_robots_disallow_raises_mirror_error(self, mock_get, tmp_path):
        """If robots.txt disallows the UA, crawl() raises MirrorError."""
        mock_get.return_value = _robots_disallow_all()

        crawler = PoliteCrawler(
            base_url="http://example.com",
            out_dir=tmp_path,
            verified_targets=None,
        )
        with pytest.raises(MirrorError) as exc_info:
            crawler.crawl()
        assert "robots.txt" in str(exc_info.value).lower()

    @patch("requests.get")
    def test_robots_allow_proceeds(self, mock_get, tmp_path):
        """If robots.txt allows, crawl proceeds (returns manifest)."""
        html_body = "<html><body>Hello world</body></html>"

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return _robots_allow_all()
            return _make_response(html_body)

        mock_get.side_effect = side_effect

        crawler = PoliteCrawler(
            base_url="http://example.com",
            out_dir=tmp_path,
            verified_targets=None,
            rate_limit_sec=0.0,
        )
        manifest = crawler.crawl()
        assert isinstance(manifest, CrawlManifest)
        assert len(manifest.pages) >= 1

    @patch("requests.get")
    def test_robots_404_proceeds(self, mock_get, tmp_path):
        """Missing robots.txt (404) does not abort the crawl."""
        html_body = "<html><body>ok</body></html>"

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return _robots_404()
            return _make_response(html_body)

        mock_get.side_effect = side_effect

        crawler = PoliteCrawler(
            base_url="http://example.com",
            out_dir=tmp_path,
            verified_targets=None,
            rate_limit_sec=0.0,
        )
        manifest = crawler.crawl()
        assert manifest.robots_txt_sha256 is None
        assert len(manifest.pages) >= 1


# ---------------------------------------------------------------------------
# Cross-origin link filtering
# ---------------------------------------------------------------------------

class TestCrossOriginFiltering:
    @patch("requests.get")
    def test_cross_origin_links_are_skipped(self, mock_get, tmp_path):
        """Links to a different host must NOT be followed."""
        html_with_external = (
            '<html><body>'
            '<a href="http://evil.com/steal">external</a>'
            '<a href="/local">local</a>'
            '</body></html>'
        )
        local_html = "<html><body>local page</body></html>"

        call_count = [0]

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return _robots_allow_all()
            call_count[0] += 1
            if call_count[0] == 1:
                return _make_response(html_with_external)
            return _make_response(local_html)

        mock_get.side_effect = side_effect

        crawler = PoliteCrawler(
            base_url="http://example.com",
            out_dir=tmp_path,
            verified_targets=None,
            rate_limit_sec=0.0,
            max_depth=2,
        )
        manifest = crawler.crawl()

        crawled_urls = [p.url for p in manifest.pages]
        assert not any("evil.com" in u for u in crawled_urls)


# ---------------------------------------------------------------------------
# Depth cap
# ---------------------------------------------------------------------------

class TestDepthCap:
    @patch("requests.get")
    def test_depth_cap_respected(self, mock_get, tmp_path):
        """Pages deeper than max_depth are not fetched."""
        # Page A -> Page B -> Page C  (depth 0 -> 1 -> 2)
        # With max_depth=1, only A and B should be fetched.
        page_a = '<html><body><a href="/b">B</a></body></html>'
        page_b = '<html><body><a href="/c">C</a></body></html>'
        page_c = "<html><body>C</body></html>"

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return _robots_allow_all()
            if url.endswith("/b"):
                return _make_response(page_b)
            if url.endswith("/c"):
                return _make_response(page_c)
            return _make_response(page_a)

        mock_get.side_effect = side_effect

        crawler = PoliteCrawler(
            base_url="http://example.com",
            out_dir=tmp_path,
            verified_targets=None,
            rate_limit_sec=0.0,
            max_depth=1,
        )
        manifest = crawler.crawl()

        crawled_urls = [p.url for p in manifest.pages]
        # C should not appear (depth 2 > max_depth 1)
        assert not any(u.endswith("/c") for u in crawled_urls)

    def test_max_depth_hard_limit(self, tmp_path):
        """max_depth > 4 raises MirrorError immediately."""
        with pytest.raises(MirrorError) as exc_info:
            PoliteCrawler(
                base_url="http://example.com",
                out_dir=tmp_path,
                verified_targets=None,
                max_depth=5,
            )
        assert "hard limit" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# max_pages cap
# ---------------------------------------------------------------------------

class TestMaxPagesCap:
    @patch("requests.get")
    def test_max_pages_cap_respected(self, mock_get, tmp_path):
        """Crawl stops after max_pages pages."""
        # Serve an HTML page that links to 20 sub-pages.
        links = "".join(f'<a href="/{i}">page {i}</a>' for i in range(20))
        index_html = f"<html><body>{links}</body></html>"
        sub_html = "<html><body>sub</body></html>"

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return _robots_allow_all()
            if url == "http://example.com" or url == "http://example.com/":
                return _make_response(index_html)
            return _make_response(sub_html)

        mock_get.side_effect = side_effect

        crawler = PoliteCrawler(
            base_url="http://example.com",
            out_dir=tmp_path,
            verified_targets=None,
            rate_limit_sec=0.0,
            max_pages=5,
            max_depth=2,
        )
        manifest = crawler.crawl()
        assert len(manifest.pages) <= 5


# ---------------------------------------------------------------------------
# max_bytes truncation
# ---------------------------------------------------------------------------

class TestMaxBytesTruncation:
    @patch("requests.get")
    def test_large_asset_is_truncated(self, mock_get, tmp_path):
        """Assets larger than max_bytes are truncated and a warning is logged."""
        large_body = "A" * 5000  # 5000 bytes

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return _robots_allow_all()
            resp = Mock()
            resp.status_code = 200
            resp.text = large_body
            resp.content = large_body.encode()
            resp.headers = {"Content-Type": "text/html"}
            # iter_content returns chunks of 1000 bytes to exercise streaming
            data = large_body.encode()
            resp.iter_content = lambda chunk_size=8192: (
                data[i:i+1000] for i in range(0, len(data), 1000)
            )
            return resp

        mock_get.side_effect = side_effect

        crawler = PoliteCrawler(
            base_url="http://example.com",
            out_dir=tmp_path,
            verified_targets=None,
            rate_limit_sec=0.0,
            max_bytes=2000,
        )
        manifest = crawler.crawl()

        assert len(manifest.pages) >= 1
        page = manifest.pages[0]
        assert page.bytes <= 2000


# ---------------------------------------------------------------------------
# Manifest written correctly
# ---------------------------------------------------------------------------

class TestManifestWritten:
    @patch("requests.get")
    def test_manifest_json_written(self, mock_get, tmp_path):
        """manifest.json is written with correct structure."""
        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return _robots_allow_all()
            return _make_response("<html><body>hi</body></html>")

        mock_get.side_effect = side_effect

        crawler = PoliteCrawler(
            base_url="http://example.com",
            out_dir=tmp_path,
            verified_targets=None,
            rate_limit_sec=0.0,
        )
        manifest = crawler.crawl()

        manifest_path = tmp_path / "manifest.json"
        assert manifest_path.exists()

        with open(manifest_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        assert data["base_url"] == "http://example.com"
        assert "started_at" in data
        assert "finished_at" in data
        assert "user_agent" in data
        assert "pages" in data
        assert isinstance(data["pages"], list)
        # Each page record has required fields
        for p in data["pages"]:
            assert "url" in p
            assert "sha256" in p
            assert "headers" in p

    @patch("requests.get")
    def test_manifest_roundtrip(self, mock_get, tmp_path):
        """CrawlManifest.from_dict(manifest.to_dict()) is lossless."""
        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return _robots_allow_all()
            return _make_response("<html><body>test</body></html>")

        mock_get.side_effect = side_effect

        crawler = PoliteCrawler(
            base_url="http://example.com",
            out_dir=tmp_path,
            verified_targets=None,
            rate_limit_sec=0.0,
        )
        original = crawler.crawl()
        restored = CrawlManifest.from_dict(original.to_dict())

        assert restored.base_url == original.base_url
        assert len(restored.pages) == len(original.pages)


# ---------------------------------------------------------------------------
# Non-200 responses and network errors handled gracefully
# ---------------------------------------------------------------------------

class TestErrorHandling:
    @patch("requests.get")
    def test_non_200_page_skipped_gracefully(self, mock_get, tmp_path):
        """Non-200 responses are logged and skipped; crawl continues."""
        import requests as _req

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return _robots_allow_all()
            resp = Mock()
            resp.status_code = 404
            resp.headers = {}
            resp.iter_content = lambda chunk_size=8192: iter([b""])
            return resp

        mock_get.side_effect = side_effect

        crawler = PoliteCrawler(
            base_url="http://example.com",
            out_dir=tmp_path,
            verified_targets=None,
            rate_limit_sec=0.0,
        )
        manifest = crawler.crawl()
        # Should not raise; pages may be empty
        assert isinstance(manifest, CrawlManifest)

    @patch("requests.get")
    def test_network_error_skipped_gracefully(self, mock_get, tmp_path):
        """Network errors are logged and skipped; crawl completes."""
        import requests as _req

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return _robots_allow_all()
            raise _req.ConnectionError("refused")

        mock_get.side_effect = side_effect

        crawler = PoliteCrawler(
            base_url="http://example.com",
            out_dir=tmp_path,
            verified_targets=None,
            rate_limit_sec=0.0,
        )
        manifest = crawler.crawl()
        assert isinstance(manifest, CrawlManifest)
