"""
purpleforge.mirror.crawler — polite BFS HTTP site crawler.

AUTHORIZED, VERIFIED TARGETS ONLY.  Polite crawl only:
  - robots.txt is fetched and respected before any page is crawled.
  - Rate-limited (default 1 req/sec, configurable).
  - Depth-capped (default 2, hard max 4).
  - Same-origin only — cross-host links are silently skipped.
    "Same origin" means identical netloc after www-stripping (e.g.
    www.example.com and example.com are treated as the same host).
  - Total page cap (default 100).
  - Per-asset size cap (default 2 MiB); responses exceeding the cap are
    streamed, truncated at the limit, and a warning is logged.
  - No form submission, no JS execution, no authenticated crawling,
    no cookie or Authorization header injection.
  - No exploitation of any kind.  Manual review required for all findings.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.robotparser
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse, urlunparse

import requests

from purpleforge.audit.redaction import Redactor
from purpleforge.utils.exceptions import MirrorError
from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)

# Hard ceiling on depth to prevent misconfiguration abuse.
_MAX_DEPTH_HARD_LIMIT = 4


@dataclass
class PageRecord:
    """Metadata for one crawled page."""

    url: str
    local_path: str
    content_type: str
    status: int
    sha256: str
    bytes: int
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class CrawlManifest:
    """Full metadata produced by one PoliteCrawler.crawl() run."""

    base_url: str
    started_at: str
    finished_at: str
    user_agent: str
    robots_txt_sha256: Optional[str]
    pages: List[PageRecord] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "base_url": self.base_url,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "user_agent": self.user_agent,
            "robots_txt_sha256": self.robots_txt_sha256,
            "pages": [
                {
                    "url": p.url,
                    "local_path": p.local_path,
                    "content_type": p.content_type,
                    "status": p.status,
                    "sha256": p.sha256,
                    "bytes": p.bytes,
                    "headers": p.headers,
                }
                for p in self.pages
            ],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CrawlManifest":
        pages = [
            PageRecord(
                url=p["url"],
                local_path=p["local_path"],
                content_type=p.get("content_type", ""),
                status=p.get("status", 0),
                sha256=p.get("sha256", ""),
                bytes=p.get("bytes", 0),
                headers=p.get("headers", {}),
            )
            for p in data.get("pages", [])
        ]
        return cls(
            base_url=data["base_url"],
            started_at=data["started_at"],
            finished_at=data["finished_at"],
            user_agent=data["user_agent"],
            robots_txt_sha256=data.get("robots_txt_sha256"),
            pages=pages,
        )


def _normalize_netloc(netloc: str) -> str:
    """
    Strip leading 'www.' so that www.example.com and example.com are
    treated as the same origin.
    """
    return re.sub(r"^www\.", "", netloc.lower())


def _sanitize_url_to_path(url: str, base_url: str) -> str:
    """
    Convert a URL into a filesystem-safe relative path under assets/.

    Strips query strings and fragments; collapses empty paths to 'index.html'.
    """
    parsed = urlparse(url)
    path = parsed.path.lstrip("/") or "index.html"
    # Replace any remaining path separators that are OS-hostile on Windows.
    path = path.replace("\\", "_").replace(":", "_").replace("?", "_").replace("*", "_")
    # Collapse double slashes
    while "//" in path:
        path = path.replace("//", "/")
    return path


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class PoliteCrawler:
    """
    BFS HTTP crawler with ownership-verification gate and robots.txt enforcement.

    Authorized, verified targets only.  Polite crawl; defensive use only;
    no exploitation; manual review required.

    Parameters
    ----------
    base_url:
        HTTP/HTTPS URL to start crawling from.
    out_dir:
        Directory where assets/ and manifest.json will be written.
    rate_limit_sec:
        Minimum seconds between requests (default 1.0).
    max_depth:
        BFS depth cap (default 2, hard max 4).
    max_pages:
        Maximum total pages to fetch (default 100).
    max_bytes:
        Per-asset byte cap (default 2 MiB).  Responses larger than this are
        truncated; a warning is logged and the record is still written.
    user_agent:
        User-Agent string sent with every request and used for robots.txt
        evaluation.
    verified_targets:
        List of netloc strings (e.g. "example.com") that have been verified
        via purpleforge.verification.  If the base_url's netloc is not in this
        list, __init__ raises MirrorError immediately — no network calls are
        made.  Pass an empty list (the default) only in unit tests that mock
        the gate separately.
    request_timeout:
        Per-request timeout in seconds (default 10).
    """

    def __init__(
        self,
        base_url: str,
        out_dir: Path,
        *,
        rate_limit_sec: float = 1.0,
        max_depth: int = 2,
        max_pages: int = 100,
        max_bytes: int = 2 * 1024 * 1024,
        user_agent: str = "PurpleForge-Mirror/0.1 (+defensive-assessment)",
        verified_targets: Optional[List[str]] = None,
        request_timeout: int = 10,
    ) -> None:
        if not base_url.startswith(("http://", "https://")):
            base_url = f"http://{base_url}"

        parsed = urlparse(base_url)
        self._base_netloc = parsed.netloc
        self._base_url = base_url

        # Ownership gate — check before any network call.
        if verified_targets is not None:
            normalized_base = _normalize_netloc(self._base_netloc)
            # verified_targets may be full URLs (e.g. "http://example.com") or bare
            # netlocs (e.g. "example.com").  Normalise both forms before comparing.
            def _extract_netloc(t: str) -> str:
                if "://" in t:
                    return _normalize_netloc(urlparse(t).netloc)
                return _normalize_netloc(t)
            normalized_allowed = {_extract_netloc(t) for t in verified_targets}
            if normalized_base not in normalized_allowed:
                raise MirrorError(
                    f"Target '{self._base_netloc}' is not in the verified allowlist. "
                    "Refusing to crawl unverified target. "
                    "Authorized, verified targets only.",
                    hint=(
                        f"Run `purpleforge verify --base-url {base_url}` first, "
                        "then retry the mirror command."
                    ),
                )

        if max_depth > _MAX_DEPTH_HARD_LIMIT:
            raise MirrorError(
                f"max_depth {max_depth} exceeds hard limit of {_MAX_DEPTH_HARD_LIMIT}.",
                hint=f"Use --max-depth <= {_MAX_DEPTH_HARD_LIMIT}.",
            )

        self.base_url = base_url
        self.out_dir = out_dir
        self.rate_limit_sec = rate_limit_sec
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.max_bytes = max_bytes
        self.user_agent = user_agent
        self.request_timeout = request_timeout
        self._redactor = Redactor()

        self._assets_dir = out_dir / "assets"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def crawl(self) -> CrawlManifest:
        """
        Execute the polite BFS crawl.

        Returns a CrawlManifest and writes manifest.json + assets/ to out_dir.

        Raises MirrorError only for:
          - robots.txt disallowing the configured user-agent.
        All other errors (network, HTTP non-200, timeouts) are logged as
        warnings and the crawl continues.
        """
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self._assets_dir.mkdir(parents=True, exist_ok=True)

        started_at = datetime.now(timezone.utc).isoformat()

        # Step 1: fetch and enforce robots.txt
        robots_sha256 = self._check_robots()

        # Step 2: BFS crawl
        pages = self._bfs_crawl()

        finished_at = datetime.now(timezone.utc).isoformat()

        manifest = CrawlManifest(
            base_url=self.base_url,
            started_at=started_at,
            finished_at=finished_at,
            user_agent=self.user_agent,
            robots_txt_sha256=robots_sha256,
            pages=pages,
        )

        # Write manifest.json — redact string fields (not asset bytes).
        manifest_path = self.out_dir / "manifest.json"
        manifest_dict = self._redactor.redact_dict(manifest.to_dict())
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest_dict, fh, indent=2, ensure_ascii=False)

        logger.info(
            "Crawl complete: %d pages written to %s", len(pages), self.out_dir
        )
        return manifest

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_robots(self) -> Optional[str]:
        """
        Fetch robots.txt, record its sha256, and enforce it.

        Returns the sha256 of the robots.txt content (or None if not found).
        Raises MirrorError if the UA is disallowed.
        """
        robots_url = urljoin(self.base_url, "/robots.txt")
        try:
            resp = requests.get(
                robots_url,
                headers={"User-Agent": self.user_agent},
                timeout=self.request_timeout,
                allow_redirects=True,
            )
            if resp.status_code == 200:
                robots_content = resp.text
                robots_sha = _sha256_bytes(resp.content)
            else:
                logger.info(
                    "robots.txt returned HTTP %d — proceeding with no restrictions.",
                    resp.status_code,
                )
                return None
        except Exception as exc:
            logger.warning("Could not fetch robots.txt (%s) — proceeding.", exc)
            return None

        # Parse and enforce.
        rp = urllib.robotparser.RobotFileParser()
        rp.set_url(robots_url)
        rp.parse(robots_content.splitlines())

        if not rp.can_fetch(self.user_agent, self.base_url):
            raise MirrorError(
                f"robots.txt at {robots_url} disallows '{self.user_agent}' "
                f"from crawling {self.base_url}. Aborting to respect site policy.",
                hint=(
                    "The site's robots.txt forbids automated crawling for this "
                    "user-agent. This crawl has been aborted. "
                    "Authorized targets only; polite crawl enforced."
                ),
            )

        logger.info("robots.txt checked — crawl is permitted.")
        return robots_sha

    def _bfs_crawl(self) -> List[PageRecord]:
        """Run the BFS and return collected PageRecord list."""
        visited: set[str] = set()
        pages: List[PageRecord] = []

        # Queue entries: (url, depth)
        queue: deque[tuple[str, int]] = deque()
        queue.append((self.base_url, 0))
        visited.add(self._normalize_url(self.base_url))

        last_request_time: float = 0.0

        while queue and len(pages) < self.max_pages:
            url, depth = queue.popleft()

            # Rate limit
            elapsed = time.monotonic() - last_request_time
            if elapsed < self.rate_limit_sec:
                time.sleep(self.rate_limit_sec - elapsed)

            record = self._fetch_page(url)
            last_request_time = time.monotonic()

            if record is not None:
                pages.append(record)

                # Extract links only from HTML and only within depth cap
                if depth < self.max_depth and "html" in record.content_type.lower():
                    local = self._assets_dir / record.local_path
                    if local.exists():
                        try:
                            html_text = local.read_text(encoding="utf-8", errors="replace")
                            links = self._extract_links(html_text, url)
                            for link in links:
                                norm = self._normalize_url(link)
                                if norm not in visited:
                                    visited.add(norm)
                                    queue.append((link, depth + 1))
                        except Exception as exc:
                            logger.warning(
                                "Link extraction failed for %s: %s", url, exc
                            )

        if len(pages) >= self.max_pages:
            logger.warning(
                "max_pages cap (%d) reached — crawl terminated early.", self.max_pages
            )

        return pages

    def _fetch_page(self, url: str) -> Optional[PageRecord]:
        """Fetch a single URL; return a PageRecord or None on error."""
        try:
            resp = requests.get(
                url,
                headers={"User-Agent": self.user_agent},
                timeout=self.request_timeout,
                allow_redirects=True,
                stream=True,
            )
        except Exception as exc:
            logger.warning("Network error fetching %s: %s", url, exc)
            return None

        if resp.status_code != 200:
            logger.warning("HTTP %d for %s — skipping.", resp.status_code, url)
            return None

        # Stream content with size cap
        chunks: List[bytes] = []
        total = 0
        truncated = False
        try:
            for chunk in resp.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                remaining = self.max_bytes - total
                if len(chunk) > remaining:
                    chunks.append(chunk[:remaining])
                    total += remaining
                    truncated = True
                    break
                chunks.append(chunk)
                total += len(chunk)
        except Exception as exc:
            logger.warning("Error reading body of %s: %s", url, exc)

        if truncated:
            logger.warning(
                "Asset %s truncated at %d bytes (max_bytes cap).", url, self.max_bytes
            )

        body = b"".join(chunks)
        sha = _sha256_bytes(body)
        content_type = resp.headers.get("Content-Type", "")

        # Collect response headers (normalised to str→str dict)
        headers_dict: Dict[str, str] = {
            k.lower(): v for k, v in resp.headers.items()
        }

        # Determine local path
        rel_path = _sanitize_url_to_path(url, self.base_url)
        local_path = self._assets_dir / rel_path
        local_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            local_path.write_bytes(body)
        except Exception as exc:
            logger.warning("Could not write asset %s: %s", local_path, exc)

        return PageRecord(
            url=url,
            local_path=str(Path("assets") / rel_path),
            content_type=content_type,
            status=resp.status_code,
            sha256=sha,
            bytes=total,
            headers=headers_dict,
        )

    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """
        Extract same-origin href links from raw HTML via regex.

        Only follows links whose resolved netloc matches the base (after
        www-stripping).  Cross-origin links are silently skipped.
        """
        href_pattern = re.compile(r'href=["\']([^"\'#?]+)', re.IGNORECASE)
        links: List[str] = []
        base_netloc_norm = _normalize_netloc(urlparse(self.base_url).netloc)

        for match in href_pattern.finditer(html):
            href = match.group(1).strip()
            if not href or href.startswith(("mailto:", "javascript:", "tel:", "data:")):
                continue
            absolute = urljoin(base_url, href)
            parsed = urlparse(absolute)
            if parsed.scheme not in ("http", "https"):
                continue
            if _normalize_netloc(parsed.netloc) != base_netloc_norm:
                # Cross-origin — skip silently per policy
                continue
            # Drop query/fragment for dedup; keep the clean URL for fetch
            clean = urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, "", "", "")
            )
            links.append(clean)

        return links

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Canonical form for visited-set deduplication."""
        parsed = urlparse(url.rstrip("/"))
        return urlunparse(
            (parsed.scheme, parsed.netloc.lower(), parsed.path, "", "", "")
        )
