"""
purpleforge.mirror — site mirror and static vulnerability hunt subpackage.

AUTHORIZED, VERIFIED TARGETS ONLY.  Polite crawl (robots.txt respected,
rate-limited, depth-capped, same-origin only).  Defensive static analysis
only — no active exploitation, no form submission, no JS execution, no
authenticated crawling.  Manual review required for all findings.

Public surface
--------------
PoliteCrawler   — BFS HTTP crawler with ownership gate and robots.txt guard.
run_static_analysis — Pure-function entry point for static analysis passes.
MirrorDiff      — Diff two crawl manifests and emit informational findings.
MirrorError     — Raised when the ownership gate or robots gate blocks crawl.
"""

from purpleforge.mirror.crawler import PoliteCrawler, CrawlManifest, PageRecord
from purpleforge.mirror.static_analysis import run_static_analysis
from purpleforge.mirror.differential import MirrorDiff, DiffResult
from purpleforge.utils.exceptions import MirrorError

__all__ = [
    "PoliteCrawler",
    "CrawlManifest",
    "PageRecord",
    "run_static_analysis",
    "MirrorDiff",
    "DiffResult",
    "MirrorError",
]
