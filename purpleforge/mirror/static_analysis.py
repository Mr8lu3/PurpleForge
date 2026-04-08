"""
purpleforge.mirror.static_analysis — pure static analysis passes on mirrored assets.

AUTHORIZED, VERIFIED TARGETS ONLY.  Defensive static analysis only.
No active exploitation, no form submission, no JS execution, no network calls.
All findings are heuristic; false positives are expected; manual review required.

Implemented passes
------------------
1. secret_scan         — regex-based detection of credentials and key material.
2. outdated_js_lib     — version-string detection for common JavaScript libraries.
3. missing_security_header — audit of HTTP response headers from the crawl manifest.
4. dom_sink_candidate  — heuristic detection of unsafe DOM sinks near URL-derived input.
   NOTE: This pass is highly false-positive prone.  Manual review required.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from purpleforge.analysis.findings_schema import Finding, dump_findings
from purpleforge.mirror.crawler import CrawlManifest, PageRecord
from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)

_SOURCE = "mirror_static"

# ---------------------------------------------------------------------------
# Pass 1: Secret scan
# ---------------------------------------------------------------------------

# Each tuple: (regex_pattern, category_label, severity, label)
_SECRET_PATTERNS: List[Tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "private_key", "high"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_access_key", "high"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "google_api_key", "medium"),
    (
        re.compile(r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'),
        "jwt_token",
        "medium",
    ),
    (
        re.compile(
            r'(?i)(?:api[_\-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9]{32,})',
            re.IGNORECASE,
        ),
        "generic_api_key",
        "medium",
    ),
    (
        re.compile(r'(?i)password\s*=\s*["\']?([^\s"\']{6,})', re.IGNORECASE),
        "plaintext_password",
        "medium",
    ),
]


def _scan_secrets(content: str, rel_path: str) -> List[Finding]:
    """Return secret-exposure findings for one file."""
    findings: List[Finding] = []
    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        for pattern, label, severity in _SECRET_PATTERNS:
            m = pattern.search(line)
            if m:
                snippet = line.strip()[:120]
                findings.append(
                    Finding(
                        source=_SOURCE,
                        category="secret_exposure",
                        title=f"Possible {label.replace('_', ' ')} found",
                        description=(
                            f"Heuristic pattern '{label}' matched in {rel_path} "
                            f"at line {lineno}. Manual review required — "
                            "false positives are possible."
                        ),
                        severity=severity,  # type: ignore[arg-type]
                        confidence="medium",
                        file_path=rel_path,
                        location=f"line {lineno}",
                        evidence={
                            "pattern_label": label,
                            "line_number": lineno,
                            "snippet": snippet,
                        },
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# Pass 2: Outdated JS library detection
# ---------------------------------------------------------------------------

# Map of library name (lower) -> minimum safe version tuple
_MIN_SAFE_VERSIONS: Dict[str, Tuple[int, ...]] = {
    "jquery": (3, 7, 0),
    "bootstrap": (5, 3, 0),
    "angular": (17, 0, 0),
    "angularjs": (1, 8, 3),
    "react": (18, 0, 0),
    "lodash": (4, 17, 21),
    "moment": (2, 30, 0),
    "underscore": (1, 13, 6),
}

_LIB_FILENAME_PATTERNS: Dict[str, re.Pattern[str]] = {
    lib: re.compile(
        rf"(?i)(?<![a-z]){re.escape(lib)}[.\-_](\d+\.\d+\.?\d*)", re.IGNORECASE
    )
    for lib in _MIN_SAFE_VERSIONS
}

# Inline banner comment patterns, e.g. /*! jQuery v3.6.0 */
_INLINE_BANNER_PATTERN = re.compile(
    r"/\*!?\s*([A-Za-z]+(?:JS|js)?)\s+v?(\d+\.\d+\.?\d*)",
    re.IGNORECASE,
)

# <script src="..."> extraction
_SCRIPT_SRC_PATTERN = re.compile(r'<script[^>]+src=["\']([^"\']+)', re.IGNORECASE)


def _version_tuple(version_str: str) -> Tuple[int, ...]:
    parts = re.split(r"[.\-]", version_str)
    result = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            break
    return tuple(result)


def _check_lib_version(
    lib: str, version_str: str, file_path: str, evidence_source: str
) -> Optional[Finding]:
    min_ver = _MIN_SAFE_VERSIONS.get(lib.lower())
    if min_ver is None:
        return None
    detected = _version_tuple(version_str)
    if not detected:
        return None
    if detected < min_ver:
        min_str = ".".join(str(x) for x in min_ver)
        return Finding(
            source=_SOURCE,
            category="outdated_js_lib",
            title=f"Outdated {lib} v{version_str} (min safe: {min_str})",
            description=(
                f"Library '{lib}' version {version_str} is below the minimum "
                f"recommended version {min_str}. Older versions may contain "
                "known vulnerabilities. Manual review required."
            ),
            severity="medium",
            confidence="medium",
            file_path=file_path,
            evidence={
                "library": lib,
                "detected_version": version_str,
                "min_safe_version": min_str,
                "source": evidence_source,
            },
        )
    return None


def _scan_outdated_libs(content: str, rel_path: str) -> List[Finding]:
    """Detect outdated JS libraries in HTML/JS file content."""
    findings: List[Finding] = []

    # Check <script src> filenames for known library patterns
    for src_match in _SCRIPT_SRC_PATTERN.finditer(content):
        src = src_match.group(1)
        for lib, pat in _LIB_FILENAME_PATTERNS.items():
            m = pat.search(src)
            if m:
                f = _check_lib_version(lib, m.group(1), rel_path, f"script src: {src}")
                if f:
                    findings.append(f)

    # Check inline banner comments
    for banner in _INLINE_BANNER_PATTERN.finditer(content):
        lib_raw, ver = banner.group(1), banner.group(2)
        lib_lower = lib_raw.lower().rstrip("js")
        if lib_lower in _MIN_SAFE_VERSIONS:
            f = _check_lib_version(
                lib_lower, ver, rel_path, f"inline comment: {banner.group(0)[:60]}"
            )
            if f:
                findings.append(f)
        elif lib_raw.lower() in _MIN_SAFE_VERSIONS:
            f = _check_lib_version(
                lib_raw.lower(), ver, rel_path, f"inline comment: {banner.group(0)[:60]}"
            )
            if f:
                findings.append(f)

    return findings


# ---------------------------------------------------------------------------
# Pass 3: Security header audit
# ---------------------------------------------------------------------------

_REQUIRED_HEADERS = [
    ("content-security-policy", "CSP", "Protects against XSS and data injection."),
    ("x-frame-options", "X-Frame-Options", "Protects against clickjacking."),
    ("x-content-type-options", "X-Content-Type-Options", "Prevents MIME-sniffing."),
    ("strict-transport-security", "HSTS", "Enforces HTTPS connections."),
    ("referrer-policy", "Referrer-Policy", "Controls referrer information leakage."),
]


def _scan_security_headers(pages: List[PageRecord]) -> List[Finding]:
    """Emit a finding per URL per missing security-relevant response header."""
    findings: List[Finding] = []
    for page in pages:
        lower_headers = {k.lower(): v for k, v in page.headers.items()}
        for header_key, header_label, rationale in _REQUIRED_HEADERS:
            if header_key not in lower_headers:
                findings.append(
                    Finding(
                        source=_SOURCE,
                        category="missing_security_header",
                        title=f"Missing {header_label} header",
                        description=(
                            f"Response for {page.url} is missing the "
                            f"'{header_label}' ({header_key}) header. "
                            f"{rationale} Manual review required."
                        ),
                        severity="low",
                        confidence="high",
                        file_path=page.local_path,
                        location=page.url,
                        evidence={
                            "url": page.url,
                            "missing_header": header_key,
                            "rationale": rationale,
                            "present_headers": list(lower_headers.keys()),
                        },
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# Pass 4: DOM sink detection (static heuristic)
# ---------------------------------------------------------------------------
# NOTE: This pass is highly false-positive prone.  It looks for unsafe sink
# patterns AND URL-derived input patterns co-occurring in the same file.
# A positive result does NOT confirm exploitability.  Manual review required.

_SINK_PATTERNS = [
    re.compile(r"innerHTML\s*=", re.IGNORECASE),
    re.compile(r"document\.write\s*\(", re.IGNORECASE),
    re.compile(r"\beval\s*\(", re.IGNORECASE),
    re.compile(r"\bFunction\s*\(", re.IGNORECASE),
]

_URL_INPUT_PATTERNS = [
    re.compile(r"location\.search", re.IGNORECASE),
    re.compile(r"location\.hash", re.IGNORECASE),
    re.compile(r"document\.URL", re.IGNORECASE),
    re.compile(r"location\.href", re.IGNORECASE),
]


def _scan_dom_sinks(content: str, rel_path: str) -> List[Finding]:
    """
    Heuristic DOM sink detection: sink pattern + URL-derived input in same file.

    NOTE: False-positive prone.  Presence of both patterns does not confirm
    exploitability — a developer may sanitise the input before passing it to
    the sink.  Manual review is required for every result.
    """
    findings: List[Finding] = []

    matched_sinks = [pat.pattern for pat in _SINK_PATTERNS if pat.search(content)]
    matched_inputs = [pat.pattern for pat in _URL_INPUT_PATTERNS if pat.search(content)]

    if matched_sinks and matched_inputs:
        findings.append(
            Finding(
                source=_SOURCE,
                category="dom_sink_candidate",
                title="Potential DOM-based XSS sink with URL-derived input",
                description=(
                    f"File {rel_path} contains both unsafe DOM sink pattern(s) "
                    f"and URL-derived input pattern(s). This is a heuristic signal "
                    "only — false positives are common. Manual code review is "
                    "required to determine exploitability. "
                    "No exploitation was attempted."
                ),
                severity="medium",
                confidence="low",
                file_path=rel_path,
                evidence={
                    "matched_sinks": matched_sinks,
                    "matched_inputs": matched_inputs,
                    "note": (
                        "Heuristic; false-positive prone; manual review required; "
                        "no exploitation performed."
                    ),
                },
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run_static_analysis(
    mirror_dir: Path,
    manifest: CrawlManifest,
    *,
    out_path: Optional[Path] = None,
) -> List[Finding]:
    """
    Run all static analysis passes over a mirror directory.

    Authorized, verified targets only.  Defensive static analysis only.
    No network calls made.  No exploitation performed.  Manual review required.

    Parameters
    ----------
    mirror_dir:
        Root of the mirror directory (contains assets/).
    manifest:
        CrawlManifest produced by PoliteCrawler.crawl().
    out_path:
        If provided, write findings JSON here.  Defaults to
        mirror_dir/mirror_findings.json.

    Returns
    -------
    List of Finding objects.
    """
    findings: List[Finding] = []

    for page in manifest.pages:
        local = mirror_dir / page.local_path
        if not local.exists():
            continue

        try:
            content = local.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            logger.warning("Could not read %s for analysis: %s", local, exc)
            continue

        content_type = page.content_type.lower()
        is_html = "html" in content_type or local.suffix.lower() in (".html", ".htm")
        is_js = "javascript" in content_type or local.suffix.lower() in (".js", ".mjs")

        rel_path = page.local_path

        # Pass 1: secrets — run on any text file
        findings.extend(_scan_secrets(content, rel_path))

        # Pass 2: outdated JS libs — run on HTML (for <script src>) and JS (banners)
        if is_html or is_js:
            findings.extend(_scan_outdated_libs(content, rel_path))

        # Pass 4: DOM sinks — run on HTML and JS
        if is_html or is_js:
            findings.extend(_scan_dom_sinks(content, rel_path))

    # Pass 3: security headers — operates on manifest page records directly
    findings.extend(_scan_security_headers(manifest.pages))

    if out_path is None:
        out_path = mirror_dir / "mirror_findings.json"

    dump_findings(findings, out_path)
    logger.info(
        "Static analysis complete: %d findings written to %s",
        len(findings),
        out_path,
    )
    return findings
