"""
Phase 9 — CI quality-gates / research-artifact packaging.

Tests that `make artifact` produces a well-formed, complete Zenodo-ready zip.

The test is marked @pytest.mark.slow so it can be excluded with:
    pytest -m "not slow"
It IS included in the default suite.

Skip policy:
    - Windows (os.name == "nt") AND make unavailable → skip.
    - Linux/macOS with make unavailable → skip.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Optional

import pytest

# ---------------------------------------------------------------------------
# Helper: locate the repo root (parent of the tests/ directory).
# ---------------------------------------------------------------------------
REPO_ROOT: Path = Path(__file__).parent.parent


def _find_make() -> Optional[str]:
    """Return the path to GNU make, or None if not on PATH."""
    return shutil.which("make")


def _make_available() -> bool:
    return _find_make() is not None


# ---------------------------------------------------------------------------
# Skip logic
# ---------------------------------------------------------------------------
_SKIP_REASON: Optional[str] = None

if os.name == "nt" and not _make_available():
    _SKIP_REASON = "Windows host and 'make' not found on PATH; install Git Bash or WSL."
elif not _make_available():
    _SKIP_REASON = "'make' not found on PATH."

skip_if_no_make = pytest.mark.skipif(
    _SKIP_REASON is not None,
    reason=_SKIP_REASON or "",
)


# ---------------------------------------------------------------------------
# Fixture: temporary copy of the repo for an isolated build
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def tmp_repo(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """
    Copy the repo root into a temp directory so `make artifact` does not
    pollute the developer's working tree.
    """
    dest: Path = tmp_path_factory.mktemp("purpleforge_repo")
    shutil.copytree(
        str(REPO_ROOT),
        str(dest / "purpleforge"),
        ignore=shutil.ignore_patterns(
            ".git",
            ".venv*",
            "dist",
            "__pycache__",
            "*.egg-info",
            ".pytest_cache",
        ),
    )
    return dest / "purpleforge"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
@pytest.mark.slow
@skip_if_no_make
def test_artifact_zip_is_created(tmp_repo: Path) -> None:
    """make artifact must exit 0 and produce dist/purpleforge_artifact.zip."""
    result = subprocess.run(
        [_find_make(), "artifact"],
        cwd=str(tmp_repo),
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, (
        f"make artifact failed (exit {result.returncode}).\n"
        f"STDOUT:\n{result.stdout}\n"
        f"STDERR:\n{result.stderr}"
    )
    zip_path = tmp_repo / "dist" / "purpleforge_artifact.zip"
    assert zip_path.exists(), f"Expected zip not found at {zip_path}"


@pytest.mark.slow
@skip_if_no_make
def test_artifact_zip_contains_required_files(tmp_repo: Path) -> None:
    """The artifact zip must contain the canonical set of required files."""
    zip_path = tmp_repo / "dist" / "purpleforge_artifact.zip"
    if not zip_path.exists():
        pytest.skip("Zip not yet built; run test_artifact_zip_is_created first.")

    required_members = [
        "artifact/purpleforge/__init__.py",
        "artifact/REPRODUCIBILITY.md",
        "artifact/CITATION.cff",
        "artifact/requirements.lock",
    ]

    with zipfile.ZipFile(zip_path, "r") as zf:
        names = set(zf.namelist())

    for member in required_members:
        assert member in names, (
            f"Required member '{member}' missing from artifact zip.\n"
            f"Zip contains {len(names)} files."
        )


@pytest.mark.slow
@skip_if_no_make
def test_artifact_sha256_is_printed(tmp_repo: Path) -> None:
    """make artifact stdout must contain a SHA-256 hex digest."""
    result = subprocess.run(
        [_find_make(), "artifact"],
        cwd=str(tmp_repo),
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, "make artifact failed"
    combined_output = result.stdout + result.stderr
    # SHA-256 is a 64-character hex string.
    import re
    sha_match = re.search(r"\b[0-9a-f]{64}\b", combined_output)
    assert sha_match is not None, (
        "No SHA-256 digest found in make artifact output.\n"
        f"Output:\n{combined_output}"
    )


@pytest.mark.slow
@skip_if_no_make
def test_artifact_sha256_matches_zip(tmp_repo: Path) -> None:
    """SHA-256 printed by make must match the computed hash of the zip."""
    import re

    result = subprocess.run(
        [_find_make(), "artifact"],
        cwd=str(tmp_repo),
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0

    combined_output = result.stdout + result.stderr
    sha_match = re.search(r"\b([0-9a-f]{64})\b", combined_output)
    assert sha_match is not None, "No SHA-256 found in output"
    printed_sha = sha_match.group(1)

    zip_path = tmp_repo / "dist" / "purpleforge_artifact.zip"
    actual_sha = hashlib.sha256(zip_path.read_bytes()).hexdigest()

    assert printed_sha == actual_sha, (
        f"Printed SHA ({printed_sha}) does not match computed SHA ({actual_sha})"
    )


@pytest.mark.slow
@skip_if_no_make
def test_requirements_lock_is_non_empty(tmp_repo: Path) -> None:
    """requirements.lock inside the zip must list at least 5 packages."""
    zip_path = tmp_repo / "dist" / "purpleforge_artifact.zip"
    if not zip_path.exists():
        pytest.skip("Zip not yet built.")

    with zipfile.ZipFile(zip_path, "r") as zf:
        try:
            lock_content = zf.read("artifact/requirements.lock").decode("utf-8")
        except KeyError:
            pytest.fail("requirements.lock not found inside the artifact zip")

    lines = [ln for ln in lock_content.splitlines() if ln.strip() and not ln.startswith("#")]
    assert len(lines) >= 5, (
        f"requirements.lock looks too short ({len(lines)} lines); "
        "expected at least 5 pinned packages."
    )
