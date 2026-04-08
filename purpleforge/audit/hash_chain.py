"""
purpleforge.audit.hash_chain — tamper-evident append-only audit log.

Each log entry is linked to its predecessor via a SHA-256 chain: any
post-write mutation of a line (or deletion / reordering of lines) is
detectable by re-walking the chain.  The log is human-readable JSONL.

Forensic integrity note: this mechanism provides *integrity evidence* for
authorised security assessments.  It does not provide confidentiality
(no encryption-at-rest) or non-repudiation (no external signing keys).
Those properties are out of scope per PurpleForge's ethical design.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Tuple

logger = logging.getLogger(__name__)

_ZERO_HASH = "0" * 64


def _canonical(payload: Dict[str, Any]) -> str:
    """Return canonical JSON for hashing (sorted keys, no extra whitespace)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _compute_hash(prev_hash: str, payload: Dict[str, Any], seq: int, ts: str) -> str:
    """SHA-256(prev_hash + canonical_json(payload) + str(seq) + ts)."""
    material = prev_hash + _canonical(payload) + str(seq) + ts
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class HashChainLog:
    """
    Append-only hash-chained audit log stored as JSONL.

    Line format (one JSON object per line)::

        {"seq": 0, "ts": "2026-...", "prev_hash": "000...", "payload": {...}, "hash": "abc..."}

    Parameters
    ----------
    log_path:
        Path to the ``.jsonl`` file.  Created on first write.

    Attributes
    ----------
    tampered:
        Set during ``__init__`` by calling :meth:`verify`.  *True* if the
        existing file fails integrity checks; *False* otherwise (including
        when the file is new / empty).
    """

    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self._seq: int = 0
        self._prev_hash: str = _ZERO_HASH
        self.tampered: bool = False

        if log_path.exists():
            # Recover state from last line so we can extend.
            last = self._read_last_line()
            if last is not None:
                self._seq = last.get("seq", 0) + 1
                self._prev_hash = last.get("hash", _ZERO_HASH)

            # Integrity check — sets self.tampered.
            ok, _bad = verify_log(log_path)
            if not ok:
                self.tampered = True
                logger.warning(
                    "HashChainLog: existing log at %s failed integrity check.", log_path
                )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def append(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Append one entry to the log.

        Assigns the next sequence number, computes the chain hash, writes the
        line, and calls ``flush()`` + ``fsync()`` before returning.

        Returns the complete entry dict (including ``seq``, ``ts``, ``hash``).
        """
        ts = datetime.now(timezone.utc).isoformat()
        seq = self._seq
        prev_hash = self._prev_hash

        entry_hash = _compute_hash(prev_hash, payload, seq, ts)

        entry: Dict[str, Any] = {
            "seq": seq,
            "ts": ts,
            "prev_hash": prev_hash,
            "payload": payload,
            "hash": entry_hash,
        }

        line = json.dumps(entry, ensure_ascii=False) + "\n"

        # Atomic-ish: open in append mode, write, flush, fsync.
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass  # Some platforms / file systems don't support fsync

        # Advance state for next append.
        self._seq += 1
        self._prev_hash = entry_hash

        return entry

    def verify(self) -> bool:
        """
        Re-walk the log and verify the hash chain.

        Returns *True* if all entries are intact, *False* on the first
        inconsistency (or if the file is missing).
        """
        ok, _ = verify_log(self.log_path)
        return ok

    def entries(self) -> Iterator[Dict[str, Any]]:
        """Iterate over all log entries in order."""
        if not self.log_path.exists():
            return
        with open(self.log_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as exc:
                    logger.warning("HashChainLog: malformed line: %s", exc)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _read_last_line(self) -> Optional[Dict[str, Any]]:
        """Return the parsed last JSONL line, or None."""
        last_line: Optional[str] = None
        try:
            with open(self.log_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    s = line.strip()
                    if s:
                        last_line = s
        except Exception as exc:
            logger.warning("HashChainLog: could not read last line: %s", exc)
            return None

        if last_line is None:
            return None
        try:
            return json.loads(last_line)
        except json.JSONDecodeError:
            return None


# ---------------------------------------------------------------------------
# Module-level helper
# ---------------------------------------------------------------------------


def verify_log(path: Path) -> Tuple[bool, Optional[int]]:
    """
    Verify the hash chain of a JSONL audit log file.

    Parameters
    ----------
    path:
        Path to the ``.jsonl`` log file.

    Returns
    -------
    ``(True, None)`` if the chain is intact (or the file is empty).
    ``(False, first_bad_seq)`` on the first inconsistency.
    """
    if not path.exists():
        return True, None  # Empty / new log is considered intact.

    expected_prev = _ZERO_HASH
    expected_seq = 0

    try:
        with open(path, "r", encoding="utf-8") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    seq = expected_seq
                    logger.warning("verify_log: JSON parse error at seq ~%d", seq)
                    return False, seq

                seq: int = entry.get("seq", -1)
                ts: str = entry.get("ts", "")
                prev_hash: str = entry.get("prev_hash", "")
                payload: Dict[str, Any] = entry.get("payload", {})
                stored_hash: str = entry.get("hash", "")

                # Check sequence continuity.
                if seq != expected_seq:
                    logger.warning(
                        "verify_log: seq gap — expected %d, got %d",
                        expected_seq,
                        seq,
                    )
                    return False, seq

                # Check prev_hash linkage.
                if prev_hash != expected_prev:
                    logger.warning(
                        "verify_log: prev_hash mismatch at seq %d", seq
                    )
                    return False, seq

                # Recompute hash.
                recomputed = _compute_hash(prev_hash, payload, seq, ts)
                if recomputed != stored_hash:
                    logger.warning(
                        "verify_log: hash mismatch at seq %d", seq
                    )
                    return False, seq

                expected_prev = stored_hash
                expected_seq += 1

    except Exception as exc:
        logger.warning("verify_log: unexpected error: %s", exc)
        return False, expected_seq

    return True, None
