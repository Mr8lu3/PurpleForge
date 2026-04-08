"""Tests for purpleforge.audit.hash_chain."""

import json
import tempfile
from pathlib import Path

import pytest

from purpleforge.audit.hash_chain import HashChainLog, verify_log, _ZERO_HASH


@pytest.fixture
def tmp_log(tmp_path):
    return tmp_path / "audit.log.jsonl"


class TestHashChainLog:
    """Unit tests for HashChainLog."""

    def test_first_entry_uses_zero_prev_hash(self, tmp_log):
        chain = HashChainLog(tmp_log)
        entry = chain.append({"event": "test"})
        assert entry["prev_hash"] == _ZERO_HASH
        assert entry["seq"] == 0

    def test_second_entry_links_to_first(self, tmp_log):
        chain = HashChainLog(tmp_log)
        e0 = chain.append({"event": "a"})
        e1 = chain.append({"event": "b"})
        assert e1["prev_hash"] == e0["hash"]
        assert e1["seq"] == 1

    def test_append_and_verify_intact(self, tmp_log):
        chain = HashChainLog(tmp_log)
        for i in range(5):
            chain.append({"event": "step", "i": i})
        assert chain.verify() is True

    def test_tamper_middle_line_verify_false(self, tmp_log):
        chain = HashChainLog(tmp_log)
        for i in range(5):
            chain.append({"event": "step", "i": i})

        # Read lines, tamper line 2 (seq=2)
        lines = tmp_log.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[2])
        entry["payload"]["tampered"] = True
        lines[2] = json.dumps(entry)
        tmp_log.write_text("\n".join(lines) + "\n", encoding="utf-8")

        ok, first_bad = verify_log(tmp_log)
        assert ok is False
        # The tampered line is seq=2
        assert first_bad == 2

    def test_verify_log_returns_first_bad_seq(self, tmp_log):
        chain = HashChainLog(tmp_log)
        for i in range(4):
            chain.append({"event": "x", "i": i})

        lines = tmp_log.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[1])
        entry["payload"]["evil"] = True
        lines[1] = json.dumps(entry)
        tmp_log.write_text("\n".join(lines) + "\n", encoding="utf-8")

        ok, first_bad = verify_log(tmp_log)
        assert ok is False
        assert first_bad == 1

    def test_empty_log_verify_intact(self, tmp_log):
        tmp_log.write_text("", encoding="utf-8")
        ok, first_bad = verify_log(tmp_log)
        assert ok is True
        assert first_bad is None

    def test_missing_log_verify_intact(self, tmp_path):
        missing = tmp_path / "no_such_file.jsonl"
        ok, first_bad = verify_log(missing)
        assert ok is True
        assert first_bad is None

    def test_reopen_and_extend(self, tmp_log):
        """Reopening an existing log continues the sequence."""
        chain1 = HashChainLog(tmp_log)
        chain1.append({"event": "a"})
        chain1.append({"event": "b"})

        chain2 = HashChainLog(tmp_log)
        chain2.append({"event": "c"})

        # All three entries should verify
        ok, _ = verify_log(tmp_log)
        assert ok is True

        # seq=2 should link to the last hash of the first session
        lines = tmp_log.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 3
        e2 = json.loads(lines[2])
        e1 = json.loads(lines[1])
        assert e2["prev_hash"] == e1["hash"]
        assert e2["seq"] == 2

    def test_payload_key_order_invariant(self, tmp_log):
        """Canonical JSON means key order does not affect hash."""
        chain = HashChainLog(tmp_log)
        e = chain.append({"z": 1, "a": 2, "m": 3})
        assert chain.verify() is True
        # The hash stored should be deterministic regardless of insertion order
        assert len(e["hash"]) == 64

    def test_entries_iterator(self, tmp_log):
        chain = HashChainLog(tmp_log)
        for i in range(3):
            chain.append({"seq_check": i})
        entries = list(chain.entries())
        assert len(entries) == 3
        for idx, entry in enumerate(entries):
            assert entry["seq"] == idx

    def test_tampered_flag_set_on_reopen(self, tmp_log):
        chain = HashChainLog(tmp_log)
        chain.append({"event": "first"})

        lines = tmp_log.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[0])
        entry["hash"] = "a" * 64  # corrupt the hash
        lines[0] = json.dumps(entry)
        tmp_log.write_text("\n".join(lines) + "\n", encoding="utf-8")

        chain2 = HashChainLog(tmp_log)
        assert chain2.tampered is True


class TestVerifyLog:
    """Module-level verify_log function tests."""

    def test_intact_chain(self, tmp_log):
        chain = HashChainLog(tmp_log)
        for i in range(3):
            chain.append({"n": i})
        ok, bad = verify_log(tmp_log)
        assert ok is True
        assert bad is None

    def test_truncated_hash_detected(self, tmp_log):
        chain = HashChainLog(tmp_log)
        chain.append({"n": 0})
        chain.append({"n": 1})

        lines = tmp_log.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[0])
        entry["hash"] = entry["hash"][:-4] + "ZZZZ"
        lines[0] = json.dumps(entry)
        tmp_log.write_text("\n".join(lines) + "\n", encoding="utf-8")

        ok, bad = verify_log(tmp_log)
        assert ok is False
        # Could fail at seq 0 or seq 1 (prev_hash mismatch)
        assert bad is not None and bad >= 0
