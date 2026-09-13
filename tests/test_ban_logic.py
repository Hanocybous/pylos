import time
import tempfile
from pathlib import Path

import pytest

# Minimal unit tests for ban timing and exponential backoff logic.
# These tests should be extended to match the real implementation in pylos.bans

class DummyBanDB:
    def __init__(self):
        self.bans = {}  # ip -> (count, until_ts)

    def record_failure(self, ip, now=None):
        now = now or time.time()
        count, _ = self.bans.get(ip, (0, 0))
        count += 1
        # simple exponential: base 60s * 2^(count-1)
        ban_seconds = 60 * (2 ** (count - 1))
        until = now + ban_seconds
        self.bans[ip] = (count, until)
        return ban_seconds

    def is_banned(self, ip, now=None):
        now = now or time.time()
        _, until = self.bans.get(ip, (0, 0))
        return now < until


def test_first_failure_sets_small_ban():
    db = DummyBanDB()
    t0 = 1_700_000_000
    seconds = db.record_failure("1.2.3.4", now=t0)
    assert seconds == 60
    assert db.is_banned("1.2.3.4", now=t0 + 30) is True
    assert db.is_banned("1.2.3.4", now=t0 + 61) is False


def test_exponential_backoff_increases():
    db = DummyBanDB()
    t0 = 1_700_000_000
    s1 = db.record_failure("5.6.7.8", now=t0)
    s2 = db.record_failure("5.6.7.8", now=t0 + 10)
    s3 = db.record_failure("5.6.7.8", now=t0 + 20)
    assert s1 == 60
    assert s2 == 120
    assert s3 == 240


def test_no_ban_for_other_ips():
    db = DummyBanDB()
    db.record_failure("9.9.9.9", now=1_700_000_000)
    assert not db.is_banned("10.0.0.1", now=1_700_000_050)
