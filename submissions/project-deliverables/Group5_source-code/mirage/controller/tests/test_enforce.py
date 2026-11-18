"""Unit tests for the shared decoy enforcement state."""

import time

from mirage_common import EnforcementState


def test_block_and_clear():
    e = EnforcementState()
    assert e.is_blocked("10.66.0.50") is False
    e.block("10.66.0.50")
    assert e.is_blocked("10.66.0.50") is True
    e.clear("10.66.0.50")
    assert e.is_blocked("10.66.0.50") is False


def test_block_expires():
    e = EnforcementState()
    e.block("10.66.0.50", duration_seconds=0.2)
    assert e.is_blocked("10.66.0.50") is True
    time.sleep(0.25)
    assert e.is_blocked("10.66.0.50") is False


def test_tarpit_delay():
    e = EnforcementState()
    assert e.tarpit_delay("10.66.0.50") == 0.0
    e.tarpit("10.66.0.50", 3.0)
    assert e.tarpit_delay("10.66.0.50") == 3.0


def test_tarpit_never_downgrades_a_block():
    e = EnforcementState()
    e.block("10.66.0.50")
    e.tarpit("10.66.0.50", 3.0)          # must not replace the block
    assert e.is_blocked("10.66.0.50") is True
    assert e.tarpit_delay("10.66.0.50") == 0.0


def test_apply_modes():
    e = EnforcementState()
    e.apply("10.66.0.50", "tarpit", delay=2.0)
    assert e.tarpit_delay("10.66.0.50") == 2.0
    e.apply("10.66.0.50", "block")
    assert e.is_blocked("10.66.0.50") is True
    e.apply("10.66.0.50", "clear")
    assert e.is_blocked("10.66.0.50") is False
