"""
test_registration.py - feed registration invariants for Phase 12 Plan 04.

Locks FEED_NAMES and build_enabled_feeds() together so new feed classes cannot
run silently while missing from /feeds/status, and keeps the high-volume CINS
feed last in the startup sequence.
"""
from api import FEED_NAMES
from main import build_enabled_feeds


def test_registration_parity():
    """The status API list must exactly match scheduler feed instances."""
    names = [feed.name for feed in build_enabled_feeds()]
    assert FEED_NAMES == names
    assert len(FEED_NAMES) == len(names) == 12
    assert FEED_NAMES[-1] == "cins"


def test_cins_registered_last():
    """CINS runs last so its first 15k-row pass cannot delay later feed statuses."""
    assert build_enabled_feeds()[-1].name == "cins"
