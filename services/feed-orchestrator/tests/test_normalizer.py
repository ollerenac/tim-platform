"""
test_normalizer.py — RED phase tests for compute_confidence() (FEED-05).

These tests will raise ImportError until normalizer.py is implemented (Wave 3, Plan 07).
That is expected and correct.

D-09 Confidence Formula (LOCKED DECISION from CONTEXT.md):
  score = min(100, seen_in_feeds * 25 + recency_bonus + quality_weight)

Quality weights (D-09):
  feodo=30, sslbl_cert=25, threatfox=20, urlhaus=15, malwarebazaar=15

Recency bonus (discretion):
  recency_bonus = max(0, 10 - days_old)   # linear decay, floor at 0

Expected value calculations (for test documentation):
  test_confidence_feodo_new:
    days_old=0, recency_bonus=max(0,10-0)=10, quality=30, seen_in_feeds=1
    score = min(100, 1*25 + 10 + 30) = min(100, 65) = 65

  test_confidence_sslbl_cert_7_days_old:
    days_old=7, recency_bonus=max(0,10-7)=3, quality=25, seen_in_feeds=1
    score = min(100, 1*25 + 3 + 25) = min(100, 53) = 53

  test_confidence_caps_at_100:
    days_old=0, recency_bonus=10, quality=30, seen_in_feeds=3
    score = min(100, 3*25 + 10 + 30) = min(100, 115) = 100

  test_recency_bonus_floors_at_zero:
    days_old=11, recency_bonus=max(0,10-11)=max(0,-1)=0, quality=15, seen_in_feeds=1
    score = min(100, 1*25 + 0 + 15) = min(100, 40) = 40
"""
import pytest
from datetime import datetime, timezone, timedelta

# RED: This import will fail until Plan 07 creates normalizer.py
from normalizer import compute_confidence


def test_confidence_feodo_new():
    """FEED-05: Feodo IOC seen today, single feed: score = min(100, 25 + 10 + 30) = 65."""
    # days_old=0 => recency_bonus=max(0,10-0)=10; quality_weight(feodo)=30; seen_in_feeds=1
    # score = min(100, 1*25 + 10 + 30) = 65
    today = datetime.now(timezone.utc)
    result = compute_confidence("feodo", today, seen_in_feeds=1)
    assert result == 65, f"Expected 65, got {result}"


def test_confidence_sslbl_cert_7_days_old():
    """FEED-05: SSLBL-cert IOC 7 days old, single feed: score = min(100, 25 + 3 + 25) = 53."""
    # days_old=7 => recency_bonus=max(0,10-7)=3; quality_weight(sslbl_cert)=25; seen_in_feeds=1
    # score = min(100, 1*25 + 3 + 25) = 53
    seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
    result = compute_confidence("sslbl_cert", seven_days_ago, seen_in_feeds=1)
    assert result == 53, f"Expected 53, got {result}"


def test_confidence_caps_at_100():
    """FEED-05: Score is capped at 100 regardless of inputs."""
    # days_old=0 => recency_bonus=10; quality_weight(feodo)=30; seen_in_feeds=3
    # raw_score = 3*25 + 10 + 30 = 115 => capped at 100
    today = datetime.now(timezone.utc)
    result = compute_confidence("feodo", today, seen_in_feeds=3)
    assert result == 100, f"Expected 100 (capped), got {result}"


def test_recency_bonus_floors_at_zero():
    """FEED-05: recency_bonus is 0 for IOCs older than 10 days (linear decay floors at 0)."""
    # days_old=11 => recency_bonus=max(0,10-11)=0; quality_weight(urlhaus)=15; seen_in_feeds=1
    # score = min(100, 1*25 + 0 + 15) = 40
    eleven_days_ago = datetime.now(timezone.utc) - timedelta(days=11)
    result = compute_confidence("urlhaus", eleven_days_ago, seen_in_feeds=1)
    assert result == 40, f"Expected 40, got {result}"


def test_confidence_unknown_feed_uses_default_weight():
    """FEED-05: Unknown feed names use a default quality weight (expected: 10)."""
    # Default weight = 10; days_old=0 => recency_bonus=10; seen_in_feeds=1
    # score = min(100, 1*25 + 10 + 10) = 45
    today = datetime.now(timezone.utc)
    result = compute_confidence("unknown_feed", today, seen_in_feeds=1)
    assert result == 45, f"Expected 45 (default weight=10), got {result}"
