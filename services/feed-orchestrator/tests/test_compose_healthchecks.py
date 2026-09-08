"""
test_compose_healthchecks.py - connector healthcheck pattern invariants.
"""

from pathlib import Path

import pytest


def _compose_text():
    parents = Path(__file__).resolve().parents
    if len(parents) < 4 or not (parents[3] / "docker-compose.yml").is_file():
        # In-container the repo root (and docker-compose.yml) is not present —
        # this invariant is only checkable from a host checkout.
        pytest.skip("docker-compose.yml not available (in-container run)")
    return (parents[3] / "docker-compose.yml").read_text()


def test_connector_healthchecks_do_not_match_pgrep_command_itself():
    """Connector pgrep patterns use [p]ython so pgrep cannot match its own argv."""
    text = _compose_text()

    # 7.x layouts: mitre/ipinfo/cve run `python -m src`; misp-feed entrypoint
    # runs `python3 main.py`; cisa-kev still runs `python main.py`.
    assert "pgrep -f '[p]ython -m src'" in text
    assert "pgrep -f '[p]ython.*main.py'" in text
    assert "pgrep -f '[p]ython3 main.py'" in text
    assert "pgrep -f 'python.*mitre'" not in text
    assert "pgrep -f 'python.*cisa'" not in text
    assert "pgrep -f 'python.*misp'" not in text
    assert "pgrep -f '[p]ython.*mitre'" not in text
    assert "pgrep -f '[p]ython.*cisa'" not in text


def _service_block(text: str, name: str) -> str:
    """Extract one service's YAML block (from its header to the next 2-space key)."""
    import re

    start = text.index(f"  {name}:")
    rest = text[start + 2:]
    m = re.search(r"\n  [a-zA-Z#]", rest)
    return text[start:start + 2 + m.start()] if m else text[start:]


def test_misp_feed_connector_declares_required_minute_interval():
    """connector-misp-feed reads MISP_FEED_INTERVAL (deprecated-but-honored in 7.x);
    CONNECTOR_DURATION_PERIOD caused _get_interval NoneType errors on 6.4.
    Scoped to the misp block — other connectors (greynoise, alienvault) legitimately
    use CONNECTOR_DURATION_PERIOD."""
    misp = _service_block(_compose_text(), "connector-misp-feed")

    assert "MISP_FEED_INTERVAL=1440" in misp
    assert "CONNECTOR_DURATION_PERIOD" not in misp


def test_alienvault_connector_declares_bounded_backfill_and_no_guessing():
    """connector-alienvault must pin the platform version, bound the pulse backfill
    (2020 default would drown the worker), and never guess malware/CVE from tags."""
    av = _service_block(_compose_text(), "connector-alienvault")

    assert "opencti/connector-alienvault:7.260706.0" in av
    assert "ALIENVAULT_PULSE_START_TIMESTAMP=2026-" in av
    assert "ALIENVAULT_GUESS_MALWARE=false" in av
    assert "ALIENVAULT_GUESS_CVE=false" in av
    assert "pgrep -f '[p]ython __main__.py'" in av
