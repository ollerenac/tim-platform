"""Elasticsearch volume-selection recovery contract."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def test_elasticsearch_volume_can_select_a_validated_recovery_copy():
    """Operators can redirect esdata without overwriting the original volume."""
    compose = (ROOT / "docker-compose.yml").read_text()
    env_example = (ROOT / ".env.example").read_text()

    assert "name: ${ESDATA_VOLUME_NAME:-opencti-7-pilot_esdata}" in compose
    assert "external: ${ESDATA_VOLUME_EXTERNAL:-false}" in compose
    assert "ESDATA_VOLUME_NAME=" in env_example
    assert "ESDATA_VOLUME_EXTERNAL=false" in env_example
