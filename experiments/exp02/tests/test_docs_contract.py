"""Contracts for the fixed-sixteen operator documents."""

from __future__ import annotations

from pathlib import Path


EXP02_ROOT = Path(__file__).resolve().parents[1]


def _text(name: str) -> str:
    return (EXP02_ROOT / name).read_text(encoding="utf-8")


def test_guide_defines_required_terms_without_banned_word() -> None:
    """Catches a guide that omits a required decision aid or uses banned jargon."""
    guide = _text("ANNOTATION-GUIDE.md").casefold()

    for required in (
        "entidad",
        "indicador de compromiso",
        "relación explícita",
        "frase de respaldo",
        "no inferir",
        "dudas",
        "ejemplo positivo",
        "ejemplo negativo",
    ):
        assert required in guide
    assert "corpus" not in guide
