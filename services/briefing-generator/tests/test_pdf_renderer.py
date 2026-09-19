import os
import pathlib
import pytest

# Import guard: skip if production module not yet implemented
try:
    from pdf_renderer import render_pdf
    import pdf_renderer as _pdf_renderer_module
    _SKIP_REASON = None
except ImportError as _e:
    _SKIP_REASON = f"pdf_renderer not yet implemented: {_e}"
    _pdf_renderer_module = None

# Resolve local font path for tests running outside Docker
_REPO_FONT = pathlib.Path(__file__).parent.parent / "fonts" / "DejaVuSans.ttf"
_DOCKER_FONT = pathlib.Path("/app/fonts/DejaVuSans.ttf")
_FONT_AVAILABLE = _REPO_FONT.exists() or _DOCKER_FONT.exists()

_skip_impl = pytest.mark.skipif(_SKIP_REASON is not None, reason=_SKIP_REASON or "")
_skip_font = pytest.mark.skipif(not _FONT_AVAILABLE, reason="DejaVuSans.ttf not found")


@_skip_impl
@_skip_font
def test_render_pdf_bytes(monkeypatch):
    # Patch FONT_PATH to repo-relative path when running outside Docker
    if _REPO_FONT.exists() and not _DOCKER_FONT.exists():
        monkeypatch.setattr(_pdf_renderer_module, "FONT_PATH", str(_REPO_FONT))
    result = render_pdf({
        "period_hours": 24,
        "created_at": "2026-06-26T02:00:00+00:00",
        "text": "Test briefing text for PDF rendering.",
    })
    assert isinstance(result, bytes)
    assert result[:4] == b"%PDF"


@_skip_impl
def test_plain_lines_strips_bold_markers_and_keeps_ioc_values_intact():
    """Bedrock writes Markdown. The PDF must not show `**`, and must never treat
    `--` as markup: punycode domains are real indicators."""
    from pdf_renderer import _plain_lines

    text = (
        "**EXECUTIVE SUMMARY: THREAT REPORT**\n"
        "## Key findings\n"
        "\n"
        "Actors used **WailingCrab** against xn--80ak6aa92e.com and a--b.example.\n"
        "Unpaired ** marker stays, as does 2 * 3 * 4."
    )
    assert _plain_lines(text) == [
        (True, "EXECUTIVE SUMMARY: THREAT REPORT"),
        (True, "Key findings"),
        (False, ""),
        (False, "Actors used WailingCrab against xn--80ak6aa92e.com and a--b.example."),
        (False, "Unpaired ** marker stays, as does 2 * 3 * 4."),
    ]


@_skip_impl
@_skip_font
def test_render_pdf_handles_markdown_headings_and_blank_lines(monkeypatch):
    if _REPO_FONT.exists() and not _DOCKER_FONT.exists():
        monkeypatch.setattr(_pdf_renderer_module, "FONT_PATH", str(_REPO_FONT))
    result = render_pdf({
        "period_hours": 1,
        "created_at": "2026-09-19T08:52:56+00:00",
        "text": "**EXECUTIVE SUMMARY**\n\nFirst paragraph with **bold** text.\n\n" + "word " * 400,
    })
    assert result[:4] == b"%PDF"
