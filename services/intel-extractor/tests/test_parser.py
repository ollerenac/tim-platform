import pytest

try:
    from parser import extract_pdf_text, extract_url_text
    _IMPORT_OK = True
except ImportError:
    _IMPORT_OK = False


_skip = pytest.mark.skipif(not _IMPORT_OK, reason="parser not yet implemented")

# Minimal valid PDF with extractable text (PyPDF2-compatible)
_MINIMAL_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R"
    b"/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj\n"
    b"4 0 obj<</Length 44>>\nstream\n"
    b"BT /F1 12 Tf 100 700 Td (Hello World) Tj ET\n"
    b"endstream\nendobj\n"
    b"5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\n"
    b"xref\n0 6\n"
    b"0000000000 65535 f \n"
    b"0000000009 00000 n \n"
    b"0000000058 00000 n \n"
    b"0000000115 00000 n \n"
    b"0000000266 00000 n \n"
    b"0000000360 00000 n \n"
    b"trailer<</Size 6/Root 1 0 R>>\n"
    b"startxref\n441\n%%EOF"
)


@_skip
def test_extract_pdf_text():
    # GREEN: extract_pdf_text(pdf_bytes) returns non-empty string for valid PDF
    result = extract_pdf_text(_MINIMAL_PDF)
    assert isinstance(result, str) and len(result) > 0


@_skip
def test_extract_url_text():
    # GREEN: extract_url_text(url) returns non-empty string
    result = extract_url_text("https://example.com")
    assert isinstance(result, str) and len(result) > 0


@_skip
def test_extract_url_text_trafilatura_fallback(monkeypatch):
    # GREEN: trafilatura.extract returns None → fallback to BeautifulSoup
    import trafilatura
    monkeypatch.setattr(trafilatura, "extract", lambda *a, **kw: None)
    result = extract_url_text("https://example.com")
    assert isinstance(result, str) and len(result) > 0
