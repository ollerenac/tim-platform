import re

from fpdf import FPDF

FONT_PATH = "/app/fonts/DejaVuSans.ttf"

_HEADING_RE = re.compile(r"^\s*(?:#{1,6}\s+(.+?)|\*\*([^*]+)\*\*:?)\s*$")
_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")


def _plain_lines(text: str) -> list[tuple[bool, str]]:
    """The model writes Markdown; the PDF is plain text. Returns (is_heading, line).

    ponytail: bold markers are stripped, not rendered. fpdf2's markdown mode needs
    bold font files we don't ship and reads `--` as underline, which would corrupt
    punycode domains (xn--...) in a threat-intel document. Add DejaVuSans-Bold and
    a custom inline renderer if emphasis ever matters.
    """
    lines = []
    for line in text.splitlines():
        heading = _HEADING_RE.match(line)
        if heading:
            lines.append((True, _BOLD_RE.sub(r"\1", heading.group(1) or heading.group(2)).strip()))
        else:
            lines.append((False, _BOLD_RE.sub(r"\1", line)))
    return lines


def render_pdf(briefing: dict) -> bytes:
    pdf = FPDF()
    pdf.add_page()
    pdf.add_font("DejaVu", fname=FONT_PATH)
    pdf.set_font("DejaVu", size=16)
    pdf.cell(text="Threat Intelligence Briefing", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("DejaVu", size=11)
    pdf.cell(
        text=f"Period: last {briefing['period_hours']}h  |  Generated: {briefing['created_at']}",
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.ln(8)
    for is_heading, line in _plain_lines(briefing["text"]):
        if not line.strip():
            pdf.ln(4)
            continue
        pdf.set_font("DejaVu", size=13 if is_heading else 11)
        pdf.multi_cell(w=0, text=line, new_x="LMARGIN", new_y="NEXT")
    return bytes(pdf.output())
