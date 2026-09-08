from fpdf import FPDF

FONT_PATH = "/app/fonts/DejaVuSans.ttf"


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
    pdf.multi_cell(w=0, text=briefing["text"])
    return bytes(pdf.output())
