import io
from datetime import datetime
from tkinter import filedialog, messagebox
from xml.sax.saxutils import escape

from matplotlib.figure import Figure
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image

from charts import draw_charts
from insights import build_summary, human_size, human_time


def export_report(df, source, mode):
    if df is None or df.empty:
        messagebox.showinfo("Nothing to export", "Run an analysis first, then export the report.")
        return
    path = filedialog.asksaveasfilename(
        title="Export report", defaultextension=".pdf", initialfile="anomflow_report",
        filetypes=[("PDF report", "*.pdf"), ("CSV (all connections)", "*.csv")])
    if not path:
        return
    try:
        if path.lower().endswith(".csv"):
            df.to_csv(path, index=False)
        else:
            _write_pdf(path, df, source, mode)
    except Exception as e:
        messagebox.showerror("Export failed", str(e))
        return
    messagebox.showinfo("Report saved", f"Saved to:\n{path}")


def _write_pdf(path, df, source, mode):
    st = getSampleStyleSheet()
    doc = SimpleDocTemplate(path, pagesize=A4, title="ANOMFLOW AI Report",
                            leftMargin=2 * cm, rightMargin=2 * cm,
                            topMargin=1.8 * cm, bottomMargin=1.8 * cm)
    n_bad = int((df["verdict"] == "Suspicious").sum())

    story = [
        Paragraph("ANOMFLOW AI - Network Analysis Report", st["Title"]),
        Paragraph(f"{escape(mode)} | Source: {escape(source)} | "
                  f"Created: {datetime.now():%Y-%m-%d %H:%M}", st["Normal"]),
        Spacer(1, 14),
        Paragraph("What happened", st["Heading2"]),
    ]
    for line in build_summary(df, source):
        story += [Paragraph(escape(line), st["BodyText"]), Spacer(1, 4)]

    stats = Table(
        [["Connections checked", "Normal", "Suspicious", "Suspicious share"],
         [f"{len(df):,}", f"{len(df) - n_bad:,}", f"{n_bad:,}", f"{n_bad / len(df):.1%}"]],
        colWidths=[4.25 * cm] * 4)
    stats.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b1d3a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("FONTSIZE", (0, 1), (-1, 1), 13),
    ]))
    story += [Spacer(1, 10), stats, Spacer(1, 12)]

    fig = Figure(figsize=(10, 6.5))
    draw_charts(fig, df, dark=False)
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, facecolor=fig.get_facecolor())
    buf.seek(0)
    story += [Image(buf, width=17 * cm, height=17 * cm * 0.3), Spacer(1, 12),
              Paragraph("Most suspicious connections", st["Heading2"])]

    rows = [["Traffic type", "Protocol", "Packets", "Data size", "Duration", "Risk", "Result"]]
    for r in df.sort_values("attack_prob", ascending=False).head(15).to_dict("records"):
        rows.append([r["service"], r.get("protocol", "-"), f"{int(r['packet_count']):,}",
                     human_size(r["total_bytes"]), human_time(r["duration"]),
                     f"{r['attack_prob']:.0%}", r["verdict"]])
    tbl = Table(rows, repeatRows=1,
                colWidths=[5.0 * cm, 2 * cm, 2 * cm, 2.2 * cm, 2.2 * cm, 1.6 * cm, 2 * cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b1d3a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eef3fb")]),
    ]))
    story += [tbl, Spacer(1, 12), Paragraph("How to read this report", st["Heading2"]),
              Paragraph("Risk is ANOMFLOW's estimated chance that a connection belongs to an attack. "
                        "A connection is marked Suspicious when the risk is 50% or higher. The model is "
                        "currently trained on DDoS attacks only, using a 2017 lab dataset, so it can miss "
                        "other attack types and can raise false alarms. Treat results as hints to "
                        "investigate, not proof.", st["BodyText"])]
    doc.build(story)