"""Generate report figures that are not exported from draw.io."""
from PIL import Image, ImageDraw, ImageFont
from pathlib import Path

A = Path(__file__).resolve().parents[1] / "assets"
F = "C:/Windows/Fonts/arial.ttf"
FB = "C:/Windows/Fonts/arialbd.ttf"

def font(size, bold=False):
    return ImageFont.truetype(FB if bold else F, size)

def relabel_block_diagram():
    im = Image.open(A / "fig3_4_block.png").convert("RGB")
    d = ImageDraw.Draw(im)
    d.rectangle((948, 134, 1046, 154), fill="white")
    f = font(12)
    t = "FastAPI + Chart.js"
    w = d.textlength(t, font=f)
    d.text((997 - w / 2, 136), t, fill="black", font=f)
    im.save(A / "fig3_4_block.png")

def arrow(d, x1, y1, x2, y2, w=4):
    d.line((x1, y1, x2, y2), fill="#333333", width=w)
    if x2 != x1:
        s = 1 if x2 > x1 else -1
        d.polygon([(x2, y2), (x2 - 16 * s, y2 - 9), (x2 - 16 * s, y2 + 9)], fill="#333333")
    else:
        s = 1 if y2 > y1 else -1
        d.polygon([(x2, y2), (x2 - 9, y2 - 16 * s), (x2 + 9, y2 - 16 * s)], fill="#333333")

def box(d, x, y, w, h, title, lines, fill, outline):
    d.rounded_rectangle((x, y, x + w, y + h), radius=22, fill=fill, outline=outline, width=4)
    ft = font(30, True)
    tw = d.textlength(title, font=ft)
    d.text((x + (w - tw) / 2, y + 16), title, fill="black", font=ft)
    fl = font(25)
    yy = y + 64
    for ln in lines:
        lw = d.textlength(ln, font=fl)
        d.rounded_rectangle((x + 18, yy, x + w - 18, yy + 46), radius=8, fill="white", outline="#555555", width=2)
        d.text((x + (w - lw) / 2, yy + 9), ln, fill="black", font=fl)
        yy += 58

def acp_pipeline():
    W, H = 2400, 1060
    im = Image.new("RGB", (W, H), "white")
    d = ImageDraw.Draw(im)
    bw, top = 340, 40
    # row 1: acquisition and ACP stages 1-5
    box(d, 30, top, bw, 300, "Input", ["PCAP upload(s)", "or live SPAN port", "Validate + merge"], "#E8DDF2", "#7A5C99")
    box(d, 440, top, bw, 300, "Suricata 8", ["ET Open + abuse.ch", "eve.json alerts", "flow/dns/dhcp/tls"], "#FDE3C8", "#C77B30")
    box(d, 850, top, 700, 300, "Logger (ACP 1-2)", ["1. Normalisation to common schema", "2. Preliminary enrichment", "Device inventory + attribution"], "#F7D1D0", "#B85450")
    box(d, 1620, top, 750, 300, "Contextor (ACP 3-5)", ["3. Aggregation (key + 300 s gap)", "4. Correlation (rules R1-R4)", "5. Incident-level enrichment"], "#F7D1D0", "#B85450")
    arrow(d, 370, top + 150, 438, top + 150)
    arrow(d, 780, top + 150, 848, top + 150)
    arrow(d, 1550, top + 150, 1618, top + 150)
    # row 2: scoring, evidence, interpretation
    y2 = 440
    box(d, 1620, y2, 750, 300, "Scorer (ACP 6)", ["OWASP factors + 3x3 matrix", "Factor breakdown stored", "Device/network risk (union)"], "#F7D1D0", "#B85450")
    box(d, 850, y2, 700, 300, "Prompt Maker + RAG (ACP 7)", ["7. Evidence package (E#, K#)", "Keyed lookup + FTS5 retrieval", "Rules, ATT&CK, playbooks"], "#D5E8D4", "#5A8F4E")
    box(d, 440, y2, bw, 300, "LLM Caller", ["Ollama", "Llama 3.2 3B Q4", "JSON schema output"], "#D5E8D4", "#5A8F4E")
    box(d, 30, y2, bw, 300, "Verifier", ["Schema, citation", "Entity, risk band", "Overclaim checks"], "#D5E8D4", "#5A8F4E")
    arrow(d, 1995, top + 300, 1995, y2 - 2)
    arrow(d, 1620, y2 + 150, 1552, y2 + 150)
    arrow(d, 850, y2 + 150, 782, y2 + 150)
    arrow(d, 440, y2 + 150, 372, y2 + 150)
    # row 3: storage and dashboard
    y3 = 820
    d.rounded_rectangle((850, y3, 2370, y3 + 200), radius=22, fill="#DAE8FC", outline="#6C8EBF", width=4)
    t = "SQLite database: analyses, alerts, devices, alert groups, incidents, interpretations"
    d.text((870, y3 + 80), t, fill="black", font=font(28))
    box(d, 30, y3 - 20, 750, 240, "Web Dashboard (FastAPI + Jinja2 + Chart.js)", ["Home, Alerts, Incidents, Devices, AI", "Network, Settings (RBAC)"], "#FFF2CC", "#D6B656")
    arrow(d, 200, y2 + 300, 200, y3 - 22)
    for x in (1200, 1995):
        d.line((x, y2 + 300, x, y3), fill="#6C8EBF", width=3)
    d.line((780, y3 + 100, 850, y3 + 100), fill="#6C8EBF", width=3)
    im.save(A / "fig4_1_acp.png")

if __name__ == "__main__":
    import sys
    if "--relabel" in sys.argv:
        relabel_block_diagram()
    acp_pipeline()
