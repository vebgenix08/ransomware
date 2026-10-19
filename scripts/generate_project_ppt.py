from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.dml import MSO_LINE_DASH_STYLE
from pptx.enum.shapes import MSO_CONNECTOR, MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Inches, Pt


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "RansomShield_Current_Implementation.pptx"

SLIDE_W = 13.333
SLIDE_H = 7.5

BG = "151713"
SURFACE = "1D211B"
SURFACE_2 = "242920"
SOFT = "292E25"
TEXT = "F2F0E9"
MUTED = "A9AFA2"
LINE = "363D32"
GREEN = "A8C9B1"
GREEN_DARK = "315C43"
GREEN_SOFT = "263B2C"
AMBER = "D8A45C"
AMBER_SOFT = "44351F"
RED = "EF9388"
RED_SOFT = "492C29"
CREAM = "F5F3ED"
INK = "20231E"
WHITE = "FFFFFF"

FONT = "Aptos"
FONT_DISPLAY = "Aptos Display"


def rgb(hex_value):
    return RGBColor.from_string(hex_value)


def set_background(slide, color=BG):
    fill = slide.background.fill
    fill.solid()
    fill.fore_color.rgb = rgb(color)


def add_rect(slide, x, y, w, h, fill=SURFACE, line=LINE, radius=True, line_width=1):
    shape_type = MSO_SHAPE.ROUNDED_RECTANGLE if radius else MSO_SHAPE.RECTANGLE
    shape = slide.shapes.add_shape(shape_type, Inches(x), Inches(y), Inches(w), Inches(h))
    shape.fill.solid()
    shape.fill.fore_color.rgb = rgb(fill)
    shape.line.color.rgb = rgb(line)
    shape.line.width = Pt(line_width)
    if radius:
        shape.adjustments[0] = 0.12
    return shape


def add_circle(slide, x, y, diameter, fill=GREEN_SOFT, line=GREEN_DARK, line_width=1):
    shape = slide.shapes.add_shape(MSO_SHAPE.OVAL, Inches(x), Inches(y), Inches(diameter), Inches(diameter))
    shape.fill.solid()
    shape.fill.fore_color.rgb = rgb(fill)
    shape.line.color.rgb = rgb(line)
    shape.line.width = Pt(line_width)
    return shape


def add_text(
    slide,
    text,
    x,
    y,
    w,
    h,
    size=18,
    color=TEXT,
    bold=False,
    font=FONT,
    align=PP_ALIGN.LEFT,
    valign=MSO_ANCHOR.TOP,
    margin=0,
    line_spacing=1.0,
):
    box = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    frame = box.text_frame
    frame.clear()
    frame.word_wrap = True
    frame.margin_left = Inches(margin)
    frame.margin_right = Inches(margin)
    frame.margin_top = Inches(margin)
    frame.margin_bottom = Inches(margin)
    frame.vertical_anchor = valign
    paragraph = frame.paragraphs[0]
    paragraph.text = text
    paragraph.alignment = align
    paragraph.line_spacing = line_spacing
    paragraph.space_after = Pt(0)
    run = paragraph.runs[0]
    run.font.name = font
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.color.rgb = rgb(color)
    return box


def add_multiline(slide, items, x, y, w, h, size=16, color=MUTED, bullet_color=GREEN, gap=9):
    box = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    frame = box.text_frame
    frame.clear()
    frame.word_wrap = True
    frame.margin_left = 0
    frame.margin_right = 0
    frame.margin_top = 0
    frame.margin_bottom = 0
    for index, item in enumerate(items):
        paragraph = frame.paragraphs[0] if index == 0 else frame.add_paragraph()
        paragraph.text = "•  " + item
        paragraph.space_after = Pt(gap)
        paragraph.line_spacing = 1.05
        run = paragraph.runs[0]
        run.font.name = FONT
        run.font.size = Pt(size)
        run.font.color.rgb = rgb(color)
    return box


def add_line(slide, x1, y1, x2, y2, color=LINE, width=1.5, dashed=False):
    connector = slide.shapes.add_connector(
        MSO_CONNECTOR.STRAIGHT,
        Inches(x1),
        Inches(y1),
        Inches(x2),
        Inches(y2),
    )
    connector.line.color.rgb = rgb(color)
    connector.line.width = Pt(width)
    if dashed:
        connector.line.dash_style = MSO_LINE_DASH_STYLE.DASH
    return connector


def add_chevron(slide, x, y, w=0.28, h=0.42, color=GREEN):
    shape = slide.shapes.add_shape(MSO_SHAPE.CHEVRON, Inches(x), Inches(y), Inches(w), Inches(h))
    shape.fill.solid()
    shape.fill.fore_color.rgb = rgb(color)
    shape.line.fill.background()
    return shape


def add_pill(slide, text, x, y, w, fill=GREEN_SOFT, color=GREEN, line=GREEN_DARK, size=10):
    shape = add_rect(slide, x, y, w, 0.34, fill=fill, line=line, radius=True)
    add_text(slide, text.upper(), x, y + 0.005, w, 0.32, size=size, color=color, bold=True, align=PP_ALIGN.CENTER, valign=MSO_ANCHOR.MIDDLE)
    return shape


def add_slide_header(slide, kicker, title, subtitle=None, number=None):
    add_text(slide, kicker.upper(), 0.7, 0.4, 6.0, 0.28, size=10, color=AMBER, bold=True)
    add_text(slide, title, 0.7, 0.78, 11.7, 0.72, size=30, color=TEXT, bold=True, font=FONT_DISPLAY)
    if subtitle:
        add_text(slide, subtitle, 0.72, 1.48, 11.4, 0.5, size=13, color=MUTED)
    if number is not None:
        add_text(slide, f"{number:02d}", 12.05, 0.4, 0.55, 0.3, size=10, color=MUTED, bold=True, align=PP_ALIGN.RIGHT)
    add_line(slide, 0.7, 1.95 if subtitle else 1.58, 12.63, 1.95 if subtitle else 1.58, color=LINE, width=1)


def add_footer(slide, number):
    add_text(slide, "RANSOMSHIELD  /  CURRENT IMPLEMENTATION", 0.7, 7.1, 5.2, 0.2, size=8, color=MUTED, bold=True)
    add_text(slide, f"{number:02d}", 12.1, 7.1, 0.5, 0.2, size=8, color=MUTED, bold=True, align=PP_ALIGN.RIGHT)


def card(slide, x, y, w, h, label, title, body, accent=GREEN, icon_text=None):
    add_rect(slide, x, y, w, h, fill=SURFACE, line=LINE)
    add_rect(slide, x, y, 0.06, h, fill=accent, line=accent, radius=False, line_width=0)
    if icon_text:
        add_circle(slide, x + 0.28, y + 0.28, 0.55, fill=GREEN_SOFT if accent == GREEN else AMBER_SOFT, line=accent)
        add_text(slide, icon_text, x + 0.28, y + 0.28, 0.55, 0.55, size=13, color=accent, bold=True, align=PP_ALIGN.CENTER, valign=MSO_ANCHOR.MIDDLE)
        text_y = y + 1.0
    else:
        text_y = y + 0.36
    add_text(slide, label.upper(), x + 0.3, text_y, w - 0.6, 0.25, size=9, color=accent, bold=True)
    add_text(slide, title, x + 0.3, text_y + 0.32, w - 0.6, 0.45, size=17, color=TEXT, bold=True)
    add_text(slide, body, x + 0.3, text_y + 0.85, w - 0.6, h - (text_y - y) - 1.05, size=12, color=MUTED, line_spacing=1.05)


def flow_box(slide, x, y, w, h, number, title, body, color=GREEN):
    add_rect(slide, x, y, w, h, fill=SURFACE, line=LINE)
    add_circle(slide, x + 0.18, y + 0.18, 0.42, fill=GREEN_SOFT if color == GREEN else AMBER_SOFT, line=color)
    add_text(slide, str(number), x + 0.18, y + 0.18, 0.42, 0.42, size=10, color=color, bold=True, align=PP_ALIGN.CENTER, valign=MSO_ANCHOR.MIDDLE)
    add_text(slide, title, x + 0.2, y + 0.78, w - 0.4, 0.4, size=15, color=TEXT, bold=True, align=PP_ALIGN.CENTER)
    add_text(slide, body, x + 0.2, y + 1.25, w - 0.4, h - 1.4, size=11, color=MUTED, align=PP_ALIGN.CENTER, valign=MSO_ANCHOR.TOP)


def metric_card(slide, x, y, w, label, value, status, status_color=GREEN):
    add_rect(slide, x, y, w, 1.45, fill=SURFACE, line=LINE)
    add_text(slide, label.upper(), x + 0.22, y + 0.2, w - 0.44, 0.22, size=8, color=MUTED, bold=True)
    add_text(slide, value, x + 0.22, y + 0.52, w - 0.44, 0.46, size=23, color=TEXT, bold=True)
    add_text(slide, status, x + 0.22, y + 1.08, w - 0.44, 0.2, size=9, color=status_color, bold=True)


def build_deck():
    prs = Presentation()
    prs.slide_width = Inches(SLIDE_W)
    prs.slide_height = Inches(SLIDE_H)
    blank = prs.slide_layouts[6]

    # 1 — Title
    slide = prs.slides.add_slide(blank)
    set_background(slide)
    add_rect(slide, 0, 0, 0.15, SLIDE_H, fill=GREEN, line=GREEN, radius=False, line_width=0)
    add_pill(slide, "Current implementation", 0.85, 0.7, 1.9)
    add_text(slide, "RansomShield", 0.85, 1.45, 8.9, 1.0, size=48, color=TEXT, bold=True, font=FONT_DISPLAY)
    add_text(slide, "Behavioral Ransomware Detection\n& Alerting Framework", 0.88, 2.4, 8.2, 1.35, size=29, color=GREEN, bold=True, font=FONT_DISPLAY)
    add_text(slide, "Flask application • Secure accounts • Live safe-folder monitoring • Persisted alerts", 0.9, 4.0, 8.8, 0.45, size=15, color=MUTED)
    add_line(slide, 0.9, 4.7, 8.8, 4.7, color=LINE)
    add_text(slide, "Department of Computer Science & Engineering", 0.9, 5.0, 6.0, 0.3, size=12, color=TEXT, bold=True)
    add_text(slide, "Bapuji Institute of Engineering and Technology, Davanagere", 0.9, 5.35, 7.0, 0.3, size=11, color=MUTED)
    add_text(slide, "Project Guide: Dr. Usha G R", 0.9, 5.82, 4.5, 0.3, size=11, color=MUTED)
    add_circle(slide, 10.1, 1.35, 2.25, fill=GREEN_SOFT, line=GREEN, line_width=2)
    add_text(slide, "RS", 10.1, 1.35, 2.25, 2.25, size=42, color=GREEN, bold=True, align=PP_ALIGN.CENTER, valign=MSO_ANCHOR.MIDDLE)
    add_text(slide, "PHASE\nPROGRESS", 10.22, 4.15, 2.0, 0.8, size=13, color=AMBER, bold=True, align=PP_ALIGN.CENTER)
    add_text(slide, "2026", 10.22, 5.0, 2.0, 0.55, size=25, color=TEXT, bold=True, align=PP_ALIGN.CENTER)

    # 2 — Project snapshot
    slide = prs.slides.add_slide(blank)
    set_background(slide)
    add_slide_header(slide, "Project snapshot", "What RansomShield is today", "A working web foundation with real, bounded monitoring logic—not yet the final ML detector.", 2)
    card(slide, 0.7, 2.25, 3.8, 3.85, "Purpose", "Early behavioral awareness", "Observe system and file behavior, assign a transparent risk score, and present events and alerts through a protected dashboard.", GREEN, "01")
    card(slide, 4.77, 2.25, 3.8, 3.85, "Implemented", "Flask application", "Responsive landing page, light/dark theme, signup, sign-in, secure sessions, protected APIs, dashboard controls, SQLite events, and alert review.", AMBER, "02")
    card(slide, 8.84, 2.25, 3.8, 3.85, "Next phase", "Hybrid ML model", "Replace the demonstration heuristic with validated TCN temporal features and an XGBoost classifier after dataset preparation and evaluation.", GREEN, "03")
    add_footer(slide, 2)

    # 3 — Problem
    slide = prs.slides.add_slide(blank)
    set_background(slide)
    add_slide_header(slide, "Problem context", "Why behavior matters", "Signature-only defenses recognize what is already known; ransomware behavior can reveal risk earlier.", 3)
    add_rect(slide, 0.7, 2.25, 5.55, 3.95, fill=SURFACE, line=LINE)
    add_text(slide, "Traditional gap", 1.05, 2.58, 4.8, 0.35, size=20, color=TEXT, bold=True)
    add_multiline(slide, ["New variants may not match existing signatures", "Detection may arrive after damaging activity begins", "Raw system events are difficult for users to interpret", "Reactive tools do not explain behavioral context"], 1.05, 3.12, 4.65, 2.35, size=15)
    add_rect(slide, 6.55, 2.25, 6.08, 3.95, fill=GREEN_SOFT, line=GREEN_DARK)
    add_text(slide, "RansomShield direction", 6.92, 2.58, 5.2, 0.35, size=20, color=GREEN, bold=True)
    add_multiline(slide, ["Observe file, process, CPU, and memory signals", "Preserve event evidence and calculated risk", "Provide clear dashboard status and alerts", "Progress toward temporal ML classification"], 6.92, 3.12, 5.0, 2.35, size=15, color=TEXT)
    add_footer(slide, 3)

    # 4 — Objectives and scope
    slide = prs.slides.add_slide(blank)
    set_background(slide)
    add_slide_header(slide, "Objectives", "Scope aligned with the current build", "Completed functions are separated from planned research claims.", 4)
    columns = [
        (0.7, "Completed now", GREEN, ["Structured Flask application", "Secure user authentication", "Protected dashboard and APIs", "Live resource metrics", "Safe-folder event monitoring", "Persisted alerts and review"]),
        (4.85, "Current detector", AMBER, ["Explainable heuristic", "Two-second polling loop", "File snapshot comparison", "Risk score capped at 100", "Safe demonstration workflow", "No malware execution"]),
        (9.0, "Planned next", GREEN, ["Dataset and labels", "Feature windows", "TCN representation", "XGBoost classification", "Threshold calibration", "Formal model evaluation"]),
    ]
    for x, heading, color, items in columns:
        add_rect(slide, x, 2.2, 3.65, 4.25, fill=SURFACE, line=LINE)
        add_rect(slide, x, 2.2, 3.65, 0.1, fill=color, line=color, radius=False, line_width=0)
        add_text(slide, heading, x + 0.3, 2.55, 3.05, 0.35, size=18, color=color, bold=True)
        add_multiline(slide, items, x + 0.3, 3.05, 2.95, 2.95, size=13, gap=10)
    add_footer(slide, 4)

    # 5 — End-to-end architecture
    slide = prs.slides.add_slide(blank)
    set_background(slide)
    add_slide_header(slide, "System design", "Current end-to-end architecture", "Each module has a bounded responsibility and can be replaced independently.", 5)
    boxes = [
        (0.55, "Inputs", "CPU • memory\nprocess count\nfile snapshots"),
        (3.1, "Monitor service", "Background thread\n2-second cycle\nsafe directory"),
        (5.65, "Risk logic", "Snapshot diff\ntransparent score\nalert threshold"),
        (8.2, "Flask API", "Protected JSON\nstart / stop / demo\nevents / alerts"),
        (10.75, "Dashboard", "Live metrics\nevent feed\nalert review"),
    ]
    for index, (x, title, body) in enumerate(boxes, start=1):
        flow_box(slide, x, 2.7, 2.05, 2.7, index, title, body, GREEN if index % 2 else AMBER)
        if index < len(boxes):
            add_chevron(slide, x + 2.15, 3.83)
    add_rect(slide, 3.85, 5.75, 5.65, 0.65, fill=SURFACE_2, line=LINE)
    add_text(slide, "SQLite persistence  →  users  •  monitoring_events  •  alerts", 4.02, 5.88, 5.3, 0.3, size=12, color=MUTED, bold=True, align=PP_ALIGN.CENTER)
    add_line(slide, 6.68, 5.4, 6.68, 5.75, color=GREEN)
    add_footer(slide, 5)

    # 6 — Flask architecture
    slide = prs.slides.add_slide(blank)
    set_background(slide)
    add_slide_header(slide, "Application architecture", "A modular Flask foundation", "Blueprints, extensions, models, services, and templates remain clearly separated.", 6)
    card(slide, 0.7, 2.25, 2.85, 3.7, "Presentation", "Templates", "base.html\nindex.html\nsignin.html\nsignup.html\ndashboard.html", GREEN, "UI")
    card(slide, 3.72, 2.25, 2.85, 3.7, "Routing", "Blueprints", "main routes\nauth routes\nprotected API\nsafe redirects\nJSON responses", AMBER, "BP")
    card(slide, 6.74, 2.25, 2.85, 3.7, "Business logic", "Services", "monitor thread\nresource metrics\nfile snapshots\nrisk calculation\nsafe demo", GREEN, "SV")
    card(slide, 9.76, 2.25, 2.85, 3.7, "Persistence", "SQLAlchemy", "User model\nmonitor events\nalerts\npassword hashes\ntimestamps", AMBER, "DB")
    add_footer(slide, 6)

    # 7 — Structure
    slide = prs.slides.add_slide(blank)
    set_background(slide)
    add_slide_header(slide, "Code organization", "Project structure", "The implementation is small enough to understand and modular enough to extend.", 7)
    add_rect(slide, 0.7, 2.2, 5.45, 4.35, fill=SURFACE, line=LINE)
    tree = (
        "ransoware/\n"
        "├── run.py\n"
        "├── requirements.txt\n"
        "├── app/\n"
        "│   ├── __init__.py\n"
        "│   ├── auth.py  ·  api.py  ·  routes.py\n"
        "│   ├── models.py  ·  forms.py\n"
        "│   ├── monitor.py  ·  extensions.py\n"
        "│   └── templates/\n"
        "│       ├── base.html  ·  index.html\n"
        "│       ├── dashboard.html\n"
        "│       └── auth/signin.html  ·  signup.html\n"
        "└── instance/  ·  database + safe samples"
    )
    add_text(slide, tree, 1.05, 2.52, 4.8, 3.7, size=13, color=TEXT, font="Cascadia Mono")
    card(slide, 6.48, 2.2, 2.92, 1.85, "Principle 01", "Separation", "Routes do not contain monitoring internals.", GREEN)
    card(slide, 9.7, 2.2, 2.92, 1.85, "Principle 02", "Reuse", "Shared navigation, theme, and security shell.", AMBER)
    card(slide, 6.48, 4.35, 2.92, 1.85, "Principle 03", "Safety", "Monitoring is restricted to one known folder.", AMBER)
    card(slide, 9.7, 4.35, 2.92, 1.85, "Principle 04", "Extensibility", "The heuristic can later become ML inference.", GREEN)
    add_footer(slide, 7)

    # 8 — Authentication
    slide = prs.slides.add_slide(blank)
    set_background(slide)
    add_slide_header(slide, "Access control", "Authentication and session flow", "The dashboard and monitoring APIs require an authenticated user session.", 8)
    auth_boxes = [
        (0.75, "Sign up", "Validate name, email, password"),
        (3.55, "Store safely", "Normalize email and hash password"),
        (6.35, "Sign in", "Verify hash and create session"),
        (9.15, "Protected access", "Dashboard and API routes"),
    ]
    for idx, (x, title, body) in enumerate(auth_boxes, 1):
        flow_box(slide, x, 2.4, 2.45, 2.45, idx, title, body, GREEN if idx in (1, 4) else AMBER)
        if idx < 4:
            add_chevron(slide, x + 2.55, 3.45)
    add_pill(slide, "Password hashing", 1.2, 5.45, 1.65)
    add_pill(slide, "CSRF protected", 3.15, 5.45, 1.65, fill=AMBER_SOFT, color=AMBER, line=AMBER)
    add_pill(slide, "Safe redirects", 5.1, 5.45, 1.55)
    add_pill(slide, "HTTP-only session", 6.95, 5.45, 1.85, fill=AMBER_SOFT, color=AMBER, line=AMBER)
    add_pill(slide, "POST logout", 9.1, 5.45, 1.4)
    add_pill(slide, "Duplicate check", 10.8, 5.45, 1.55, fill=AMBER_SOFT, color=AMBER, line=AMBER)
    add_footer(slide, 8)

    # 9 — Dashboard
    slide = prs.slides.add_slide(blank)
    set_background(slide)
    add_slide_header(slide, "User experience", "Live protected dashboard", "A visual control plane for the monitoring prototype.", 9)
    add_rect(slide, 0.7, 2.18, 11.93, 4.35, fill=SURFACE_2, line=LINE)
    add_text(slide, "Welcome, authenticated user", 1.0, 2.48, 4.8, 0.4, size=21, color=TEXT, bold=True)
    add_pill(slide, "Start monitoring", 8.1, 2.48, 1.5)
    add_pill(slide, "Stop", 9.78, 2.48, 0.8, fill=SOFT, color=MUTED, line=LINE)
    add_pill(slide, "Run safe demo", 10.76, 2.48, 1.4, fill=AMBER_SOFT, color=AMBER, line=AMBER)
    metric_card(slide, 1.0, 3.2, 2.6, "Monitoring agent", "Live", "CONNECTED", GREEN)
    metric_card(slide, 3.82, 3.2, 2.6, "CPU usage", "3.6%", "HEURISTIC DEMO", AMBER)
    metric_card(slide, 6.64, 3.2, 2.6, "Behavior events", "1", "PERSISTED", GREEN)
    metric_card(slide, 9.46, 3.2, 2.6, "Alerts", "1", "REVIEW", RED)
    add_rect(slide, 1.0, 4.95, 7.65, 1.15, fill=SURFACE, line=LINE)
    add_text(slide, "FILE ACTIVITY", 1.22, 5.18, 1.4, 0.2, size=8, color=AMBER, bold=True)
    add_text(slide, "12 created • 0 modified • 0 deleted", 1.22, 5.46, 4.8, 0.28, size=13, color=TEXT, bold=True)
    add_pill(slide, "84 / 100", 7.1, 5.32, 1.1, fill=AMBER_SOFT, color=AMBER, line=AMBER)
    add_rect(slide, 8.9, 4.95, 3.16, 1.15, fill=AMBER_SOFT, line=AMBER)
    add_text(slide, "SAFE SCOPE", 9.15, 5.18, 1.2, 0.2, size=8, color=AMBER, bold=True)
    add_text(slide, "instance/monitor_samples", 9.15, 5.48, 2.6, 0.22, size=10, color=TEXT, font="Cascadia Mono")
    add_footer(slide, 9)

    # 10 — Monitoring logic
    slide = prs.slides.add_slide(blank)
    set_background(slide)
    add_slide_header(slide, "Detection logic", "How the current monitor works", "An explainable polling heuristic provides real behavior before the trained model is available.", 10)
    steps = [
        (0.7, "Snapshot", "Record relative path, modified time, and size."),
        (3.42, "Compare", "Find created, modified, and deleted files."),
        (6.14, "Measure", "Read CPU, memory, and process count."),
        (8.86, "Score", "Calculate risk and persist evidence."),
    ]
    for idx, (x, title, body) in enumerate(steps, 1):
        flow_box(slide, x, 2.25, 2.35, 2.15, idx, title, body, GREEN if idx % 2 else AMBER)
        if idx < len(steps):
            add_chevron(slide, x + 2.45, 3.1)
    add_rect(slide, 1.35, 4.85, 10.65, 1.2, fill=SURFACE, line=LINE)
    add_text(slide, "risk = 7 × file changes  +  8 × deletions  +  CPU flag  +  memory flag", 1.7, 5.08, 9.95, 0.35, size=19, color=GREEN, bold=True, align=PP_ALIGN.CENTER, font="Cascadia Mono")
    add_text(slide, "CPU flag = 15 at ≥90%   •   memory flag = 10 at ≥92%   •   score capped at 100   •   alert at ≥60", 1.7, 5.55, 9.95, 0.25, size=10, color=MUTED, align=PP_ALIGN.CENTER)
    add_footer(slide, 10)

    # 11 — Safe demo
    slide = prs.slides.add_slide(blank)
    set_background(slide)
    add_slide_header(slide, "Demonstration", "Safe end-to-end detection workflow", "The test uses harmless text files and never runs malware.", 11)
    demo_steps = [
        (0.6, "Start", "User starts the background monitor."),
        (3.1, "Generate", "App creates 12 harmless .txt files."),
        (5.6, "Detect", "Next polling cycle sees 12 new files."),
        (8.1, "Alert", "Risk 84 creates a medium alert."),
        (10.6, "Review", "User acknowledges the persisted alert."),
    ]
    for idx, (x, title, body) in enumerate(demo_steps, 1):
        flow_box(slide, x, 2.5, 2.05, 2.6, idx, title, body, GREEN if idx in (1, 3, 5) else AMBER)
        if idx < 5:
            add_chevron(slide, x + 2.12, 3.6, w=0.24)
    add_rect(slide, 3.15, 5.5, 7.05, 0.62, fill=GREEN_SOFT, line=GREEN_DARK)
    add_text(slide, "Validated result:  1 event  •  risk 84/100  •  medium alert  •  acknowledgement saved", 3.35, 5.67, 6.65, 0.25, size=11, color=GREEN, bold=True, align=PP_ALIGN.CENTER)
    add_footer(slide, 11)

    # 12 — Data and APIs
    slide = prs.slides.add_slide(blank)
    set_background(slide)
    add_slide_header(slide, "Backend interfaces", "Database and protected API", "The dashboard reads JSON endpoints; all state-changing requests require login and CSRF protection.", 12)
    add_rect(slide, 0.7, 2.2, 4.0, 4.25, fill=SURFACE, line=LINE)
    add_text(slide, "SQLite data model", 1.0, 2.52, 3.35, 0.35, size=20, color=TEXT, bold=True)
    for idx, (table, fields, color) in enumerate([
        ("users", "name • email • password hash", GREEN),
        ("monitoring_events", "type • severity • details • risk", AMBER),
        ("alerts", "title • severity • risk • reviewed", RED),
    ]):
        y = 3.2 + idx * 0.92
        add_rect(slide, 1.0, y, 3.35, 0.68, fill=SURFACE_2, line=LINE)
        add_text(slide, table, 1.2, y + 0.12, 1.45, 0.22, size=11, color=color, bold=True, font="Cascadia Mono")
        add_text(slide, fields, 1.2, y + 0.37, 2.85, 0.18, size=8, color=MUTED)
    add_rect(slide, 5.0, 2.2, 7.63, 4.25, fill=SURFACE, line=LINE)
    add_text(slide, "Protected endpoints", 5.32, 2.52, 3.35, 0.35, size=20, color=TEXT, bold=True)
    endpoints = [
        ("GET", "/api/monitor/status", "metrics + counts"),
        ("POST", "/api/monitor/start", "launch service"),
        ("POST", "/api/monitor/stop", "stop service"),
        ("POST", "/api/monitor/demo", "safe event test"),
        ("GET", "/api/events  •  /api/alerts", "recent records"),
        ("POST", "/api/alerts/{id}/acknowledge", "review alert"),
    ]
    for idx, (method, path, purpose) in enumerate(endpoints):
        y = 3.12 + idx * 0.48
        add_pill(slide, method, 5.32, y, 0.65, fill=GREEN_SOFT if method == "GET" else AMBER_SOFT, color=GREEN if method == "GET" else AMBER, line=GREEN_DARK if method == "GET" else AMBER, size=8)
        add_text(slide, path, 6.15, y + 0.05, 3.9, 0.22, size=10, color=TEXT, font="Cascadia Mono")
        add_text(slide, purpose, 10.18, y + 0.05, 1.9, 0.22, size=9, color=MUTED, align=PP_ALIGN.RIGHT)
    add_footer(slide, 12)

    # 13 — Verification
    slide = prs.slides.add_slide(blank)
    set_background(slide)
    add_slide_header(slide, "Verification", "Implemented flows tested successfully", "Automated Flask test-client checks exercised both authentication and monitoring behavior.", 13)
    tests = [
        ("Authentication", "Signup, normalized email, password hash, sign-in, bad-password rejection, logout", "PASS"),
        ("Access control", "Anonymous dashboard and monitoring API requests redirect to sign-in", "PASS"),
        ("Request security", "CSRF token required for forms and state-changing monitoring endpoints", "PASS"),
        ("Redirect safety", "External post-login redirect target rejected", "PASS"),
        ("Live monitoring", "CPU, memory, process count, start, stop, and polling verified", "PASS"),
        ("Detection workflow", "12 safe files produced event risk 84, medium alert, and saved acknowledgement", "PASS"),
    ]
    for idx, (name, detail, state) in enumerate(tests):
        y = 2.18 + idx * 0.7
        add_rect(slide, 0.7, y, 11.93, 0.56, fill=SURFACE, line=LINE)
        add_circle(slide, 0.92, y + 0.11, 0.34, fill=GREEN_SOFT, line=GREEN_DARK)
        add_text(slide, "✓", 0.92, y + 0.09, 0.34, 0.34, size=10, color=GREEN, bold=True, align=PP_ALIGN.CENTER, valign=MSO_ANCHOR.MIDDLE)
        add_text(slide, name, 1.42, y + 0.15, 2.0, 0.2, size=11, color=TEXT, bold=True)
        add_text(slide, detail, 3.3, y + 0.15, 7.8, 0.2, size=10, color=MUTED)
        add_text(slide, state, 11.48, y + 0.15, 0.65, 0.2, size=9, color=GREEN, bold=True, align=PP_ALIGN.RIGHT)
    add_footer(slide, 13)

    # 14 — Roadmap
    slide = prs.slides.add_slide(blank)
    set_background(slide)
    add_slide_header(slide, "Progress", "Project roadmap", "The web and monitoring foundation is ready for controlled data and model work.", 14)
    add_line(slide, 1.2, 3.55, 12.0, 3.55, color=LINE, width=3)
    phases = [
        (1.2, "01", "Research", "Complete", GREEN),
        (3.9, "02", "Flask + auth", "Complete", GREEN),
        (6.6, "03", "Safe monitor", "Complete", GREEN),
        (9.3, "04", "TCN + XGBoost", "Next", AMBER),
        (12.0, "05", "Evaluation", "Planned", MUTED),
    ]
    for x, number, title, state, color in phases:
        add_circle(slide, x - 0.3, 3.25, 0.6, fill=GREEN_SOFT if color == GREEN else AMBER_SOFT if color == AMBER else SOFT, line=color, line_width=2)
        add_text(slide, number, x - 0.3, 3.25, 0.6, 0.6, size=10, color=color, bold=True, align=PP_ALIGN.CENTER, valign=MSO_ANCHOR.MIDDLE)
        add_text(slide, title, x - 0.9, 2.45, 1.8, 0.4, size=14, color=TEXT, bold=True, align=PP_ALIGN.CENTER)
        add_pill(slide, state, x - 0.65, 4.05, 1.3, fill=GREEN_SOFT if color == GREEN else AMBER_SOFT if color == AMBER else SOFT, color=color, line=color, size=8)
    add_rect(slide, 2.6, 5.1, 8.15, 0.85, fill=SURFACE, line=LINE)
    add_text(slide, "Current handoff: a verified protected dashboard and safe behavioral event pipeline", 2.9, 5.35, 7.55, 0.3, size=13, color=GREEN, bold=True, align=PP_ALIGN.CENTER)
    add_footer(slide, 14)

    # 15 — Limitations and next work
    slide = prs.slides.add_slide(blank)
    set_background(slide)
    add_slide_header(slide, "Honest assessment", "Current limitations and next technical work", "The prototype is functional, but it is not yet a production ransomware defense.", 15)
    add_rect(slide, 0.7, 2.2, 5.7, 4.35, fill=RED_SOFT, line=RED)
    add_text(slide, "Current limitations", 1.05, 2.55, 4.8, 0.4, size=21, color=RED, bold=True)
    add_multiline(slide, ["Heuristic is not a trained ransomware classifier", "Only one isolated demonstration folder is watched", "Monitoring state is local to one Flask process", "Events and alerts are currently system-wide", "No recovery, quarantine, or process termination", "SQLite and development server are not production deployment"], 1.05, 3.15, 4.85, 2.85, size=13, color=TEXT, gap=8)
    add_rect(slide, 6.7, 2.2, 5.93, 4.35, fill=GREEN_SOFT, line=GREEN_DARK)
    add_text(slide, "Next technical work", 7.05, 2.55, 4.9, 0.4, size=21, color=GREEN, bold=True)
    add_multiline(slide, ["Define dataset, label policy, and temporal window size", "Train TCN and export stable feature representation", "Train and calibrate XGBoost classifier", "Add per-user or per-agent ownership", "Measure precision, recall, F1, false positives, and latency", "Add migrations, rate limiting, HTTPS, and deployment configuration"], 7.05, 3.15, 4.95, 2.85, size=13, color=TEXT, gap=8)
    add_footer(slide, 15)

    # 16 — Team
    slide = prs.slides.add_slide(blank)
    set_background(slide)
    add_slide_header(slide, "Project team", "Meet the RansomShield team", "Department of Computer Science & Engineering, BIET, Davanagere.", 16)
    members = [("AM", "Archana M"), ("CT", "Chandan T N"), ("GP", "Gouri K Patil"), ("KS", "Karan S")]
    for idx, (initials, name) in enumerate(members):
        x = 0.7 + idx * 3.02
        add_rect(slide, x, 2.35, 2.72, 3.4, fill=SURFACE, line=LINE)
        add_circle(slide, x + 0.76, 2.75, 1.2, fill=GREEN_SOFT if idx % 2 == 0 else AMBER_SOFT, line=GREEN if idx % 2 == 0 else AMBER, line_width=2)
        add_text(slide, initials, x + 0.76, 2.75, 1.2, 1.2, size=21, color=GREEN if idx % 2 == 0 else AMBER, bold=True, align=PP_ALIGN.CENTER, valign=MSO_ANCHOR.MIDDLE)
        add_text(slide, name, x + 0.25, 4.25, 2.22, 0.4, size=16, color=TEXT, bold=True, align=PP_ALIGN.CENTER)
        add_text(slide, "Research & Development\nTeam Member", x + 0.25, 4.8, 2.22, 0.7, size=11, color=MUTED, align=PP_ALIGN.CENTER)
    add_rect(slide, 3.4, 6.0, 6.5, 0.52, fill=SURFACE_2, line=LINE)
    add_text(slide, "Project Guide: Dr. Usha G R  •  Associate Professor, Dept. of CS&E", 3.6, 6.14, 6.1, 0.2, size=10, color=MUTED, align=PP_ALIGN.CENTER)
    add_footer(slide, 16)

    # 17 — Closing
    slide = prs.slides.add_slide(blank)
    set_background(slide)
    add_circle(slide, 5.42, 0.85, 2.5, fill=GREEN_SOFT, line=GREEN, line_width=2)
    add_text(slide, "RS", 5.42, 0.85, 2.5, 2.5, size=44, color=GREEN, bold=True, align=PP_ALIGN.CENTER, valign=MSO_ANCHOR.MIDDLE)
    add_text(slide, "A functional foundation.\nA measurable next phase.", 2.1, 3.55, 9.15, 1.15, size=34, color=TEXT, bold=True, font=FONT_DISPLAY, align=PP_ALIGN.CENTER)
    add_text(slide, "RansomShield now has secure access, real monitoring logic, persistent evidence, and a clear path to TCN + XGBoost validation.", 2.25, 4.9, 8.85, 0.75, size=15, color=MUTED, align=PP_ALIGN.CENTER)
    add_pill(slide, "Questions & discussion", 5.48, 6.15, 2.38, fill=AMBER_SOFT, color=AMBER, line=AMBER, size=10)
    add_footer(slide, 17)

    prs.core_properties.title = "RansomShield — Current Implementation"
    prs.core_properties.subject = "Flask authentication, safe monitoring, dashboard, and project roadmap"
    prs.core_properties.author = "RansomShield Project Team"
    prs.core_properties.keywords = "RansomShield, Flask, ransomware detection, behavioral monitoring, cybersecurity"
    prs.save(OUTPUT)
    print(OUTPUT)
    print(f"slides={len(prs.slides)}")


if __name__ == "__main__":
    build_deck()
