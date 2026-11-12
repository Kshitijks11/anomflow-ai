import os
import sys

if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")

import queue
import threading
import tkinter as tk
from datetime import datetime
from tkinter import ttk, messagebox, filedialog

import pandas as pd
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from engine import capture_and_score, analyze_pcap, load_csv_flows, feature_importance, get_metadata, get_model
from insights import prepare, build_summary, human_size, human_time, endpoint
from charts import draw_charts, draw_timeline
from ai_explain import explain_flow, load_settings, save_settings, DEFAULT_MODELS, PROVIDER_LABELS
from report import export_report

# ---------- theme ----------
BG = "#0b1d3a"
PANEL = "#12294d"
ACCENT = "#2f80ed"
ACCENT_HOVER = "#4a94f5"
TEXT = "#e8eefc"
MUTED = "#8fa3c7"
BAD = "#ff6b6b"
GOOD = "#4cd7a0"
ROW_BAD = "#5c1f2b"
OK_BG = "#14402f"
FONT = "Segoe UI"

# (attack name, model trained yet?)
ATTACKS = [
    ("🌊", "DDoS", True,
     "Floods a target with huge traffic from many sources at once, so real users can't get through — "
     "like a crowd blocking one doorway."),
    ("🚪", "PortScan", True,
     "Quietly checks which doors (network ports) are open on a device, usually scouting for weak spots "
     "before a bigger attack."),
    ("⚡", "DoS (Hulk, GoldenEye, slowloris)", True,
     "Overwhelms a single service with requests from one source until it slows down or crashes."),
    ("🔑", "FTP-Patator (brute force)", True,
     "Repeatedly guesses file-server passwords until one works."),
    ("🔐", "SSH-Patator (brute force)", True,
     "Repeatedly guesses remote-login passwords until one works."),
    ("🕸️", "Web attacks (XSS, SQL injection)", True,
     "Tricks a website into running malicious code or leaking its database."),
    ("🤖", "Botnet", False,
     "Traffic from a device that's been secretly taken over and remote-controlled as part of a larger "
     "attack network."),
    ("🕵️", "Infiltration", False,
     "An attacker who's already gotten inside the network, quietly moving around or stealing data."),
]

TABLE_COLS = [
    ("when", "When", 90), ("service", "What kind of traffic", 190), ("kind", "Looks like", 120),
    ("size", "Data size", 85), ("duration", "Duration", 85), ("packets", "Packets", 75),
    ("risk", "Risk", 65), ("verdict", "Result", 95), ("proto", "Protocol", 75),
    ("src", "Endpoint A", 240), ("dst", "Endpoint B", 240),
]
ALL_COLS = tuple(c[0] for c in TABLE_COLS)
FRIENDLY = ("when", "service", "kind", "size", "duration", "packets", "risk", "verdict")

INTRO = ("Choose a .pcap capture or a flow .csv file to begin.\n"
         "Tip: from your data folder, the Monday CIC-IDS2017 CSV is all normal traffic (shows false alarms), "
         "and the Friday DDoS CSV contains attacks (shows detection).")


# ---------- helpers ----------
def setup_styles(root):
    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT,
                rowheight=28, font=(FONT, 11), borderwidth=0)
    s.configure("Treeview.Heading", background=BG, foreground=TEXT,
                font=(FONT, 11, "bold"), relief="flat")
    s.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", "white")])
    s.map("Treeview.Heading", background=[("active", PANEL)])
    s.configure("Vertical.TScrollbar", background=PANEL, troughcolor=BG,
                arrowcolor=TEXT, bordercolor=BG)


def make_button(parent, text, command, size=14, primary=True):
    bg = ACCENT if primary else PANEL
    hover = ACCENT_HOVER if primary else "#1b3a6b"
    btn = tk.Button(parent, text=text, command=command, bg=bg, fg="white",
                    activebackground=hover, activeforeground="white",
                    disabledforeground=MUTED, relief="flat", bd=0,
                    font=(FONT, size, "bold"), padx=20, pady=9, cursor="hand2")
    btn.bind("<Enter>", lambda e: btn.config(bg=hover) if str(btn["state"]) == "normal" else None)
    btn.bind("<Leave>", lambda e: btn.config(bg=bg))
    return btn


def stat_card(parent, label, color=TEXT):
    card = tk.Frame(parent, bg=PANEL, padx=22, pady=10)
    card.pack(side="left", padx=(0, 15))
    var = tk.StringVar(value="-")
    tk.Label(card, textvariable=var, font=(FONT, 24, "bold"), fg=color, bg=PANEL).pack(anchor="w")
    tk.Label(card, text=label, font=(FONT, 11), fg=MUTED, bg=PANEL).pack(anchor="w")
    return var


def build_header(screen, title, subtitle):
    bar = tk.Frame(screen, bg=BG)
    bar.pack(fill="x", padx=30, pady=(18, 5))
    screen.back_btn = make_button(bar, "← Back", lambda: screen.app.show(Setup),
                                  size=12, primary=False)
    screen.back_btn.pack(side="left")
    box = tk.Frame(bar, bg=BG)
    box.pack(side="left", padx=20)
    tk.Label(box, text=title, font=(FONT, 26, "bold"), fg=TEXT, bg=BG).pack(anchor="w")
    tk.Label(box, text=subtitle, font=(FONT, 12), fg=MUTED, bg=BG).pack(anchor="w")


def spinbox(parent, var, lo, hi):
    return tk.Spinbox(parent, from_=lo, to=hi, textvariable=var, width=5, font=(FONT, 14),
                      bg=PANEL, fg=TEXT, insertbackground=TEXT, buttonbackground=PANEL,
                      relief="flat")


def threshold_slider(parent, var, on_release):
    """A themed 0-100 slider. Label updates live while dragging; heavy recompute
    only fires on release, so dragging stays smooth even on large datasets."""
    box = tk.Frame(parent, bg=BG)
    label = tk.StringVar(value=f"Alert threshold: {int(var.get())}%")
    tk.Label(box, textvariable=label, font=(FONT, 12, "bold"), fg=TEXT, bg=BG).pack(anchor="w")
    scale = tk.Scale(box, from_=5, to=95, orient="horizontal", variable=var, showvalue=False,
                     length=220, bg=BG, fg=TEXT, troughcolor=PANEL, highlightthickness=0,
                     activebackground=ACCENT, sliderrelief="flat",
                     command=lambda v: label.set(f"Alert threshold: {int(float(v))}%"))
    scale.pack(fill="x")
    scale.bind("<ButtonRelease-1>", lambda e: on_release())
    return box


class Screen(tk.Frame):
    def __init__(self, app):
        super().__init__(app.container, bg=BG)
        self.app = app


# ---------- AI windows ----------
class SettingsWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("AI Settings")
        self.configure(bg=BG)
        self.geometry("620x560")
        self.resizable(False, False)
        s = load_settings()
        self.provider = tk.StringVar(value=s["provider"])
        self.key = tk.StringVar(value=s["api_key"])
        self.model = tk.StringVar(value=s["model"])

        tk.Label(self, text="AI Settings", font=(FONT, 22, "bold"), fg=TEXT, bg=BG).pack(pady=(20, 4))
        tk.Label(self, text="Used by 'Explain selected with AI'. IP addresses are never sent.",
                 font=(FONT, 11), fg=MUTED, bg=BG).pack()

        box = tk.Frame(self, bg=PANEL, padx=22, pady=16)
        box.pack(fill="x", padx=25, pady=16)
        tk.Label(box, text="Provider", font=(FONT, 12, "bold"), fg=TEXT, bg=PANEL).pack(anchor="w")

        self.provider_buttons = {}
        grid = tk.Frame(box, bg=PANEL)
        grid.pack(fill="x", pady=(6, 14))
        for i, (value, text) in enumerate(PROVIDER_LABELS.items()):
            btn = tk.Button(grid, text=text, font=(FONT, 11, "bold"), relief="flat", bd=0,
                            padx=14, pady=10, cursor="hand2",
                            command=lambda v=value: self.pick(v))
            btn.grid(row=i // 2, column=i % 2, sticky="ew", padx=4, pady=4)
            self.provider_buttons[value] = btn
        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=1)
        self.refresh_buttons()

        for label, var, hide in (("API key", self.key, "•"), ("Model", self.model, "")):
            tk.Label(box, text=label, font=(FONT, 12, "bold"), fg=TEXT, bg=PANEL).pack(anchor="w")
            tk.Entry(box, textvariable=var, show=hide, font=(FONT, 12), bg=BG, fg=TEXT,
                     insertbackground=TEXT, relief="flat").pack(fill="x", pady=(2, 10), ipady=5)
        make_button(self, "Save", self.save, size=13).pack()

    def refresh_buttons(self):
        for value, btn in self.provider_buttons.items():
            active = value == self.provider.get()
            btn.config(bg=ACCENT if active else BG, fg="white" if active else MUTED,
                       activebackground=ACCENT_HOVER)

    def pick(self, value):
        self.provider.set(value)
        self.refresh_buttons()
        if self.model.get() in DEFAULT_MODELS.values():
            self.model.set(DEFAULT_MODELS[value])

    def save(self):
        provider = self.provider.get()
        save_settings({"provider": provider, "api_key": self.key.get().strip(),
                       "model": self.model.get().strip() or DEFAULT_MODELS[provider]})
        messagebox.showinfo("Saved", "AI settings saved.", parent=self)
        self.destroy()

class ExplainWindow(tk.Toplevel):
    def __init__(self, parent, record):
        super().__init__(parent)
        self.title("Explain this connection")
        self.geometry("780x620")
        self.configure(bg=BG)
        bad = record["verdict"] == "Suspicious"
        tk.Label(self, text=f"{record['service']}  •  {record['verdict']}  •  {record['attack_prob']:.0%} risk",
                 font=(FONT, 18, "bold"), fg=BAD if bad else GOOD, bg=BG).pack(anchor="w", padx=25, pady=(20, 2))
        tk.Label(self, text=f"{human_size(record['total_bytes'])} in {int(record['packet_count'])} packets "
                            f"over {human_time(record['duration'])}",
                 font=(FONT, 12), fg=MUTED, bg=BG).pack(anchor="w", padx=25)
        self.text = tk.Text(self, wrap="word", font=(FONT, 13), bg=PANEL, fg=TEXT, relief="flat",
                            padx=18, pady=16, spacing2=4)
        self.text.pack(fill="both", expand=True, padx=25, pady=15)
        self.set_text("Asking the AI to explain this connection...")
        self.q = queue.Queue()
        threading.Thread(target=self.work, args=(record,), daemon=True).start()
        self.after(250, self.poll)

    def set_text(self, msg):
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", msg)
        self.text.config(state="disabled")

    def work(self, record):
        try:
            self.q.put(explain_flow(record, feature_importance()))
        except Exception as e:
            self.q.put(f"Could not get an explanation.\n\n{e}")

    def poll(self):
        try:
            self.set_text(self.q.get_nowait())
        except queue.Empty:
            self.after(250, self.poll)


# ---------- results table (shared) ----------
class ResultsPanel(tk.Frame):
    def __init__(self, parent, order="risk", limit=500):
        super().__init__(parent, bg=BG)
        self.order, self.limit = order, limit
        self.records = {}

        bar = tk.Frame(self, bg=BG)
        bar.pack(fill="x", pady=(0, 6))
        tk.Label(bar, text="Connections", font=(FONT, 16, "bold"), fg=TEXT, bg=BG).pack(side="left")
        self.hint = tk.StringVar()
        tk.Label(bar, textvariable=self.hint, font=(FONT, 11), fg=MUTED, bg=BG).pack(side="left", padx=15)
        make_button(bar, "AI Settings", lambda: SettingsWindow(self.winfo_toplevel()),
                    size=11, primary=False).pack(side="right", padx=(8, 0))
        make_button(bar, "Explain selected with AI", self.explain, size=11).pack(side="right")
        self.tech = tk.BooleanVar(value=False)
        tk.Checkbutton(bar, text="Show technical details", variable=self.tech, command=self.toggle_tech,
                       font=(FONT, 11), fg=TEXT, bg=BG, activebackground=BG, activeforeground=TEXT,
                       selectcolor=PANEL).pack(side="right", padx=20)

        holder = tk.Frame(self, bg=BG)
        holder.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(holder, columns=ALL_COLS, show="headings", displaycolumns=FRIENDLY)
        for key, title, width in TABLE_COLS:
            self.tree.heading(key, text=title, anchor="w")
            self.tree.column(key, width=width, anchor="w")
        self.tree.tag_configure("bad", background=ROW_BAD, foreground="#ffd9d9")
        sb = ttk.Scrollbar(holder, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", lambda e: self.explain())

    def toggle_tech(self):
        self.tree.configure(displaycolumns=ALL_COLS if self.tech.get() else FRIENDLY)

    def show(self, df):
        self.tree.delete(*self.tree.get_children())
        self.records = {}
        if df.empty:
            self.hint.set("")
            return
        total = len(df)
        if self.order == "risk":
            df = df.sort_values("attack_prob", ascending=False)
        df = df.head(self.limit)
        word = "highest-risk" if self.order == "risk" else "latest"
        self.hint.set(f"Showing the {len(df):,} {word} of {total:,}  •  double-click a row to explain it")
        for i, r in enumerate(df.to_dict("records")):
            iid = str(i)
            self.records[iid] = r
            tag = ("bad",) if r["verdict"] == "Suspicious" else ()
            self.tree.insert("", "end", iid=iid, tags=tag, values=(
                r.get("seen_at", "-"), r["service"], r.get("attack_type", "-"),
                human_size(r["total_bytes"]), human_time(r["duration"]), int(r["packet_count"]),
                f"{r['attack_prob']:.0%}", r["verdict"], r.get("protocol", "-"),
                endpoint(r.get("src_ip"), r.get("src_port")),
                endpoint(r.get("dst_ip"), r.get("dst_port"))))

    def explain(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Select a connection", "Click a row in the table first, then press Explain.")
            return
        ExplainWindow(self.winfo_toplevel(), self.records[sel[0]])


# ---------- screen 1: start ----------
class Splash(Screen):
    def __init__(self, app):
        super().__init__(app)
        box = tk.Frame(self, bg=BG)
        box.place(relx=0.5, rely=0.45, anchor="center")
        tk.Label(box, text="ANOMFLOW AI", font=(FONT, 54, "bold"), fg=TEXT, bg=BG).pack()
        tk.Frame(box, bg=ACCENT, height=4, width=420).pack(pady=12)
        tk.Label(box, text="Network Anomaly Detection Framework",
                 font=(FONT, 20), fg=MUTED, bg=BG).pack(pady=(0, 40))
        make_button(box, "START", lambda: app.show(Setup), size=20).pack()


# ---------- screen 2: attacks + mode ----------
class AttackCard(tk.Frame):
    def __init__(self, parent, icon, name, trained, desc, var):
        super().__init__(parent, bg=PANEL, highlightthickness=0)
        active = trained
        stripe = tk.Frame(self, bg=ACCENT if active else "#2a3f63", width=4)
        stripe.pack(side="left", fill="y")
        body = tk.Frame(self, bg=PANEL, padx=14, pady=10)
        body.pack(side="left", fill="both", expand=True)

        top = tk.Frame(body, bg=PANEL)
        top.pack(fill="x")
        tk.Label(top, text=icon, font=(FONT, 16), bg=PANEL, fg=TEXT).pack(side="left")
        tk.Label(top, text=name, font=(FONT, 13, "bold"), bg=PANEL,
                 fg=TEXT if active else MUTED, anchor="w",
                 wraplength=300, justify="left").pack(side="left", padx=(8, 8), fill="x", expand=True)
        badge = tk.Label(top, text="ACTIVE" if active else "LOCKED",
                         font=(FONT, 9, "bold"), bg=OK_BG if active else "#2a3f63",
                         fg=GOOD if active else MUTED, padx=8, pady=2)
        badge.pack(side="right")
        if active:
            tk.Checkbutton(top, variable=var, bg=PANEL, activebackground=PANEL,
                           fg=TEXT, activeforeground=TEXT,
                           selectcolor=BG).pack(side="right", padx=(0, 8))

        tk.Label(body, text=desc, font=(FONT, 10), bg=PANEL, fg=MUTED, anchor="w",
                 justify="left", wraplength=320).pack(fill="x", pady=(4, 0))


class ModeCard(tk.Frame):
    def __init__(self, parent, icon, title, desc, command):
        super().__init__(parent, bg=PANEL, cursor="hand2", highlightbackground=ACCENT,
                         highlightthickness=0)
        pad = tk.Frame(self, bg=PANEL, padx=22, pady=18)
        pad.pack(fill="both", expand=True)
        tk.Label(pad, text=icon, font=(FONT, 30), bg=PANEL, fg=ACCENT).pack(anchor="w")
        tk.Label(pad, text=title, font=(FONT, 18, "bold"), bg=PANEL, fg=TEXT,
                 anchor="w").pack(fill="x", pady=(8, 4))
        tk.Label(pad, text=desc, font=(FONT, 11), bg=PANEL, fg=MUTED, anchor="w",
                 justify="left", wraplength=360).pack(fill="x")
        btn = make_button(pad, "Open →", command, size=12)
        btn.pack(anchor="w", pady=(14, 0))
        for widget in (self, pad):
            widget.bind("<Button-1>", lambda e: command())


class Setup(Screen):
    def __init__(self, app):
        super().__init__(app)
        top = tk.Frame(self, bg=BG)
        top.pack(fill="x", padx=30, pady=(18, 0))
        make_button(top, "ℹ Model Info", lambda: app.show(ModelInfo), size=11, primary=False).pack(side="right")

        tk.Label(self, text="ANOMFLOW AI", font=(FONT, 22, "bold"), fg=MUTED, bg=BG).pack(pady=(4, 0))
        tk.Label(self, text="Select Detection Mode", font=(FONT, 30, "bold"),
                 fg=TEXT, bg=BG).pack(pady=(2, 4))
        tk.Label(self, text="Tick the attacks you want flagged, then choose how to analyse traffic.",
                 font=(FONT, 13), fg=MUTED, bg=BG).pack()

        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=40, pady=22)

        left_wrap = tk.Frame(body, bg=BG)
        left_wrap.pack(side="left", fill="both", expand=True, padx=(0, 15))
        tk.Label(left_wrap, text="Attacks ANOMFLOW can check for",
                 font=(FONT, 16, "bold"), fg=TEXT, bg=BG).pack(anchor="w", pady=(0, 10))

        grid = tk.Frame(left_wrap, bg=BG)
        grid.pack(fill="both", expand=True)
        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=1)

        self.vars = {}
        for i, (icon, name, trained, desc) in enumerate(ATTACKS):
            var = tk.BooleanVar(value=trained and name in app.selected)
            self.vars[name] = var
            card = AttackCard(grid, icon, name, trained, desc, var)
            card.grid(row=i // 2, column=i % 2, sticky="nsew", padx=6, pady=6)

        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", padx=(15, 0))
        tk.Label(right, text="Choose a mode", font=(FONT, 16, "bold"),
                 fg=TEXT, bg=BG).pack(anchor="w", pady=(0, 10))

        ModeCard(right, "📡", "Real-Time Analysis",
                 "Watch live traffic from this PC. Capture once, or start continuous monitoring "
                 "and see results update as they happen.",
                 lambda: self.go(Realtime)).pack(fill="x", pady=(0, 14))
        ModeCard(right, "📁", "File Analysis (PCAP/CSV)",
                 "Open a saved capture or dataset file and see what happened in plain English, "
                 "with graphs. Works fully offline.",
                 lambda: self.go(FileAnalysis)).pack(fill="x")

    def go(self, screen_cls):
        chosen = [n for n, v in self.vars.items() if v.get()]
        if not chosen:
            messagebox.showwarning("Select an attack", "Tick at least one attack to check for.")
            return
        self.app.selected = chosen
        self.app.show(screen_cls)



# ---------- screen 2b: model info ----------

class ModelInfo(Screen):
    def __init__(self, app):
        super().__init__(app)
        build_header(self, "Model Info", "Technical details about the trained detection model")
        try:
            meta = get_metadata()
        except Exception:
            meta = {}

        def fmt(key, kind=str, suffix=""):
            v = meta.get(key)
            if v is None or v == "":
                return "Unknown (retrain to record this)"
            if kind is int and isinstance(v, (int, float)):
                return f"{int(v):,}{suffix}"
            if kind is float and isinstance(v, (int, float)):
                return f"{v:.3f}{suffix}"
            if isinstance(v, list):
                return ", ".join(str(x) for x in v) if v else "Unknown"
            return str(v) + suffix

        try:
            model_name = type(get_model()[0]).__name__
        except Exception:
            model_name = "Unknown"

        card = tk.Frame(self, bg=PANEL, padx=28, pady=22)
        card.pack(fill="both", expand=True, padx=30, pady=15)

        rows = [
            ("Model type", model_name),
            ("Trained on files", fmt("files")),
            ("Training date", fmt("trained_at")),
            ("Classes detected", fmt("classes")),
            ("Features used", fmt("feature_count", int)),
            ("Trees (n_estimators)", fmt("n_estimators", int)),
            ("Max depth", fmt("max_depth", int) if meta.get("max_depth") else "No limit"),
            ("Rows trained on", fmt("rows_trained", int)),
            ("Test macro F1 score", fmt("test_macro_f1", float)),
        ]
        for label, value in rows:
            row = tk.Frame(card, bg=PANEL)
            row.pack(fill="x", pady=8)
            tk.Label(row, text=label, font=(FONT, 13, "bold"), fg=MUTED, bg=PANEL,
                     width=20, anchor="w").pack(side="left")
            tk.Label(row, text=value, font=(FONT, 13), fg=TEXT, bg=PANEL, anchor="w",
                     justify="left", wraplength=650).pack(side="left", fill="x", expand=True)
        tk.Label(card, text="Macro F1 averages precision/recall equally across classes, "
                            "so a small class (like a rare attack type) still counts fully.",
                 font=(FONT, 11), fg=MUTED, bg=PANEL, wraplength=800, justify="left").pack(anchor="w", pady=(16, 0))
        
# ---------- screen 3a: real-time ----------
class Realtime(Screen):
    def __init__(self, app):
        super().__init__(app)
        self.q = queue.Queue()
        self.stop_event = threading.Event()
        self.running = False
        self.raw_session = pd.DataFrame()
        self.history = []
        self.threshold_var = tk.DoubleVar(value=50)
        build_header(self, "Real-Time Analysis", "Monitoring for: " + ", ".join(app.selected))

        ctrl = tk.Frame(self, bg=BG)
        ctrl.pack(fill="x", padx=30, pady=8)
        tk.Label(ctrl, text="Seconds per capture", font=(FONT, 13), fg=TEXT, bg=BG).pack(side="left")
        self.seconds = tk.StringVar(value="10")
        spinbox(ctrl, self.seconds, 3, 300).pack(side="left", padx=10)
        self.btn_once = make_button(ctrl, "Capture Once", lambda: self.start(False), size=13)
        self.btn_once.pack(side="left", padx=6)
        self.btn_monitor = make_button(ctrl, "Start Monitoring", self.toggle_monitor, size=13)
        self.btn_monitor.pack(side="left", padx=6)
        self.btn_export = make_button(ctrl, "Export Report", self.export, size=13, primary=False)
        self.btn_export.pack(side="left", padx=6)
        threshold_slider(ctrl, self.threshold_var, self.refresh_display).pack(side="left", padx=20)
        self.status = tk.StringVar(value="Ready")
        tk.Label(ctrl, textvariable=self.status, font=(FONT, 12), fg=MUTED, bg=BG).pack(side="right")

        self.banner = tk.Label(self, text="Ready. Capture once, or start continuous monitoring.",
                               font=(FONT, 13, "bold"), fg=TEXT, bg=PANEL, anchor="w", padx=18, pady=8)
        self.banner.pack(fill="x", padx=30, pady=(0, 10))

        self.fig = Figure(figsize=(10, 1.8), facecolor=BG)
        self.canvas = FigureCanvasTkAgg(self.fig, master=self)
        self.canvas.get_tk_widget().configure(bg=BG, highlightthickness=0)
        self.canvas.get_tk_widget().pack(fill="x", padx=30, pady=(0, 8))
        draw_timeline(self.fig, self.history, dark=True)
        self.canvas.draw()

        stats = tk.Frame(self, bg=BG)
        stats.pack(fill="x", padx=30)
        self.total_var = stat_card(stats, "Connections checked")
        self.anom_var = stat_card(stats, "Suspicious", BAD)
        self.rate_var = stat_card(stats, "Suspicious share")

        self.panel = ResultsPanel(self, order="recent", limit=300)
        self.panel.pack(fill="both", expand=True, padx=30, pady=12)

    def read_seconds(self):
        try:
            secs = int(self.seconds.get())
            if secs < 3:
                raise ValueError
            return secs
        except ValueError:
            messagebox.showwarning("Invalid input", "Enter the capture length as a whole number of seconds (3 or more).")
            return None

    def toggle_monitor(self):
        if self.running:
            self.stop_event.set()
            self.btn_monitor.config(state="disabled")
            self.status.set("Stopping after the current capture...")
        else:
            self.start(True)

    def start(self, loop):
        secs = self.read_seconds()
        if secs is None:
            return
        self.stop_event.clear()
        self.running = True
        self.btn_once.config(state="disabled")
        self.back_btn.config(state="disabled")
        if loop:
            self.btn_monitor.config(text="■ Stop Monitoring")
            self.status.set(f"Monitoring... new results every {secs} seconds")
        else:
            self.btn_monitor.config(state="disabled")
            self.status.set(f"Capturing for {secs} seconds...")
        threading.Thread(target=self.worker, args=(secs, loop), daemon=True).start()
        self.after(300, self.poll)

    def worker(self, secs, loop):
        try:
            while True:
                self.q.put(("batch", capture_and_score(secs, self.stop_event)))
                if not loop or self.stop_event.is_set():
                    break
        except Exception as e:
            self.q.put(("error", e))
        self.q.put(("done", None))

    def poll(self):
        done = False
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "batch":
                    self.add_batch(payload)
                elif kind == "error":
                    messagebox.showerror(
                        "Capture failed",
                        f"{payload}\n\nMake sure Npcap is installed and the app is run as Administrator.")
                elif kind == "done":
                    done = True
        except queue.Empty:
            pass
        if done:
            self.finish()
        else:
            self.after(300, self.poll)

    def finish(self):
        self.running = False
        self.btn_once.config(state="normal")
        self.btn_monitor.config(text="Start Monitoring", state="normal")
        self.back_btn.config(state="normal")
        self.status.set("Stopped" if self.stop_event.is_set() else "Done")

    def set_banner(self, text, ok):
        self.banner.config(text=text, bg=OK_BG if ok else ROW_BAD, fg=GOOD if ok else "#ffd9d9")

    def add_batch(self, df):
        stamp = datetime.now().strftime("%H:%M:%S")
        threshold = self.threshold_var.get() / 100
        if df.empty:
            self.history.append({"time": stamp, "total": 0, "suspicious": 0})
        else:
            self.raw_session = df if self.raw_session.empty else pd.concat([self.raw_session, df], ignore_index=True)
            self.raw_session = self.raw_session.tail(5000).reset_index(drop=True)
            n_bad_batch = int((df["attack_prob"] >= threshold).sum())
            self.history.append({"time": stamp, "total": len(df), "suspicious": n_bad_batch})
        self.history = self.history[-20:]
        self.refresh_display()

    def refresh_display(self):
        threshold = self.threshold_var.get() / 100
        draw_timeline(self.fig, self.history, dark=True)
        self.canvas.draw()

        last = self.history[-1] if self.history else None
        if last is None:
            self.set_banner("Ready. Capture once, or start continuous monitoring.", True)
        elif last["suspicious"]:
            self.set_banner(f"⚠ {last['suspicious']} suspicious connection(s) in the last capture ({last['time']})", False)
        else:
            self.set_banner(f"✔ All clear in the last capture ({last['time']})", True)

        if self.raw_session.empty:
            self.total_var.set("0")
            self.anom_var.set("0")
            self.rate_var.set("-")
            self.panel.show(pd.DataFrame())
            return
        prepared = prepare(self.raw_session, threshold)
        total = len(prepared)
        bad = int((prepared["verdict"] == "Suspicious").sum())
        self.total_var.set(f"{total:,}")
        self.anom_var.set(f"{bad:,}")
        self.rate_var.set(f"{bad / total:.1%}")
        self.panel.show(prepared.iloc[::-1])

    def export(self):
        if self.raw_session.empty:
            messagebox.showinfo("Nothing to export", "Run a capture first, then export the report.")
            return
        prepared = prepare(self.raw_session, self.threshold_var.get() / 100)
        export_report(prepared, "Live capture on this PC", "Real-Time Analysis")


# ---------- screen 3b: file analysis ----------
class FileAnalysis(Screen):
    def __init__(self, app):
        super().__init__(app)
        self.q = queue.Queue()
        self.raw_df = pd.DataFrame()
        self.df = pd.DataFrame()
        self.source = "-"
        self.threshold_var = tk.DoubleVar(value=50)
        build_header(self, "File Analysis",
                     "Open a saved packet capture (.pcap) or a flow dataset (.csv). Works offline.")

        ctrl = tk.Frame(self, bg=BG)
        ctrl.pack(fill="x", padx=30, pady=8)
        self.btn_open = make_button(ctrl, "Open file...", self.open_file, size=13)
        self.btn_open.pack(side="left")
        self.btn_export = make_button(ctrl, "Export Report", self.export, size=13, primary=False)
        self.btn_export.pack(side="left", padx=10)
        threshold_slider(ctrl, self.threshold_var, self.refresh_display).pack(side="left", padx=20)
        self.status = tk.StringVar(value="No file loaded")
        tk.Label(ctrl, textvariable=self.status, font=(FONT, 12), fg=MUTED, bg=BG).pack(side="right")

        card = tk.Frame(self, bg=PANEL, padx=20, pady=12)
        card.pack(fill="x", padx=30, pady=(0, 8))
        tk.Label(card, text="What happened", font=(FONT, 15, "bold"), fg=TEXT, bg=PANEL).pack(anchor="w")
        self.summary = tk.StringVar(value=INTRO)
        lbl = tk.Label(card, textvariable=self.summary, font=(FONT, 12), fg=TEXT, bg=PANEL,
                       justify="left", anchor="w")
        lbl.pack(fill="x", pady=(4, 0))
        lbl.bind("<Configure>", lambda e: lbl.config(wraplength=max(e.width - 10, 200)))

        self.fig = Figure(figsize=(10, 5.0), facecolor=BG)
        self.canvas = FigureCanvasTkAgg(self.fig, master=self)
        self.canvas.get_tk_widget().configure(bg=BG, highlightthickness=0)
        self.canvas.get_tk_widget().pack(fill="x", padx=30, pady=4)

        self.panel = ResultsPanel(self, order="risk", limit=500)
        self.panel.pack(fill="both", expand=True, padx=30, pady=(4, 12))

    def open_file(self):
        path = filedialog.askopenfilename(
            title="Choose a file",
            filetypes=[("Packet capture or flow CSV", "*.pcap *.pcapng *.cap *.csv"), ("All files", "*.*")])
        if not path:
            return
        self.source = os.path.basename(path)
        self.btn_open.config(state="disabled")
        self.btn_export.config(state="disabled")
        self.back_btn.config(state="disabled")
        self.status.set("Reading file... large files can take a minute")
        threading.Thread(target=self.worker, args=(path,), daemon=True).start()
        self.after(300, self.poll)

    def worker(self, path):
        try:
            if path.lower().endswith((".pcap", ".pcapng", ".cap")):
                df = analyze_pcap(path, lambda n: self.q.put(("progress", n)))
            else:
                df = load_csv_flows(path)
            self.q.put(("result", df))
        except Exception as e:
            self.q.put(("error", e))

    def poll(self):
        finished = False
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "progress":
                    self.status.set(f"Read {payload:,} packets...")
                elif kind == "result":
                    self.show_result(payload)
                    finished = True
                elif kind == "error":
                    messagebox.showerror("Could not analyse file", str(payload))
                    self.status.set("Failed")
                    finished = True
        except queue.Empty:
            pass
        if finished:
            self.btn_open.config(state="normal")
            self.btn_export.config(state="normal")
            self.back_btn.config(state="normal")
        else:
            self.after(300, self.poll)

    def show_result(self, df):
        if df.empty:
            self.raw_df = pd.DataFrame()
            self.df = pd.DataFrame()
            self.summary.set("No usable connections were found. ANOMFLOW needs TCP or UDP "
                             "connections with at least 2 packets.")
            self.status.set("No connections found")
            self.fig.clear()
            self.canvas.draw()
            self.panel.show(pd.DataFrame())
            return
        self.raw_df = df
        self.status.set(f"Done: {len(df):,} connections analysed")
        self.refresh_display()

    def refresh_display(self):
        if self.raw_df.empty:
            return
        threshold = self.threshold_var.get() / 100
        self.df = prepare(self.raw_df, threshold)
        self.summary.set("\n".join(build_summary(self.df, self.source)))
        draw_charts(self.fig, self.df, dark=True)
        self.canvas.draw()
        self.panel.show(self.df)

    def export(self):
        if self.df.empty:
            messagebox.showinfo("Nothing to export", "Open a file first, then export the report.")
            return
        export_report(self.df, self.source, "File Analysis")


# ---------- app ----------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ANOMFLOW AI")
        self.geometry("1280x860")
        self.minsize(1000, 680)
        self.configure(bg=BG)
        try:
            self.state("zoomed")
        except tk.TclError:
            pass
        setup_styles(self)
        self.selected = ["DDoS"]
        self.container = tk.Frame(self, bg=BG)
        self.container.pack(fill="both", expand=True)
        self.current = None
        self.show(Splash)

    def show(self, screen_cls):
        if self.current is not None:
            self.current.destroy()
        self.current = screen_cls(self)
        self.current.pack(fill="both", expand=True)


if __name__ == "__main__":
    App().mainloop()