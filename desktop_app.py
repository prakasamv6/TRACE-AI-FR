"""
TRACE-AI-FR Desktop Application
Transparent Reporting of AI-related Claims in Evidence: A Forensic Reasoning Framework
"""
# cSpell:words MEIPASS Neue Menlo Segoe Consolas startfile TOPBAR
# cSpell:words fieldbackground bordercolor troughcolor rowheight insertcolor
# cSpell:words insertbackground activebackground activeforeground tearoff
# cSpell:words wclass padx pady textvariable yscrollcommand xscrollcommand
import os
import sys
import json
import platform
import queue
import re
import struct
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog
from datetime import datetime
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Resolve package path so the app works both as script and bundled .exe / .app
# ---------------------------------------------------------------------------
if getattr(sys, "frozen", False):
    _BASE = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
else:
    _BASE = os.path.dirname(os.path.abspath(__file__))

if _BASE not in sys.path:
    sys.path.insert(0, _BASE)

from ai_usage_evidence_analyzer import __version__, __product__, __full_name__
from ai_usage_evidence_analyzer.engine import AnalysisEngine
from ai_usage_evidence_analyzer.models import ForensicReport

# ---------------------------------------------------------------------------
# Cross-platform helpers
# ---------------------------------------------------------------------------
IS_MAC = platform.system() == "Darwin"
IS_WIN = platform.system() == "Windows"

# Fonts: use platform-native families
if IS_MAC:
    FONT_UI = "Helvetica Neue"
    FONT_MONO = "Menlo"
    MOD_KEY = "Command"
    MOD_SYMBOL = "⌘"
    MOD_BIND = "Command"
else:
    FONT_UI = "Segoe UI"
    FONT_MONO = "Consolas"
    MOD_KEY = "Ctrl"
    MOD_SYMBOL = "Ctrl"
    MOD_BIND = "Control"


def open_file_cross_platform(filepath: str):
    """Open a file with the default application on any platform."""
    if IS_WIN:
        os.startfile(filepath)
    elif IS_MAC:
        subprocess.Popen(["open", filepath])
    else:
        subprocess.Popen(["xdg-open", filepath])


# ═══════════════════════════════════════════════════════════════════════════
# Colour palette  (dark / light forensic themes)
# ═══════════════════════════════════════════════════════════════════════════
THEMES = {
    "dark": {
        "BG":       "#0f172a",
        "SURFACE":  "#1e293b",
        "SURFACE2": "#334155",
        "PRIMARY":  "#38bdf8",
        "ACCENT":   "#818cf8",
        "SUCCESS":  "#4ade80",
        "WARNING":  "#fbbf24",
        "DANGER":   "#f87171",
        "TEXT":     "#e2e8f0",
        "TEXT_DIM": "#94a3b8",
        "BORDER":   "#475569",
        "TOPBAR":   "#020617",
    },
    "light": {
        "BG":       "#f8fafc",
        "SURFACE":  "#ffffff",
        "SURFACE2": "#e2e8f0",
        "PRIMARY":  "#0284c7",
        "ACCENT":   "#6366f1",
        "SUCCESS":  "#16a34a",
        "WARNING":  "#d97706",
        "DANGER":   "#dc2626",
        "TEXT":     "#1e293b",
        "TEXT_DIM": "#64748b",
        "BORDER":   "#cbd5e1",
        "TOPBAR":   "#e2e8f0",
    },
}

_current_theme = "light"
_t = THEMES[_current_theme]
BG       = _t["BG"]
SURFACE  = _t["SURFACE"]
SURFACE2 = _t["SURFACE2"]
PRIMARY  = _t["PRIMARY"]
ACCENT   = _t["ACCENT"]
SUCCESS  = _t["SUCCESS"]
WARNING  = _t["WARNING"]
DANGER   = _t["DANGER"]
TEXT     = _t["TEXT"]
TEXT_DIM = _t["TEXT_DIM"]
BORDER   = _t["BORDER"]
TOPBAR   = _t["TOPBAR"]


# ═══════════════════════════════════════════════════════════════════════════
# Main Application Window
# ═══════════════════════════════════════════════════════════════════════════
class TraceAIApp(tk.Tk):
    """Main TRACE-AI-FR desktop window."""

    def __init__(self):
        super().__init__()

        self.title(f"{__product__} v{__version__}")
        self.geometry("1360x820")
        self.minsize(1000, 650)
        self.configure(bg=BG)

        # State
        self.evidence_path: str = ""
        self.output_dir: str = ""
        self.questions_docx_path: str = ""
        self.report: ForensicReport | None = None
        self._analysis_thread: threading.Thread | None = None
        self._msg_queue: queue.Queue[Any] = queue.Queue()
        self._polling: bool = False

        self.evidence_var: tk.StringVar = tk.StringVar()
        self.output_var: tk.StringVar = tk.StringVar()
        self.questions_var: tk.StringVar = tk.StringVar()
        self.case_var: tk.StringVar = tk.StringVar()
        self.examiner_var: tk.StringVar = tk.StringVar()
        self.org_var: tk.StringVar = tk.StringVar()
        self.carving_var: tk.BooleanVar = tk.BooleanVar(value=False)
        self.mode_var: tk.StringVar = tk.StringVar(value="auto")

        # Icon (optional, Windows only)
        try:
            if IS_WIN:
                self.iconbitmap(default="")
        except Exception:
            pass

        self._apply_styles()
        self._build_menu()
        self._build_toolbar()
        self._build_body()
        self._build_statusbar()

        self._set_status("Ready — select evidence to begin analysis.")

    # ── Styles ─────────────────────────────────────────────────────────
    def _apply_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam" if not IS_MAC else "aqua")

        # General
        style.configure(".", background=BG, foreground=TEXT,
                         fieldbackground=SURFACE, bordercolor=BORDER,
                         troughcolor=SURFACE2, font=(FONT_UI, 10))
        style.configure("TFrame", background=BG)
        style.configure("Surface.TFrame", background=SURFACE)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Surface.TLabel", background=SURFACE, foreground=TEXT)
        style.configure("Dim.TLabel", background=BG, foreground=TEXT_DIM,
                         font=(FONT_UI, 9))
        style.configure("Header.TLabel", background=BG, foreground=PRIMARY,
                         font=(FONT_UI, 13, "bold"))
        style.configure("Big.TLabel", background=SURFACE, foreground=PRIMARY,
                         font=(FONT_UI, 22, "bold"))
        style.configure("StatVal.TLabel", background=SURFACE, foreground=TEXT,
                         font=(FONT_UI, 11))

        # Buttons
        style.configure("Accent.TButton", background=PRIMARY, foreground=TOPBAR,
                         font=(FONT_UI, 10, "bold"), padding=(12, 6))
        style.map("Accent.TButton",
                  background=[("active", ACCENT), ("disabled", SURFACE2)])

        style.configure("TButton", padding=(10, 5))
        style.map("TButton",
                  background=[("active", SURFACE2)])

        # Notebook (tabs)
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=SURFACE2, foreground=TEXT,
                         padding=(14, 6), font=(FONT_UI, 10))
        style.map("TNotebook.Tab",
                  background=[("selected", PRIMARY)],
                  foreground=[("selected", TOPBAR)])

        # Treeview
        style.configure("Treeview", background=SURFACE, foreground=TEXT,
                         fieldbackground=SURFACE, rowheight=26,
                         font=(FONT_UI, 10))
        style.configure("Treeview.Heading", background=SURFACE2,
                         foreground=TEXT, font=(FONT_UI, 10, "bold"))
        style.map("Treeview",
                  background=[("selected", PRIMARY)],
                  foreground=[("selected", TOPBAR)])

        # Progress bar
        style.configure("Green.Horizontal.TProgressbar",
                         troughcolor=SURFACE2, background=SUCCESS)

        # Entry
        style.configure("TEntry", fieldbackground=SURFACE, foreground=TEXT,
                         insertcolor=TEXT)

        # LabelFrame
        style.configure("TLabelframe", background=BG, foreground=PRIMARY)
        style.configure("TLabelframe.Label", background=BG, foreground=PRIMARY,
                         font=(FONT_UI, 10, "bold"))

    # ── Theme toggle ──────────────────────────────────────────────────
    def _toggle_theme(self):
        global _current_theme, _t, BG, SURFACE, SURFACE2, PRIMARY, ACCENT
        global SUCCESS, WARNING, DANGER, TEXT, TEXT_DIM, BORDER, TOPBAR

        _current_theme = "light" if _current_theme == "dark" else "dark"
        _t = THEMES[_current_theme]
        BG       = _t["BG"]
        SURFACE  = _t["SURFACE"]
        SURFACE2 = _t["SURFACE2"]
        PRIMARY  = _t["PRIMARY"]
        ACCENT   = _t["ACCENT"]
        SUCCESS  = _t["SUCCESS"]
        WARNING  = _t["WARNING"]
        DANGER   = _t["DANGER"]
        TEXT     = _t["TEXT"]
        TEXT_DIM = _t["TEXT_DIM"]
        BORDER   = _t["BORDER"]
        TOPBAR   = _t["TOPBAR"]

        # Re-apply all ttk styles
        self._apply_styles()
        self.configure(bg=BG)

        # Update the menu label
        new_label = "Switch to Dark Theme" if _current_theme == "light" else "Switch to Light Theme"
        self._view_menu.entryconfigure(0, label=new_label)

        # Update all tk widgets (non-ttk) recursively
        self._reapply_tk_colors(self)

    def _reapply_tk_colors(self, widget):
        """Recursively update bg/fg on plain tk widgets."""
        try:
            wclass = widget.winfo_class()
            if wclass in ("Frame", "Labelframe"):
                widget.configure(bg=BG)
            elif wclass == "Label":
                # Preserve brand / special labels by checking current fg
                cur_bg = str(widget.cget("bg")).lower()
                # Toolbar labels
                if cur_bg in ("#020617", "#e2e8f0"):
                    widget.configure(bg=TOPBAR)
                else:
                    widget.configure(bg=BG, fg=TEXT)
            elif wclass == "Text":
                widget.configure(bg=SURFACE, fg=TEXT,
                                 insertbackground=TEXT)
            elif wclass == "Button":
                cur_bg = str(widget.cget("bg")).lower()
                # Keep accent-colored buttons distinguishable
                if cur_bg in ("#4ade80", "#16a34a", "#22c55e"):
                    widget.configure(bg=SUCCESS, fg=TOPBAR,
                                     activebackground=SUCCESS)
                elif cur_bg in ("#818cf8", "#6366f1"):
                    widget.configure(bg=ACCENT, fg=TOPBAR,
                                     activebackground=PRIMARY)
                else:
                    widget.configure(bg=SURFACE2, fg=TEXT,
                                     activebackground=PRIMARY,
                                     activeforeground=TOPBAR)
            elif wclass == "Menu":
                widget.configure(bg=SURFACE, fg=TEXT,
                                 activebackground=PRIMARY,
                                 activeforeground=TOPBAR)
        except tk.TclError:
            pass

        for child in widget.winfo_children():
            self._reapply_tk_colors(child)

    # ── Menu bar ───────────────────────────────────────────────────────
    def _build_menu(self):
        menubar = tk.Menu(self, bg=TOPBAR, fg=TEXT, activebackground=PRIMARY,
                          activeforeground=TOPBAR, relief="flat",
                          font=(FONT_UI, 10))

        # File
        file_menu = tk.Menu(menubar, tearoff=0, bg=SURFACE, fg=TEXT,
                            activebackground=PRIMARY, activeforeground=TOPBAR)
        file_menu.add_command(label="Open Evidence…", command=self._open_evidence,
                              accelerator="Ctrl+O")
        file_menu.add_command(label="Open Questions (.docx)…",
                              command=self._open_questions, accelerator="Ctrl+Q")
        file_menu.add_command(label="Set Output Folder…", command=self._set_output,
                              accelerator="Ctrl+Shift+O")
        file_menu.add_separator()
        file_menu.add_command(label="Export Report as HTML…",
                              command=self._open_html_report)
        file_menu.add_command(label="Generate Word Report…",
                              command=self._generate_word_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy,
                              accelerator="\u2318Q" if IS_MAC else "Alt+F4")
        menubar.add_cascade(label="  File  ", menu=file_menu)

        # Analysis
        analysis_menu = tk.Menu(menubar, tearoff=0, bg=SURFACE, fg=TEXT,
                                activebackground=PRIMARY, activeforeground=TOPBAR)
        analysis_menu.add_command(label="Run Analysis", command=self._run_analysis,
                                  accelerator="F5")
        analysis_menu.add_command(label="Clear Results", command=self._clear_results)
        menubar.add_cascade(label="  Analysis  ", menu=analysis_menu)

        # Help
        help_menu = tk.Menu(menubar, tearoff=0, bg=SURFACE, fg=TEXT,
                            activebackground=PRIMARY, activeforeground=TOPBAR)
        help_menu.add_command(label="Framework Info", command=self._show_info)
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="  Help  ", menu=help_menu)

        # View
        view_menu = tk.Menu(menubar, tearoff=0, bg=SURFACE, fg=TEXT,
                            activebackground=PRIMARY, activeforeground=TOPBAR)
        self._theme_label_var = tk.StringVar(value="Switch to Dark Theme")
        view_menu.add_command(label="Switch to Dark Theme",
                              command=self._toggle_theme)
        self._view_menu = view_menu
        menubar.add_cascade(label="  View  ", menu=view_menu)

        self.config(menu=menubar)

        # Key bindings
        self.bind_all(f"<{MOD_BIND}-o>", lambda e: self._open_evidence())
        self.bind_all(f"<{MOD_BIND}-q>", lambda e: self._open_questions())
        self.bind_all("<F5>", lambda e: self._run_analysis())

    # ── Toolbar ────────────────────────────────────────────────────────
    def _build_toolbar(self):
        tb = tk.Frame(self, bg=TOPBAR, height=44)
        tb.pack(fill="x", side="top")
        tb.pack_propagate(False)

        # Brand
        lbl = tk.Label(tb, text="  TRACE", fg=PRIMARY,
                       bg=TOPBAR, font=(FONT_UI, 14, "bold"))
        lbl.pack(side="left")
        lbl2 = tk.Label(tb, text="-AI-", fg=ACCENT,
                        bg=TOPBAR, font=(FONT_UI, 14, "bold"))
        lbl2.pack(side="left")
        lbl3 = tk.Label(tb, text="FR  ", fg=SUCCESS,
                        bg=TOPBAR, font=(FONT_UI, 14, "bold"))
        lbl3.pack(side="left")
        sep = tk.Label(tb, text="│", fg=BORDER, bg=TOPBAR,
                       font=(FONT_UI, 14))
        sep.pack(side="left", padx=4)

        # Buttons
        btn_kw: dict[str, Any] = dict(
            bg=SURFACE2,
            fg=TEXT,
            relief="flat",
            activebackground=PRIMARY,
            activeforeground=TOPBAR,
            font=(FONT_UI, 10),
            padx=10,
            pady=3,
            cursor="hand2",
        )

        tk.Button(tb, text="📂 Open Evidence", command=self._open_evidence,
                  **btn_kw).pack(side="left", padx=2, pady=6)
        tk.Button(tb, text="📁 Output Folder", command=self._set_output,
                  **btn_kw).pack(side="left", padx=2, pady=6)
        tk.Button(tb, text="📝 Questions (.docx)", command=self._open_questions,
                  **btn_kw).pack(side="left", padx=2, pady=6)

        sep2 = tk.Label(tb, text="│", fg=BORDER, bg=TOPBAR,
                        font=(FONT_UI, 14))
        sep2.pack(side="left", padx=4)

        self.btn_run = tk.Button(
            tb, text="▶  Run Analysis", command=self._run_analysis,
            bg=SUCCESS, fg=TOPBAR, relief="flat",
            activebackground="#22c55e", activeforeground=TOPBAR,
            font=(FONT_UI, 10, "bold"), padx=14, pady=3, cursor="hand2")
        self.btn_run.pack(side="left", padx=2, pady=6)

        self.btn_report = tk.Button(
            tb, text="📄 Generate Report", command=self._generate_word_report,
            bg=ACCENT, fg=TOPBAR, relief="flat",
            activebackground=PRIMARY, activeforeground=TOPBAR,
            font=(FONT_UI, 10, "bold"), padx=14, pady=3, cursor="hand2")
        self.btn_report.pack(side="left", padx=2, pady=6)

        tk.Button(tb, text="🗑 Clear", command=self._clear_results,
                  **btn_kw).pack(side="left", padx=2, pady=6)

        # Right side - version
        ver = tk.Label(tb, text=f"v{__version__}",
                       bg=TOPBAR, fg=TEXT_DIM, font=(FONT_UI, 9))
        ver.pack(side="right", padx=12)

    # ── Body (left config + right tabs) ────────────────────────────────
    def _build_body(self):
        body = ttk.PanedWindow(self, orient="horizontal")
        body.pack(fill="both", expand=True, padx=4, pady=4)

        # ─ Left panel ─
        left = ttk.Frame(body, style="TFrame", width=320)
        body.add(left, weight=0)

        self._build_config_panel(left)
        self._build_evidence_tree(left)

        # ─ Right panel ─
        right = ttk.Frame(body, style="TFrame")
        body.add(right, weight=1)

        self._build_tabs(right)

    # --- Config panel ---
    def _build_config_panel(self, parent):
        cfg = ttk.LabelFrame(parent, text="  Analysis Configuration  ",
                             padding=10)
        cfg.pack(fill="x", padx=6, pady=(6, 3))

        rows = [
            ("Evidence:", "evidence_var", self.evidence_var),
            ("Output:", "output_var", self.output_var),
            ("Questions:", "questions_var", self.questions_var),
            ("Case Name:", "case_var", self.case_var),
            ("Examiner:", "examiner_var", self.examiner_var),
            ("Organization:", "org_var", self.org_var),
        ]
        for i, (label, attr, var) in enumerate(rows):
            ttk.Label(cfg, text=label).grid(row=i, column=0, sticky="w",
                                            pady=3, padx=(0, 6))
            if attr in ("evidence_var", "output_var", "questions_var"):
                frm = ttk.Frame(cfg)
                frm.grid(row=i, column=1, sticky="ew", pady=3)
                ttk.Entry(frm, textvariable=var, width=22).pack(
                    side="left", fill="x", expand=True)
                if attr == "evidence_var":
                    cmd = self._open_evidence
                elif attr == "output_var":
                    cmd = self._set_output
                else:
                    cmd = self._open_questions
                ttk.Button(frm, text="…", width=3, command=cmd).pack(
                    side="right", padx=(4, 0))
            else:
                ttk.Entry(cfg, textvariable=var, width=28).grid(
                    row=i, column=1, sticky="ew", pady=3)

        cfg.columnconfigure(1, weight=1)

        # Options row
        opt_frm = ttk.Frame(cfg)
        opt_frm.grid(row=len(rows), column=0, columnspan=2, sticky="ew",
                     pady=(8, 0))
        ttk.Checkbutton(opt_frm, text="Enable carving",
                        variable=self.carving_var).pack(side="left")

        ttk.Label(opt_frm, text="  Mode:").pack(side="left", padx=(12, 4))
        mode_cb = ttk.Combobox(opt_frm, textvariable=self.mode_var,
                               values=["auto", "e01", "mounted", "zip"],
                               width=8, state="readonly")
        mode_cb.pack(side="left")

    # --- Evidence tree ---
    def _build_evidence_tree(self, parent):
        lf = ttk.LabelFrame(parent, text="  Evidence Tree  ", padding=6)
        lf.pack(fill="both", expand=True, padx=6, pady=(3, 6))

        self.ev_tree = ttk.Treeview(lf, show="tree headings", columns=("size",),
                                    selectmode="browse")
        self.ev_tree.heading("#0", text="Name", anchor="w")
        self.ev_tree.heading("size", text="Size")
        self.ev_tree.column("#0", width=200, stretch=True)
        self.ev_tree.column("size", width=70, anchor="e")

        ysb = ttk.Scrollbar(lf, orient="vertical", command=self.ev_tree.yview)
        self.ev_tree.configure(yscrollcommand=ysb.set)

        self.ev_tree.pack(side="left", fill="both", expand=True)
        ysb.pack(side="right", fill="y")

    # --- Results tabs ---
    def _build_tabs(self, parent):
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill="both", expand=True, padx=4, pady=4)

        # Tab: Dashboard
        self.tab_dash = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_dash, text="  Dashboard  ")
        self._build_dashboard_tab(self.tab_dash)

        # Tab: Artifacts
        self.tab_art = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_art, text="  Artifacts  ")
        self._build_artifacts_tab(self.tab_art)

        # Tab: FRAUEs
        self.tab_fraue = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_fraue, text="  FRAUEs  ")
        self._build_fraue_tab(self.tab_fraue)

        # Tab: Timeline
        self.tab_tl = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_tl, text="  Timeline  ")
        self._build_timeline_tab(self.tab_tl)

        # Tab: Governance
        self.tab_gov = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_gov, text="  Governance  ")
        self._build_governance_tab(self.tab_gov)

        # Tab: Questions
        self.tab_questions = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_questions, text="  Questions  ")
        self._build_questions_tab(self.tab_questions)

        # Tab: FR Assessment
        self.tab_fr = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_fr, text="  FR Assessment  ")
        self._build_fr_tab(self.tab_fr)

        # Tab: AI Tools (v5.0 — forensic tool inventory checklist)
        self.tab_checklist = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_checklist, text="  AI Tools  ")
        self._build_checklist_tab(self.tab_checklist)

        # Tab: Log
        self.tab_log = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_log, text="  Log  ")
        self._build_log_tab(self.tab_log)

    # ---------- Dashboard ----------
    def _build_dashboard_tab(self, parent):
        # Welcome / stats cards
        self.dash_frame = ttk.Frame(parent)
        self.dash_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Welcome banner (shown before analysis)
        self.welcome_frame = ttk.Frame(self.dash_frame)
        self.welcome_frame.pack(expand=True)

        ttk.Label(self.welcome_frame, text=__product__,
                  style="Header.TLabel",
                  font=(FONT_UI, 28, "bold")).pack(pady=(40, 4))
        ttk.Label(self.welcome_frame,
                  text=__full_name__,
                  style="Dim.TLabel",
                  font=(FONT_UI, 11)).pack(pady=(0, 20))
        ttk.Label(self.welcome_frame,
                  text="Open an evidence source and press ▶ Run Analysis to begin.",
                  style="Dim.TLabel").pack()
        ttk.Label(self.welcome_frame,
                  text="Supports E01 images · ZIP archives · Mounted directories",
                  style="Dim.TLabel").pack(pady=(6, 0))

        # Stats frame (hidden until analysis done)
        self.stats_frame = ttk.Frame(self.dash_frame)

    # ---------- Artifacts ----------
    def _build_artifacts_tab(self, parent):
        cols = ("platform", "family", "classification", "confidence",
                "source", "timestamp")
        self.art_tree = ttk.Treeview(parent, columns=cols, show="headings",
                                     selectmode="browse")
        headers = {"platform": "Platform", "family": "Artifact Family",
                   "classification": "Classification", "confidence": "Confidence",
                   "source": "Evidence Source", "timestamp": "Timestamp"}
        widths =  {"platform": 100, "family": 150, "classification": 100,
                   "confidence": 100, "source": 180, "timestamp": 170}
        for c in cols:
            self.art_tree.heading(c, text=headers[c])
            self.art_tree.column(c, width=widths[c], anchor="w")

        ysb = ttk.Scrollbar(parent, orient="vertical",
                            command=self.art_tree.yview)
        self.art_tree.configure(yscrollcommand=ysb.set)
        self.art_tree.pack(side="left", fill="both", expand=True)
        ysb.pack(side="right", fill="y")

    # ---------- FRAUEs ----------
    def _build_fraue_tab(self, parent):
        cols = ("id", "platform", "activity", "window", "confidence",
                "claim", "artifacts", "persistence")
        self.fraue_tree = ttk.Treeview(parent, columns=cols, show="headings",
                                       selectmode="browse")
        headers = {"id": "FRAUE ID", "platform": "Platform",
                   "activity": "Activity", "window": "Time Window",
                   "confidence": "Confidence", "claim": "Claim Level",
                   "artifacts": "Artifacts", "persistence": "Persistence"}
        widths = {"id": 120, "platform": 90, "activity": 110, "window": 180,
                  "confidence": 100, "claim": 200, "artifacts": 70,
                  "persistence": 130}
        for c in cols:
            self.fraue_tree.heading(c, text=headers[c])
            self.fraue_tree.column(c, width=widths[c], anchor="w")

        ysb = ttk.Scrollbar(parent, orient="vertical",
                            command=self.fraue_tree.yview)
        self.fraue_tree.configure(yscrollcommand=ysb.set)
        self.fraue_tree.pack(side="left", fill="both", expand=True)
        ysb.pack(side="right", fill="y")

        # Detail panel below
        self.fraue_detail = scrolledtext.ScrolledText(
            parent, height=8, bg=SURFACE, fg=TEXT, insertbackground=TEXT,
            font=(FONT_MONO, 10), wrap="word", state="disabled",
            relief="flat", borderwidth=0)
        self.fraue_detail.pack(fill="x", padx=4, pady=4)

        self.fraue_tree.bind("<<TreeviewSelect>>", self._on_fraue_select)

    # ---------- Timeline ----------
    def _build_timeline_tab(self, parent):
        cols = ("time", "platform", "event", "source")
        self.tl_tree = ttk.Treeview(parent, columns=cols, show="headings",
                                     selectmode="browse")
        headers = {"time": "Timestamp", "platform": "Platform",
                   "event": "Event Description", "source": "Source File"}
        widths = {"time": 170, "platform": 100, "event": 350, "source": 280}
        for c in cols:
            self.tl_tree.heading(c, text=headers[c])
            self.tl_tree.column(c, width=widths[c], anchor="w")

        ysb = ttk.Scrollbar(parent, orient="vertical",
                            command=self.tl_tree.yview)
        self.tl_tree.configure(yscrollcommand=ysb.set)
        self.tl_tree.pack(side="left", fill="both", expand=True)
        ysb.pack(side="right", fill="y")

    # ---------- Governance ----------
    def _build_governance_tab(self, parent):
        self.gov_text = scrolledtext.ScrolledText(
            parent, bg=SURFACE, fg=TEXT, insertbackground=TEXT,
            font=(FONT_MONO, 10), wrap="word", state="disabled",
            relief="flat", borderwidth=0)
        self.gov_text.pack(fill="both", expand=True, padx=4, pady=4)

    # ---------- AI Tools Checklist (v5.0) ----------
    def _build_checklist_tab(self, parent):
        # Header / filter row
        hdr_frm = ttk.Frame(parent)
        hdr_frm.pack(fill="x", padx=8, pady=(8, 4))

        ttk.Label(hdr_frm, text="AI Tool Inventory Scan",
                  font=(FONT_UI, 11, "bold")).pack(side="left")

        # Status filter
        ttk.Label(hdr_frm, text="  Filter:").pack(side="left", padx=(16, 4))
        self.checklist_filter_var = tk.StringVar(value="ALL")
        filter_cb = ttk.Combobox(
            hdr_frm,
            textvariable=self.checklist_filter_var,
            values=["ALL", "FOUND", "NOT_FOUND", "NOT_VERIFIED", "PARTIAL"],
            width=14,
            state="readonly",
        )
        filter_cb.pack(side="left")
        filter_cb.bind("<<ComboboxSelected>>", self._on_checklist_filter)

        # Category filter
        ttk.Label(hdr_frm, text="  Category:").pack(side="left", padx=(12, 4))
        self.checklist_cat_var = tk.StringVar(value="ALL")
        self.checklist_cat_cb = ttk.Combobox(
            hdr_frm,
            textvariable=self.checklist_cat_var,
            values=["ALL"],
            width=18,
            state="readonly",
        )
        self.checklist_cat_cb.pack(side="left")
        self.checklist_cat_cb.bind("<<ComboboxSelected>>", self._on_checklist_filter)

        # Export button
        ttk.Button(
            hdr_frm, text="Export CSV",
            command=self._export_checklist_csv,
        ).pack(side="right", padx=4)

        # Caveat warning banner
        self.checklist_caveat_lbl = ttk.Label(
            parent,
            text="⚠  Run analysis to populate the AI tool inventory checklist.",
            style="Dim.TLabel",
            wraplength=900,
        )
        self.checklist_caveat_lbl.pack(fill="x", padx=8, pady=(0, 4))

        # Treeview
        cols = ("tool_name", "category", "status", "confidence",
                "surface", "found_paths", "caveats", "notes")
        self.checklist_tree = ttk.Treeview(
            parent, columns=cols, show="headings", selectmode="browse"
        )
        headers = {
            "tool_name": "Tool Name",
            "category": "Category",
            "status": "Evidence Status",
            "confidence": "Confidence",
            "surface": "Execution Surface",
            "found_paths": "Artifact Path(s) Found",
            "caveats": "Caveat Flags",
            "notes": "Notes",
        }
        widths = {
            "tool_name": 160,
            "category": 110,
            "status": 100,
            "confidence": 80,
            "surface": 140,
            "found_paths": 280,
            "caveats": 200,
            "notes": 240,
        }
        for c in cols:
            self.checklist_tree.heading(c, text=headers[c])
            self.checklist_tree.column(c, width=widths[c], anchor="w")

        # Tag colours for status
        self.checklist_tree.tag_configure("FOUND",
            foreground=SUCCESS)
        self.checklist_tree.tag_configure("NOT_FOUND",
            foreground=TEXT_DIM)
        self.checklist_tree.tag_configure("NOT_VERIFIED",
            foreground=WARNING)
        self.checklist_tree.tag_configure("PARTIAL",
            foreground=ACCENT)

        ysb = ttk.Scrollbar(parent, orient="vertical",
                            command=self.checklist_tree.yview)
        xsb = ttk.Scrollbar(parent, orient="horizontal",
                            command=self.checklist_tree.xview)
        self.checklist_tree.configure(
            yscrollcommand=ysb.set, xscrollcommand=xsb.set)

        self.checklist_tree.pack(side="left", fill="both", expand=True,
                                  padx=(8, 0), pady=4)
        ysb.pack(side="right", fill="y", pady=4, padx=(0, 4))

        self.checklist_tree.bind("<<TreeviewSelect>>", self._on_checklist_select)
        self._checklist_data = {}
        self._all_checklist_entries = []

        # Detail panel
        self.checklist_detail = scrolledtext.ScrolledText(
            parent, height=7, bg=SURFACE, fg=TEXT, insertbackground=TEXT,
            font=(FONT_MONO, 9), wrap="word", state="disabled",
            relief="flat", borderwidth=0)
        self.checklist_detail.pack(fill="x", padx=8, pady=(0, 8))

    def _populate_checklist_tab(self, checklist_entries):
        """Fill the AI Tools tab from a list of ForensicChecklistEntry objects."""
        self._all_checklist_entries = checklist_entries
        # Update category filter values
        cats = sorted({e.category for e in checklist_entries})
        self.checklist_cat_cb.config(values=["ALL"] + cats)

        n_found = sum(1 for e in checklist_entries
                      if str(e.evidence_status) in ("FOUND", "EvidenceStatus.FOUND"))

        self.checklist_caveat_lbl.config(
            text=(
                f"⚠  PRESENCE ≠ USE.  {n_found}/{len(checklist_entries)} tool(s) "
                "detected in evidence.  All findings require corroboration. "
                "Attribution to a specific person is NOT established by installation artefacts alone."
            )
        )
        self._render_checklist(checklist_entries)

    def _render_checklist(self, entries):
        """Render a subset of checklist entries into the treeview."""
        self.checklist_tree.delete(*self.checklist_tree.get_children())
        self._checklist_data = {}

        for entry in entries:
            status_raw = str(entry.evidence_status).replace("EvidenceStatus.", "")
            caveats_str = ", ".join(
                str(f).replace("CaveatFlag.", "") for f in (entry.caveat_flags or [])
            )
            paths_str = "; ".join(entry.artifact_paths[:2]) if entry.artifact_paths else "—"
            iid = self.checklist_tree.insert(
                "", "end",
                values=(
                    entry.tool_name,
                    entry.category,
                    status_raw,
                    entry.confidence or "N/A",
                    entry.execution_surface or "—",
                    paths_str,
                    caveats_str[:80] or "—",
                    (entry.notes or "")[:100],
                ),
                tags=(status_raw,),
            )
            self._checklist_data[iid] = entry

    def _on_checklist_filter(self, event=None):
        """Re-render checklist based on active status and category filters."""
        status_f = self.checklist_filter_var.get()
        cat_f = self.checklist_cat_var.get()
        filtered = []
        for entry in self._all_checklist_entries:
            status_raw = str(entry.evidence_status).replace("EvidenceStatus.", "")
            if status_f != "ALL" and status_raw != status_f:
                continue
            if cat_f != "ALL" and entry.category != cat_f:
                continue
            filtered.append(entry)
        self._render_checklist(filtered)

    def _on_checklist_select(self, event=None):
        sel = self.checklist_tree.selection()
        if not sel:
            return
        entry = self._checklist_data.get(sel[0])
        if not entry:
            return

        status_raw = str(entry.evidence_status).replace("EvidenceStatus.", "")
        caveats = [str(f).replace("CaveatFlag.", "") for f in (entry.caveat_flags or [])]

        # Resolve caveat language
        try:
            from ai_usage_evidence_analyzer.caveats import get_caveat_text
            caveat_texts = get_caveat_text(entry.caveat_flags or [])
        except Exception:
            caveat_texts = caveats

        lines = [
            f"Tool:           {entry.tool_name}",
            f"Vendor/Category:{entry.category}",
            f"Evidence Status:{status_raw}",
            f"Confidence:     {entry.confidence or 'N/A'}",
            f"Surface:        {entry.execution_surface or '—'}",
            f"Inference:      {entry.inference_location or '—'}",
            f"Corroboration:  {str(entry.corroboration_level).replace('CorroborationLevel.', '')}",
            f"Attribution:    {str(entry.attribution_scope).replace('AttributionScope.', '')}",
            f"Detection:      {entry.detection_method or '—'}",
            f"Acq. Source:    {entry.acquisition_source or '—'}",
            f"Artifact Count: {entry.artifact_count}",
            "",
        ]
        if entry.artifact_paths:
            lines.append("Matched Artifact Path(s):")
            for p in entry.artifact_paths:
                lines.append(f"  • {p}")
            lines.append("")
        if caveat_texts:
            lines.append("Caveats & Enforcement Notes:")
            for ct in caveat_texts:
                lines.append(f"  ⚠ {ct}")
            lines.append("")
        lines.append(f"Notes: {entry.notes or '(none)'}")
        lines.append("")
        lines.append(
            "—  REMINDER: Presence ≠ Use.  Device ≠ Person.  "
            "Installation ≠ Execution.  Configuration ≠ Output."
        )

        self.checklist_detail.config(state="normal")
        self.checklist_detail.delete("1.0", "end")
        self.checklist_detail.insert("1.0", "\n".join(lines))
        self.checklist_detail.config(state="disabled")

    def _export_checklist_csv(self):
        """Export the current checklist to a CSV file."""
        if not self._all_checklist_entries:
            messagebox.showwarning(
                "No Checklist", "Run analysis first to generate the tool checklist.")
            return
        from tkinter import filedialog as _fd
        path = _fd.asksaveasfilename(
            title="Export AI Tool Checklist",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            from ai_usage_evidence_analyzer.forensic_checklist import (
                ForensicChecklistGenerator, ForensicChecklistEntry as _FCE,
            )
            from ai_usage_evidence_analyzer.tool_registry import ToolRegistry
            # Build a temporary generator just for CSV export
            import csv
            with open(path, "w", newline="", encoding="utf-8") as f:
                fieldnames = list(self._all_checklist_entries[0].to_dict().keys())
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for entry in self._all_checklist_entries:
                    writer.writerow(entry.to_dict())
            self._log(f"Checklist exported to: {path}")
            messagebox.showinfo("Export Complete",
                                f"Checklist saved to:\n{path}")
        except Exception as exc:
            messagebox.showerror("Export Error", str(exc))

    # ---------- Log ----------
    def _build_log_tab(self, parent):
        self.log_text = scrolledtext.ScrolledText(
            parent, bg=SURFACE, fg=TEXT, insertbackground=TEXT,
            font=(FONT_MONO, 9), wrap="word", state="disabled",
            relief="flat", borderwidth=0)
        self.log_text.pack(fill="both", expand=True, padx=4, pady=4)

    # ---------- Questions ----------
    def _build_questions_tab(self, parent):
        # Top: info label
        info_frm = ttk.Frame(parent)
        info_frm.pack(fill="x", padx=8, pady=(8, 4))
        self.questions_info_lbl = ttk.Label(
            info_frm,
            text="Load a Word document (.docx) containing examination questions "
                 "via the toolbar or config panel.",
            style="Dim.TLabel", wraplength=700)
        self.questions_info_lbl.pack(anchor="w")

        # Questions tree
        cols = ("num", "question", "answer")
        self.q_tree = ttk.Treeview(parent, columns=cols, show="headings",
                                    selectmode="browse")
        self.q_tree.heading("num", text="#")
        self.q_tree.heading("question", text="Examination Question")
        self.q_tree.heading("answer", text="Forensic Answer")
        self.q_tree.column("num", width=40, anchor="center")
        self.q_tree.column("question", width=400, anchor="w")
        self.q_tree.column("answer", width=500, anchor="w")

        ysb = ttk.Scrollbar(parent, orient="vertical",
                            command=self.q_tree.yview)
        self.q_tree.configure(yscrollcommand=ysb.set)
        self.q_tree.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=4)
        ysb.pack(side="right", fill="y", pady=4, padx=(0, 8))

        # Detail panel below
        self.q_detail = scrolledtext.ScrolledText(
            parent, height=10, bg=SURFACE, fg=TEXT, insertbackground=TEXT,
            font=(FONT_MONO, 10), wrap="word", state="disabled",
            relief="flat", borderwidth=0)
        self.q_detail.pack(fill="x", padx=8, pady=(0, 8))

        self.q_tree.bind("<<TreeviewSelect>>", self._on_question_select)
        self._question_data = {}

    # ---------- FR Assessment ----------
    def _build_fr_tab(self, parent):
        # Top: synthesis label
        synth_frm = ttk.Frame(parent)
        synth_frm.pack(fill="x", padx=8, pady=(8, 4))
        self.fr_synth_lbl = ttk.Label(
            synth_frm,
            text="Functional Requirements (FR-1 through FR-9) assess the tool's "
                 "capabilities against the AI-forensics research gap. "
                 "Run analysis to evaluate.",
            style="Dim.TLabel", wraplength=700)
        self.fr_synth_lbl.pack(anchor="w")

        # FR tree
        cols = ("fr_id", "title", "status", "summary")
        self.fr_tree = ttk.Treeview(parent, columns=cols, show="headings",
                                     selectmode="browse")
        self.fr_tree.heading("fr_id", text="FR")
        self.fr_tree.heading("title", text="Requirement")
        self.fr_tree.heading("status", text="Status")
        self.fr_tree.heading("summary", text="Capability Summary")
        self.fr_tree.column("fr_id", width=50, anchor="center")
        self.fr_tree.column("title", width=250, anchor="w")
        self.fr_tree.column("status", width=140, anchor="center")
        self.fr_tree.column("summary", width=500, anchor="w")

        ysb = ttk.Scrollbar(parent, orient="vertical",
                            command=self.fr_tree.yview)
        self.fr_tree.configure(yscrollcommand=ysb.set)
        self.fr_tree.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=4)
        ysb.pack(side="right", fill="y", pady=4, padx=(0, 8))

        # Detail panel
        self.fr_detail = scrolledtext.ScrolledText(
            parent, height=12, bg=SURFACE, fg=TEXT, insertbackground=TEXT,
            font=(FONT_MONO, 10), wrap="word", state="disabled",
            relief="flat", borderwidth=0)
        self.fr_detail.pack(fill="x", padx=8, pady=(0, 8))

        self.fr_tree.bind("<<TreeviewSelect>>", self._on_fr_select)
        self._fr_data = {}

    # ── Status bar ─────────────────────────────────────────────────────
    def _build_statusbar(self):
        sb = tk.Frame(self, bg=TOPBAR, height=28)
        sb.pack(fill="x", side="bottom")
        sb.pack_propagate(False)

        self.status_lbl = tk.Label(sb, text="", bg=TOPBAR, fg=TEXT_DIM,
                                   font=(FONT_UI, 9), anchor="w")
        self.status_lbl.pack(side="left", padx=8, fill="x", expand=True)

        self.progress = ttk.Progressbar(sb, mode="indeterminate", length=160,
                                        style="Green.Horizontal.TProgressbar")
        self.progress.pack(side="right", padx=8, pady=4)

    def _set_status(self, msg: str):
        self.status_lbl.config(text=msg)

    def _log(self, msg: str):
        self.log_text.config(state="normal")
        self.log_text.insert("end",
                             f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def _stream_log(self, level: str, message: str):
        """Called from the worker thread (via self.after) to stream engine logs."""
        prefix = {"ERROR": "❌", "WARNING": "⚠️", "INFO": "ℹ️"}.get(level, "•")
        self._log(f"{prefix}  {message}")
        # Also update status bar with latest message
        self._set_status(f"[{level}] {message[:120]}")

    # ══════════════════════════════════════════════════════════════════
    # Commands
    # ══════════════════════════════════════════════════════════════════
    def _open_evidence(self):
        path = filedialog.askopenfilename(
            title="Select Evidence File",
            filetypes=[("Forensic images", "*.e01 *.E01 *.ex01"),
                       ("ZIP archives", "*.zip"),
                       ("All files", "*.*")])
        if path:
            self.evidence_path = path
            self.evidence_var.set(path)
            self._populate_evidence_tree(path)
            self._log(f"Evidence loaded: {path}")
            self._set_status(f"Evidence: {path}")

    def _open_evidence_dir(self):
        path = filedialog.askdirectory(title="Select Evidence Directory")
        if path:
            self.evidence_path = path
            self.evidence_var.set(path)
            self._populate_evidence_tree(path)
            self._log(f"Evidence loaded: {path}")
            self._set_status(f"Evidence: {path}")

    def _open_questions(self):
        path = filedialog.askopenfilename(
            title="Select Questions Document",
            filetypes=[("Word Documents", "*.docx"),
                       ("All files", "*.*")])
        if path:
            self.questions_docx_path = path
            self.questions_var.set(path)
            self._log(f"Questions document loaded: {path}")
            self._set_status(f"Questions: {os.path.basename(path)}")

            # Preview questions immediately
            try:
                from ai_usage_evidence_analyzer.docx_parser import parse_questions_from_docx
                questions = parse_questions_from_docx(path)
                self._populate_questions_preview(questions)
                self._log(f"Parsed {len(questions)} questions from document")
            except Exception as e:
                self._log(f"Could not preview questions: {e}")

    def _populate_questions_preview(self, questions):
        """Show parsed questions in the Questions tab (before analysis)."""
        self.q_tree.delete(*self.q_tree.get_children())
        self._question_data = {}
        for q in questions:
            iid = self.q_tree.insert(
                "", "end",
                values=(q.number, q.text[:120], "(run analysis to generate answers)"))
            self._question_data[iid] = q
        self.questions_info_lbl.config(
            text=f"📝 {len(questions)} examination questions loaded — "
                 f"run analysis to generate forensic answers.")
        self.notebook.select(self.tab_questions)

    def _on_question_select(self, event):
        sel = self.q_tree.selection()
        if not sel:
            return
        q = self._question_data.get(sel[0])
        if not q:
            return
        self.q_detail.config(state="normal")
        self.q_detail.delete("1.0", "end")
        lines = [
            f"Question #{q.number}",
            f"{'─' * 60}",
            f"{q.text}",
            f"",
            f"Answer:",
            f"{'─' * 60}",
            q.answer if q.answer else "(not yet answered — run analysis)",
        ]
        if q.evidence_references:
            lines.append(f"")
            lines.append(f"Evidence References:")
            for ref in q.evidence_references:
                lines.append(f"  • {ref}")
        self.q_detail.insert("1.0", "\n".join(lines))
        self.q_detail.config(state="disabled")

    def _on_fr_select(self, event):
        sel = self.fr_tree.selection()
        if not sel:
            return
        fr = self._fr_data.get(sel[0])
        if not fr:
            return
        self.fr_detail.config(state="normal")
        self.fr_detail.delete("1.0", "end")
        lines = [
            f"{fr.fr_id}: {fr.title}",
            f"{'═' * 70}",
            f"Status: {fr.status.value if hasattr(fr.status, 'value') else fr.status}",
            f"",
            f"Description:",
            f"{'─' * 60}",
            fr.description,
            f"",
            f"Capability Summary:",
            f"{'─' * 60}",
            fr.capability_summary,
        ]
        if fr.evidence_from_analysis:
            lines.append("")
            lines.append("Evidence from Analysis:")
            lines.append("─" * 60)
            for e in fr.evidence_from_analysis:
                lines.append(f"  ✓ {e}")
        if fr.gaps:
            lines.append("")
            lines.append("Identified Gaps:")
            lines.append("─" * 60)
            for g in fr.gaps:
                lines.append(f"  ⚠ {g}")
        if fr.caveats:
            lines.append("")
            lines.append("Caveats:")
            lines.append("─" * 60)
            for c in fr.caveats:
                lines.append(f"  • {c}")
        self.fr_detail.insert("1.0", "\n".join(lines))
        self.fr_detail.config(state="disabled")

    def _set_output(self):
        path = filedialog.askdirectory(title="Select Output Directory")
        if path:
            self.output_dir = path
            self.output_var.set(path)
            self._log(f"Output directory: {path}")

    def _populate_evidence_tree(self, root_path: str):
        """Populate the evidence tree with the directory structure or E01 internal listing."""
        self.ev_tree.delete(*self.ev_tree.get_children())

        if not os.path.exists(root_path):
            return

        # ── E01 image: parse internal structure ──
        lower = root_path.lower()
        if lower.endswith((".e01", ".ex01")):
            self._populate_e01_tree(root_path)
            return

        if not os.path.isdir(root_path):
            # Single non-E01 file
            sz = os.path.getsize(root_path)
            self.ev_tree.insert("", "end", text=os.path.basename(root_path),
                                values=(self._human_size(sz),))
            return

        def _insert(parent_id, dir_path, depth=0):
            if depth > 4:
                return
            try:
                entries = sorted(os.listdir(dir_path))
            except PermissionError:
                return
            for entry in entries[:200]:  # cap to prevent UI freeze
                full = os.path.join(dir_path, entry)
                if os.path.isdir(full):
                    node = self.ev_tree.insert(parent_id, "end",
                                               text=f"📁 {entry}", values=("",))
                    _insert(node, full, depth + 1)
                else:
                    try:
                        sz = os.path.getsize(full)
                    except OSError:
                        sz = 0
                    self.ev_tree.insert(parent_id, "end",
                                        text=f"  {entry}",
                                        values=(self._human_size(sz),))

        root_node = self.ev_tree.insert("", "end",
                                         text=f"📂 {os.path.basename(root_path)}",
                                         values=("",))
        _insert(root_node, root_path)
        self.ev_tree.item(root_node, open=True)

    # ── E01 internal tree builder ─────────────────────────────────
    def _populate_e01_tree(self, e01_path: str):
        """Build evidence tree from an E01 image by scanning for file paths."""
        import zlib

        fname = os.path.basename(e01_path)
        file_size = os.path.getsize(e01_path)
        root_node = self.ev_tree.insert(
            "", "end",
            text=f"🔒 {fname}",
            values=(self._human_size(file_size),))

        self._log(f"Scanning E01 image for internal structure: {fname}")
        self._set_status(f"Scanning E01 image structure…")
        self.update_idletasks()

        # Try pyewf/pytsk3 first
        try:
            from ai_usage_evidence_analyzer.e01_handler import (
                E01Handler, HAS_PYEWF, HAS_PYTSK3,
            )
            if HAS_PYEWF and HAS_PYTSK3:
                handler = E01Handler(e01_path)
                handler.open()
                partitions = handler.detect_partitions()

                if partitions:
                    for pi in partitions:
                        if not pi.accessible:
                            self.ev_tree.insert(
                                root_node, "end",
                                text=f"═ {pi.description}",
                                values=(self._human_size(pi.length),))
                            continue
                        part_node = self.ev_tree.insert(
                            root_node, "end",
                            text=f"📀 {pi.description}",
                            values=(self._human_size(pi.length),))

                        fs = handler.open_filesystem(partition_offset=pi.offset)
                        if fs:
                            self._insert_fs_entries(handler, fs, "/", part_node, 0)

                handler.close()
                self.ev_tree.item(root_node, open=True)
                self._log(f"E01 tree populated via pyewf/pytsk3")
                self._set_status(f"E01 image loaded: {fname}")
                return
        except Exception as exc:
            self._log(f"pyewf/pytsk3 tree building failed: {exc}")

        # Fallback: scan E01 binary for paths using zlib decompression
        paths_found = set()
        ewf_metadata = {}

        try:
            CHUNK = 4 * 1024 * 1024
            MAX_SCAN = 80 * 1024 * 1024  # scan first 80 MB
            bytes_read = 0
            valid_second = frozenset((0x01, 0x5E, 0x9C, 0xDA))

            with open(e01_path, "rb") as f:
                # Read EWF header for metadata
                header_data = f.read(min(file_size, 8192))
                f.seek(0)

                # Check for EWF signature
                if header_data[:8] in (b"EVF\x09\x0d\x0a\xff\x00",
                                        b"EVF2\r\n\x81\x00"):
                    ewf_metadata["format"] = "EWF/E01"

                while bytes_read < min(file_size, MAX_SCAN):
                    chunk = f.read(CHUNK)
                    if not chunk:
                        break
                    bytes_read += len(chunk)

                    # Decompress zlib streams
                    decompressed = bytearray()
                    offset = 0
                    attempts = 0
                    while offset < len(chunk) - 2 and attempts < 30:
                        idx = chunk.find(b"\x78", offset)
                        if idx == -1 or idx + 1 >= len(chunk):
                            break
                        if chunk[idx + 1] in valid_second:
                            attempts += 1
                            try:
                                d = zlib.decompress(chunk[idx:idx + 65536])
                                decompressed.extend(d)
                            except (zlib.error, Exception):
                                pass
                        offset = idx + 1

                    # Scan for file paths in both raw and decompressed data
                    for data in (chunk, bytes(decompressed)):
                        if not data:
                            continue
                        try:
                            text = data.decode("latin-1")
                        except Exception:
                            continue

                        # Windows paths (e.g., \Users\John\AppData)
                        for m in re.finditer(
                            r'(?:\\[A-Za-z0-9_.$ @\-]{1,60}){2,8}',
                            text
                        ):
                            path = m.group(0)
                            if len(path) > 8 and not path.startswith("\\x"):
                                paths_found.add(path)

                        # Also look for UTF-16LE paths (common in NTFS)
                        try:
                            text16 = data.decode("utf-16-le", errors="ignore")
                            for m in re.finditer(
                                r'(?:\\[A-Za-z0-9_.$ @\-]{1,60}){2,8}',
                                text16
                            ):
                                path = m.group(0)
                                if len(path) > 8:
                                    paths_found.add(path)
                        except Exception:
                            pass

                    # Scan for partition table signatures  
                    # MBR check
                    if bytes_read <= CHUNK:
                        if len(chunk) >= 512 and chunk[510:512] == b"\x55\xAA":
                            ewf_metadata["partition_table"] = "MBR"
                            # Read partition entries
                            for pi in range(4):
                                entry_off = 446 + pi * 16
                                if entry_off + 16 <= len(chunk):
                                    ptype = chunk[entry_off + 4]
                                    if ptype != 0:
                                        sectors = struct.unpack_from(
                                            "<I", chunk, entry_off + 12)[0]
                                        size = sectors * 512
                                        type_names = {
                                            0x07: "NTFS", 0x0B: "FAT32",
                                            0x0C: "FAT32 LBA", 0x83: "Linux",
                                            0xEE: "GPT Protective",
                                        }
                                        tname = type_names.get(ptype, f"Type 0x{ptype:02X}")
                                        pnode = self.ev_tree.insert(
                                            root_node, "end",
                                            text=f"📀 Partition {pi + 1} [{tname}]",
                                            values=(self._human_size(size),))

                        # Check for NTFS in decompressed data
                        for data in (chunk, bytes(decompressed) if decompressed else b""):
                            if b"NTFS    " in data:
                                ewf_metadata["filesystem"] = "NTFS"
                                break

        except Exception as exc:
            self._log(f"E01 binary scan error: {exc}")

        # Build tree from discovered paths
        if paths_found:
            # Organize paths into a tree structure
            tree_dict: dict = {}
            for path in sorted(paths_found):
                parts = [p for p in path.split("\\") if p]
                node = tree_dict
                for part in parts:
                    if part not in node:
                        node[part] = {}
                    node = node[part]

            # Insert into treeview — filter to meaningful top-level folders
            priority_folders = {
                "Users", "USERS", "Windows", "Program Files",
                "Program Files (x86)", "Documents and Settings",
                "$RECYCLE.BIN", "System Volume Information",
            }

            def _insert_dict_tree(parent, d, depth=0):
                if depth > 5:
                    return
                for name in sorted(d.keys()):
                    children = d[name]
                    if children:
                        n = self.ev_tree.insert(
                            parent, "end", text=f"📁 {name}", values=("",))
                        _insert_dict_tree(n, children, depth + 1)
                    else:
                        self.ev_tree.insert(
                            parent, "end", text=f"  {name}", values=("",))

            # Find the root of the filesystem in the tree
            inserted = False
            for top_key in list(tree_dict.keys()):
                if top_key in priority_folders:
                    n = self.ev_tree.insert(
                        root_node, "end", text=f"📁 {top_key}", values=("",))
                    _insert_dict_tree(n, tree_dict[top_key], 1)
                    inserted = True

            if not inserted:
                _insert_dict_tree(root_node, tree_dict, 0)

            self._log(f"E01 tree: {len(paths_found)} paths discovered via binary scan")
        else:
            self.ev_tree.insert(
                root_node, "end",
                text="(Install pyewf/pytsk3 for full tree expansion)",
                values=("",))

        # Show metadata
        if ewf_metadata:
            for k, v in ewf_metadata.items():
                self.ev_tree.insert(
                    root_node, "end",
                    text=f"ℹ️ {k}: {v}", values=("",))

        self.ev_tree.item(root_node, open=True)
        self._set_status(f"E01 image loaded: {fname}")

    def _insert_fs_entries(self, handler, fs, path, parent_node, depth):
        """Insert filesystem entries from pytsk3 into the evidence tree."""
        if depth > 4:
            return
        try:
            entries = handler.list_directory(fs, path)
            for entry in entries[:300]:
                name = entry.get("name", "")
                size = entry.get("size", 0)
                etype = entry.get("type", "file")
                if etype == "dir":
                    n = self.ev_tree.insert(
                        parent_node, "end",
                        text=f"📁 {name}",
                        values=(self._human_size(size) if size else "",))
                    subpath = entry.get("path", f"{path.rstrip('/')}/{name}")
                    self._insert_fs_entries(handler, fs, subpath, n, depth + 1)
                else:
                    self.ev_tree.insert(
                        parent_node, "end",
                        text=f"  {name}",
                        values=(self._human_size(size),))
        except Exception:
            pass

    @staticmethod
    def _human_size(nbytes: int) -> str:
        size = float(nbytes)
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    # ── Run analysis ──────────────────────────────────────────────────
    def _run_analysis(self):
        ev = self.evidence_var.get().strip()
        out = self.output_var.get().strip()

        if not ev:
            messagebox.showwarning("Missing Evidence",
                                   "Please select an evidence source first.")
            return
        if not out:
            # Default output next to evidence
            out = os.path.join(os.path.dirname(ev), "trace_output")
            self.output_var.set(out)
            self.output_dir = out

        os.makedirs(out, exist_ok=True)
        self.btn_run.config(state="disabled", text="⏳ Analyzing…")
        self.progress.start(12)
        self._set_status("Analysis in progress — please wait…")
        self._log("Starting analysis pipeline…")
        self.notebook.select(self.tab_log)  # Show log tab during analysis

        # Start polling the message queue from the main thread
        self._polling = True
        self._poll_queue()

        def _worker():
            try:
                # Set LLM model for report narration (key from env)
                llm_model_var = getattr(self, 'llm_model_var', None)
                if llm_model_var:
                    llm_model = llm_model_var.get().strip()
                    if llm_model:
                        os.environ["AIUEA_LLM_MODEL"] = llm_model
                # Reset cached LLM client so new keys take effect
                from ai_usage_evidence_analyzer.llm_narrator import reset_client
                reset_client()

                engine = AnalysisEngine(
                    evidence_path=ev,
                    output_dir=out,
                    case_name=self.case_var.get().strip() or "Untitled Case",
                    examiner=self.examiner_var.get().strip() or "",
                    organization=self.org_var.get().strip() or "",
                    carving_enabled=self.carving_var.get(),
                    input_mode=self.mode_var.get(),
                    questions_docx_path=self.questions_docx_path,
                    # v4.0 defaults — GUI does not expose these yet
                    enable_voice_analysis=False,
                    import_provider_exports="",
                    import_shared_links=False,
                    allow_report_fallback=True,
                )

                # Hook into the engine's _log method to stream logs via queue
                original_log = engine._log
                def _log_hook(level, module, message):
                    original_log(level, module, message)
                    self._msg_queue.put(("log", level, message))
                engine._log = _log_hook

                report = engine.run()
                self._msg_queue.put(("done", report, out))
            except Exception as exc:
                self._msg_queue.put(("error", exc))

        self._analysis_thread = threading.Thread(target=_worker, daemon=True)
        self._analysis_thread.start()

    def _poll_queue(self):
        """Poll the thread-safe message queue from the main GUI thread."""
        try:
            while True:
                msg = self._msg_queue.get_nowait()
                kind = msg[0]
                if kind == "log":
                    self._stream_log(msg[1], msg[2])
                elif kind == "done":
                    self._on_analysis_done(msg[1], msg[2])
                    self._polling = False
                    return
                elif kind == "error":
                    self._on_analysis_error(msg[1])
                    self._polling = False
                    return
        except queue.Empty:
            pass
        if self._polling:
            self.after(100, self._poll_queue)

    def _on_analysis_done(self, report: ForensicReport, output_dir: str):
        self.report = report
        self.progress.stop()
        self.btn_run.config(state="normal", text="▶  Run Analysis")

        n_art = len(report.all_artifacts)
        n_fraue = len(report.fraues)
        n_plat = len(report.ai_footprints)
        n_tl = len(report.timeline)

        self._set_status(
            f"Analysis complete — {n_art} artifacts · {n_fraue} FRAUEs · "
            f"{n_plat} platforms · {n_tl} timeline events  |  Output: {output_dir}")
        self._log(f"Analysis complete: {n_art} artifacts, {n_fraue} FRAUEs, "
                  f"{n_plat} platforms detected.")
        self._log(f"Reports saved to: {output_dir}")

        # Auto-generate DOCX as primary report
        docx_path = self._auto_generate_docx(report, output_dir)
        if docx_path:
            self._log(f"Primary report (DOCX): {docx_path}")
            self._set_status(
                f"Analysis complete — DOCX report: {os.path.basename(docx_path)}  |  "
                f"{n_art} artifacts · {n_fraue} FRAUEs · {n_plat} platforms")

        # Populate all result tabs
        self._populate_dashboard(report)
        self._populate_artifacts(report)
        self._populate_fraues(report)
        self._populate_timeline(report)
        self._populate_governance(report)
        self._populate_questions(report)
        self._populate_fr(report)
        if hasattr(report, "forensic_checklist") and report.forensic_checklist:
            self._populate_checklist_tab(report.forensic_checklist)

        self.notebook.select(self.tab_dash)

    def _auto_generate_docx(self, report: ForensicReport, output_dir: str) -> str:
        """Auto-generate DOCX report as the primary deliverable after analysis."""
        try:
            from ai_usage_evidence_analyzer.docx_report import generate_docx_report
            case_prefix = report.case_info.case_id[:8] if report.case_info.case_id else "report"
            docx_path = os.path.join(output_dir, f"{case_prefix}_report.docx")
            generate_docx_report(
                report=report,
                output_path=docx_path,
                examiner_name=self.examiner_var.get().strip() or "",
                examination_name=self.case_var.get().strip() or "",
                in_the_matter_of=self.case_var.get().strip() or "",
                organization=self.org_var.get().strip() or "",
            )
            report.docx_generated = True
            report.docx_path = docx_path
            return docx_path
        except Exception as exc:
            self._log(f"WARNING: DOCX auto-generation failed: {exc}")
            report.report_fallback_used = True
            report.report_fallback_reason = str(exc)
            return ""

    def _on_analysis_error(self, exc: Exception):
        self.progress.stop()
        self.btn_run.config(state="normal", text="▶  Run Analysis")
        self._set_status(f"Error: {exc}")
        self._log(f"ERROR: {exc}")
        messagebox.showerror("Analysis Error", str(exc))

    # ── Populate results ──────────────────────────────────────────────
    def _populate_dashboard(self, report: ForensicReport):
        # Hide welcome, show stats
        self.welcome_frame.pack_forget()

        # Clear previous stats
        for w in self.stats_frame.winfo_children():
            w.destroy()
        self.stats_frame.pack(fill="both", expand=True)

        # Title
        ttk.Label(self.stats_frame, text="Analysis Results",
                  style="Header.TLabel",
                  font=(FONT_UI, 18, "bold")).pack(anchor="w", pady=(10, 12))

        # Stat cards row
        cards_frame = ttk.Frame(self.stats_frame)
        cards_frame.pack(fill="x", pady=(0, 16))

        stats = [
            ("Artifacts", str(len(report.all_artifacts)), PRIMARY),
            ("FRAUEs", str(len(report.fraues)), ACCENT),
            ("Platforms", str(len(report.ai_footprints)), SUCCESS),
            ("Timeline Events", str(len(report.timeline)), WARNING),
            ("Parsers Run", str(len(report.parser_results)), TEXT_DIM),
            ("Matrix Rows", str(len(report.matrix_rows)), TEXT_DIM),
        ]
        for i, (label, value, color) in enumerate(stats):
            card = tk.Frame(cards_frame, bg=SURFACE, padx=18, pady=12,
                            highlightbackground=BORDER, highlightthickness=1)
            card.pack(side="left", padx=6, pady=4, fill="both", expand=True)
            tk.Label(card, text=value, bg=SURFACE, fg=color,
                     font=(FONT_UI, 26, "bold")).pack()
            tk.Label(card, text=label, bg=SURFACE, fg=TEXT_DIM,
                     font=(FONT_UI, 10)).pack()

        # Platform summary
        if report.ai_footprints:
            ttk.Label(self.stats_frame, text="Detected AI Platforms",
                      style="Header.TLabel").pack(anchor="w", pady=(8, 6))

            plat_frame = ttk.Frame(self.stats_frame)
            plat_frame.pack(fill="x", pady=(0, 12))

            for fp in report.ai_footprints:
                card = tk.Frame(plat_frame, bg=SURFACE, padx=16, pady=10,
                                highlightbackground=BORDER,
                                highlightthickness=1)
                card.pack(side="left", padx=6, fill="both", expand=True)

                plat_name = fp.platform.value if hasattr(fp.platform, "value") else str(fp.platform)
                conf = fp.overall_confidence.value if hasattr(fp.overall_confidence, "value") else str(fp.overall_confidence)

                conf_color = SUCCESS if "High" in conf else (
                    WARNING if "Moderate" in conf else DANGER)

                tk.Label(card, text=plat_name, bg=SURFACE, fg=TEXT,
                         font=(FONT_UI, 14, "bold")).pack(anchor="w")
                tk.Label(card, text=f"Confidence: {conf}", bg=SURFACE,
                         fg=conf_color, font=(FONT_UI, 10)).pack(anchor="w")
                tk.Label(card, text=f"{fp.total_artifacts} artifacts · "
                         f"{fp.direct_artifacts} direct · {fp.inferred_artifacts} inferred",
                         bg=SURFACE, fg=TEXT_DIM,
                         font=(FONT_UI, 9)).pack(anchor="w", pady=(4, 0))

        # FRAUE summary
        if report.fraues:
            ttk.Label(self.stats_frame, text="FRAUE Summary",
                      style="Header.TLabel").pack(anchor="w", pady=(8, 6))

            for f in report.fraues:
                plat = f.platform.value if hasattr(f.platform, "value") else str(f.platform)
                conf = f.event_confidence.value if hasattr(f.event_confidence, "value") else str(f.event_confidence)
                claim = f.claim_level.value if hasattr(f.claim_level, "value") else str(f.claim_level)
                activity = f.likely_activity_class or "unknown"

                row = tk.Frame(self.stats_frame, bg=SURFACE,
                               highlightbackground=BORDER,
                               highlightthickness=1)
                row.pack(fill="x", padx=6, pady=2)

                conf_color = SUCCESS if "High" in conf else (
                    WARNING if "Moderate" in conf else (
                        "#fb923c" if "Low" in conf else DANGER))

                tk.Label(row, text=f"  {f.fraue_id[:16]}…", bg=SURFACE,
                         fg=TEXT_DIM, font=(FONT_MONO, 9),
                         width=18, anchor="w").pack(side="left")
                tk.Label(row, text=plat, bg=SURFACE, fg=PRIMARY,
                         font=(FONT_UI, 10, "bold"),
                         width=10, anchor="w").pack(side="left")
                tk.Label(row, text=activity, bg=SURFACE, fg=TEXT,
                         font=(FONT_UI, 10), width=14,
                         anchor="w").pack(side="left")
                tk.Label(row, text=conf, bg=SURFACE, fg=conf_color,
                         font=(FONT_UI, 10, "bold"),
                         width=12, anchor="w").pack(side="left")
                tk.Label(row, text=claim, bg=SURFACE, fg=TEXT_DIM,
                         font=(FONT_UI, 9)).pack(side="left", padx=8)

        # Scope of conclusion
        if report.scope_of_conclusion:
            ttk.Label(self.stats_frame, text="Scope of Conclusion",
                      style="Header.TLabel").pack(anchor="w", pady=(12, 6))
            scope_lbl = tk.Label(self.stats_frame, text=report.scope_of_conclusion,
                                 bg=SURFACE, fg=TEXT, wraplength=800,
                                 justify="left", padx=14, pady=10,
                                 font=(FONT_UI, 10))
            scope_lbl.pack(fill="x", padx=6)

        # Caveat enforcement summary panel
        try:
            from ai_usage_evidence_analyzer.caveats import (
                GLOBAL_REPORT_FOOTER, UI_WARNINGS
            )
            ttk.Label(self.stats_frame, text="Evidentiary Caveats",
                      style="Header.TLabel").pack(anchor="w", pady=(12, 6))
            caveat_frame = tk.Frame(self.stats_frame, bg="#1c1917",
                                    highlightbackground=WARNING,
                                    highlightthickness=1)
            caveat_frame.pack(fill="x", padx=6, pady=(0, 8))
            for warn in UI_WARNINGS:
                tk.Label(caveat_frame, text=f"⚠  {warn}",
                         bg="#1c1917", fg=WARNING,
                         font=(FONT_UI, 9), anchor="w",
                         padx=12, pady=2).pack(fill="x")
            tk.Label(caveat_frame, text="",
                     bg="#1c1917", fg=TEXT_DIM).pack()
            tk.Label(caveat_frame, text=GLOBAL_REPORT_FOOTER,
                     bg="#1c1917", fg=TEXT_DIM,
                     wraplength=800, justify="left",
                     font=(FONT_UI, 8), padx=12, pady=6).pack(fill="x")
        except Exception:
            pass

    def _populate_artifacts(self, report: ForensicReport):
        self.art_tree.delete(*self.art_tree.get_children())
        for a in report.all_artifacts:
            plat = a.suspected_platform.value if hasattr(a.suspected_platform, "value") else str(a.suspected_platform)
            fam = a.artifact_family.value if hasattr(a.artifact_family, "value") else str(a.artifact_family)
            cls = a.classification.value if hasattr(a.classification, "value") else str(a.classification)
            conf = a.confidence.value if hasattr(a.confidence, "value") else str(a.confidence)
            src = a.artifact_path or ""
            ts = ""
            if a.timestamp:
                try:
                    ts = a.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    ts = str(a.timestamp)
            self.art_tree.insert("", "end", values=(plat, fam, cls, conf, src, ts))

    def _populate_fraues(self, report: ForensicReport):
        self.fraue_tree.delete(*self.fraue_tree.get_children())
        self._fraue_data = {}  # store for detail view
        for f in report.fraues:
            fid = f.fraue_id
            plat = f.platform.value if hasattr(f.platform, "value") else str(f.platform)
            activity = f.likely_activity_class or ""
            w_start = f.window_start.strftime("%m/%d %H:%M") if f.window_start else "?"
            w_end = f.window_end.strftime("%m/%d %H:%M") if f.window_end else "?"
            window = f"{w_start} — {w_end}"
            conf = f.event_confidence.value if hasattr(f.event_confidence, "value") else str(f.event_confidence)
            claim = f.claim_level.value if hasattr(f.claim_level, "value") else str(f.claim_level)
            n_art = str(len(f.artifact_ids))
            persist = f.persistence_state.value if hasattr(f.persistence_state, "value") else str(f.persistence_state)

            iid = self.fraue_tree.insert("", "end",
                                          values=(fid[:16], plat, activity,
                                                  window, conf, claim,
                                                  n_art, persist))
            self._fraue_data[iid] = f

    def _on_fraue_select(self, event):
        sel = self.fraue_tree.selection()
        if not sel:
            return
        f = self._fraue_data.get(sel[0])
        if not f:
            return
        d = f.to_dict()
        self.fraue_detail.config(state="normal")
        self.fraue_detail.delete("1.0", "end")
        self.fraue_detail.insert("1.0", json.dumps(d, indent=2, default=str))
        self.fraue_detail.config(state="disabled")

    def _populate_timeline(self, report: ForensicReport):
        self.tl_tree.delete(*self.tl_tree.get_children())
        for ev in sorted(report.timeline,
                         key=lambda e: e.timestamp if e.timestamp else datetime.min):
            ts = ""
            if ev.timestamp:
                try:
                    ts = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    ts = str(ev.timestamp)
            plat = ev.platform.value if hasattr(ev.platform, "value") else str(ev.platform)
            desc = ev.description or ""
            src = ev.artifact_record_id or ""
            self.tl_tree.insert("", "end", values=(ts, plat, desc, src))

    def _populate_governance(self, report: ForensicReport):
        self.gov_text.config(state="normal")
        self.gov_text.delete("1.0", "end")

        gr = report.governance_record
        if not gr:
            self.gov_text.insert("1.0", "No governance record generated.")
            self.gov_text.config(state="disabled")
            return

        lines = []
        lines.append("=" * 70)
        lines.append("  GOVERNANCE RECORD")
        lines.append("=" * 70)
        lines.append(f"\nFramework: {gr.framework_name} v{gr.framework_version}")
        lines.append(f"Case: {gr.case_id}")
        lines.append(f"Generated: {gr.generated_at}")
        lines.append(f"Validation: {gr.validation_state.value if hasattr(gr.validation_state, 'value') else gr.validation_state}")

        lines.append(f"\n{'─' * 50}")
        lines.append("  RULES APPLIED")
        lines.append(f"{'─' * 50}")
        for r in gr.rules_applied:
            lines.append(f"  ✓  {r}")

        if gr.required_disclosures:
            lines.append(f"\n{'─' * 50}")
            lines.append("  REQUIRED DISCLOSURES")
            lines.append(f"{'─' * 50}")
            for d in gr.required_disclosures:
                lines.append(f"  ⚠  {d}")

        if gr.known_blind_spots:
            lines.append(f"\n{'─' * 50}")
            lines.append("  KNOWN BLIND SPOTS")
            lines.append(f"{'─' * 50}")
            for b in gr.known_blind_spots:
                lines.append(f"  •  {b}")

        if gr.inference_boundaries:
            lines.append(f"\n{'─' * 50}")
            lines.append("  INFERENCE BOUNDARIES")
            lines.append(f"{'─' * 50}")
            for ib in gr.inference_boundaries:
                lines.append(f"  ▸  {ib}")

        if report.scope_of_conclusion:
            lines.append(f"\n{'─' * 50}")
            lines.append("  SCOPE OF CONCLUSION")
            lines.append(f"{'─' * 50}")
            lines.append(f"\n{report.scope_of_conclusion}")

        if report.inference_boundaries:
            lines.append(f"\n{'─' * 50}")
            lines.append("  REPORT INFERENCE BOUNDARIES")
            lines.append(f"{'─' * 50}")
            for ib in report.inference_boundaries:
                lines.append(f"  ▸  {ib}")

        self.gov_text.insert("1.0", "\n".join(lines))
        self.gov_text.config(state="disabled")

    def _populate_questions(self, report: ForensicReport):
        """Populate the Questions tab with answered examination questions."""
        if not report.examination_questions:
            return
        self.q_tree.delete(*self.q_tree.get_children())
        self._question_data = {}
        for q in report.examination_questions:
            answer_preview = q.answer[:120] + "…" if len(q.answer) > 120 else q.answer
            iid = self.q_tree.insert(
                "", "end",
                values=(q.number, q.text[:120], answer_preview))
            self._question_data[iid] = q
        self.questions_info_lbl.config(
            text=f"✅ {len(report.examination_questions)} examination questions "
                 f"answered based on forensic analysis.")

    def _populate_fr(self, report: ForensicReport):
        """Populate the FR Assessment tab with requirement evaluations."""
        if not report.fr_assessments:
            return
        self.fr_tree.delete(*self.fr_tree.get_children())
        self._fr_data = {}
        for fr in report.fr_assessments:
            status = fr.status.value if hasattr(fr.status, "value") else str(fr.status)
            summary = fr.capability_summary[:100] + "…" if len(fr.capability_summary) > 100 else fr.capability_summary
            iid = self.fr_tree.insert(
                "", "end",
                values=(fr.fr_id, fr.title, status, summary))
            self._fr_data[iid] = fr
        fully = sum(1 for a in report.fr_assessments
                    if a.status.value == "Fully Addressed")
        partial = sum(1 for a in report.fr_assessments
                      if a.status.value == "Partially Addressed")
        gaps = len(report.fr_assessments) - fully - partial
        self.fr_synth_lbl.config(
            text=f"FR Assessment: {fully} Fully Addressed · {partial} Partially "
                 f"Addressed · {gaps} Gap(s) Identified  —  Select a row for details.")

    # ── Clear ──────────────────────────────────────────────────────────
    def _clear_results(self):
        self.report = None

        self.art_tree.delete(*self.art_tree.get_children())
        self.fraue_tree.delete(*self.fraue_tree.get_children())
        self.tl_tree.delete(*self.tl_tree.get_children())

        self.fraue_detail.config(state="normal")
        self.fraue_detail.delete("1.0", "end")
        self.fraue_detail.config(state="disabled")

        self.gov_text.config(state="normal")
        self.gov_text.delete("1.0", "end")
        self.gov_text.config(state="disabled")

        self.q_tree.delete(*self.q_tree.get_children())
        self.q_detail.config(state="normal")
        self.q_detail.delete("1.0", "end")
        self.q_detail.config(state="disabled")
        self.questions_info_lbl.config(
            text="Load a Word document (.docx) containing examination questions "
                 "via the toolbar or config panel.")

        self.fr_tree.delete(*self.fr_tree.get_children())
        self.fr_detail.config(state="normal")
        self.fr_detail.delete("1.0", "end")
        self.fr_detail.config(state="disabled")
        self.fr_synth_lbl.config(
            text="Functional Requirements (FR-1 through FR-9) assess the tool's "
                 "capabilities against the AI-forensics research gap. "
                 "Run analysis to evaluate.")

        # Restore welcome
        for w in self.stats_frame.winfo_children():
            w.destroy()
        self.stats_frame.pack_forget()
        self.welcome_frame.pack(expand=True)

        self._set_status("Results cleared.")
        self._log("Results cleared.")

    # ── Generate Word Report ──────────────────────────────────────
    def _generate_word_report(self):
        """Show a dialog for report metadata, then generate a .docx report."""
        if self.report is None:
            messagebox.showwarning(
                "No Analysis Results",
                "Please run an analysis first before generating a report.")
            return

        # ── Prompt dialog ──
        dialog = tk.Toplevel(self)
        dialog.title("Generate Forensic Report")
        dialog.geometry("520x340")
        dialog.configure(bg=BG)
        dialog.resizable(False, False)
        dialog.transient(self)
        dialog.grab_set()

        # Center on parent
        dialog.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() - 520) // 2
        y = self.winfo_y() + (self.winfo_height() - 340) // 2
        dialog.geometry(f"+{x}+{y}")

        # Title
        tk.Label(dialog, text="📄  Generate Forensic Report",
                 bg=BG, fg=PRIMARY,
                 font=(FONT_UI, 14, "bold")).pack(pady=(18, 12))

        form = tk.Frame(dialog, bg=BG)
        form.pack(fill="x", padx=30)

        # Examination Name
        tk.Label(form, text="Forensic Examination Name:",
                 bg=BG, fg=TEXT, font=(FONT_UI, 10),
                 anchor="w").pack(fill="x", pady=(8, 2))
        exam_name_var = tk.StringVar(
            value=self.case_var.get().strip() or "")
        tk.Entry(form, textvariable=exam_name_var,
                 bg=SURFACE, fg=TEXT, insertbackground=TEXT,
                 font=(FONT_UI, 11), relief="flat",
                 highlightbackground=BORDER, highlightthickness=1
                 ).pack(fill="x", ipady=4)

        # In the matter of
        tk.Label(form, text="Forensic Examination in the matter of:",
                 bg=BG, fg=TEXT, font=(FONT_UI, 10),
                 anchor="w").pack(fill="x", pady=(12, 2))
        matter_var = tk.StringVar()
        tk.Entry(form, textvariable=matter_var,
                 bg=SURFACE, fg=TEXT, insertbackground=TEXT,
                 font=(FONT_UI, 11), relief="flat",
                 highlightbackground=BORDER, highlightthickness=1
                 ).pack(fill="x", ipady=4)

        # Examiner (pre-filled)
        tk.Label(form, text="Examiner Name:",
                 bg=BG, fg=TEXT, font=(FONT_UI, 10),
                 anchor="w").pack(fill="x", pady=(12, 2))
        examiner_var = tk.StringVar(
            value=self.examiner_var.get().strip() or "")
        tk.Entry(form, textvariable=examiner_var,
                 bg=SURFACE, fg=TEXT, insertbackground=TEXT,
                 font=(FONT_UI, 11), relief="flat",
                 highlightbackground=BORDER, highlightthickness=1
                 ).pack(fill="x", ipady=4)

        confirmed_var = tk.BooleanVar(value=False)
        result: dict[str, str] = {
            "exam_name": "",
            "matter": "",
            "examiner": "",
        }

        def _on_generate():
            confirmed_var.set(True)
            result["exam_name"] = exam_name_var.get().strip()
            result["matter"] = matter_var.get().strip()
            result["examiner"] = examiner_var.get().strip()
            dialog.destroy()

        def _on_cancel():
            dialog.destroy()

        # Buttons
        btn_frame = tk.Frame(dialog, bg=BG)
        btn_frame.pack(pady=(18, 12))

        tk.Button(btn_frame, text="Generate Report",
                  command=_on_generate,
                  bg=SUCCESS, fg=TOPBAR, relief="flat",
                  activebackground="#22c55e", activeforeground=TOPBAR,
                  font=(FONT_UI, 10, "bold"), padx=20, pady=6,
                  cursor="hand2").pack(side="left", padx=8)
        tk.Button(btn_frame, text="Cancel",
                  command=_on_cancel,
                  bg=SURFACE2, fg=TEXT, relief="flat",
                  activebackground=PRIMARY, activeforeground=TOPBAR,
                  font=(FONT_UI, 10), padx=20, pady=6,
                  cursor="hand2").pack(side="left", padx=8)

        self.wait_window(dialog)

        if not confirmed_var.get():
            return

        # ── Generate the Word report ──
        if not result["exam_name"] and not result["matter"]:
            messagebox.showwarning(
                "Missing Information",
                "Please provide at least the examination name or "
                "'in the matter of' field.")
            return

        try:
            from ai_usage_evidence_analyzer.docx_report import generate_docx_report

            out_dir = self.output_var.get().strip()
            if not out_dir:
                out_dir = os.path.join(
                    os.path.dirname(self.evidence_path or "."),
                    "trace_output")
                self.output_var.set(out_dir)
            os.makedirs(out_dir, exist_ok=True)

            case_id = (self.report.case_info.case_id
                       if self.report.case_info else "report")
            safe_name = re.sub(r'[^\w\-]', '_', case_id)[:40]
            docx_path = os.path.join(out_dir, f"{safe_name}_report.docx")

            generate_docx_report(
                report=self.report,
                output_path=docx_path,
                examiner_name=result["examiner"],
                examination_name=result["exam_name"],
                in_the_matter_of=result["matter"],
                organization=self.org_var.get().strip()
                    or "University of North Carolina at Charlotte",
            )

            self._log(f"Word report generated: {docx_path}")
            self._set_status(f"Report saved: {os.path.basename(docx_path)}")

            # Ask to open
            if messagebox.askyesno(
                "Report Generated",
                f"Forensic report saved to:\n{docx_path}\n\nOpen the file now?"
            ):
                open_file_cross_platform(docx_path)

        except ImportError:
            messagebox.showerror(
                "Missing Dependency",
                "python-docx is required for Word report generation.\n\n"
                "Install it with: pip install python-docx")
        except Exception as exc:
            messagebox.showerror("Report Error", f"Failed to generate report:\n{exc}")
            self._log(f"ERROR generating Word report: {exc}")

    # ── Open HTML report ──────────────────────────────────────────────
    def _open_html_report(self):
        out = self.output_var.get().strip()
        if not out or not os.path.isdir(out):
            messagebox.showinfo("No Output", "Run an analysis first.")
            return
        html_files = [f for f in os.listdir(out) if f.endswith("_report.html")]
        if html_files:
            open_file_cross_platform(os.path.join(out, html_files[0]))
        else:
            messagebox.showinfo("No Report", "No HTML report found in output.")

    # ── Info / About dialogs ──────────────────────────────────────────
    def _show_info(self):
        info = (
            f"Framework:  {__product__}\n"
            f"Full Name:  {__full_name__}\n"
            f"Version:    {__version__}\n\n"
            "Architecture: 8-Layer Governed Forensic Pipeline\n"
            "Unit of Analysis:  FRAUE\n"
            "Rules Engine: 12 Enforceable Forensic Rules\n\n"
            "AI Platforms:  ChatGPT · Claude · Gemini · Perplexity · Copilot · Meta AI · Grok · Poe\n"
            "OS Support:    Windows · macOS · iPhone (logical)\n"
            "Browsers:      Chrome · Edge · Firefox · Brave · Safari\n\n"
            "Input:  E01 images · ZIP archives · Mounted directories\n"
            "Output: JSON · Markdown · HTML · SQLite · Governance JSON"
        )
        messagebox.showinfo("Framework Info", info)

    def _show_about(self):
        messagebox.showinfo(
            "About TRACE-AI-FR",
            f"{__product__} v{__version__}\n\n"
            f"{__full_name__}\n\n"
            "Course: ITIS-5250-092 — Computer Forensics (UNCC)\n"
            "Author: Hemal\n"
            "License: MIT")


# ═══════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════
def main():
    app = TraceAIApp()
    app.mainloop()


if __name__ == "__main__":
    main()
