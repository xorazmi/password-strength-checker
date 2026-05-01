"""
gui.py — Password Strength Checker GUI
----------------------------------------
Author   : Eldor Matmurodov
GitHub   : https://github.com/xorazmi
Telegram : @moein101
Channel  : @cybersecattack0
Email    : eldormatmurodov@gmail.com
License  : MIT

Tkinter-based graphical interface with:
  - Real-time strength analysis as you type
  - Animated strength meter bar
  - Dark cybersecurity theme
  - Show / hide password toggle
  - Full metrics, pattern detection, and feedback panels
"""

import sys
import os
import tkinter as tk
from tkinter import ttk, font as tkfont
import threading

# Ensure sibling modules resolve correctly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from checker import compute_score
from common_passwords import auto_load_wordlists, load_wordlists_folder, wordlist_info
import download_wordlists as _dl

# ---------------------------------------------------------------------------
# Theme colours
# ---------------------------------------------------------------------------

BG_DARK     = "#0d1117"
BG_CARD     = "#161b22"
BG_INPUT    = "#21262d"
BG_BORDER   = "#30363d"

TEXT_PRIMARY   = "#e6edf3"
TEXT_SECONDARY = "#8b949e"
TEXT_DIM       = "#484f58"

COLOR_RED    = "#f85149"
COLOR_ORANGE = "#d29922"
COLOR_YELLOW = "#e3b341"
COLOR_GREEN  = "#3fb950"
COLOR_CYAN   = "#58a6ff"
COLOR_PURPLE = "#bc8cff"

STRENGTH_COLORS = {
    "VERY WEAK":  COLOR_RED,
    "WEAK":       COLOR_ORANGE,
    "MODERATE":   COLOR_YELLOW,
    "STRONG":     COLOR_GREEN,
    "VERY STRONG": "#39d353",
}

# ---------------------------------------------------------------------------
# Reusable widget helpers
# ---------------------------------------------------------------------------

def _card(parent, **kw) -> tk.Frame:
    defaults = dict(bg=BG_CARD, bd=0, highlightbackground=BG_BORDER,
                    highlightthickness=1, padx=16, pady=12)
    defaults.update(kw)
    return tk.Frame(parent, **defaults)


def _label(parent, text="", size=10, bold=False, color=TEXT_PRIMARY, **kw) -> tk.Label:
    weight = "bold" if bold else "normal"
    f = tkfont.Font(family="Consolas", size=size, weight=weight)
    return tk.Label(parent, text=text, font=f, fg=color, bg=parent["bg"],
                    anchor="w", **kw)


def _section_title(parent, text: str) -> tk.Label:
    lbl = _label(parent, text=f"  {text}", size=9, bold=True, color=TEXT_SECONDARY)
    lbl.pack(fill="x", pady=(8, 4))
    return lbl


# ---------------------------------------------------------------------------
# Strength meter canvas
# ---------------------------------------------------------------------------

class StrengthMeter(tk.Canvas):
    """Animated horizontal bar that fills and colour-shifts with score."""

    HEIGHT = 8
    RADIUS = 4

    def __init__(self, parent, **kw):
        super().__init__(parent, height=self.HEIGHT, bg=BG_CARD,
                         highlightthickness=0, **kw)
        self._score = 0
        self._color = COLOR_RED
        self.bind("<Configure>", lambda e: self._draw())

    def set_score(self, score: int, color: str):
        self._score = score
        self._color = color
        self._draw()

    def _draw(self):
        self.delete("all")
        w = self.winfo_width()
        h = self.HEIGHT
        r = self.RADIUS

        # Background track
        self._rounded_rect(0, 0, w, h, r, fill=BG_INPUT, outline="")

        # Filled portion
        filled = int(w * self._score / 100)
        if filled > r * 2:
            self._rounded_rect(0, 0, filled, h, r, fill=self._color, outline="")

    def _rounded_rect(self, x1, y1, x2, y2, r, **kw):
        pts = [
            x1 + r, y1,
            x2 - r, y1,
            x2,     y1,
            x2,     y1 + r,
            x2,     y2 - r,
            x2,     y2,
            x2 - r, y2,
            x1 + r, y2,
            x1,     y2,
            x1,     y2 - r,
            x1,     y1 + r,
            x1,     y1,
        ]
        self.create_polygon(pts, smooth=True, **kw)


# ---------------------------------------------------------------------------
# Main application window
# ---------------------------------------------------------------------------

class PasswordCheckerApp(tk.Tk):

    WINDOW_W = 780
    WINDOW_H = 720

    def __init__(self):
        super().__init__()

        self.title("Password Strength Checker")
        self.configure(bg=BG_DARK)
        self.resizable(True, True)
        self.minsize(640, 600)

        # Centre on screen
        self.geometry(f"{self.WINDOW_W}x{self.WINDOW_H}")
        self.after(0, self._center)

        self._show_password   = False
        self._after_id        = None
        self._dl_thread       = None

        self._build_ui()

        # Auto-load wordlists folder if it already exists
        self.after(200, self._auto_load_wordlists)

        self._analyse("")       # initial empty state

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _center(self):
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x  = (sw - self.WINDOW_W) // 2
        y  = (sh - self.WINDOW_H) // 2
        self.geometry(f"{self.WINDOW_W}x{self.WINDOW_H}+{x}+{y}")

    def _build_ui(self):
        # ── Outer scroll container ────────────────────────────────────
        outer = tk.Frame(self, bg=BG_DARK)
        outer.pack(fill="both", expand=True)

        canvas = tk.Canvas(outer, bg=BG_DARK, highlightthickness=0)
        scrollbar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        self._scroll_frame = tk.Frame(canvas, bg=BG_DARK)
        self._scroll_win = canvas.create_window((0, 0), window=self._scroll_frame,
                                                anchor="nw")

        self._scroll_frame.bind("<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",
            lambda e: canvas.itemconfig(self._scroll_win, width=e.width))

        # Mousewheel
        def _on_wheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        canvas.bind_all("<MouseWheel>", _on_wheel)

        root = self._scroll_frame
        pad = dict(padx=20, pady=6)

        # ── Header ───────────────────────────────────────────────────
        hdr = tk.Frame(root, bg=BG_DARK)
        hdr.pack(fill="x", **pad)
        tk.Label(hdr, text="🔐 PASSWORD STRENGTH CHECKER",
                 font=tkfont.Font(family="Consolas", size=15, weight="bold"),
                 fg=COLOR_CYAN, bg=BG_DARK).pack(anchor="w", pady=(18, 0))
        tk.Label(hdr, text="Real-time cybersecurity analysis tool",
                 font=tkfont.Font(family="Consolas", size=9),
                 fg=TEXT_SECONDARY, bg=BG_DARK).pack(anchor="w")

        tk.Frame(root, height=1, bg=BG_BORDER).pack(fill="x", padx=20, pady=8)

        # ── Input card ───────────────────────────────────────────────
        input_card = _card(root)
        input_card.pack(fill="x", **pad)

        _label(input_card, "Enter Password", size=9, color=TEXT_SECONDARY).pack(anchor="w")

        input_row = tk.Frame(input_card, bg=BG_CARD)
        input_row.pack(fill="x", pady=(6, 0))

        self._password_var = tk.StringVar()
        self._password_var.trace_add("write", self._on_type)

        self._entry = tk.Entry(
            input_row,
            textvariable=self._password_var,
            show="●",
            font=tkfont.Font(family="Consolas", size=14),
            bg=BG_INPUT, fg=TEXT_PRIMARY,
            insertbackground=COLOR_CYAN,
            relief="flat", bd=0,
            highlightthickness=1,
            highlightbackground=BG_BORDER,
            highlightcolor=COLOR_CYAN,
        )
        self._entry.pack(side="left", fill="x", expand=True, ipady=10, ipadx=10)
        self._entry.focus_set()

        self._toggle_btn = tk.Button(
            input_row,
            text="👁",
            command=self._toggle_show,
            font=tkfont.Font(size=12),
            bg=BG_INPUT, fg=TEXT_SECONDARY,
            activebackground=BG_INPUT, activeforeground=TEXT_PRIMARY,
            relief="flat", bd=0, cursor="hand2",
            padx=10, pady=8,
        )
        self._toggle_btn.pack(side="left", padx=(2, 0))

        # Clear button
        tk.Button(
            input_row, text="✕",
            command=self._clear,
            font=tkfont.Font(size=10),
            bg=BG_INPUT, fg=TEXT_SECONDARY,
            activebackground=BG_INPUT, activeforeground=COLOR_RED,
            relief="flat", bd=0, cursor="hand2",
            padx=10, pady=8,
        ).pack(side="left", padx=(2, 0))

        # ── Strength bar + label ──────────────────────────────────────
        strength_card = _card(root)
        strength_card.pack(fill="x", **pad)

        top_row = tk.Frame(strength_card, bg=BG_CARD)
        top_row.pack(fill="x", pady=(0, 8))

        self._label_var = tk.StringVar(value="—")
        self._label_lbl = tk.Label(
            top_row, textvariable=self._label_var,
            font=tkfont.Font(family="Consolas", size=13, weight="bold"),
            fg=TEXT_DIM, bg=BG_CARD, anchor="w",
        )
        self._label_lbl.pack(side="left")

        self._score_var = tk.StringVar(value="")
        tk.Label(top_row, textvariable=self._score_var,
                 font=tkfont.Font(family="Consolas", size=11),
                 fg=TEXT_SECONDARY, bg=BG_CARD).pack(side="right")

        self._meter = StrengthMeter(strength_card, width=200)
        self._meter.pack(fill="x", pady=(0, 6))

        self._crack_var = tk.StringVar(value="")
        tk.Label(strength_card, textvariable=self._crack_var,
                 font=tkfont.Font(family="Consolas", size=9),
                 fg=TEXT_SECONDARY, bg=BG_CARD, anchor="w").pack(fill="x")

        # ── Metrics row ───────────────────────────────────────────────
        metrics_row = tk.Frame(root, bg=BG_DARK)
        metrics_row.pack(fill="x", padx=20, pady=6)

        self._metric_frames = {}
        for key, title in [("length", "LENGTH"), ("entropy", "ENTROPY"),
                            ("charset", "CHARSET POOL")]:
            mf = _card(metrics_row, padx=12, pady=10)
            mf.pack(side="left", fill="both", expand=True, padx=(0, 6))
            _label(mf, title, size=8, color=TEXT_SECONDARY).pack(anchor="w")
            val_lbl = _label(mf, "—", size=16, bold=True, color=TEXT_PRIMARY)
            val_lbl.pack(anchor="w")
            sub_lbl = _label(mf, "", size=8, color=TEXT_DIM)
            sub_lbl.pack(anchor="w")
            self._metric_frames[key] = (val_lbl, sub_lbl)

        # ── Character classes ─────────────────────────────────────────
        cls_card = _card(root)
        cls_card.pack(fill="x", **pad)
        _section_title(cls_card, "CHARACTER CLASSES")

        cls_grid = tk.Frame(cls_card, bg=BG_CARD)
        cls_grid.pack(fill="x")

        self._class_labels = {}
        classes = [
            ("lowercase", "Lowercase  a–z"),
            ("uppercase", "Uppercase  A–Z"),
            ("digits",    "Digits     0–9"),
            ("special",   "Special    !@#…"),
            ("unicode",   "Unicode    >127"),
        ]
        for i, (key, name) in enumerate(classes):
            row = i // 3
            col = i % 3
            cell = tk.Frame(cls_grid, bg=BG_CARD)
            cell.grid(row=row, column=col, sticky="w", padx=8, pady=3)
            dot = tk.Label(cell, text="●", font=tkfont.Font(size=8),
                           fg=TEXT_DIM, bg=BG_CARD)
            dot.pack(side="left")
            lbl = _label(cell, f"  {name}", size=9, color=TEXT_SECONDARY)
            lbl.pack(side="left")
            self._class_labels[key] = (dot, lbl)

        # ── Pattern analysis ──────────────────────────────────────────
        pat_card = _card(root)
        pat_card.pack(fill="x", **pad)
        _section_title(pat_card, "PATTERN ANALYSIS")

        self._pattern_text = tk.Text(
            pat_card, height=4, wrap="word",
            font=tkfont.Font(family="Consolas", size=9),
            bg=BG_INPUT, fg=TEXT_PRIMARY,
            relief="flat", bd=0,
            highlightthickness=0,
            state="disabled",
            padx=10, pady=8,
        )
        self._pattern_text.pack(fill="x")
        self._pattern_text.tag_config("ok",   foreground=COLOR_GREEN)
        self._pattern_text.tag_config("warn", foreground=COLOR_ORANGE)
        self._pattern_text.tag_config("bad",  foreground=COLOR_RED)
        self._pattern_text.tag_config("dim",  foreground=TEXT_SECONDARY)

        # ── Recommendations ───────────────────────────────────────────
        rec_card = _card(root)
        rec_card.pack(fill="x", **pad)
        _section_title(rec_card, "RECOMMENDATIONS")

        self._rec_text = tk.Text(
            rec_card, height=6, wrap="word",
            font=tkfont.Font(family="Consolas", size=9),
            bg=BG_INPUT, fg=TEXT_PRIMARY,
            relief="flat", bd=0,
            highlightthickness=0,
            state="disabled",
            padx=10, pady=8,
        )
        self._rec_text.pack(fill="x", pady=(0, 4))
        self._rec_text.tag_config("tip",      foreground=TEXT_PRIMARY)
        self._rec_text.tag_config("critical", foreground=COLOR_RED)
        self._rec_text.tag_config("dim",      foreground=TEXT_SECONDARY)

        # ── Wordlist / RockYou 2025 panel ────────────────────────────
        wl_card = _card(root)
        wl_card.pack(fill="x", **pad)
        _section_title(wl_card, "ROCKYOU 2025 WORDLIST  (~150 MB)")

        wl_top = tk.Frame(wl_card, bg=BG_CARD)
        wl_top.pack(fill="x", pady=(0, 6))

        self._wl_status_var = tk.StringVar(
            value="⬜  Not loaded — download to enable 6M+ common password checks"
        )
        self._wl_status_lbl = tk.Label(
            wl_top, textvariable=self._wl_status_var,
            font=tkfont.Font(family="Consolas", size=9),
            fg=TEXT_SECONDARY, bg=BG_CARD, anchor="w", wraplength=580, justify="left",
        )
        self._wl_status_lbl.pack(side="left", fill="x", expand=True)

        self._dl_btn = tk.Button(
            wl_card,
            text="⬇  Download Wordlists",
            command=self._start_download,
            font=tkfont.Font(family="Consolas", size=9, weight="bold"),
            bg=COLOR_CYAN, fg=BG_DARK,
            activebackground=COLOR_PURPLE, activeforeground=BG_DARK,
            relief="flat", bd=0, cursor="hand2",
            padx=14, pady=7,
        )
        self._dl_btn.pack(anchor="w", pady=(4, 0))

        self._dl_progress_var = tk.StringVar(value="")
        self._dl_progress_lbl = tk.Label(
            wl_card, textvariable=self._dl_progress_var,
            font=tkfont.Font(family="Consolas", size=8),
            fg=TEXT_SECONDARY, bg=BG_CARD, anchor="w",
        )
        self._dl_progress_lbl.pack(fill="x", pady=(4, 0))

        # ── Footer ───────────────────────────────────────────────────
        tk.Frame(root, height=1, bg=BG_BORDER).pack(fill="x", padx=20, pady=(12, 4))

        footer = tk.Frame(root, bg=BG_DARK)
        footer.pack(fill="x", padx=20, pady=(0, 16))

        tk.Label(footer,
                 text="All analysis is performed locally. No data is transmitted.",
                 font=tkfont.Font(family="Consolas", size=8),
                 fg=TEXT_DIM, bg=BG_DARK, anchor="w").pack(fill="x")

        tk.Label(footer,
                 text="Built by Eldor Matmurodov  •  github.com/xorazmi  •  @cybersecattack0  •  MIT License",
                 font=tkfont.Font(family="Consolas", size=8),
                 fg=TEXT_DIM, bg=BG_DARK, anchor="w").pack(fill="x", pady=(2, 0))

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _on_type(self, *_):
        """Debounce: wait 120 ms after last keystroke before analysing."""
        if self._after_id:
            self.after_cancel(self._after_id)
        self._after_id = self.after(120, self._run_analysis)

    def _run_analysis(self):
        password = self._password_var.get()
        self._analyse(password)

    def _toggle_show(self):
        self._show_password = not self._show_password
        self._entry.config(show="" if self._show_password else "●")
        self._toggle_btn.config(text="🔒" if self._show_password else "👁")

    def _clear(self):
        self._password_var.set("")
        self._entry.focus_set()

    # ------------------------------------------------------------------
    # Analysis → UI update
    # ------------------------------------------------------------------

    def _analyse(self, password: str):
        if not password:
            self._reset_ui()
            return

        r = compute_score(password)
        self._update_strength(r)
        self._update_metrics(r)
        self._update_classes(r)
        self._update_patterns(r)
        self._update_recommendations(r)

    def _reset_ui(self):
        self._label_var.set("—")
        self._label_lbl.config(fg=TEXT_DIM)
        self._score_var.set("")
        self._crack_var.set("")
        self._meter.set_score(0, BG_BORDER)

        for key, (val, sub) in self._metric_frames.items():
            val.config(text="—", fg=TEXT_DIM)
            sub.config(text="")

        for key, (dot, lbl) in self._class_labels.items():
            dot.config(fg=TEXT_DIM)
            lbl.config(fg=TEXT_SECONDARY)

        self._set_text(self._pattern_text, [("Type a password to begin…", "dim")])
        self._set_text(self._rec_text,     [("", "dim")])

    def _update_strength(self, r: dict):
        label = r["label"]
        score = r["score"]
        color = STRENGTH_COLORS.get(label, TEXT_DIM)

        self._label_var.set(label)
        self._label_lbl.config(fg=color)
        self._score_var.set(f"{score}/100")
        self._meter.set_score(score, color)

        crack = r["crack_time"]
        self._crack_var.set(f"Est. offline crack time: {crack}")

    def _update_metrics(self, r: dict):
        length_val, length_sub = self._metric_frames["length"]
        length_val.config(text=str(r["length"]), fg=TEXT_PRIMARY)
        length_sub.config(text="characters")

        ent_val, ent_sub = self._metric_frames["entropy"]
        ent_val.config(text=f"{r['entropy_bits']:.1f}", fg=TEXT_PRIMARY)
        ent_sub.config(text="bits")

        cs_val, cs_sub = self._metric_frames["charset"]
        cs_val.config(text=str(r["charset_size"]), fg=TEXT_PRIMARY)
        cs_sub.config(text="symbols")

    def _update_classes(self, r: dict):
        classes = r["classes_used"]
        for key, (dot, lbl) in self._class_labels.items():
            present = classes.get(key, False)
            dot.config(fg=COLOR_GREEN if present else TEXT_DIM)
            lbl.config(fg=TEXT_PRIMARY if present else TEXT_SECONDARY)

    def _update_patterns(self, r: dict):
        pi = r["pattern_info"]
        ci = r["common_info"]
        segments = []

        if ci["is_common"]:
            src = ci["source"].upper()
            mt  = ci["match_type"].upper()
            segments.append((f"✗  COMMON PASSWORD — {src} ({mt} match)\n", "bad"))

        if pi["keyboard"]:
            examples = ", ".join(pi["keyboard"][:4])
            segments.append((f"✗  Keyboard walk: {examples}\n", "warn"))

        if pi["sequential"]:
            examples = ", ".join(pi["sequential"][:4])
            segments.append((f"✗  Sequential run: {examples}\n", "warn"))

        if pi["repeated"]:
            examples = ", ".join(pi["repeated"][:4])
            segments.append((f"✗  Repeated chars: {examples}\n", "warn"))

        if pi["dates"]:
            examples = ", ".join(pi["dates"][:4])
            segments.append((f"✗  Date pattern: {examples}\n", "warn"))

        if not segments:
            segments.append(("✓  No dangerous patterns detected.", "ok"))

        self._set_text(self._pattern_text, segments)

    def _update_recommendations(self, r: dict):
        tips = r["feedback"]
        if not tips:
            self._set_text(self._rec_text, [("✓  Password looks good!", "dim")])
            return

        segments = []
        for i, tip in enumerate(tips):
            tag = "critical" if i == 0 and r["score"] < 36 else "tip"
            segments.append((f"▸  {tip}\n\n", tag))

        self._set_text(self._rec_text, segments)

        # Auto-resize text widget height
        lines = sum(t.count("\n") + 1 for t, _ in segments)
        self._rec_text.config(height=max(4, min(lines + 1, 12)))

    # ------------------------------------------------------------------
    # Text widget helper
    # ------------------------------------------------------------------

    @staticmethod
    def _set_text(widget: tk.Text, segments: list):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        for text, tag in segments:
            widget.insert("end", text, tag)
        widget.config(state="disabled")

    # ------------------------------------------------------------------
    # Wordlist auto-load & download
    # ------------------------------------------------------------------

    def _auto_load_wordlists(self):
        """Check for existing wordlists folder and load silently."""
        result = auto_load_wordlists()
        if result["loaded_files"]:
            info = wordlist_info()
            self._set_wordlist_status_loaded(info["count"], len(result["loaded_files"]))

    def _set_wordlist_status_loaded(self, count: int, num_files: int):
        self._wl_status_var.set(
            f"✅  Loaded: {count:,} passwords from {num_files} file(s) — "
            "dictionary attacks will be fully simulated"
        )
        self._wl_status_lbl.config(fg=COLOR_GREEN)
        self._dl_btn.config(text="✓  Wordlists Ready", state="disabled",
                            bg=BG_BORDER, fg=TEXT_SECONDARY)
        # Re-analyse current password with the new wordlist
        pwd = self._password_var.get()
        if pwd:
            self._analyse(pwd)

    def _start_download(self):
        """Start the wordlist download in a background thread."""
        if self._dl_thread and self._dl_thread.is_alive():
            return  # already running

        self._dl_btn.config(text="⏳  Downloading…", state="disabled",
                            bg=BG_BORDER, fg=TEXT_SECONDARY)
        self._wl_status_var.set("⬇  Downloading RockYou 2025 wordlists…")
        self._wl_status_lbl.config(fg=COLOR_CYAN)
        self._dl_progress_var.set("")

        def _run():
            _dl.main(
                quiet=True,
                callback_per_file=self._on_download_progress,
            )
            # When done, load them and update UI from main thread
            result = load_wordlists_folder()
            info   = wordlist_info()
            self.after(0, lambda: self._set_wordlist_status_loaded(
                info["count"], len(result["loaded_files"])
            ))
            self.after(0, lambda: self._dl_progress_var.set(""))

        self._dl_thread = threading.Thread(target=_run, daemon=True)
        self._dl_thread.start()

    def _on_download_progress(self, filename: str, downloaded: int, total: int):
        """Called from background thread — schedules a UI update on main thread."""
        if total > 0:
            pct = downloaded / total * 100
            mb  = downloaded / 1_048_576
            tot = total      / 1_048_576
            msg = f"{filename}:  {mb:.1f} / {tot:.1f} MB  ({pct:.0f}%)"
        else:
            msg = f"{filename}:  downloading…"
        # Schedule on main thread (thread-safe)
        self.after(0, lambda m=msg: self._dl_progress_var.set(m))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    app = PasswordCheckerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
