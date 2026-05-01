"""
formatter.py — Terminal Output Formatting Module
-------------------------------------------------
Author   : Eldor Matmurodov
GitHub   : https://github.com/xorazmi
Telegram : @moein101
Channel  : @cybersecattack0
Email    : eldormatmurodov@gmail.com
License  : MIT

Provides rich, ANSI-coloured terminal output that makes the tool feel like
a real cybersecurity utility rather than a toy script.

Supports auto-detection of terminal colour capability and a --no-color flag
via the FORCE_NO_COLOR environment variable (https://no-color.org/).

Visual conventions
------------------
  - Red      → critical weakness / VERY WEAK / WEAK
  - Yellow   → moderate concern / MODERATE
  - Green    → acceptable / STRONG / VERY STRONG
  - Cyan     → informational labels and section headers
  - Bold     → emphasis on key values
  - Dim/Grey → secondary metadata
"""

import os
import sys
import shutil


# ---------------------------------------------------------------------------
# Colour detection
# ---------------------------------------------------------------------------

def _supports_color() -> bool:
    """Return True if the current terminal supports ANSI escape codes."""
    # Respect the no-colour standard (https://no-color.org/)
    if os.environ.get("NO_COLOR") or os.environ.get("FORCE_NO_COLOR"):
        return False
    # Windows cmd without ANSI support
    if sys.platform == "win32":
        return os.environ.get("ANSICON") is not None or "WT_SESSION" in os.environ
    return sys.stdout is not None and sys.stdout.isatty()


_USE_COLOR = _supports_color()


# ---------------------------------------------------------------------------
# ANSI codes
# ---------------------------------------------------------------------------

class _C:
    """ANSI escape sequences. Strings are empty when colour is disabled."""
    RESET     = "\033[0m"    if _USE_COLOR else ""
    BOLD      = "\033[1m"    if _USE_COLOR else ""
    DIM       = "\033[2m"    if _USE_COLOR else ""
    UNDERLINE = "\033[4m"    if _USE_COLOR else ""

    BLACK     = "\033[30m"   if _USE_COLOR else ""
    RED       = "\033[31m"   if _USE_COLOR else ""
    GREEN     = "\033[32m"   if _USE_COLOR else ""
    YELLOW    = "\033[33m"   if _USE_COLOR else ""
    BLUE      = "\033[34m"   if _USE_COLOR else ""
    MAGENTA   = "\033[35m"   if _USE_COLOR else ""
    CYAN      = "\033[36m"   if _USE_COLOR else ""
    WHITE     = "\033[37m"   if _USE_COLOR else ""

    BRIGHT_RED    = "\033[91m" if _USE_COLOR else ""
    BRIGHT_GREEN  = "\033[92m" if _USE_COLOR else ""
    BRIGHT_YELLOW = "\033[93m" if _USE_COLOR else ""
    BRIGHT_CYAN   = "\033[96m" if _USE_COLOR else ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _terminal_width() -> int:
    """Return the current terminal width, defaulting to 72."""
    return shutil.get_terminal_size(fallback=(72, 24)).columns


def _hr(char: str = "─") -> str:
    """Return a full-width horizontal rule."""
    width = min(_terminal_width(), 72)
    return _C.DIM + char * width + _C.RESET


def _label_color(label: str) -> str:
    """Map a strength label to its ANSI colour string."""
    mapping = {
        "VERY WEAK":  _C.BRIGHT_RED,
        "WEAK":       _C.RED,
        "MODERATE":   _C.BRIGHT_YELLOW,
        "STRONG":     _C.GREEN,
        "VERY STRONG": _C.BRIGHT_GREEN,
    }
    return mapping.get(label, _C.WHITE)


def _score_bar(score: int, width: int = 30) -> str:
    """
    Render a coloured ASCII progress bar representing the strength score.

    Example (score = 72):
        [██████████████████████░░░░░░░░]  72/100
    """
    filled     = int(width * score / 100)
    empty      = width - filled
    color      = _label_color(_score_to_label(score))
    bar_filled = color + "█" * filled + _C.RESET
    bar_empty  = _C.DIM + "░" * empty + _C.RESET
    return f"[{bar_filled}{bar_empty}]  {_C.BOLD}{score}/100{_C.RESET}"


def _score_to_label(score: int) -> str:
    if score <= 15:  return "VERY WEAK"
    if score <= 35:  return "WEAK"
    if score <= 55:  return "MODERATE"
    if score <= 75:  return "STRONG"
    return "VERY STRONG"


def _bullet(text: str, color: str = _C.YELLOW) -> str:
    return f"  {color}▸{_C.RESET} {text}"


def _kv(key: str, value: str, key_width: int = 22) -> str:
    padded_key = f"{_C.CYAN}{key:<{key_width}}{_C.RESET}"
    return f"  {padded_key}  {value}"


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = r"""
  ██████╗  █████╗ ███████╗███████╗██╗    ██╗ ██████╗ ██████╗ ██████╗
  ██╔══██╗██╔══██╗██╔════╝██╔════╝██║    ██║██╔═══██╗██╔══██╗██╔══██╗
  ██████╔╝███████║███████╗███████╗██║ █╗ ██║██║   ██║██████╔╝██║  ██║
  ██╔═══╝ ██╔══██║╚════██║╚════██║██║███╗██║██║   ██║██╔══██╗██║  ██║
  ██║     ██║  ██║███████║███████║╚███╔███╔╝╚██████╔╝██║  ██║██████╔╝
  ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝
         ███████╗████████╗██████╗ ███████╗███╗   ██╗ ██████╗ ████████╗██╗  ██╗
         ██╔════╝╚══██╔══╝██╔══██╗██╔════╝████╗  ██║██╔════╝ ╚══██╔══╝██║  ██║
         ███████╗   ██║   ██████╔╝█████╗  ██╔██╗ ██║██║  ███╗   ██║   ███████║
         ╚════██║   ██║   ██╔══██╗██╔══╝  ██║╚██╗██║██║   ██║   ██║   ██╔══██║
         ███████║   ██║   ██║  ██║███████╗██║ ╚████║╚██████╔╝   ██║   ██║  ██║
         ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝
                        ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗███████╗██████╗
                       ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗
                       ██║     ███████║█████╗  ██║     █████╔╝ █████╗  ██████╔╝
                       ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗
                       ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████╗██║  ██║
                        ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
"""

BANNER_SIMPLE = """
╔══════════════════════════════════════════════════════════════════════╗
║         PASSWORD STRENGTH CHECKER — Cybersecurity Utility           ║
╚══════════════════════════════════════════════════════════════════════╝"""


def print_banner(simple: bool = False) -> None:
    """Print the ASCII art banner to stdout."""
    if simple or not _USE_COLOR:
        print(_C.CYAN + BANNER_SIMPLE + _C.RESET)
    else:
        print(_C.CYAN + BANNER + _C.RESET)

    print(_C.DIM + "  Version 1.0.0  |  Python Password Strength Checker  |  @portfolio-project" + _C.RESET)
    print()


# ---------------------------------------------------------------------------
# Main report renderer
# ---------------------------------------------------------------------------

def print_report(result: dict, mask: bool = False) -> None:
    """
    Print a full analysis report to stdout for a single password result.

    Parameters
    ----------
    result : dict
        The dict returned by checker.compute_score().
    mask : bool
        If True, display the password as asterisks (for interactive mode).
    """
    label        = result["label"]
    score        = result["score"]
    label_color  = _label_color(label)
    password_display = "*" * result["length"] if mask else result["password"]

    print(_hr())
    print()

    # ── Password + Score ──────────────────────────────────────────────────
    print(f"  {_C.BOLD}Password:{_C.RESET}  {_C.DIM}{password_display}{_C.RESET}")
    print()
    print(f"  Strength:  {label_color}{_C.BOLD}{label}{_C.RESET}")
    print(f"  Score:     {_score_bar(score)}")
    print()

    # ── Core Metrics ──────────────────────────────────────────────────────
    print(f"  {_C.BOLD}{_C.UNDERLINE}Core Metrics{_C.RESET}")
    print()
    print(_kv("Length",          f"{_C.BOLD}{result['length']}{_C.RESET} characters"))
    print(_kv("Entropy",         f"{_C.BOLD}{result['entropy_bits']:.2f}{_C.RESET} bits"))
    print(_kv("Charset pool",    f"{_C.BOLD}{result['charset_size']}{_C.RESET} symbols"))
    print(_kv("Est. crack time", f"{_C.BOLD}{result['crack_time']}{_C.RESET}  "
                                  f"{_C.DIM}(offline bcrypt attacker){_C.RESET}"))
    print()

    # ── Character Classes ─────────────────────────────────────────────────
    print(f"  {_C.BOLD}{_C.UNDERLINE}Character Classes{_C.RESET}")
    print()
    classes = result["classes_used"]
    _print_class_row("Lowercase  (a–z)", classes["lowercase"])
    _print_class_row("Uppercase  (A–Z)", classes["uppercase"])
    _print_class_row("Digits     (0–9)", classes["digits"])
    _print_class_row("Special (!@#…)", classes["special"])
    _print_class_row("Unicode    (>127)", classes["unicode"])
    print()

    # ── Pattern Analysis ─────────────────────────────────────────────────
    pattern = result["pattern_info"]
    print(f"  {_C.BOLD}{_C.UNDERLINE}Pattern Analysis{_C.RESET}")
    print()

    if not pattern["has_patterns"] and not result["is_common"]:
        print(f"  {_C.GREEN}✓{_C.RESET}  No dangerous patterns detected.")
    else:
        if result["is_common"]:
            ci = result["common_info"]
            src  = ci["source"].upper()
            mtype = ci["match_type"].upper()
            print(f"  {_C.BRIGHT_RED}✗  COMMON PASSWORD — found in {src} list ({mtype} match){_C.RESET}")

        if pattern["keyboard"]:
            print(_bullet(f"Keyboard walk:   {_C.DIM}{', '.join(pattern['keyboard'][:5])}{_C.RESET}", _C.RED))
        if pattern["sequential"]:
            print(_bullet(f"Sequential run:  {_C.DIM}{', '.join(pattern['sequential'][:5])}{_C.RESET}", _C.RED))
        if pattern["repeated"]:
            print(_bullet(f"Repeated chars:  {_C.DIM}{', '.join(pattern['repeated'][:5])}{_C.RESET}", _C.RED))
        if pattern["dates"]:
            print(_bullet(f"Date fragment:   {_C.DIM}{', '.join(pattern['dates'][:5])}{_C.RESET}", _C.YELLOW))

    print()

    # ── Feedback ─────────────────────────────────────────────────────────
    if result["feedback"]:
        print(f"  {_C.BOLD}{_C.UNDERLINE}Recommendations{_C.RESET}")
        print()
        for idx, tip in enumerate(result["feedback"], 1):
            # First 2 tips → critical (red bullet), rest → advisory (yellow)
            bullet_color = _C.RED if idx <= 2 and score < 56 else _C.YELLOW
            print(_bullet(tip, bullet_color))
            print()

    print(_hr())
    print()


def _print_class_row(label: str, present: bool) -> None:
    tick  = f"{_C.GREEN}✓{_C.RESET}" if present else f"{_C.RED}✗{_C.RESET}"
    state = f"{_C.GREEN}present{_C.RESET}" if present else f"{_C.DIM}absent{_C.RESET}"
    print(f"    {tick}  {label:<20} {state}")


# ---------------------------------------------------------------------------
# Batch mode summary table
# ---------------------------------------------------------------------------

def print_batch_summary(results: list) -> None:
    """
    Print a compact summary table when multiple passwords are analysed at once.
    """
    col_pass = 24
    col_score = 6
    col_label = 12
    col_entropy = 10
    col_crack = 26

    header = (
        f"  {'PASSWORD':<{col_pass}} "
        f"{'SCORE':>{col_score}} "
        f"{'LABEL':<{col_label}} "
        f"{'ENTROPY':>{col_entropy}} "
        f"{'EST. CRACK TIME':<{col_crack}}"
    )

    print(_hr("═"))
    print(f"  {_C.BOLD}BATCH ANALYSIS SUMMARY{_C.RESET}")
    print(_hr("═"))
    print(_C.CYAN + header + _C.RESET)
    print(_hr())

    for r in results:
        label       = r["label"]
        label_color = _label_color(label)
        pwd_display = (r["password"][:21] + "...") if len(r["password"]) > 24 else r["password"]
        row = (
            f"  {_C.DIM}{pwd_display:<{col_pass}}{_C.RESET} "
            f"{r['score']:>{col_score}} "
            f"{label_color}{label:<{col_label}}{_C.RESET} "
            f"{r['entropy_bits']:>{col_entropy}.1f} "
            f"{r['crack_time']:<{col_crack}}"
        )
        print(row)

    print(_hr("═"))
    print()


# ---------------------------------------------------------------------------
# Wordlist load notification
# ---------------------------------------------------------------------------

def print_wordlist_info(info: dict) -> None:
    if info["loaded"]:
        print(
            f"  {_C.GREEN}✓{_C.RESET}  External wordlist loaded: "
            f"{_C.BOLD}{info['count']:,}{_C.RESET} entries from "
            f"{_C.DIM}{info['path']}{_C.RESET}"
        )
        print()
