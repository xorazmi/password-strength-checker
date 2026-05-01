#!/usr/bin/env python3
"""
main.py — Password Strength Checker — Entry Point
--------------------------------------------------
Author   : Eldor Matmurodov
GitHub   : https://github.com/xorazmi
Telegram : @moein101
Channel  : @cybersecattack0
Email    : eldormatmurodov@gmail.com
License  : MIT

Cybersecurity utility for analysing password strength, entropy, and
vulnerability to common attack vectors.

Usage
-----
  # Interactive mode (prompts for each password)
  python main.py

  # Analyse a single password
  python main.py --password "MyP@ssw0rd!"

  # Load a custom wordlist and analyse
  python main.py --wordlist /path/to/rockyou.txt --password "test123"

  # Batch mode — read from a file (one password per line)
  python main.py --batch passwords.txt

  # Suppress colour output (for piping / logging)
  python main.py --no-color --password "test"

See: usage.md for full documentation.
"""

import sys
import os
import argparse
import getpass

# ---------------------------------------------------------------------------
# Path setup — ensure sibling modules resolve correctly regardless of cwd
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from checker import compute_score
from common_passwords import load_wordlist, wordlist_info, auto_load_wordlists
from formatter import (
    print_banner,
    print_report,
    print_batch_summary,
    print_wordlist_info,
    _C,                  # colour strings for inline use
)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password-checker",
        description="Password Strength Checker — A cybersecurity utility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python main.py
  python main.py --password "MyP@ssword!"
  python main.py --wordlist rockyou.txt --password "test"
  python main.py --batch passwords.txt --no-color
  python main.py --batch passwords.txt --summary-only
        """,
    )

    parser.add_argument(
        "-p", "--password",
        metavar="PASSWORD",
        help="Analyse a single password directly (use quotes if it contains spaces).",
    )
    parser.add_argument(
        "-b", "--batch",
        metavar="FILE",
        help="Batch mode: read passwords line-by-line from FILE and print a summary table.",
    )
    parser.add_argument(
        "-w", "--wordlist",
        metavar="FILE",
        help="Load an external password wordlist (plain text, one entry per line) for "
             "improved dictionary-attack simulation. Example: rockyou.txt.",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="In batch mode, print only the summary table — skip individual reports.",
    )
    parser.add_argument(
        "--mask",
        action="store_true",
        help="Mask the password with asterisks in all output (useful for screen recordings).",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colour output (also respected via NO_COLOR env var).",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Skip printing the ASCII art banner.",
    )
    parser.add_argument(
        "--simple-banner",
        action="store_true",
        help="Use the compact text banner instead of ASCII art.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="password-checker 1.0.0",
    )

    return parser


# ---------------------------------------------------------------------------
# Mode handlers
# ---------------------------------------------------------------------------

def handle_single(password: str, mask: bool = False) -> int:
    """Analyse and print a single password. Returns the strength score."""
    result = compute_score(password)
    print_report(result, mask=mask)
    return result["score"]


def handle_batch(filepath: str, summary_only: bool = False, mask: bool = False) -> None:
    """
    Read passwords from *filepath* (one per line) and analyse each one.

    Prints individual reports (unless --summary-only) and a compact
    summary table at the end.
    """
    if not os.path.isfile(filepath):
        print(f"\n  {_C.RED}Error:{_C.RESET} File not found: {filepath}\n", file=sys.stderr)
        sys.exit(1)

    with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
        lines = [line.rstrip("\n") for line in fh if line.strip()]

    if not lines:
        print(f"\n  {_C.YELLOW}Warning:{_C.RESET} No passwords found in {filepath}\n")
        return

    results = []
    for pwd in lines:
        result = compute_score(pwd)
        results.append(result)
        if not summary_only:
            print_report(result, mask=mask)

    print_batch_summary(results)

    # Print aggregate statistics
    total  = len(results)
    by_label = {}
    for r in results:
        by_label[r["label"]] = by_label.get(r["label"], 0) + 1

    print(f"  {_C.BOLD}Aggregate statistics for {total} password(s):{_C.RESET}\n")
    for label in ["VERY WEAK", "WEAK", "MODERATE", "STRONG", "VERY STRONG"]:
        count = by_label.get(label, 0)
        bar   = "█" * count + "░" * (total - count) if total else ""
        print(f"    {label:<12} {count:>4}  {_C.DIM}{bar[:40]}{_C.RESET}")

    avg_score = sum(r["score"] for r in results) / total if total else 0
    print(f"\n  Average score: {_C.BOLD}{avg_score:.1f}/100{_C.RESET}\n")


def handle_interactive() -> None:
    """
    Run an interactive REPL-style loop where the user enters passwords
    and receives instant analysis until they type 'quit' or press Ctrl+C.
    """
    print(f"  {_C.CYAN}Interactive mode{_C.RESET} — type a password to analyse, "
          f"{_C.BOLD}'quit'{_C.RESET} to exit, {_C.BOLD}'help'{_C.RESET} for tips.\n")

    print(f"  {_C.DIM}Note: input is hidden (password is not echoed to terminal).{_C.RESET}\n")

    while True:
        try:
            # getpass hides input — important for demo / screen sharing
            password = getpass.getpass(f"  {_C.BOLD}Enter password:{_C.RESET}  ")
        except (KeyboardInterrupt, EOFError):
            print(f"\n\n  {_C.DIM}Exiting. Stay secure.{_C.RESET}\n")
            break

        stripped = password.strip()

        if not stripped:
            continue
        if stripped.lower() in ("quit", "exit", "q"):
            print(f"\n  {_C.DIM}Exiting. Stay secure.{_C.RESET}\n")
            break
        if stripped.lower() in ("help", "?"):
            _print_inline_help()
            continue
        if stripped.lower() == "clear":
            os.system("clear" if os.name != "nt" else "cls")
            continue

        result = compute_score(password)
        print_report(result, mask=False)

        # Quick re-prompt after report
        print(f"  {_C.DIM}(Analyse another password or type 'quit' to exit){_C.RESET}\n")


def _print_inline_help() -> None:
    print()
    print(f"  {_C.BOLD}Inline commands:{_C.RESET}")
    print(f"    {_C.CYAN}quit / exit / q{_C.RESET}  — exit the tool")
    print(f"    {_C.CYAN}clear{_C.RESET}            — clear the screen")
    print(f"    {_C.CYAN}help / ?{_C.RESET}         — show this message")
    print()
    print(f"  {_C.BOLD}What makes a strong password?{_C.RESET}")
    print(f"    ▸ At least {_C.BOLD}16 characters{_C.RESET} long")
    print(f"    ▸ Mix of uppercase, lowercase, digits, and special characters")
    print(f"    ▸ No keyboard sequences, repeated blocks, or dictionary words")
    print(f"    ▸ Consider a {_C.BOLD}passphrase{_C.RESET}: four random unrelated words")
    print(f"    ▸ Use a {_C.BOLD}password manager{_C.RESET} — do not reuse passwords")
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    # Honour --no-color flag at module level (before any output)
    if args.no_color:
        os.environ["NO_COLOR"] = "1"

    # Print banner unless suppressed
    if not args.no_banner:
        print_banner(simple=args.simple_banner)

    # Auto-detect and load 'wordlists/' folder if present
    auto_result = auto_load_wordlists()
    if auto_result["loaded_files"]:
        info = wordlist_info()
        print(
            f"  {_C.GREEN}✓{_C.RESET}  Wordlist folder detected: "
            f"{_C.BOLD}{info['count']:,}{_C.RESET} passwords loaded from "
            f"{len(auto_result['loaded_files'])} file(s)\n"
        )

    # Load additional external wordlist if explicitly provided
    if args.wordlist:
        try:
            count = load_wordlist(args.wordlist)
            info  = wordlist_info()
            print_wordlist_info(info)
        except FileNotFoundError as exc:
            print(f"\n  {_C.RED}Error:{_C.RESET} {exc}\n", file=sys.stderr)
            sys.exit(1)

    # ── Dispatch to the appropriate mode ──────────────────────────────────
    if args.batch:
        handle_batch(args.batch, summary_only=args.summary_only, mask=args.mask)

    elif args.password:
        handle_single(args.password, mask=args.mask)

    else:
        handle_interactive()


if __name__ == "__main__":
    main()
