"""
download_wordlists.py — RockYou 2025 Wordlist Downloader
---------------------------------------------------------
Author   : Eldor Matmurodov
GitHub   : https://github.com/xorazmi
Telegram : @moein101
Channel  : @cybersecattack0
Email    : eldormatmurodov@gmail.com
License  : MIT

Downloads the RockYou 2025 common password lists into a local
'wordlists/' folder. The password checker automatically detects
and loads these files on startup.

Total download: ~150 MB (6 files × ~25 MB each)
"""

import os
import sys
import urllib.request
import urllib.error
import time


def _get_base_dir() -> str:
    """Return the EXE directory when frozen, or the script directory otherwise."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Wordlist sources
# ---------------------------------------------------------------------------

BASE_URL = "https://github.com/josuamarcelc/common-password-list/raw/refs/heads/main/"

WORDLIST_FILES = [
    "rockyou_2025_00.txt",
    "rockyou_2025_01.txt",
    "rockyou_2025_02.txt",
    "rockyou_2025_03.txt",
    "rockyou_2025_04.txt",
    "rockyou_2025_05.txt",
]

WORDLISTS_DIR = os.path.join(_get_base_dir(), "wordlists")

# ---------------------------------------------------------------------------
# ANSI colours (disabled on Windows without ANSI support)
# ---------------------------------------------------------------------------

USE_COLOR = (sys.stdout is not None and sys.stdout.isatty()
             and sys.platform != "win32")
GREEN  = "\033[92m" if USE_COLOR else ""
YELLOW = "\033[93m" if USE_COLOR else ""
CYAN   = "\033[96m" if USE_COLOR else ""
RED    = "\033[91m" if USE_COLOR else ""
DIM    = "\033[2m"  if USE_COLOR else ""
BOLD   = "\033[1m"  if USE_COLOR else ""
RESET  = "\033[0m"  if USE_COLOR else ""


# ---------------------------------------------------------------------------
# Progress bar
# ---------------------------------------------------------------------------

def _progress_bar(downloaded: int, total: int, width: int = 35) -> str:
    if total <= 0:
        return "[" + "?" * width + "]"
    pct    = downloaded / total
    filled = int(width * pct)
    bar    = "█" * filled + "░" * (width - filled)
    mb_dl  = downloaded / 1_048_576
    mb_tot = total      / 1_048_576
    return f"[{bar}] {mb_dl:.1f}/{mb_tot:.1f} MB  ({pct*100:.0f}%)"


# ---------------------------------------------------------------------------
# Single file download
# ---------------------------------------------------------------------------

def download_file(filename: str, dest_dir: str, callback=None) -> bool:
    """
    Download *filename* from BASE_URL into *dest_dir*.

    Parameters
    ----------
    filename : str
        The file to download (basename only).
    dest_dir : str
        Local directory to save into.
    callback : callable, optional
        Called with (downloaded_bytes, total_bytes) during download.

    Returns
    -------
    bool — True on success, False on failure.
    """
    url      = BASE_URL + filename
    dest     = os.path.join(dest_dir, filename)
    dest_tmp = dest + ".part"

    # Resume support: check if partial download exists
    resume_pos = 0
    if os.path.exists(dest_tmp):
        resume_pos = os.path.getsize(dest_tmp)

    headers = {"User-Agent": "Mozilla/5.0 (password-checker-downloader/1.0)"}
    if resume_pos > 0:
        headers["Range"] = f"bytes={resume_pos}-"

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as response:
            total = int(response.headers.get("content-length", 0)) + resume_pos
            mode  = "ab" if resume_pos > 0 else "wb"

            downloaded = resume_pos
            chunk_size = 65_536  # 64 KB

            with open(dest_tmp, mode) as fh:
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    fh.write(chunk)
                    downloaded += len(chunk)
                    if callback:
                        callback(downloaded, total)

        # Rename to final name on success
        if os.path.exists(dest):
            os.remove(dest)
        os.rename(dest_tmp, dest)
        return True

    except urllib.error.URLError as e:
        print(f"\n  {RED}Network error:{RESET} {e}")
        return False
    except KeyboardInterrupt:
        print(f"\n  {YELLOW}Download paused. Re-run to resume.{RESET}")
        return False
    except Exception as e:
        print(f"\n  {RED}Unexpected error:{RESET} {e}")
        return False


# ---------------------------------------------------------------------------
# Main downloader routine
# ---------------------------------------------------------------------------

def main(files=None, dest_dir=None, quiet=False, callback_per_file=None):
    """
    Download all wordlist files.

    Parameters
    ----------
    files            : list[str], optional — subset of WORDLIST_FILES to download
    dest_dir         : str, optional       — override default WORDLISTS_DIR
    quiet            : bool                — suppress console output
    callback_per_file: callable            — called with (filename, downloaded, total)

    Returns
    -------
    dict  {filename: "ok" | "skip" | "fail"}
    """
    target_files = files or WORDLIST_FILES
    target_dir   = dest_dir or WORDLISTS_DIR

    os.makedirs(target_dir, exist_ok=True)

    results = {}
    total_start = time.time()

    if not quiet:
        print(f"\n  {BOLD}{CYAN}RockYou 2025 Wordlist Downloader{RESET}")
        print(f"  {DIM}Destination: {target_dir}{RESET}")
        print(f"  {DIM}Files: {len(target_files)} × ~25 MB = ~{len(target_files)*25} MB total{RESET}\n")

    for idx, filename in enumerate(target_files, 1):
        dest_path = os.path.join(target_dir, filename)

        # Skip if already fully downloaded
        if os.path.exists(dest_path) and os.path.getsize(dest_path) > 1_000_000:
            if not quiet:
                size_mb = os.path.getsize(dest_path) / 1_048_576
                print(f"  {GREEN}✓{RESET}  [{idx}/{len(target_files)}] {filename}  "
                      f"{DIM}already downloaded ({size_mb:.1f} MB){RESET}")
            results[filename] = "skip"
            continue

        if not quiet:
            print(f"  {CYAN}↓{RESET}  [{idx}/{len(target_files)}] {filename}")

        last_print = [time.time()]

        def _progress(dl, total, fn=filename):
            now = time.time()
            if not quiet and (now - last_print[0] >= 0.25 or dl == total):
                bar = _progress_bar(dl, total)
                print(f"\r      {bar}", end="", flush=True)
                last_print[0] = now
            if callback_per_file:
                callback_per_file(fn, dl, total)

        ok = download_file(filename, target_dir, callback=_progress)

        if not quiet:
            print()  # newline after progress bar

        if ok:
            size_mb = os.path.getsize(dest_path) / 1_048_576
            if not quiet:
                print(f"      {GREEN}✓ Done{RESET}  ({size_mb:.1f} MB)\n")
            results[filename] = "ok"
        else:
            if not quiet:
                print(f"      {RED}✗ Failed{RESET}\n")
            results[filename] = "fail"

    # Summary
    if not quiet:
        elapsed   = time.time() - total_start
        succeeded = sum(1 for v in results.values() if v in ("ok", "skip"))
        failed    = sum(1 for v in results.values() if v == "fail")

        print(f"  {'─' * 50}")
        print(f"  {BOLD}Done in {elapsed:.1f}s{RESET}  —  "
              f"{GREEN}{succeeded} OK{RESET}  /  "
              f"{RED}{failed} failed{RESET}")
        if succeeded == len(target_files):
            print(f"\n  {GREEN}All wordlists ready.{RESET} "
                  "The password checker will load them automatically.\n")
        else:
            print(f"\n  {YELLOW}Re-run to retry failed downloads.{RESET}\n")

    return results


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Download RockYou 2025 password wordlists for the checker tool."
    )
    parser.add_argument("--dest", metavar="DIR", default=WORDLISTS_DIR,
                        help=f"Destination directory (default: {WORDLISTS_DIR})")
    parser.add_argument("--files", metavar="N", nargs="+",
                        choices=[f"rockyou_2025_0{i}.txt" for i in range(6)],
                        help="Download only specific files")
    args = parser.parse_args()

    main(files=args.files, dest_dir=args.dest)
