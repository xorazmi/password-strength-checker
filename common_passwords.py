"""
common_passwords.py — Common Password Dictionary Module
--------------------------------------------------------
Author   : Eldor Matmurodov
GitHub   : https://github.com/xorazmi
Telegram : @moein101
Channel  : @cybersecattack0
Email    : eldormatmurodov@gmail.com
License  : MIT

Maintains an in-memory set of the most frequently leaked / guessed passwords
and provides look-up utilities used during strength analysis.

Security rationale
------------------
The single most effective attack against real-world passwords is a dictionary
attack using leaked credential databases (RockYou, HaveIBeenPwned, etc.).
Even a "strong-looking" password like "P@ssword1" appears in every modern
wordlist and will be cracked instantly.

This module ships with a curated built-in list (top-500 class) and supports
loading an external wordlist file for more thorough checks.
"""

import os
import sys
import unicodedata
from typing import Optional, Set, List


def _get_base_dir() -> str:
    """
    Return the correct base directory whether running as:
      - a normal Python script  → directory of this .py file
      - a PyInstaller EXE       → directory of the .exe file
    This ensures 'wordlists/' is always found next to the executable/script.
    """
    if getattr(sys, "frozen", False):
        # PyInstaller sets sys.frozen = True and sys.executable = path to .exe
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


# Default wordlists folder (sits next to this file / the EXE)
_WORDLISTS_DIR = os.path.join(_get_base_dir(), "wordlists")

# ---------------------------------------------------------------------------
# Built-in common password list (representative subset — extend via file)
# ---------------------------------------------------------------------------

_BUILTIN_COMMON: Set[str] = {
    # Classics
    "password", "password1", "password123", "passw0rd", "p@ssword",
    "p@ssw0rd", "pa$$word", "password!", "password!1",
    # Numeric sequences
    "123456", "1234567", "12345678", "123456789", "1234567890",
    "0987654321", "987654321", "111111", "1111111", "11111111",
    "000000", "123123", "121212", "123321",
    # Names + numbers (extremely common pattern)
    "abc123", "abc1234", "admin", "admin123", "admin1234",
    "root", "root123", "toor", "user", "user123", "guest", "guest123",
    "test", "test123", "demo", "demo123",
    # Keyboard walks
    "qwerty", "qwerty123", "qwerty1", "qwertyu", "qwertyuiop",
    "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm",
    "qazwsx", "wsxedc", "1qaz2wsx", "2wsx3edc",
    # Sport teams / phrases
    "football", "baseball", "basketball", "soccer", "hockey",
    "letmein", "letmein1", "welcome", "welcome1", "iloveyou",
    "i love you", "monkey", "monkey1", "dragon", "dragon1",
    "master", "master123", "sunshine", "princess", "princess1",
    "shadow", "shadow1", "superman", "batman", "spiderman",
    "starwars", "trustno1", "hello", "hello123", "hello1234",
    # Generic word + year combinations
    "summer2023", "winter2023", "spring2023", "autumn2023",
    "summer2024", "winter2024", "password2023", "password2024",
    # Company / site placeholders
    "google", "facebook", "twitter", "instagram", "linkedin",
    "microsoft", "windows", "apple123", "iphone", "android",
    # Short / trivial
    "1234", "12345", "pass", "pass1", "passwd", "secret",
    "secret1", "secret123", "changeme", "change_me",
    # Repeated characters
    "aaaaaaa", "aaaaaaaaa", "qqqqqq", "zzzzzz",
    # Common phrases
    "corvette", "mustang", "harley", "ranger",
    "killer", "hunter", "hunter2", "hockey1",
    "ncc1701", "startrek", "thomas", "thomas1",
    "charlie", "charlie1", "jessica", "jessica1",
    "michael", "michael1", "jennifer", "jennifer1",
    "joshua", "joshua1", "andrew", "andrew1",
    "maggie", "maggie1", "jordan", "jordan1",
    "soccer1", "hockey2", "baseball1",
    # PIN-based
    "0000", "1111", "2222", "3333", "4444", "5555",
    "6666", "7777", "8888", "9999", "0101", "1010",
}


# ---------------------------------------------------------------------------
# Runtime storage — populated once, shared across calls
# ---------------------------------------------------------------------------

_loaded_wordlist: Optional[Set[str]] = None
_wordlist_path: Optional[str] = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_wordlist(filepath: str) -> int:
    """
    Load an external password wordlist into memory.

    Expects a plain-text file with one password per line (e.g. rockyou.txt).
    Returns the number of passwords successfully loaded.

    Parameters
    ----------
    filepath : str
        Absolute or relative path to the wordlist file.

    Raises
    ------
    FileNotFoundError
        If *filepath* does not exist.
    """
    global _loaded_wordlist, _wordlist_path

    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"Wordlist not found: {filepath}")

    words: Set[str] = set()
    with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            word = line.strip().lower()
            if word:
                words.add(word)

    _loaded_wordlist = words
    _wordlist_path = filepath
    return len(words)


def is_common_password(password: str, leet_normalised: Optional[str] = None) -> dict:
    """
    Check whether *password* appears in any known-bad list.

    Performs three layered checks:
    1. Exact match (case-insensitive) against the built-in list.
    2. Exact match against the loaded external wordlist (if any).
    3. Leet-speak normalised match against both lists.

    Parameters
    ----------
    password : str
        The raw password to evaluate.
    leet_normalised : str, optional
        Pre-computed de-leet'd version (from patterns.detect_leet_speak).

    Returns
    -------
    dict with keys:
        is_common    : bool
        match_type   : str  — "exact", "leet", or "none"
        matched_word : str  — the matching entry, or ""
        source       : str  — "builtin", "wordlist", or ""
    """
    lower = password.lower()
    leet  = (leet_normalised or lower).lower()

    # --- built-in exact ---
    if lower in _BUILTIN_COMMON:
        return {"is_common": True, "match_type": "exact", "matched_word": lower, "source": "builtin"}

    # --- built-in leet ---
    if leet != lower and leet in _BUILTIN_COMMON:
        return {"is_common": True, "match_type": "leet", "matched_word": leet, "source": "builtin"}

    # --- external wordlist ---
    if _loaded_wordlist is not None:
        if lower in _loaded_wordlist:
            return {"is_common": True, "match_type": "exact", "matched_word": lower, "source": "wordlist"}
        if leet != lower and leet in _loaded_wordlist:
            return {"is_common": True, "match_type": "leet", "matched_word": leet, "source": "wordlist"}

    return {"is_common": False, "match_type": "none", "matched_word": "", "source": ""}


def load_wordlists_folder(folder: Optional[str] = None) -> dict:
    """
    Load every .txt file from *folder* (defaults to the 'wordlists/' directory
    sitting next to this module) into the shared in-memory set.

    Returns
    -------
    dict with keys:
        loaded_files : list[str]  — filenames successfully loaded
        total_count  : int        — total unique passwords now in memory
        skipped      : list[str]  — files that could not be read
    """
    global _loaded_wordlist, _wordlist_path

    target = folder or _WORDLISTS_DIR
    if not os.path.isdir(target):
        return {"loaded_files": [], "total_count": 0, "skipped": []}

    txt_files = sorted(
        f for f in os.listdir(target)
        if f.lower().endswith(".txt")
    )

    if not txt_files:
        return {"loaded_files": [], "total_count": 0, "skipped": []}

    if _loaded_wordlist is None:
        _loaded_wordlist = set()

    loaded_files: List[str] = []
    skipped: List[str] = []

    for filename in txt_files:
        filepath = os.path.join(target, filename)
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    word = line.strip().lower()
                    if word:
                        _loaded_wordlist.add(word)
            loaded_files.append(filename)
        except Exception:
            skipped.append(filename)

    _wordlist_path = target
    return {
        "loaded_files": loaded_files,
        "total_count":  len(_loaded_wordlist),
        "skipped":      skipped,
    }


def auto_load_wordlists() -> dict:
    """
    Silently check if the default 'wordlists/' folder exists and load it.
    Call this at startup — returns immediately if folder is absent.
    """
    if os.path.isdir(_WORDLISTS_DIR):
        return load_wordlists_folder(_WORDLISTS_DIR)
    return {"loaded_files": [], "total_count": 0, "skipped": []}


def wordlist_info() -> dict:
    """Return metadata about the currently loaded external wordlist."""
    if _loaded_wordlist is None:
        return {"loaded": False, "path": "N/A", "count": 0}

    # Determine source label
    if _wordlist_path and os.path.isdir(_wordlist_path):
        files = [f for f in os.listdir(_wordlist_path) if f.endswith(".txt")]
        path_label = f"{_wordlist_path}  ({len(files)} files)"
    else:
        path_label = _wordlist_path or "N/A"

    return {
        "loaded": True,
        "path":   path_label,
        "count":  len(_loaded_wordlist),
    }
