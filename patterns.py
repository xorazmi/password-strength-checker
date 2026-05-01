"""
patterns.py — Pattern Detection Module
---------------------------------------
Author   : Eldor Matmurodov
GitHub   : https://github.com/xorazmi
Telegram : @moein101
Channel  : @cybersecattack0
Email    : eldormatmurodov@gmail.com
License  : MIT

Detects common structural weaknesses in passwords:
  - Sequential numeric runs (e.g. "12345", "9876")
  - Keyboard row sequences (e.g. "qwerty", "asdf")
  - Repeated character groups (e.g. "aaaa", "abababab")
  - Common date formats (e.g. "2001", "19xx", "dd/mm")
  - Leet-speak substitutions that add no real entropy
"""

import re
from typing import List

# ---------------------------------------------------------------------------
# Keyboard layout data
# ---------------------------------------------------------------------------

# Horizontal rows of a standard QWERTY keyboard, both forward and reverse
KEYBOARD_ROWS: List[str] = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]

# Common diagonal / adjacent clusters users type when lazy
KEYBOARD_ADJACENT_CLUSTERS: List[str] = [
    "qweasd", "wersdf", "ertdfg", "rtyfgh", "tyughj",
    "yuihkj", "uiojkl", "qazwsx", "wsxedc", "edcrfv",
    "rfvtgb", "tgbyhn", "yhnujm",
]

# Sequences of digits users frequently use
NUMERIC_SEQUENCES: List[str] = [
    "0123456789", "9876543210",
]

# Leet-speak mapping — used to normalise passwords before common-word checks
LEET_MAP: dict = {
    "4": "a", "@": "a",
    "3": "e",
    "1": "i", "!": "i",
    "0": "o",
    "5": "s", "$": "s",
    "7": "t",
    "+": "t",
    "8": "b",
    "6": "g",
    "|": "l",
    "9": "g",
}


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

def _substrings_of_min_length(text: str, min_len: int = 3) -> List[str]:
    """Yield all contiguous substrings of *text* with length >= *min_len*."""
    results = []
    n = len(text)
    for start in range(n):
        for end in range(start + min_len, n + 1):
            results.append(text[start:end])
    return results


def detect_sequential_runs(password: str, min_length: int = 3) -> List[str]:
    """
    Identify numeric or alphabetic sequential runs of at least *min_length*.

    For example: "abc", "987", "xyz" are sequences.

    Security rationale: sequential runs are trivially guessable and should be
    treated as near-zero entropy contributions.
    """
    found: List[str] = []
    lower = password.lower()

    for i in range(len(lower) - min_length + 1):
        chunk = lower[i : i + min_length]
        # Check if every consecutive pair of characters differs by exactly 1
        if all(ord(chunk[j + 1]) - ord(chunk[j]) == 1 for j in range(len(chunk) - 1)):
            found.append(chunk)
        # Same check in reverse (descending)
        elif all(ord(chunk[j + 1]) - ord(chunk[j]) == -1 for j in range(len(chunk) - 1)):
            found.append(chunk)
    return list(set(found))


def detect_keyboard_sequences(password: str, min_length: int = 3) -> List[str]:
    """
    Detect runs of characters that follow keyboard row / column adjacency.

    These patterns appear in the vast majority of "creative" weak passwords
    ("qwerty123", "asdfjkl;") and are known to crackers.
    """
    found: List[str] = []
    lower = password.lower()

    sources = KEYBOARD_ROWS + [row[::-1] for row in KEYBOARD_ROWS]  # add reverses
    sources += NUMERIC_SEQUENCES

    for source in sources:
        for length in range(min_length, len(source) + 1):
            for start in range(len(source) - length + 1):
                substring = source[start : start + length]
                if substring in lower and len(substring) >= min_length:
                    found.append(substring)

    # Also check adjacent clusters
    for cluster in KEYBOARD_ADJACENT_CLUSTERS:
        if cluster in lower:
            found.append(cluster)

    # Deduplicate and keep longest non-redundant matches
    found = list(set(found))
    found.sort(key=len, reverse=True)
    unique: List[str] = []
    for item in found:
        if not any(item in longer for longer in unique):
            unique.append(item)
    return unique


def detect_repeated_characters(password: str) -> List[str]:
    """
    Find repeated character blocks (e.g. "aaa", "1111") and repeated n-gram
    patterns (e.g. "abababab").

    Attackers enumerate repetition-based passwords first because they vastly
    shrink the search space.
    """
    found: List[str] = []

    # Repeated single characters: 3 or more of the same
    for match in re.finditer(r"(.)\1{2,}", password, re.IGNORECASE):
        found.append(match.group())

    # Repeated n-gram patterns (n = 2..4)
    for n in range(2, 5):
        pattern = re.compile(r"(.{" + str(n) + r"})\1+", re.IGNORECASE)
        for match in pattern.finditer(password):
            if len(match.group()) >= n * 2:
                found.append(match.group())

    return list(set(found))


def detect_date_patterns(password: str) -> List[str]:
    """
    Identify probable date-like substrings embedded in the password.

    Users frequently append birth years (1990–2009) or MM/DD/YYYY fragments.
    Regex patterns cover the most common formats without false-positive noise.
    """
    patterns = [
        r"\b(19[0-9]{2}|20[0-2][0-9])\b",          # Years 1900-2029
        r"\b(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])\b",  # MMDD
        r"\b(0[1-9]|[12][0-9]|3[01])(0[1-9]|1[0-2])\b",  # DDMM
        r"\b\d{1,2}[-/]\d{1,2}[-/]\d{2,4}\b",      # D/M/Y or M/D/Y
    ]
    found: List[str] = []
    for pat in patterns:
        for match in re.finditer(pat, password):
            found.append(match.group())
    return list(set(found))


def detect_leet_speak(password: str) -> str:
    """
    Translate common leet-speak substitutions back to plain ASCII.

    Returns the normalised (de-leet'd) version for use in dictionary checks.
    """
    normalised = ""
    for char in password.lower():
        normalised += LEET_MAP.get(char, char)
    return normalised


# ---------------------------------------------------------------------------
# Aggregated pattern report
# ---------------------------------------------------------------------------

def analyse_patterns(password: str) -> dict:
    """
    Run all pattern detectors and return a structured summary dict.

    Keys
    ----
    sequential        : list of detected sequential runs
    keyboard          : list of detected keyboard sequences
    repeated          : list of detected repeated blocks
    dates             : list of detected date-like fragments
    leet_normalised   : the leet-translated version of the password
    has_patterns      : bool — True if any pattern was found
    penalty           : int — total penalty score (used by checker.py)
    """
    sequential = detect_sequential_runs(password)
    keyboard   = detect_keyboard_sequences(password)
    repeated   = detect_repeated_characters(password)
    dates      = detect_date_patterns(password)
    leet_norm  = detect_leet_speak(password)

    # Each detected pattern type applies a penalty to the overall score
    penalty = 0
    penalty += len(sequential) * 15
    penalty += len(keyboard)   * 20
    penalty += len(repeated)   * 20
    penalty += len(dates)      * 10

    return {
        "sequential":      sequential,
        "keyboard":        keyboard,
        "repeated":        repeated,
        "dates":           dates,
        "leet_normalised": leet_norm,
        "has_patterns":    bool(sequential or keyboard or repeated or dates),
        "penalty":         min(penalty, 60),  # cap to avoid double-punishment
    }
