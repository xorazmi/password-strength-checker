"""
checker.py — Core Password Analysis Engine
-------------------------------------------
Author   : Eldor Matmurodov
GitHub   : https://github.com/xorazmi
Telegram : @moein101
Channel  : @cybersecattack0
Email    : eldormatmurodov@gmail.com
License  : MIT

Implements all cryptographic and statistical password scoring logic:

  - Shannon entropy estimation
  - Character-set analysis (width of the alphabet used)
  - Composite strength scoring (0–100)
  - Categorical label assignment: VERY WEAK / WEAK / MODERATE / STRONG / VERY STRONG
  - Crack-time estimation for common attack scenarios
  - Actionable feedback generation

Design philosophy
-----------------
Passwords are not scored on length alone or complexity rules alone, because
neither metric captures real-world guessability. Instead we:
  1. Estimate true entropy from the effective alphabet size and length.
  2. Apply penalties for structural patterns (delegated to patterns.py).
  3. Apply a hard penalty (or outright rejection) for dictionary matches.
  4. Convert the adjusted bit-score into an estimated crack time under a
     GPU-accelerated offline brute-force scenario (bcrypt-equivalent).
"""

import math
import string
from typing import List, Tuple

from patterns import analyse_patterns
from common_passwords import is_common_password


# ---------------------------------------------------------------------------
# Alphabet-width constants
# ---------------------------------------------------------------------------

CHARSET_LOWERCASE  = set(string.ascii_lowercase)      # 26
CHARSET_UPPERCASE  = set(string.ascii_uppercase)      # 26
CHARSET_DIGITS     = set(string.digits)               # 10
CHARSET_SPECIAL    = set(string.punctuation)          # 32
CHARSET_SPACE      = {" "}                             # 1

# Characters outside printable ASCII (unicode): approx. pool size assumed
CHARSET_UNICODE_POOL = 65_000


# ---------------------------------------------------------------------------
# Crack-time estimation
# ---------------------------------------------------------------------------

# Modern GPU rigs can attempt ~10 billion MD5 hashes per second offline.
# For a proper bcrypt ($2b$, cost=12) the rate is ~5,000 / second.
# We display times calibrated to an *offline bcrypt* attacker — the worst
# case a password actually protects against in a properly stored system.
_BCRYPT_GUESSES_PER_SECOND = 5_000

# Labels for crack-time brackets (in seconds)
_CRACK_TIME_LABELS: List[Tuple[int, str]] = [
    (1,                  "less than a second"),
    (60,                 "a few seconds"),
    (3_600,              "a few minutes"),
    (86_400,             "a few hours"),
    (604_800,            "a few days"),
    (2_592_000,          "a few weeks"),
    (31_536_000,         "a few months"),
    (3_153_600_000,      "a few years"),
    (315_360_000_000,    "decades"),
    (31_536_000_000_000, "centuries"),
]


def estimate_crack_time(entropy_bits: float) -> str:
    """
    Convert entropy bits into a human-readable offline crack-time estimate.

    Uses an offline bcrypt attacker model (5 000 guesses/s) as the baseline,
    which reflects realistic threat models for properly hashed credentials.
    """
    if entropy_bits <= 0:
        return "instantly"

    # Number of guesses needed to exhaust half the keyspace (expected case)
    guesses_needed = 2 ** (entropy_bits - 1)
    seconds_needed = guesses_needed / _BCRYPT_GUESSES_PER_SECOND

    for threshold, label in _CRACK_TIME_LABELS:
        if seconds_needed <= threshold:
            return label
    return "practically uncrackable"


# ---------------------------------------------------------------------------
# Entropy calculation
# ---------------------------------------------------------------------------

def calculate_charset_size(password: str) -> int:
    """
    Determine the effective character-set size (pool width) used by *password*.

    Each unique character class present multiplies the attacker's search space.
    Unicode characters outside ASCII are counted as a large pool.
    """
    pool = 0
    chars = set(password)

    if chars & CHARSET_LOWERCASE:
        pool += 26
    if chars & CHARSET_UPPERCASE:
        pool += 26
    if chars & CHARSET_DIGITS:
        pool += 10
    if chars & CHARSET_SPECIAL:
        pool += 32
    if chars & CHARSET_SPACE:
        pool += 1

    # Detect non-ASCII Unicode characters
    non_ascii = [c for c in password if ord(c) > 127]
    if non_ascii:
        pool += CHARSET_UNICODE_POOL

    return max(pool, 1)  # avoid log(0)


def calculate_entropy(password: str) -> float:
    """
    Estimate the theoretical Shannon entropy of *password* in bits.

    Formula:  H = L × log₂(N)
    where L = password length, N = effective character-pool size.

    Note: this is an upper-bound estimate assuming uniform random character
    selection. Structural patterns (handled separately) will reduce the
    *effective* entropy below this theoretical maximum.
    """
    length       = len(password)
    charset_size = calculate_charset_size(password)

    if length == 0 or charset_size == 0:
        return 0.0

    entropy = length * math.log2(charset_size)
    return round(entropy, 2)


# ---------------------------------------------------------------------------
# Composite scoring
# ---------------------------------------------------------------------------

def _score_length(length: int) -> int:
    """Award points for password length on a sliding scale."""
    if length < 6:   return 0
    if length < 8:   return 10
    if length < 10:  return 20
    if length < 12:  return 30
    if length < 16:  return 40
    if length < 20:  return 50
    return 60


def _score_charset(password: str) -> int:
    """Award points for character class diversity."""
    chars  = set(password)
    points = 0
    if chars & CHARSET_LOWERCASE:  points += 5
    if chars & CHARSET_UPPERCASE:  points += 10
    if chars & CHARSET_DIGITS:     points += 5
    if chars & CHARSET_SPECIAL:    points += 15
    if any(ord(c) > 127 for c in password):
        points += 10  # Unicode bonus
    return points


def _score_entropy(entropy: float) -> int:
    """Translate entropy bits into a partial score component."""
    if entropy < 20:   return 0
    if entropy < 40:   return 5
    if entropy < 60:   return 10
    if entropy < 80:   return 15
    if entropy < 100:  return 20
    return 25


def compute_score(password: str) -> dict:
    """
    Run the full password analysis pipeline and return a structured report.

    Pipeline
    --------
    1. Reject empty/whitespace-only input.
    2. Detect structural patterns (patterns.py).
    3. Check common-password dictionary (common_passwords.py).
    4. Calculate theoretical entropy.
    5. Build composite score (0–100) with penalties applied.
    6. Assign categorical label and crack-time estimate.
    7. Generate actionable feedback messages.

    Returns
    -------
    dict with keys:
        password         : str  — the raw input
        length           : int
        entropy_bits     : float
        charset_size     : int
        score            : int  (0–100, post-penalty)
        raw_score        : int  (pre-penalty)
        label            : str  — "VERY WEAK" / "WEAK" / "MODERATE" / "STRONG" / "VERY STRONG"
        crack_time       : str  — human-readable estimate
        is_common        : bool
        common_info      : dict — from common_passwords.is_common_password
        pattern_info     : dict — from patterns.analyse_patterns
        feedback         : list[str] — ordered improvement suggestions
        classes_used     : dict — booleans for each character class
    """
    # ------------------------------------------------------------------ #
    # 0. Trivial rejection                                                 #
    # ------------------------------------------------------------------ #
    if not password or not password.strip():
        return _empty_result(password)

    # ------------------------------------------------------------------ #
    # 1. Pattern analysis                                                  #
    # ------------------------------------------------------------------ #
    pattern_info = analyse_patterns(password)

    # ------------------------------------------------------------------ #
    # 2. Dictionary check                                                  #
    # ------------------------------------------------------------------ #
    common_info = is_common_password(password, leet_normalised=pattern_info["leet_normalised"])

    # ------------------------------------------------------------------ #
    # 3. Entropy                                                           #
    # ------------------------------------------------------------------ #
    entropy      = calculate_entropy(password)
    charset_size = calculate_charset_size(password)
    length       = len(password)

    # ------------------------------------------------------------------ #
    # 4. Character-class map                                               #
    # ------------------------------------------------------------------ #
    chars = set(password)
    classes_used = {
        "lowercase" : bool(chars & CHARSET_LOWERCASE),
        "uppercase" : bool(chars & CHARSET_UPPERCASE),
        "digits"    : bool(chars & CHARSET_DIGITS),
        "special"   : bool(chars & CHARSET_SPECIAL),
        "unicode"   : any(ord(c) > 127 for c in password),
    }

    # ------------------------------------------------------------------ #
    # 5. Composite scoring                                                 #
    # ------------------------------------------------------------------ #
    raw_score = (
        _score_length(length)
        + _score_charset(password)
        + _score_entropy(entropy)
    )

    # Apply pattern penalties
    score = raw_score - pattern_info["penalty"]

    # Hard penalty for common passwords
    if common_info["is_common"]:
        score = min(score, 10)   # cap at 10 regardless of other factors

    score = max(0, min(score, 100))

    # ------------------------------------------------------------------ #
    # 6. Label + crack time                                                #
    # ------------------------------------------------------------------ #
    # Use effective entropy (penalised) for crack-time display
    effective_entropy = max(0.0, entropy * (score / 100)) if score > 0 else 0.0
    crack_time        = estimate_crack_time(effective_entropy)
    label             = _assign_label(score)

    # ------------------------------------------------------------------ #
    # 7. Feedback                                                          #
    # ------------------------------------------------------------------ #
    feedback = _generate_feedback(
        password=password,
        length=length,
        score=score,
        classes_used=classes_used,
        pattern_info=pattern_info,
        common_info=common_info,
        entropy=entropy,
    )

    return {
        "password":     password,
        "length":       length,
        "entropy_bits": entropy,
        "charset_size": charset_size,
        "score":        score,
        "raw_score":    raw_score,
        "label":        label,
        "crack_time":   crack_time,
        "is_common":    common_info["is_common"],
        "common_info":  common_info,
        "pattern_info": pattern_info,
        "feedback":     feedback,
        "classes_used": classes_used,
    }


# ---------------------------------------------------------------------------
# Label assignment
# ---------------------------------------------------------------------------

def _assign_label(score: int) -> str:
    if score <= 15:  return "VERY WEAK"
    if score <= 35:  return "WEAK"
    if score <= 55:  return "MODERATE"
    if score <= 75:  return "STRONG"
    return "VERY STRONG"


# ---------------------------------------------------------------------------
# Feedback generation
# ---------------------------------------------------------------------------

def _generate_feedback(
    password: str,
    length: int,
    score: int,
    classes_used: dict,
    pattern_info: dict,
    common_info: dict,
    entropy: float,
) -> List[str]:
    """
    Generate prioritised, actionable improvement suggestions.

    Feedback is ordered from most-critical to least-critical so the user
    addresses the biggest weaknesses first.
    """
    tips: List[str] = []

    # Critical: common password
    if common_info["is_common"]:
        match_type = common_info["match_type"]
        if match_type == "leet":
            tips.append(
                "This password is a known dictionary entry — even with leet-speak "
                "substitutions. Crackers apply these transforms automatically."
            )
        else:
            tips.append(
                "This password appears in known leaked password databases and will "
                "be guessed immediately in any dictionary attack. Change it entirely."
            )

    # Critical: length too short
    if length < 8:
        tips.append(
            f"Password is only {length} characters long. Use at least 12 characters; "
            "16+ is strongly recommended for sensitive accounts."
        )
    elif length < 12:
        tips.append(
            "Increase length to at least 12 characters. Length is the single most "
            "cost-effective way to raise cracking resistance."
        )

    # Keyboard patterns
    if pattern_info["keyboard"]:
        examples = ", ".join(f'"{s}"' for s in pattern_info["keyboard"][:3])
        tips.append(
            f"Keyboard walk detected ({examples}). These sequences are in every "
            "cracker's ruleset and add minimal real entropy."
        )

    # Sequential runs
    if pattern_info["sequential"]:
        examples = ", ".join(f'"{s}"' for s in pattern_info["sequential"][:3])
        tips.append(
            f"Sequential character run detected ({examples}). Avoid alphabetical "
            "or numeric sequences — they are tried first in brute-force attacks."
        )

    # Repeated characters
    if pattern_info["repeated"]:
        examples = ", ".join(f'"{s}"' for s in pattern_info["repeated"][:2])
        tips.append(
            f"Repeated character pattern detected ({examples}). Repetition shrinks "
            "the effective key space and is caught by simple rules."
        )

    # Date patterns
    if pattern_info["dates"]:
        tips.append(
            "Date-like substring detected. Birth years, anniversaries, and dates are "
            "commonly guessed based on social-engineering data."
        )

    # Missing character classes
    if not classes_used["uppercase"]:
        tips.append("Add uppercase letters (A–Z) to widen the character pool.")
    if not classes_used["lowercase"]:
        tips.append("Add lowercase letters (a–z).")
    if not classes_used["digits"]:
        tips.append("Include at least one digit (0–9).")
    if not classes_used["special"]:
        tips.append(
            "Add special characters (!@#$%^&*…). They contribute the largest "
            "per-character entropy boost (log₂ 32 ≈ 5 bits each)."
        )

    # Low entropy despite apparent complexity
    if entropy < 40 and score > 20:
        tips.append(
            f"Theoretical entropy is low ({entropy:.1f} bits). Consider a passphrase: "
            "four random unrelated words give ~50–60 bits of entropy and are memorable."
        )

    # Good password — minimal tips
    if score >= 76 and not tips:
        tips.append(
            "Strong password. Consider using a password manager to store it safely "
            "and enable MFA on accounts where it is available."
        )

    return tips


# ---------------------------------------------------------------------------
# Edge-case result
# ---------------------------------------------------------------------------

def _empty_result(password: str) -> dict:
    return {
        "password":     password,
        "length":       0,
        "entropy_bits": 0.0,
        "charset_size": 0,
        "score":        0,
        "raw_score":    0,
        "label":        "VERY WEAK",
        "crack_time":   "instantly",
        "is_common":    False,
        "common_info":  {"is_common": False, "match_type": "none", "matched_word": "", "source": ""},
        "pattern_info": {"sequential": [], "keyboard": [], "repeated": [], "dates": [],
                         "leet_normalised": "", "has_patterns": False, "penalty": 0},
        "feedback":     ["Password cannot be empty."],
        "classes_used": {"lowercase": False, "uppercase": False,
                         "digits": False, "special": False, "unicode": False},
    }
