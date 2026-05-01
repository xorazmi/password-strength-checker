# Usage Guide — Password Strength Checker

## Requirements

- Python 3.8 or later
- No external libraries required (pure standard library)

---

## Running the Tool

### Interactive Mode (default)

The recommended way to test passwords. Input is hidden via `getpass` — the password is not echoed to the terminal.

```bash
python main.py
```

At the prompt, type any password. The tool analyses it and prints a full report. Type `quit` or press `Ctrl+C` to exit.

Available inline commands:
- `quit` / `exit` / `q` — exit the session
- `clear` — clear the screen
- `help` / `?` — show inline help and quick tips

---

### Single Password Mode (`--password` / `-p`)

Analyse one password and exit. Useful for scripting and CI pipelines.

```bash
python main.py --password "MyP@ssword!99"
python main.py -p "correct horse battery staple"
```

> **Note:** wrap the password in quotes if it contains spaces or shell-special characters.

---

### Batch Mode (`--batch` / `-b`)

Read passwords from a file (one per line) and analyse all of them.

```bash
python main.py --batch passwords.txt
```

Prints a full report for each password, followed by a compact summary table and aggregate statistics.

**Summary-only output** (skip individual reports):
```bash
python main.py --batch passwords.txt --summary-only
```

---

### External Wordlist (`--wordlist` / `-w`)

Load a custom password wordlist for deeper dictionary-attack simulation. Any plain-text file works (one password per line). Large files like `rockyou.txt` are fully supported.

```bash
python main.py --wordlist /path/to/rockyou.txt --password "dragon99"
python main.py -w wordlist.txt -p "test123"
```

The built-in common-password list is always active regardless of whether an external wordlist is loaded.

---

## Full CLI Reference

```
usage: password-checker [-h] [-p PASSWORD] [-b FILE] [-w FILE]
                        [--summary-only] [--mask] [--no-color]
                        [--no-banner] [--simple-banner] [--version]

Password Strength Checker — A cybersecurity utility

options:
  -h, --help            show this help message and exit
  -p PASSWORD, --password PASSWORD
                        Analyse a single password directly
  -b FILE, --batch FILE
                        Batch mode: read passwords from FILE (one per line)
  -w FILE, --wordlist FILE
                        Load an external password wordlist for dictionary checks
  --summary-only        In batch mode, skip individual reports; print summary only
  --mask                Mask passwords with asterisks in all output
  --no-color            Disable ANSI colour output
  --no-banner           Skip the ASCII art banner
  --simple-banner       Use compact text banner instead of ASCII art
  --version             Print version and exit
```

---

## Output Format Explained

### Strength Bar
```
[███████████████████████░░░░░░░]  78/100
```
The bar fills proportionally to the score. Colour indicates category:
- Red → VERY WEAK / WEAK
- Yellow → MODERATE
- Green → STRONG / VERY STRONG

### Core Metrics

| Field | Meaning |
|---|---|
| Length | Character count |
| Entropy | Theoretical Shannon entropy in bits (H = L × log₂N) |
| Charset pool | Number of distinct characters the attacker must search |
| Est. crack time | Time estimate under offline bcrypt attack (~5,000 guesses/sec) |

### Character Classes

Shows which character categories are present or absent in the password.

### Pattern Analysis

Lists detected structural weaknesses: keyboard walks, sequential runs, repeated blocks, and date fragments.

### Recommendations

Ordered list of specific, actionable improvements — most critical weakness first.

---

## Programmatic Usage

Import `compute_score` for use in your own Python code:

```python
from checker import compute_score

result = compute_score("MyP@ssword!99")

print(result["score"])          # int: 0–100
print(result["label"])          # str: "STRONG"
print(result["entropy_bits"])   # float: 72.4
print(result["crack_time"])     # str: "centuries"
print(result["is_common"])      # bool: False
print(result["feedback"])       # list[str]: improvement tips
print(result["pattern_info"])   # dict: pattern detection results
print(result["classes_used"])   # dict: character class breakdown
```

Full return schema:

```python
{
    "password":     str,
    "length":       int,
    "entropy_bits": float,
    "charset_size": int,
    "score":        int,          # 0–100, post-penalty
    "raw_score":    int,          # 0–100, pre-penalty
    "label":        str,          # VERY WEAK / WEAK / MODERATE / STRONG / VERY STRONG
    "crack_time":   str,
    "is_common":    bool,
    "common_info":  dict,
    "pattern_info": dict,
    "feedback":     list[str],
    "classes_used": dict,
}
```

---

## Disabling Colour Output

Set the `NO_COLOR` environment variable (per [https://no-color.org/](https://no-color.org/)) or pass `--no-color`:

```bash
NO_COLOR=1 python main.py --password "test"
python main.py --no-color --password "test"
```

---

## Piping and Scripting

```bash
# Single check, no banner, no colour
python main.py --no-banner --no-color --password "mypassword" | grep "Strength"

# Batch check from stdin via a heredoc
printf "password\nsecret\nTr0ub4dor&3\n" > /tmp/pwds.txt
python main.py --batch /tmp/pwds.txt --summary-only --no-color
```

---

## Tips for Better Passwords

1. **Use a passphrase**: four unrelated random words (e.g. `correct-horse-battery-staple`) give ~50+ bits of entropy and are memorable.
2. **Aim for 16+ characters**: length is the cheapest form of entropy.
3. **Avoid dictionary words** — even with leet-speak substitution. Crackers apply these transforms automatically.
4. **Never reuse passwords** — use a password manager (Bitwarden, 1Password, KeePass).
5. **Enable MFA everywhere it is offered** — a compromised password alone is not enough to break in.
