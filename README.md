# Password Strength Checker

> **Author:** Eldor Matmurodov
> **GitHub:** [@xorazmi](https://github.com/xorazmi)
> **Telegram:** [@moein101](https://t.me/moein101)
> **Channel:** [@cybersecattack0](https://t.me/cybersecattack0)
> **Email:** eldormatmurodov@gmail.com
> **License:** MIT

A production-quality command-line utility for analysing password strength from a real cybersecurity perspective. Built as a portfolio project demonstrating applied password security, entropy theory, and Python software architecture.

---

## Features

| Feature | Description |
|---|---|
| **Entropy calculation** | Shannon entropy estimation based on effective character-pool size |
| **Composite strength scoring** | 0–100 score combining length, charset diversity, entropy, and penalties |
| **Dictionary attack simulation** | Checks against a built-in list of common/leaked passwords |
| **External wordlist support** | Load RockYou or any custom wordlist for deeper dictionary analysis |
| **Leet-speak detection** | Normalises `p@ssw0rd` → `password` before dictionary checks |
| **Keyboard sequence detection** | Catches `qwerty`, `asdf`, `1qaz2wsx`, and similar patterns |
| **Sequential run detection** | Identifies alphabetic or numeric sequences (`abc`, `456789`) |
| **Repeated character detection** | Flags `aaaa`, `abababab`, and similar low-entropy patterns |
| **Date pattern detection** | Detects embedded dates and birth years |
| **Crack-time estimation** | Estimates time-to-crack under an offline bcrypt attack model |
| **Rich terminal output** | ANSI-coloured, formatted reports with strength bars and recommendations |
| **Interactive REPL mode** | Hidden input (via `getpass`) for live password checking |
| **Batch mode** | Analyse multiple passwords from a file with a summary table |

---

## Project Structure

```
password-strength-checker/
├── main.py               # Entry point, argument parsing, mode dispatch
├── checker.py            # Core analysis engine (scoring, entropy, feedback)
├── patterns.py           # Pattern detection (keyboard walks, sequences, repeats)
├── common_passwords.py   # Dictionary attack simulation module
├── formatter.py          # ANSI terminal output and report formatting
├── wordlist.txt          # Bundled common password list (sample)
├── README.md             # This file
├── usage.md              # Usage guide and CLI reference
└── theory.md             # Password security concepts and background
```

---

## Quick Start

```bash
# Interactive mode
python main.py

# Single password analysis
python main.py --password "MySecurePass!99"

# With external wordlist
python main.py --wordlist wordlist.txt --password "test123"

# Batch analysis
python main.py --batch passwords.txt --summary-only
```

See [usage.md](usage.md) for the full CLI reference.

---

## Strength Labels

| Label | Score Range | Description |
|---|---|---|
| VERY WEAK | 0–15 | Trivially guessable, cracked immediately |
| WEAK | 16–35 | Vulnerable to dictionary and rule-based attacks |
| MODERATE | 36–55 | Resists casual attacks; still improvable |
| STRONG | 56–75 | Solid password; review feedback for final polish |
| VERY STRONG | 76–100 | Excellent resistance to known attack vectors |

---

## Security Design Notes

- **Crack-time model**: all estimates assume an offline attacker using bcrypt ($2b$, cost 12) at ~5,000 hashes/second on commodity GPU hardware. This is the correct threat model for properly stored credentials.
- **Entropy formula**: `H = L × log₂(N)` where `L` = password length and `N` = effective character-pool size. This is an upper bound; structural penalties reduce the effective entropy.
- **Dictionary checks**: performed on both the raw password and its leet-speak-normalised equivalent to catch substitution attempts.
- **No data is transmitted**: all analysis is performed locally. No network calls are made.

---

## Extending the Tool

**Custom wordlist** — any plain-text file (one password per line) works:
```bash
python main.py --wordlist /path/to/rockyou.txt --password "dragon"
```

**Programmatic API** — import `checker.compute_score` directly:
```python
from checker import compute_score
result = compute_score("MyPassword123!")
print(result["score"], result["label"], result["entropy_bits"])
```

---

## Requirements

- Python 3.8+
- No third-party dependencies (standard library only)

---

## Background Reading

See [theory.md](theory.md) for the underlying concepts: entropy, NIST guidelines, attack models, and passphrase strategies.

---

## License

MIT — free to use, modify, and distribute.
