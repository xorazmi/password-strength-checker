# Password Security — Theory & Background

This document covers the foundational concepts behind the Password Strength Checker. Understanding these principles is essential for both evaluating the tool's design decisions and for thinking seriously about credential security.

---

## 1. What Is Password Entropy?

**Entropy** (measured in bits) quantifies the unpredictability — and therefore the guessing resistance — of a password. The higher the entropy, the more attempts an attacker must make on average to guess it correctly.

### Formula

```
H = L × log₂(N)
```

Where:
- `H` = entropy in bits
- `L` = password length (number of characters)
- `N` = size of the character pool (alphabet width)

### Character Pool Sizes

| Character Set | Pool Size | Bits per Character |
|---|---|---|
| Digits only (0–9) | 10 | 3.32 |
| Lowercase letters (a–z) | 26 | 4.70 |
| Lowercase + uppercase | 52 | 5.70 |
| Lowercase + uppercase + digits | 62 | 5.95 |
| All printable ASCII | 95 | 6.57 |
| + Unicode (estimated) | ~65,000 | 15.99 |

### Example Calculations

| Password | Length | Pool | Entropy |
|---|---|---|---|
| `abc` | 3 | 26 | 14.1 bits |
| `password` | 8 | 26 | 37.6 bits |
| `P@ssword!` | 9 | 95 | 59.1 bits |
| `Tr0ub4dor&3` | 11 | 95 | 72.2 bits |
| Four-word passphrase | 28 | 26+space | 131.6 bits |

> **Important**: this formula gives the *theoretical maximum* entropy assuming each character is chosen independently and uniformly at random. Real-world passwords — even "complex" ones — often have far lower *effective* entropy due to predictable patterns and dictionary words.

---

## 2. Why Complexity Rules Are Insufficient

Many systems enforce "complexity rules": require one uppercase, one digit, one symbol. This approach is well-intentioned but creates a false sense of security.

**Problems:**
- `P@ssword1` satisfies all four rules but appears in every modern wordlist.
- Users predictably substitute `@` for `a`, `0` for `o`, `1` for `l` — attackers apply these transforms first.
- Complexity rules encourage short passwords with predictable substitutions over long random ones.

**NIST SP 800-63B (2017)** explicitly recommends:
- **Length over complexity**: minimum 8 characters; allow up to 64+.
- **Check against known-bad lists**: compare against leaked password corpuses.
- **Do not enforce character-class mandates** unless the verifier can check for predictable patterns.
- **Do not require periodic rotation** unless compromise is suspected.

---

## 3. Attack Models

Understanding how attackers operate is essential to calibrate password strength correctly.

### 3.1 Online Attacks

The attacker sends guesses directly to a login service. Services mitigate this with rate-limiting, lockouts, and CAPTCHAs.

- Realistic rate: 10–100 guesses/second (with lockout evasion)
- Even a 6-character lowercase password survives online attacks if the service is properly hardened.
- **Threat model**: low risk for well-configured services.

### 3.2 Offline Attacks

The attacker has obtained the password hash (via data breach) and runs cracking software locally. No rate-limiting applies.

| Hash Algorithm | Guesses/Second (GPU cluster) | Notes |
|---|---|---|
| MD5 | ~100 billion/s | Never store passwords with MD5 |
| SHA-1 | ~50 billion/s | Deprecated |
| SHA-256 | ~20 billion/s | Not designed for passwords |
| bcrypt (cost 12) | ~5,000/s | Designed for passwords |
| Argon2id | ~2,000/s | Current gold standard |
| scrypt | ~3,000/s | Memory-hard |

> This tool calibrates crack-time estimates to **bcrypt ($2b$, cost 12) at 5,000 guesses/second** — a realistic worst-case for passwords stored with a proper algorithm.

### 3.3 Dictionary Attacks

Rather than brute-forcing every character combination, attackers use:
1. Known leaked passwords (RockYou: 14M, HaveIBeenPwned: 800M+)
2. Common words, names, sports teams, keyboard patterns
3. Rule-based mutations: capitalise first letter, append year, leet-speak substitution

A password in a leaked database is cracked **instantly** regardless of its apparent complexity.

### 3.4 Credential Stuffing

Attackers reuse username/password pairs from one breach against other services. If a user reuses passwords, a single breach compromises all their accounts. This underscores the importance of unique passwords per service, enforced by a password manager.

---

## 4. Common Structural Weaknesses

The pattern detection in this tool targets weaknesses that statistical entropy calculations miss.

### 4.1 Keyboard Walks

Sequences of adjacent keys on a keyboard layout:
- Row sequences: `qwerty`, `asdfgh`, `zxcvbn`, `1234567890`
- Column sequences: `qazwsx`, `1qaz2wsx`
- Diagonal sequences: `qweasd`, `tgbyhn`

These appear so frequently in real passwords that every serious cracking tool includes them as first-tier candidates.

### 4.2 Sequential Runs

Ascending or descending alphabetic or numeric runs: `abc`, `xyz`, `123`, `9876`. These contribute nearly zero entropy beyond their length.

### 4.3 Repeated Characters and N-grams

- Single-char repeats: `aaaa`, `1111`
- N-gram repeats: `abababab`, `xyzxyzxyz`

An attacker with a simple regex rule `(.)\1+` or `(.{2,})\1+` exhausts all of these instantly.

### 4.4 Date Patterns

Birth years, anniversaries, and date formats are commonly derived from social engineering or publicly available data (LinkedIn, Facebook). Patterns like `1990`, `0407`, `15/09` reduce the effective search space dramatically when attackers target specific individuals.

### 4.5 Leet-Speak

The substitution of letters with visually similar digits or symbols:

| Letter | Leet Substitutions |
|---|---|
| a | 4, @ |
| e | 3 |
| i | 1, ! |
| o | 0 |
| s | 5, $ |
| t | 7, + |

Crackers apply these transforms as rule sets before attempting unmodified dictionary attacks. `p@ssw0rd` is cracked at the same speed as `password`.

---

## 5. Passphrases

A **passphrase** is a sequence of randomly chosen, unrelated words. They are:
- **Memorisable**: humans remember words better than random characters.
- **High-entropy**: four random words from a 7,776-word list (Diceware) gives log₂(7776⁴) ≈ 51.7 bits — resistant to all practical attacks.
- **Pattern-free**: no keyboard walks, no date fragments, no obvious structure.

```
correct-horse-battery-staple      → ~51 bits entropy
Tr0ub4dor&3                       → ~28 bits effective (dictionary-prone)
```

The XKCD #936 comic popularised this concept. Diceware and EFF Wordlists are the canonical implementations.

**Best practice for most users**: a four-to-six word passphrase stored in a password manager, with unique passwords per service.

---

## 6. Storage: How Passwords Should Be Protected

A password strength checker is most meaningful when passwords are stored correctly. If a service stores passwords incorrectly, even strong passwords are at risk.

### Never Acceptable

- Plaintext storage
- Reversible encryption (AES, etc.) — keys can be compromised
- Unsalted hashes (MD5, SHA-1, SHA-256) — rainbow table attacks

### Minimum Acceptable

- **bcrypt** with cost factor ≥ 10 (OWASP recommendation: 12+)

### Recommended

- **Argon2id** (winner of the Password Hashing Competition, 2015) — memory-hard, resistant to GPU/ASIC acceleration, configurable parallelism.

### Essential Additions

- **Unique salt per user** — prevents precomputed rainbow table and batch cracking
- **Pepper** — application-level secret mixed into hashes; mitigates DB-only breaches
- **Account lockout + rate-limiting** — mitigates online brute force

---

## 7. NIST SP 800-63B Summary

Key recommendations from the current U.S. federal standard for digital identity:

1. **Minimum 8 characters** for user-chosen passwords; allow up to 64+.
2. **Check against known-compromised passwords** (this tool implements this).
3. **Do not enforce character composition rules** (uppercase + digit + symbol).
4. **Do not require periodic password changes** without evidence of compromise.
5. **Allow all printable ASCII and Unicode** in passwords.
6. **Provide a strength meter** (this tool implements this).
7. **Offer MFA** wherever possible.

---

## 8. Multi-Factor Authentication (MFA)

Even a perfect password is insufficient protection if it is the only factor. MFA requires proof from at least two of:
- **Something you know** (password)
- **Something you have** (TOTP app, hardware key)
- **Something you are** (biometric)

A TOTP (Time-based One-Time Password) code, even if an attacker has the password, prevents login. Hardware keys (YubiKey, Passkey) are phishing-resistant and represent the current best practice.

**Recommendation**: use a strong unique password *and* enable MFA wherever offered.

---

## 9. Further Reading

- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) — Digital Identity Guidelines
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [HaveIBeenPwned](https://haveibeenpwned.com/) — check if an email/password has been in a breach
- [EFF Diceware Wordlist](https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases)
- [Argon2 Specification](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf)
- [XKCD #936: Password Strength](https://xkcd.com/936/)
