# CodeNova Internship Program • Cybersecurity Track (Batch 01)

## Task 1: Password Strength Checker (Credential Auditing & Entropy Engine)

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/) ![GUI Modern Web & PyQt6](https://img.shields.io/badge/GUI-Modern%20Web%20%26%20PyQt6-green.svg) ![Security Zero--Persistence](https://img.shields.io/badge/security-zero--persistence-brightgreen.svg) [![Author raqinalasraar](https://img.shields.io/badge/author-Ali%20Abbas%20Haidar%20(%40raqinalasraar)-cyan.svg)](https://github.com/raqinalasraar) ![License MIT](https://img.shields.io/badge/license-MIT-purple.svg)

**Developed by:** Ali Abbas Haidar (`@raqinalasraar`)  
**Track:** CodeNova Internship Batch 01 (Cybersecurity)

> A standalone defensive security engineering tool that evaluates credential strength locally in volatile memory, computes Shannon entropy and keyspace search spaces, detects predictable patterns and leetspeak substitutions (e.g., `p@ssword`), and provides actionable strengthening recommendations.


## Table of Contents

- [1. Overview & Architecture](#1-overview--architecture)

- [2. Mathematical & Cryptographic Models](#2-mathematical--cryptographic-models)

  - [Shannon Entropy Formula](#shannon-entropy-formula)

  - [Keyspace Combinatorial Entropy](#keyspace-combinatorial-entropy)

  - [Multi-Scenario Crack Time Estimation](#multi-scenario-crack-time-estimation)

- [3. Threat Heuristics & Pattern Detection](#3-threat-heuristics--pattern-detection)

  - [Leetspeak Normalization](#leetspeak-normalization)

  - [Sequential & Keyboard Walk Detection](#sequential--keyboard-walk-detection)

  - [Common Breached Dictionary Matching](#common-breached-dictionary-matching)

- [4. Security Architecture & Privacy Guarantees](#4-security-architecture--privacy-guarantees)

- [5. Installation & Setup (`setup.sh`)](#5-installation--setup-setupsh)

- [6. Usage Guide](#6-usage-guide)

  - [Graphical User Interface (GUI)](#graphical-user-interface-gui)

  - [Command-Line Interface (CLI)](#command-line-interface-cli)

  - [Cryptographic Generator](#cryptographic-generator)

- [7. Unit Test Suite & Acceptance Criteria](#7-unit-test-suite--acceptance-criteria)


## 1. Overview & Architecture

The **CodeNova Password Strength Checker** was engineered under defensive cybersecurity principles to address credential vulnerabilities before deployment. It pairs a **modern PyQt6 desktop graphical interface** with an extensible **Python auditing engine**.

### Directory Structure

```
password-strength-checker/
├── .gitignore                   # Excludes virtual environments and build cache
├── LICENSE                      # MIT Open Source License
├── setup.sh                     # Linux OS auto-detection, environment setup & runner
├── run.sh                       # Fast 1-command launcher script
├── requirements.txt             # Python dependencies (PyQt6, pytest)
├── main.py                      # Master entry point (detects GUI vs CLI mode)
├── data/
│   └── common_passwords.txt     # Offline database of leaked & high-frequency credentials
├── src/
│   ├── web/                     # Clean, modern desktop GUI (Chromium app mode / browser)
│   │   ├── index.html           # Minimalist single-column interface
│   │   ├── style.css            # Dark mode responsive CSS
│   │   ├── app.js               # Reactive client-side logic
│   │   └── server.py            # Local in-memory HTTP server
│   ├── gui/                     # Native PyQt6 desktop GUI
│   │   ├── main_window.py       # Qt window layout & widgets
│   │   └── styles.py            # Qt dark theme stylesheet (QSS)
│   ├── core/                    # Defensive security auditing engine
│   │   ├── entropy.py           # Shannon entropy H and Keyspace entropy calculations
│   │   ├── patterns.py          # Leetspeak decoder, sequence & keyboard walk detector
│   │   ├── dictionary.py        # Volatile in-memory dictionary matcher
│   │   ├── crack_time.py        # Threat modeling & brute-force time estimators
│   │   ├── evaluator.py         # Master scoring pipeline (0-100 score, tier & advice)
│   │   └── generator.py         # Hardware-backed RNG password & Diceware generator
│   └── cli/
│       └── console.py           # ANSI-colored interactive terminal interface
└── tests/
    ├── test_entropy.py          # Unit tests for Shannon & Keyspace mathematical formulas
    ├── test_patterns.py         # Unit tests for sequences, keyboard walks, repetitions
    ├── test_evaluator.py        # Unit tests for weak, moderate, robust credentials
    └── test_security.py         # Automated proof of zero disk I/O and zero networking
```


## 2. Mathematical & Cryptographic Models

### Shannon Entropy Formula

Shannon entropy measures the average information density (uncertainty) produced by characters in a string. For a password of length $L$ containing unique characters $c\_i$ with empirical probabilities $p(c\_i) = \\frac\{\\text\{count\}(c\_i)\}\{L\}$:

$$H = -\\sum\_\{i=1\}^\{k\} p(c\_i) \\log\_2(p(c\_i)) \\quad \\text\{(bits per character)\}$$

The **Total Shannon Entropy** is:

$$E\_\{\\text\{shannon\}\} = L \\times H \\quad \\text\{(bits)\}$$

- A uniform random string over $k$ distinct characters achieves maximum Shannon entropy $H\_\{\\text\{max\}\} = \\log\_2(k)$.

- Passwords with repeated characters (e.g. `aaaaaa`) produce $H = 0.0\\text\{ bits\}$, penalizing predictability.

### Keyspace Combinatorial Entropy

Combinatorial entropy reflects the raw brute-force search space based on the size of the active character pool $|R|$:

$$E\_\{\\text\{keyspace\}\} = L \\times \\log\_2(|R|) \\quad \\text\{(bits)\}$$

$$\\text\{Search Space Combinations \} N = |R|^L = 2^\{E\_\{\\text\{keyspace\}\}\}$$

Character pool classification:

- **Lowercase ($a-z$):** $|R| = 26$

- **Uppercase ($A-Z$):** $|R| = 26$

- **Numerical Digits ($0-9$):** $|R| = 10$

- **ASCII Punctuation / Symbols:** $|R| = 33$

- **Full Standard Pool:** $|R| = 26 + 26 + 10 + 33 = 95$

### Multi-Scenario Crack Time Estimation

Assuming an attacker checks on average 50% of the search space ($\\frac\{N\}\{2\} = 2^\{E\_\{\\text\{effective\}\} - 1\}$ guesses):

$$\\text\{Time (seconds)\} = \\frac\{2^\{E\_\{\\text\{effective\}\} - 1\}\}\{\\text\{Guesses per second\}\}$$

The tool models three realistic threat scenarios:

1. **Online Web Service Attack:** Rate-limited login APIs ($\\approx 100\\text\{ guesses/sec\}$).

2. **Fast Hash Offline Attack:** High-end multi-GPU cluster attacking fast hashes like MD5, SHA-256, NTLM ($\\approx 10^\{10\} = 10\\text\{ billion hashes/sec\}$).

3. **Slow Key-Stretched Offline Attack:** Memory-hard password hashing like Argon2id or Bcrypt ($\\approx 10^4 = 10,000\\text\{ hashes/sec\}$).


## 3. Threat Heuristics & Pattern Detection

### Leetspeak Normalization

Attackers use rule-based wordlist mutation engines (such as Hashcat's `best64.rule` or John the Ripper). The auditor normalizes weak substitutions before evaluating dictionary matches:

| Obfuscated Character | Canonical Mapping | Example Detection |
| :-: | :-: | :-: |
| `@`, `4` | `a` | `p@ssword` $\\rightarrow$ `password` |
| `0` | `o` | `r00t` $\\rightarrow$ `root` |
| `3` | `e` | `s3cur3` $\\rightarrow$ `secure` |
| `$`, `5` | `s` | `P@55w0rd` $\\rightarrow$ `password` |
| `1`, `!` | `i` / `l` | `4dm!n` $\\rightarrow$ `admin` |
| `7` | `t` | `h4ck3r7` $\\rightarrow$ `hackert` |


### Sequential & Keyboard Walk Detection

1. **Predictable Sequences:** Scans for ascending and descending runs in numbers (`123456`, `987654`) and alphabetical characters (`abcdef`, `zyxwv`).

2. **Spatial Keyboard Walks:** Detects key sequences traced along standard QWERTY layouts:

   - Rows: `qwerty`, `asdfgh`, `zxcvbn`

   - Diagonals & Columns: `1qaz`, `2wsx`, `qazwsx`

3. **Repetition:** Detects consecutive identical characters (`aaaaa`) and n-gram repeat blocks (`abcabc`).

### Common Breached Dictionary Matching

The tool loads a local database (`data/common_passwords.txt`) into RAM. It checks:

- Exact full-string matches against breached passwords.

- Exact matches via leetspeak normalization.

- Dominant substring matches (e.g. `Summer2023!`, `Welcome#2024`).


## 4. Security Architecture & Privacy Guarantees

As mandated by the CodeNova specification, the tool enforces strict privacy guarantees:

1. **Volatile RAM Processing:** Passwords entered by the user are evaluated strictly in transient memory. Variables are garbage collected immediately upon function completion.

2. **Zero Persistent Storage:** The application contains **zero disk writes** (`open(..., 'w')`, `open(..., 'a')`). No logs, caches, or history databases are created.

3. **Zero Network Transmission:** The program runs **100% offline**. It makes no HTTP requests, socket calls, telemetry pings, or analytics transmissions.

4. **Automated Verification:** Verified by unit test suite in [`tests/test_security.py`](file:///home/raqin/workshop/codenova-intern/password-strength-checker/tests/test_security.py), which uses Python runtime monkeypatching to assert that any attempt to open files in write mode or establish network sockets results in immediate test failure.


## 5. Installation & Setup (`setup.sh`)

The automated setup script detects your operating system distribution and sets up the environment cleanly:

```
# Clone or navigate to the project directory
cd password-strength-checker

# Make setup.sh executable (if not already)
chmod +x setup.sh run.sh

# Run the smart setup script after installation
./setup.sh

# Run this to start the tool everytime
./run.sh
```

### Supported Linux Distributions & Package Managers

| Platform | Distribution | Package Manager | Automatic Handling |
| - | - | - | - |
| **Linux** | Debian, Ubuntu, Kali, Mint, Pop!\_OS | `apt-get` | Installs Python 3, venv, and PyQt6 |
| **Linux** | Arch Linux, Manjaro, EndeavourOS | `pacman` | Installs Python and PyQt6 |
| **Linux** | Fedora, RHEL, CentOS, AlmaLinux | `dnf` / `yum` | Installs Python 3 and PyQt6 |
| **Linux** | openSUSE, SLES | `zypper` | Installs Python 3 and PyQt6 |
| **Linux** | Alpine Linux | `apk` | Installs Python 3 and PyQt6 |


### CLI Options for `setup.sh`

```
./setup.sh              # Auto-detect OS, configure environment, and launch clean modern desktop GUI (Default)
./setup.sh --qt         # Launch streamlined native PyQt6 desktop interface
./setup.sh --install    # Install system & pip dependencies without running
./setup.sh --cli        # Launch terminal CLI auditor
./setup.sh --test       # Run automated unit test suite
./setup.sh --check "pw" # Audit a specific password from the command line
./setup.sh --help       # Display help menu
```


## 6. Usage Guide

### Modern Clean Desktop Interface (Flagship Default)

Run via `./setup.sh` or `./run.sh` or `python3 main.py`:

Designed with a **clean, minimalist, Flutter-style aesthetic**:

- **Uncluttered & Focused**: Centered card layout with generous whitespace, eliminating visual noise.

- **Hero Input Box**: Smooth rounded field with instant reveal (👁️) and copy actions.

- **Fluid Strength Meter**: Animated progress fill, dynamic pill badge (`VERY STRONG 95/100`), and real-time GPU crack time estimate.

- **Checklist Chips**: Instant visual tags for Length, Uppercase, Lowercase, Digits, and Symbols.

- **Context-Aware Alerts**: Only displays threat banners when actual vulnerabilities exist (e.g., flagging `p@ssword` with leetspeak substitutions).

- **Cryptographic Generator**: Clean slider with live number bubble for generating high-entropy credentials and Diceware passphrases.

- **Technical Math Deep Dive**: Collapsible accordion for Shannon Entropy formula ( H ) and Keyspace metrics, keeping the primary interface clean.

### Native PyQt6 Desktop Interface

If you prefer traditional native Qt desktop widgets:

```
./setup.sh --qt
# or
python3 main.py --qt
```

### Command-Line Interface (CLI)

For headless servers or terminal lovers:

```
# Interactive interactive audit
python3 main.py --cli

# Audit a password directly
python3 main.py --check "p@ssword"

# Hidden input prompt (does not echo to terminal)
python3 main.py -i

# Generate an 18-character robust password
python3 main.py --generate --length 18

# Generate a 5-word Diceware passphrase
python3 main.py --generate --passphrase
```


## 7. Unit Test Suite & Acceptance Criteria

Run the test suite using `setup.sh` or `unittest`:

```
./setup.sh --test
# or
python3 -m unittest discover -s tests -v
```

### Acceptance Criteria Verification Matrix

| Criteria Requirement | Implementation Component | Verification Test | Status |
| - | - | - | :-: |
| **Shannon Entropy Calculation** | `src/core/entropy.py` | `test_entropy.py` | **PASS (100%)** |
| **Keyspace Combinatorial Entropy** | `src/core/entropy.py` | `test_entropy.py` | **PASS (100%)** |
| **Flag Leetspeak Substitutions (`p@ssword`)** | `src/core/patterns.py`, `dictionary.py` | `test_evaluator.py` | **PASS (100%)** |
| **Detect Sequences (`123456`, `abcdef`)** | `src/core/patterns.py` | `test_patterns.py` | **PASS (100%)** |
| **Detect Keyboard Walks (`qwerty`)** | `src/core/patterns.py` | `test_patterns.py` | **PASS (100%)** |
| **Actionable Improvement Recommendations** | `src/core/evaluator.py` | `test_evaluator.py` | **PASS (100%)** |
| **Zero Persistent Storage (Volatile RAM)** | Pure in-memory architecture | `test_security.py` | **PASS (100%)** |
| **Zero Outbound Transmission (Offline)** | Offline operation | `test_security.py` | **PASS (100%)** |
| **Cross-Platform OS Detection** | `setup.sh` | Shell runtime validation | **PASS (100%)** |



## License & Credits

- **Internship:** CodeNova Internship Program • Batch 01 (Cybersecurity)

- **Task:** Task 1 — Password Strength Checker (Credential Auditing & Entropy)

- **Author:** Ali Abbas Haidar (Raqin Al-Asraar)

- **Alias / GitHub:** [`@raqinalasraar`](https://github.com/raqinalasraar) (`raqin`)

- **Contact:** `aliabbashaidar313@gmail.com`

- **License:** MIT Open Source

