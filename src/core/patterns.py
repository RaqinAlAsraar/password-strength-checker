"""
Pattern, Sequence, Repetition, and Leetspeak Auditing Module.

Detects:
1. Leetspeak substitutions (e.g. 'p@ssword' -> 'password', 'P@55w0rd' -> 'password')
2. Predictable sequential runs (numerical: '12345', '98765'; alphabetical: 'abcdef', 'fedcba')
3. Spatial keyboard walk sequences ('qwerty', 'asdfgh', 'zxcvbn', '1qaz', etc.)
4. Consecutive repeating characters ('aaaaa', '111111')
5. Repeated chunks / repeating n-grams ('abcabc', 'passpass')
"""

from dataclasses import dataclass
import re


# Standard Leetspeak mapping to possible base characters
LEET_MAP: dict[str, str] = {
    "@": "a",
    "4": "a",
    "8": "b",
    "3": "e",
    "1": "i",
    "!": "i",
    "|": "l",
    "0": "o",
    "$": "s",
    "5": "s",
    "7": "t",
    "+": "t",
    "9": "g",
    "2": "z",
}

# Common QWERTY keyboard sequences for spatial walk detection
KEYBOARD_PATTERNS: list[str] = [
    # Number row
    "`1234567890-=",
    "~!@#$%^&*()_+",
    # QWERTY top row
    "qwertyuiop[]\\",
    "QWERTYUIOP{}|",
    # Home row
    "asdfghjkl;'",
    "ASDFGHJKL:\"",
    # Bottom row
    "zxcvbnm,./",
    "ZXCVBNM<>?",
    # Common vertical / diagonal keyboard walks
    "1qaz",
    "2wsx",
    "3edc",
    "4rfv",
    "5tgb",
    "6yhn",
    "7ujm",
    "8ik,",
    "9ol.",
    "0p;/",
    "qazwsx",
    "1q2w3e4r",
]


@dataclass(frozen=True)
class PatternFinding:
    category: str  # 'leetspeak', 'sequence', 'keyboard_walk', 'repetition', 'repeated_chunk'
    description: str
    match_snippet: str
    severity: str  # 'high', 'medium', 'low'
    penalty_score: int  # Deductions from strength score


def normalize_leetspeak(text: str) -> tuple[str, list[tuple[str, str, int]]]:
    """
    Normalizes a string by decoding common leetspeak substitutions.
    Returns:
        normalized_text: lowercased string with leet chars replaced by standard letters
        substitutions: list of (original_char, replaced_char, index)
    """
    lower = text.lower()
    normalized_chars = []
    substitutions: list[tuple[str, str, int]] = []

    for idx, ch in enumerate(lower):
        if ch in LEET_MAP:
            replacement = LEET_MAP[ch]
            normalized_chars.append(replacement)
            substitutions.append((ch, replacement, idx))
        else:
            normalized_chars.append(ch)

    return "".join(normalized_chars), substitutions


def detect_repeated_characters(password: str) -> list[PatternFinding]:
    """Detect consecutive identical characters (e.g. 'aaaa', '11111')."""
    findings: list[PatternFinding] = []
    if not password:
        return findings

    # Look for 3 or more identical consecutive characters
    matches = re.finditer(r"(.)\1{2,}", password, re.IGNORECASE)
    for m in matches:
        snippet = m.group(0)
        char = snippet[0]
        count = len(snippet)
        severity = "high" if count >= 4 else "medium"
        penalty = min(30, 8 * (count - 1))
        findings.append(
            PatternFinding(
                category="repetition",
                description=f"Detected character '{char}' repeated {count} times consecutively.",
                match_snippet=snippet,
                severity=severity,
                penalty_score=penalty,
            )
        )
    return findings


def detect_repeated_chunks(password: str) -> list[PatternFinding]:
    """Detect repeated n-gram chunks (e.g., 'abcabc', 'passpass', '121212')."""
    findings: list[PatternFinding] = []
    length = len(password)
    if length < 4:
        return findings

    # Check for repeating blocks of length 2 to 6
    seen_chunks: set[str] = set()
    for block_len in range(2, min(7, (length // 2) + 1)):
        for i in range(length - (2 * block_len) + 1):
            chunk = password[i : i + block_len]
            next_chunk = password[i + block_len : i + 2 * block_len]
            if chunk.lower() == next_chunk.lower() and chunk.lower() not in seen_chunks:
                # Avoid flagging if chunk itself is just single repeating char (handled by detect_repeated_characters)
                if len(set(chunk)) > 1:
                    seen_chunks.add(chunk.lower())
                    findings.append(
                        PatternFinding(
                            category="repeated_chunk",
                            description=f"Detected repeating chunk pattern '{chunk}'.",
                            match_snippet=f"{chunk}{next_chunk}",
                            severity="medium",
                            penalty_score=15,
                        )
                    )
    return findings


def detect_predictable_sequences(password: str) -> list[PatternFinding]:
    """Detect ascending or descending numerical and alphabetical runs of 3+ characters."""
    findings: list[PatternFinding] = []
    if len(password) < 3:
        return findings

    lower = password.lower()

    # Numerical runs (e.g. '12345', '98765')
    digits = "0123456789"
    rev_digits = "9876543210"

    # Alphabetical runs (e.g. 'abcdef', 'zyxwvu')
    letters = "abcdefghijklmnopqrstuvwxyz"
    rev_letters = "zyxwvutsrqponmlkjihgfedcba"

    sequences_to_check = [
        ("numerical ascending", digits, 3),
        ("numerical descending", rev_digits, 3),
        ("alphabetical ascending", letters, 4),
        ("alphabetical descending", rev_letters, 4),
    ]

    for name, seq, min_len in sequences_to_check:
        # Check runs of length >= min_len
        for run_len in range(len(lower), min_len - 1, -1):
            for i in range(len(lower) - run_len + 1):
                sub = lower[i : i + run_len]
                if sub in seq:
                    # check if already covered
                    already_covered = any(sub in f.match_snippet.lower() for f in findings)
                    if not already_covered:
                        severity = "high" if run_len >= 4 else "medium"
                        penalty = min(30, 6 * run_len if run_len >= 4 else 8)
                        findings.append(
                            PatternFinding(
                                category="sequence",
                                description=f"Predictable {name} sequence of {run_len} characters.",
                                match_snippet=password[i : i + run_len],
                                severity=severity,
                                penalty_score=penalty,
                            )
                        )
    return findings


def detect_keyboard_walks(password: str) -> list[PatternFinding]:
    """Detect spatial keyboard walks along QWERTY rows and common keyboard diagonals."""
    findings: list[PatternFinding] = []
    if len(password) < 3:
        return findings

    lower = password.lower()

    for pattern in KEYBOARD_PATTERNS:
        p_lower = pattern.lower()
        p_rev = p_lower[::-1]

        # Scan for matches of length >= 3
        for k_seq in (p_lower, p_rev):
            for match_len in range(len(lower), 2, -1):
                for i in range(len(lower) - match_len + 1):
                    sub = lower[i : i + match_len]
                    if sub in k_seq:
                        already_covered = any(sub in f.match_snippet.lower() for f in findings)
                        if not already_covered:
                            severity = "high" if match_len >= 4 else "medium"
                            findings.append(
                                PatternFinding(
                                    category="keyboard_walk",
                                    description=f"Predictable keyboard walk pattern ({match_len} adjacent keys).",
                                    match_snippet=password[i : i + match_len],
                                    severity=severity,
                                    penalty_score=min(40, 8 * match_len),
                                )
                            )
    return findings


def audit_patterns(password: str) -> list[PatternFinding]:
    """Run full suite of pattern checks on the input password."""
    findings: list[PatternFinding] = []
    if not password:
        return findings

    findings.extend(detect_repeated_characters(password))
    findings.extend(detect_repeated_chunks(password))
    findings.extend(detect_predictable_sequences(password))
    findings.extend(detect_keyboard_walks(password))

    return findings
