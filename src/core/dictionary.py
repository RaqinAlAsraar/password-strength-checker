"""
Offline Dictionary Auditing and Common Password Matching Module.

Loads curated password and dictionary word lists purely into volatile RAM.
Detects:
1. Exact matches against top breached/common credentials
2. Leetspeak obfuscations of common passwords (e.g. 'p@ssword', 'P@55w0rd')
3. Embedded dictionary words and breached tokens within longer strings
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from src.core.patterns import normalize_leetspeak


@dataclass(frozen=True)
class DictionaryFinding:
    matched_word: str
    match_type: str  # 'exact', 'exact_leetspeak', 'substring', 'substring_leetspeak'
    severity: str    # 'critical', 'high', 'medium'
    description: str
    penalty_score: int
    original_snippet: str


class PasswordDictionary:
    """In-memory dictionary auditor for common passwords and keywords."""

    _instance: Optional["PasswordDictionary"] = None

    def __init__(self, dictionary_path: Optional[str | Path] = None):
        self.exact_set: set[str] = set()
        self.word_list: list[str] = []

        if dictionary_path is None:
            # Locate data/common_passwords.txt relative to package root
            current_dir = Path(__file__).resolve().parent
            project_root = current_dir.parent.parent
            dictionary_path = project_root / "data" / "common_passwords.txt"

        self.load_dictionary(Path(dictionary_path))

    def load_dictionary(self, path: Path) -> None:
        """Load common word list into volatile memory sets."""
        if not path.exists():
            return

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip().lower()
                if word and not word.startswith("#"):
                    self.exact_set.add(word)
                    # Keep words with length >= 4 for substring matching
                    if len(word) >= 4:
                        self.word_list.append(word)

        # Sort word list by length descending to prioritize longer matches
        self.word_list.sort(key=len, reverse=True)

    @classmethod
    def get_instance(cls, custom_path: Optional[str | Path] = None) -> "PasswordDictionary":
        """Singleton accessor to avoid re-reading disk file repeatedly."""
        if cls._instance is None:
            cls._instance = cls(custom_path)
        return cls._instance

    def audit(self, password: str) -> list[DictionaryFinding]:
        """Perform dictionary audit on password and its leetspeak normalized forms."""
        findings: list[DictionaryFinding] = []
        if not password:
            return findings

        clean_lower = password.strip().lower()
        normalized_leet, leet_subs = normalize_leetspeak(password)

        # 1. Exact direct match
        if clean_lower in self.exact_set:
            findings.append(
                DictionaryFinding(
                    matched_word=clean_lower,
                    match_type="exact",
                    severity="critical",
                    description=f"Exact match found in common leaked password database: '{clean_lower}'.",
                    penalty_score=60,
                    original_snippet=password,
                )
            )
            return findings

        # 2. Exact match via leetspeak normalization (e.g. 'p@ssword', 'P@55w0rd')
        if leet_subs and normalized_leet in self.exact_set:
            subs_desc = ", ".join(f"'{orig}'->'{norm}'" for orig, norm, _ in leet_subs)
            findings.append(
                DictionaryFinding(
                    matched_word=normalized_leet,
                    match_type="exact_leetspeak",
                    severity="critical",
                    description=(
                        f"Matches common password '{normalized_leet}' with weak leetspeak substitution ({subs_desc})."
                    ),
                    penalty_score=55,
                    original_snippet=password,
                )
            )
            return findings

        # 3. Substring matching for words of length >= 4
        matched_substrings: set[str] = set()

        for word in self.word_list:
            if len(word) < 4:
                continue

            # Direct substring match
            if word in clean_lower and word not in matched_substrings:
                if not any(word in seen for seen in matched_substrings):
                    matched_substrings.add(word)
                    is_dominant = (len(word) >= 0.50 * len(clean_lower)) or (len(word) >= 6)
                    severity = "high" if is_dominant else "medium"
                    penalty = 30 if is_dominant else min(18, 3 * len(word))
                    desc = (
                        f"Predominantly composed of common password '{word}' ({int(len(word)/len(clean_lower)*100)}% of length)."
                        if is_dominant
                        else f"Contains common dictionary word: '{word}'."
                    )
                    findings.append(
                        DictionaryFinding(
                            matched_word=word,
                            match_type="substring",
                            severity=severity,
                            description=desc,
                            penalty_score=penalty,
                            original_snippet=word,
                        )
                    )

            # Leetspeak normalized substring match (e.g. 'my_p@ssword_99')
            if leet_subs and word in normalized_leet and word not in matched_substrings:
                if not any(word in seen for seen in matched_substrings):
                    matched_substrings.add(word)
                    is_dominant = (len(word) >= 0.50 * len(normalized_leet)) or (len(word) >= 6)
                    severity = "high" if is_dominant else "medium"
                    penalty = 28 if is_dominant else min(16, 2 * len(word))
                    desc = (
                        f"Predominantly composed of obfuscated common password '{word}'."
                        if is_dominant
                        else f"Contains common dictionary word '{word}' obfuscated with leetspeak."
                    )
                    findings.append(
                        DictionaryFinding(
                            matched_word=word,
                            match_type="substring_leetspeak",
                            severity=severity,
                            description=desc,
                            penalty_score=penalty,
                            original_snippet=word,
                        )
                    )

            # Limit to top 2 substring findings to keep feedback concise
            if len(findings) >= 2:
                break

        return findings
