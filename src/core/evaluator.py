"""
Master Password Evaluation Engine.

Orchestrates:
1. Shannon and Keyspace entropy calculations
2. Character variety and length auditing
3. Pattern, sequence, keyboard walk, and repetition detection
4. Common password and leetspeak dictionary matching
5. Multi-scenario crack time estimations
6. Dynamic scoring (0-100), strength tier classification, and actionable feedback

Zero-Persistence Guarantee:
Evaluated purely in volatile memory; never logged, written to disk, or transmitted over network.
"""

from dataclasses import dataclass
from typing import Optional

from src.core.crack_time import CrackTimeEstimates, estimate_crack_times
from src.core.dictionary import DictionaryFinding, PasswordDictionary
from src.core.entropy import EntropyResult, evaluate_entropy
from src.core.patterns import PatternFinding, audit_patterns


@dataclass(frozen=True)
class EvaluationReport:
    password_length: int
    score: int  # 0 to 100
    tier: str   # 'Very Weak', 'Weak', 'Moderate', 'Strong', 'Very Strong'
    tier_color: str  # Hex code for GUI rendering (#ef4444, #f97316, #eab308, #22c55e, #06b6d4)
    entropy: EntropyResult
    effective_entropy_bits: float
    crack_times: CrackTimeEstimates
    pattern_findings: list[PatternFinding]
    dictionary_findings: list[DictionaryFinding]
    suggestions: list[str]
    passed_checks: list[str]
    failed_checks: list[str]


class PasswordEvaluator:
    """Master evaluator coordinating all auditing checks."""

    def __init__(self, dictionary: Optional[PasswordDictionary] = None):
        self.dictionary = dictionary or PasswordDictionary.get_instance()

    def evaluate(self, password: str) -> EvaluationReport:
        """Audit a credential in volatile memory and produce an EvaluationReport."""
        if not password:
            empty_entropy = evaluate_entropy("")
            empty_crack = estimate_crack_times(0.0, 0.0)
            return EvaluationReport(
                password_length=0,
                score=0,
                tier="Empty",
                tier_color="#94a3b8",
                entropy=empty_entropy,
                effective_entropy_bits=0.0,
                crack_times=empty_crack,
                pattern_findings=[],
                dictionary_findings=[],
                suggestions=["Enter a password to begin security auditing."],
                passed_checks=[],
                failed_checks=["Length is 0 characters", "No character variety"],
            )

        length = len(password)
        entropy_res = evaluate_entropy(password)
        pattern_findings = audit_patterns(password)
        dict_findings = self.dictionary.audit(password)

        passed_checks: list[str] = []
        failed_checks: list[str] = []
        suggestions: list[str] = []

        # 1. Base Score calculation from length
        if length >= 16:
            base_score = 45
            passed_checks.append("Length is 16+ characters (Optimal)")
        elif length >= 12:
            base_score = 35
            passed_checks.append("Length is 12-15 characters (Good)")
        elif length >= 8:
            base_score = 20
            passed_checks.append("Length is 8-11 characters (Minimum standard)")
            failed_checks.append("Length is under 12 characters")
        else:
            base_score = max(5, length * 2)
            failed_checks.append(f"Length is critically short ({length} characters)")

        # 2. Variety scoring
        var = entropy_res.variety
        variety_points = 0
        if var.has_lower:
            variety_points += 10
            passed_checks.append("Contains lowercase letters")
        else:
            failed_checks.append("Missing lowercase letters")

        if var.has_upper:
            variety_points += 10
            passed_checks.append("Contains uppercase letters")
        else:
            failed_checks.append("Missing uppercase letters")

        if var.has_digits:
            variety_points += 10
            passed_checks.append("Contains numbers (0-9)")
        else:
            failed_checks.append("Missing numerical digits")

        if var.has_symbols:
            variety_points += 15
            passed_checks.append("Contains special characters / symbols")
        else:
            failed_checks.append("Missing special symbols")

        # 3. Entropy-based score addition
        # Keyspace entropy contribution (scaled up to 25 points)
        entropy_points = min(25, int(entropy_res.keyspace_entropy_bits * 0.35))

        raw_score = base_score + variety_points + entropy_points

        # Check if structured as a multi-word Diceware passphrase
        is_passphrase = False
        passphrase_words = set()
        for sep in ("-", "_", " ", "."):
            parts = [p.strip().lower() for p in password.split(sep) if p.strip()]
            if len(parts) >= 3 and length >= 16:
                is_passphrase = True
                passphrase_words = set(parts)
                break

        # 4. Pattern and Dictionary Penalties
        total_penalties = 0

        # Dictionary findings
        has_exact_match = False
        for df in dict_findings:
            if df.match_type in ("exact", "exact_leetspeak"):
                total_penalties += df.penalty_score
                has_exact_match = True
                failed_checks.append(df.description)
            elif is_passphrase and df.matched_word in passphrase_words:
                # Diceware multi-word passphrases intentionally combine random dictionary words
                passed_checks.append(f"Passphrase component word: '{df.matched_word}'")
            else:
                total_penalties += df.penalty_score
                failed_checks.append(df.description)

        # Pattern findings
        for pf in pattern_findings:
            total_penalties += pf.penalty_score
            failed_checks.append(f"{pf.description} (Pattern: '{pf.match_snippet}')")

        # Deduct penalties
        score = max(5, raw_score - total_penalties)

        # Hard caps for severe vulnerabilities
        has_high_dict_match = any(
            df.severity in ("critical", "high")
            for df in dict_findings
            if not (is_passphrase and df.matched_word in passphrase_words)
        )

        if has_exact_match:
            # If it's literally 'password', 'p@ssword', '123456', etc.
            score = min(score, 12)
        elif has_high_dict_match:
            # Dominant dictionary component: cap at Moderate
            score = min(score, 55)
        elif length < 8:
            score = min(score, 25)
        elif var.variety_count <= 1:
            score = min(score, 30)

        score = min(100, max(1, score))

        # Effective entropy: reduce keyspace entropy by penalty ratio
        penalty_ratio = min(0.95, total_penalties / 100.0)
        effective_entropy = max(0.0, entropy_res.keyspace_entropy_bits * (1.0 - penalty_ratio))
        if has_exact_match:
            effective_entropy = min(effective_entropy, 5.0)

        # Estimate crack times
        crack_times = estimate_crack_times(entropy_res.keyspace_entropy_bits, effective_entropy)

        # Classify Strength Tier
        if score <= 25:
            tier = "Very Weak"
            tier_color = "#ef4444"  # Red
        elif score <= 50:
            tier = "Weak"
            tier_color = "#f97316"  # Orange
        elif score <= 70:
            tier = "Moderate"
            tier_color = "#eab308"  # Yellow
        elif score <= 85:
            tier = "Strong"
            tier_color = "#22c55e"  # Green
        else:
            tier = "Very Strong"
            tier_color = "#06b6d4"  # Cyan

        # Generate Actionable Constructive Suggestions
        if has_exact_match:
            suggestions.append(
                "CRITICAL: Do not use common dictionary words or simple leetspeak substitutions (e.g. '@' for 'a')."
            )

        if length < 12:
            suggestions.append(
                f"Increase length to at least 14 characters (currently {length}). Length is the single biggest factor in resisting brute-force."
            )

        if not var.has_upper:
            suggestions.append("Add uppercase letters (A-Z) to expand character pool size.")
        if not var.has_lower:
            suggestions.append("Add lowercase letters (a-z).")
        if not var.has_digits:
            suggestions.append("Add numbers (0-9).")
        if not var.has_symbols:
            suggestions.append("Add special characters (e.g., !@#$%^&*).")

        any_sequences = any(pf.category == "sequence" for pf in pattern_findings)
        if any_sequences:
            suggestions.append("Avoid predictable sequential runs (such as '12345' or 'abcdef').")

        any_walks = any(pf.category == "keyboard_walk" for pf in pattern_findings)
        if any_walks:
            suggestions.append("Avoid keyboard walk patterns (such as 'qwerty' or 'asdfgh').")

        any_repeats = any(pf.category in ("repetition", "repeated_chunk") for pf in pattern_findings)
        if any_repeats:
            suggestions.append("Eliminate repeating character blocks (e.g., 'aaaa' or 'abcabc').")

        if entropy_res.unique_chars < length * 0.6 and length > 6:
            suggestions.append("Increase character diversity; too many repeated characters reduce entropy.")

        if score >= 85 and not suggestions:
            suggestions.append(
                "Excellent password! Consider storing it securely in an offline password manager."
            )
        elif score >= 70 and not suggestions:
            suggestions.append(
                "Strong credential! Consider adding 2-4 more characters to maximize resistance against quantum and GPU clusters."
            )

        # Suggest Diceware passphrase if user wants an easy-to-remember yet high-entropy credential
        if score < 70:
            suggestions.append(
                "Pro-Tip: Try a Diceware passphrase with 4-5 random words (e.g., 'correct-horse-battery-staple')."
            )

        return EvaluationReport(
            password_length=length,
            score=score,
            tier=tier,
            tier_color=tier_color,
            entropy=entropy_res,
            effective_entropy_bits=round(effective_entropy, 2),
            crack_times=crack_times,
            pattern_findings=pattern_findings,
            dictionary_findings=dict_findings,
            suggestions=suggestions,
            passed_checks=passed_checks,
            failed_checks=failed_checks,
        )
