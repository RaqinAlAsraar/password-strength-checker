"""
Core Cryptographic and Entropy Auditing Engine.
"""

from src.core.crack_time import CrackTimeEstimates, estimate_crack_times
from src.core.dictionary import DictionaryFinding, PasswordDictionary
from src.core.entropy import CharsetVariety, EntropyResult, evaluate_entropy
from src.core.evaluator import EvaluationReport, PasswordEvaluator
from src.core.generator import generate_diceware_passphrase, generate_random_password
from src.core.patterns import PatternFinding, audit_patterns, normalize_leetspeak

__all__ = [
    "CharsetVariety",
    "EntropyResult",
    "evaluate_entropy",
    "PatternFinding",
    "audit_patterns",
    "normalize_leetspeak",
    "DictionaryFinding",
    "PasswordDictionary",
    "CrackTimeEstimates",
    "estimate_crack_times",
    "EvaluationReport",
    "PasswordEvaluator",
    "generate_random_password",
    "generate_diceware_passphrase",
]
