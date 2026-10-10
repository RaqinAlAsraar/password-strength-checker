r"""
Shannon Entropy and Keyspace Entropy Calculation Engine.

Mathematical models:
1. Shannon Entropy (Information Theory):
   H = - \sum_{i=1}^{k} p(c_i) \log_2(p(c_i))
   Total Shannon Entropy = L * H  (in bits)
   where L is length and p(c_i) is the frequency of character c_i.

2. Keyspace Entropy (Brute-Force Combinatorial Space):
   E = L * \log_2(|R|)
   Total Search Space = |R|^L = 2^E
   where |R| is the total character pool size based on character variety.
"""

from collections import Counter
from dataclasses import dataclass
import math
import string


@dataclass(frozen=True)
class CharsetVariety:
    has_lower: bool
    has_upper: bool
    has_digits: bool
    has_symbols: bool
    has_other: bool
    lower_count: int
    upper_count: int
    digit_count: int
    symbol_count: int
    other_count: int
    pool_size: int

    @property
    def variety_count(self) -> int:
        """Count of distinct active character sets."""
        return sum([self.has_lower, self.has_upper, self.has_digits, self.has_symbols, self.has_other])


@dataclass(frozen=True)
class EntropyResult:
    length: int
    unique_chars: int
    shannon_bits_per_char: float
    total_shannon_entropy: float
    keyspace_pool_size: int
    keyspace_entropy_bits: float
    search_space_combinations: float
    variety: CharsetVariety


def analyze_charset_variety(password: str) -> CharsetVariety:
    """Analyze character classes present in the password and calculate pool size |R|."""
    lower_count = 0
    upper_count = 0
    digit_count = 0
    symbol_count = 0
    other_count = 0

    symbol_set = set(string.punctuation)

    for char in password:
        if char in string.ascii_lowercase:
            lower_count += 1
        elif char in string.ascii_uppercase:
            upper_count += 1
        elif char in string.digits:
            digit_count += 1
        elif char in symbol_set or char.isascii() and not char.isalnum() and not char.isspace():
            symbol_count += 1
        elif char.isspace():
            symbol_count += 1
        else:
            other_count += 1

    has_lower = lower_count > 0
    has_upper = upper_count > 0
    has_digits = digit_count > 0
    has_symbols = symbol_count > 0
    has_other = other_count > 0

    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digits:
        pool_size += 10
    if has_symbols:
        pool_size += 33  # punctuation + space
    if has_other:
        pool_size += 128  # unicode extended range approximation

    return CharsetVariety(
        has_lower=has_lower,
        has_upper=has_upper,
        has_digits=has_digits,
        has_symbols=has_symbols,
        has_other=has_other,
        lower_count=lower_count,
        upper_count=upper_count,
        digit_count=digit_count,
        symbol_count=symbol_count,
        other_count=other_count,
        pool_size=pool_size,
    )


def calculate_shannon_entropy(password: str) -> tuple[float, float]:
    """
    Calculate Shannon entropy:
    Returns (bits_per_char, total_bits).
    H = - sum(p_i * log2(p_i))
    Total = length * H
    """
    if not password:
        return 0.0, 0.0

    length = len(password)
    frequencies = Counter(password)

    h = 0.0
    for count in frequencies.values():
        p = count / length
        h -= p * math.log2(p)

    total_bits = length * h
    return round(h, 4), round(total_bits, 2)


def calculate_keyspace_entropy(password: str, variety: CharsetVariety) -> tuple[float, float]:
    """
    Calculate Keyspace Combinatorial Entropy:
    E = L * log2(|R|)
    Returns (entropy_bits, search_space_combinations).
    """
    if not password or variety.pool_size <= 0:
        return 0.0, 0.0

    length = len(password)
    entropy_bits = length * math.log2(variety.pool_size)
    try:
        combinations = float(variety.pool_size ** length)
    except OverflowError:
        combinations = float("inf")

    return round(entropy_bits, 2), combinations


def evaluate_entropy(password: str) -> EntropyResult:
    """Run full entropy evaluation on a credential."""
    if not password:
        empty_variety = CharsetVariety(
            has_lower=False,
            has_upper=False,
            has_digits=False,
            has_symbols=False,
            has_other=False,
            lower_count=0,
            upper_count=0,
            digit_count=0,
            symbol_count=0,
            other_count=0,
            pool_size=0,
        )
        return EntropyResult(
            length=0,
            unique_chars=0,
            shannon_bits_per_char=0.0,
            total_shannon_entropy=0.0,
            keyspace_pool_size=0,
            keyspace_entropy_bits=0.0,
            search_space_combinations=0.0,
            variety=empty_variety,
        )

    variety = analyze_charset_variety(password)
    bits_per_char, total_shannon = calculate_shannon_entropy(password)
    keyspace_bits, combinations = calculate_keyspace_entropy(password, variety)

    return EntropyResult(
        length=len(password),
        unique_chars=len(set(password)),
        shannon_bits_per_char=bits_per_char,
        total_shannon_entropy=total_shannon,
        keyspace_pool_size=variety.pool_size,
        keyspace_entropy_bits=keyspace_bits,
        search_space_combinations=combinations,
        variety=variety,
    )
