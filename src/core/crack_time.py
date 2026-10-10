"""
Brute-Force Crack Time Estimation Engine.

Estimates the time required to crack a password across multiple threat scenarios:
1. Online Attack (Rate-limited API/Login): ~100 guesses/sec
2. Fast Offline Hash (GPU cluster attacking SHA-256 / MD5 / NTLM): ~10^10 hashes/sec (10 billion/sec)
3. Slow Offline Hash (Memory-hard key derivation: Argon2 / Bcrypt / PBKDF2): ~10^4 hashes/sec (10,000/sec)

Calculations assume an attacker explores on average 50% of the keyspace:
Expected Guesses = (Combinations / 2)
Time (seconds) = Expected Guesses / (Guesses Per Second)
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class CrackTimeScenario:
    name: str
    rate_desc: str
    guesses_per_sec: float
    estimated_seconds: float
    human_readable: str


@dataclass(frozen=True)
class CrackTimeEstimates:
    online_attack: CrackTimeScenario
    offline_fast_hash: CrackTimeScenario
    offline_slow_hash: CrackTimeScenario


def format_duration(seconds: float) -> str:
    """Format duration in seconds into clear human-readable string."""
    if seconds <= 0:
        return "Instant (< 1 ms)"
    if seconds < 0.001:
        return "Instant (< 1 ms)"
    if seconds < 1.0:
        return f"{seconds * 1000:.0f} milliseconds"
    if seconds < 60:
        return f"{seconds:.1f} seconds"

    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f} minutes"

    hours = minutes / 60
    if hours < 24:
        return f"{hours:.1f} hours"

    days = hours / 24
    if days < 30:
        return f"{days:.1f} days"

    months = days / 30.44
    if months < 12:
        return f"{months:.1f} months"

    years = days / 365.25
    if years < 100:
        return f"{years:.1f} years"
    if years < 1_000:
        return f"{years:.0f} years"
    if years < 1_000_000:
        return f"{years / 1000:.1f} thousand years"
    if years < 1_000_000_000:
        return f"{years / 1_000_000:.1f} million years"
    if years < 1_000_000_000_000:
        return f"{years / 1_000_000_000:.1f} billion years"

    return "Trillions of years (Astronomical)"


def estimate_crack_times(keyspace_entropy_bits: float, effective_entropy_bits: float) -> CrackTimeEstimates:
    """
    Calculate crack times based on effective entropy (after pattern penalties).
    Uses 2^(effective_entropy - 1) as the average search steps.
    """
    # Clamp effective entropy between 0 and 256 bits
    eff_bits = max(0.0, min(effective_entropy_bits, 256.0))

    try:
        # Average guesses to find the password = 2^(eff_bits - 1)
        if eff_bits <= 1:
            guesses = 1.0
        else:
            guesses = 2 ** (eff_bits - 1)
    except OverflowError:
        guesses = float("inf")

    # Scenarios
    # 1. Online web/API brute-force (100 guesses/sec)
    online_rate = 100.0
    sec_online = guesses / online_rate if guesses != float("inf") else float("inf")

    # 2. Offline fast hash GPU cluster (10 billion guesses/sec)
    fast_rate = 10_000_000_000.0
    sec_fast = guesses / fast_rate if guesses != float("inf") else float("inf")

    # 3. Offline slow hash (Bcrypt / Argon2) (10,000 guesses/sec)
    slow_rate = 10_000.0
    sec_slow = guesses / slow_rate if guesses != float("inf") else float("inf")

    return CrackTimeEstimates(
        online_attack=CrackTimeScenario(
            name="Online Web Attack",
            rate_desc="100 guesses / sec (rate-limited / network)",
            guesses_per_sec=online_rate,
            estimated_seconds=sec_online,
            human_readable=format_duration(sec_online),
        ),
        offline_fast_hash=CrackTimeScenario(
            name="Offline Fast Hash (GPU)",
            rate_desc="10B hashes / sec (MD5, SHA-256, NTLM)",
            guesses_per_sec=fast_rate,
            estimated_seconds=sec_fast,
            human_readable=format_duration(sec_fast),
        ),
        offline_slow_hash=CrackTimeScenario(
            name="Offline Slow Hash (Bcrypt/Argon2)",
            rate_desc="10K hashes / sec (Key-Stretched)",
            guesses_per_sec=slow_rate,
            estimated_seconds=sec_slow,
            human_readable=format_duration(sec_slow),
        ),
    )
