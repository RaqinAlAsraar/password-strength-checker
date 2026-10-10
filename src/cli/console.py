"""
Command-Line Interface (CLI) for CodeNova Password Strength Checker.
Provides rich terminal output with color-coded auditing and entropy breakdowns.
"""

import argparse
import getpass
import sys

from src.core.evaluator import PasswordEvaluator
from src.core.generator import generate_diceware_passphrase, generate_random_password

# ANSI Terminal Colors
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"


def print_banner() -> None:
    print(f"\n{BOLD}{CYAN}========================================================================{RESET}")
    print(f"{BOLD}{CYAN}      CODENOVA • CREDENTIAL AUDITING & SHANNON ENTROPY SUITE           {RESET}")
    print(f"{DIM}   Task 1 • Defensive Security Engineering • Pure Volatile Memory      {RESET}")
    print(f"{BOLD}{CYAN}========================================================================{RESET}\n")


def print_report(rep) -> None:
    # Color mapping
    tier_colors = {
        "Very Weak": RED,
        "Weak": YELLOW,
        "Moderate": YELLOW,
        "Strong": GREEN,
        "Very Strong": CYAN,
        "Empty": DIM,
    }
    tier_color = tier_colors.get(rep.tier, WHITE)

    print(f"{BOLD}Auditing Summary:{RESET}")
    print(f"  Length:           {BOLD}{rep.password_length}{RESET} characters")
    print(f"  Score:            {BOLD}{tier_color}{rep.score} / 100{RESET}")
    print(f"  Strength Tier:    {BOLD}{tier_color}{rep.tier.upper()}{RESET}")
    print()

    print(f"{BOLD}Information Theory & Entropy Breakdown:{RESET}")
    print(f"  Shannon Entropy:      {BOLD}{rep.entropy.total_shannon_entropy:.2f} bits{RESET} ({rep.entropy.shannon_bits_per_char:.2f} bits/char)")
    print(f"  Keyspace Entropy:     {BOLD}{rep.entropy.keyspace_entropy_bits:.2f} bits{RESET} (Pool size: {rep.entropy.keyspace_pool_size})")
    print(f"  Effective Entropy:    {BOLD}{rep.effective_entropy_bits:.2f} bits{RESET} (After pattern penalties)")
    print(f"  Unique Characters:    {BOLD}{rep.entropy.unique_chars}{RESET} / {rep.password_length}")
    print()

    v = rep.entropy.variety
    print(f"{BOLD}Character Variety:{RESET}")
    print(f"  Lowercase (a-z):   {GREEN + '✓' if v.has_lower else RED + '✗'}{RESET} ({v.lower_count})")
    print(f"  Uppercase (A-Z):   {GREEN + '✓' if v.has_upper else RED + '✗'}{RESET} ({v.upper_count})")
    print(f"  Digits (0-9):      {GREEN + '✓' if v.has_digits else RED + '✗'}{RESET} ({v.digit_count})")
    print(f"  Symbols:           {GREEN + '✓' if v.has_symbols else RED + '✗'}{RESET} ({v.symbol_count})")
    print()

    print(f"{BOLD}Estimated Brute-Force Crack Times:{RESET}")
    print(f"  • Online Web Service (100 guesses/s):     {BOLD}{rep.crack_times.online_attack.human_readable}{RESET}")
    print(f"  • Fast Hash GPU Cluster (10B hashes/s):   {BOLD}{rep.crack_times.offline_fast_hash.human_readable}{RESET}")
    print(f"  • Slow Key-Stretched Hash (Argon2):       {BOLD}{rep.crack_times.offline_slow_hash.human_readable}{RESET}")
    print()

    if rep.dictionary_findings:
        print(f"{BOLD}{RED}🚨 Common Dictionary & Leetspeak Matches:{RESET}")
        for df in rep.dictionary_findings:
            print(f"  {RED}✖{RESET} {df.description}")
        print()

    if rep.pattern_findings:
        print(f"{BOLD}{YELLOW}⚠️  Detected Vulnerabilities & Predictable Patterns:{RESET}")
        for pf in rep.pattern_findings:
            print(f"  {YELLOW}⚠{RESET} {pf.description} [Matched snippet: '{pf.match_snippet}']")
        print()

    if rep.suggestions:
        print(f"{BOLD}{CYAN}💡 Actionable Strengthening Recommendations:{RESET}")
        for idx, sugg in enumerate(rep.suggestions, 1):
            print(f"  {idx}. {sugg}")
        print()
    else:
        print(f"{BOLD}{GREEN}✓ Excellent! Credential satisfies all entropy benchmarks.{RESET}\n")

    print(f"{DIM}🛡️ Privacy Guarantee: Input evaluated purely in RAM. Never written to disk or network.{RESET}\n")


def run_cli() -> None:
    parser = argparse.ArgumentParser(description="CodeNova Password Strength & Entropy Auditor (CLI)")
    parser.add_argument("--check", "-c", type=str, help="Password string to audit directly")
    parser.add_argument("--interactive", "-i", action="store_true", help="Prompt securely for password without echo")
    parser.add_argument("--generate", "-g", action="store_true", help="Generate a cryptographically secure credential")
    parser.add_argument("--length", "-l", type=int, default=18, help="Length of generated password (default: 18)")
    parser.add_argument("--passphrase", "-p", action="store_true", help="Generate Diceware multi-word passphrase")

    args = parser.parse_args()
    evaluator = PasswordEvaluator()

    if args.generate:
        print_banner()
        if args.passphrase:
            cred = generate_diceware_passphrase(num_words=max(3, args.length // 4))
            print(f"{BOLD}Generated Diceware Passphrase:{RESET}\n  {CYAN}{cred}{RESET}\n")
        else:
            cred = generate_random_password(length=args.length)
            print(f"{BOLD}Generated Cryptographic Password:{RESET}\n  {CYAN}{cred}{RESET}\n")

        rep = evaluator.evaluate(cred)
        print_report(rep)
        return

    if args.check:
        print_banner()
        rep = evaluator.evaluate(args.check)
        print_report(rep)
        return

    if args.interactive:
        print_banner()
        pwd = getpass.getpass("Enter password to audit (hidden): ")
        rep = evaluator.evaluate(pwd)
        print_report(rep)
        return

    # Default interactive loop
    print_banner()
    print("Interactive CLI Audit Mode. Type 'quit' or press Ctrl+C to exit.\n")
    try:
        while True:
            pwd = input(f"{BOLD}Enter credential to audit:{RESET} ")
            if pwd.strip().lower() in ("quit", "exit", "q"):
                print("Exiting auditor.")
                break
            if not pwd:
                continue
            rep = evaluator.evaluate(pwd)
            print_report(rep)
    except (KeyboardInterrupt, EOFError):
        print("\nExiting auditor.")


if __name__ == "__main__":
    run_cli()
