"""
Comprehensive Unit Tests for PasswordEvaluator & Acceptance Criteria.
"""

import unittest

from src.core.evaluator import PasswordEvaluator
from src.core.generator import generate_diceware_passphrase, generate_random_password


class TestPasswordEvaluator(unittest.TestCase):

    def setUp(self):
        self.evaluator = PasswordEvaluator()

    def test_weak_credentials(self):
        weak_samples = [
            "123456",
            "password",
            "qwerty",
            "p@ssword",
            "P@55w0rd",
            "admin",
            "111111",
            "abc123",
        ]
        for pwd in weak_samples:
            rep = self.evaluator.evaluate(pwd)
            self.assertIn(
                rep.tier,
                ("Very Weak", "Weak"),
                f"Password '{pwd}' was rated {rep.tier} (score: {rep.score}), expected Weak or Very Weak",
            )
            self.assertLessEqual(rep.score, 40)
            self.assertTrue(len(rep.suggestions) > 0)

    def test_acceptance_criteria_leetspeak_p_at_ssword(self):
        """Acceptance Criteria: Accurately flags predictable patterns and weak substitutions (e.g., 'p@ssword')."""
        rep = self.evaluator.evaluate("p@ssword")
        # Must detect dictionary match or leetspeak substitution
        has_dict_flag = len(rep.dictionary_findings) > 0
        self.assertTrue(has_dict_flag, "Failed to flag 'p@ssword' as dictionary or leetspeak match")
        self.assertLessEqual(rep.score, 20)
        self.assertEqual(rep.tier, "Very Weak")

        # Check P@55w0rd as well
        rep_leet = self.evaluator.evaluate("P@55w0rd")
        self.assertTrue(len(rep_leet.dictionary_findings) > 0)
        self.assertLessEqual(rep_leet.score, 20)

    def test_moderate_credentials(self):
        moderate_samples = [
            "Summer2023!",
            "Welcome#2024",
            "DragonMaster99",
        ]
        for pwd in moderate_samples:
            rep = self.evaluator.evaluate(pwd)
            self.assertIn(
                rep.tier,
                ("Weak", "Moderate"),
                f"Password '{pwd}' scored {rep.score} ({rep.tier})",
            )

    def test_robust_credentials(self):
        robust_samples = [
            "K9#mQ$8vL!xZ2@wP",
            "vR8!pQ3#mL9$kX2*",
            "7f#B9$xL2!zK4@mQ",
        ]
        for pwd in robust_samples:
            rep = self.evaluator.evaluate(pwd)
            self.assertIn(
                rep.tier,
                ("Strong", "Very Strong"),
                f"Password '{pwd}' scored {rep.score} ({rep.tier})",
            )
            self.assertGreaterEqual(rep.score, 80)
            self.assertGreaterEqual(rep.entropy.total_shannon_entropy, 45.0)

    def test_generated_passwords_are_robust(self):
        for _ in range(5):
            pwd = generate_random_password(length=18)
            rep = self.evaluator.evaluate(pwd)
            self.assertEqual(rep.tier, "Very Strong")
            self.assertGreaterEqual(rep.score, 85)

        for _ in range(5):
            passphrase = generate_diceware_passphrase(num_words=5)
            rep = self.evaluator.evaluate(passphrase)
            self.assertIn(rep.tier, ("Strong", "Very Strong"))
            self.assertGreaterEqual(rep.score, 70)

    def test_actionable_suggestions_provided(self):
        """Acceptance Criteria: Provides clear, constructive improvement recommendations."""
        rep = self.evaluator.evaluate("short")
        self.assertTrue(any("length" in s.lower() for s in rep.suggestions))
        self.assertTrue(any("uppercase" in s.lower() for s in rep.suggestions))
        self.assertTrue(any("numbers" in s.lower() for s in rep.suggestions))
        self.assertTrue(any("special" in s.lower() for s in rep.suggestions))


if __name__ == "__main__":
    unittest.main()
