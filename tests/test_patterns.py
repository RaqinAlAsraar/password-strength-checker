"""
Unit Tests for Pattern, Sequence, Keyboard Walk, Repetition, and Leetspeak Detectors.
"""

import unittest

from src.core.patterns import (
    audit_patterns,
    detect_keyboard_walks,
    detect_predictable_sequences,
    detect_repeated_characters,
    detect_repeated_chunks,
    normalize_leetspeak,
)


class TestPatternEngine(unittest.TestCase):

    def test_leetspeak_normalization(self):
        norm, subs = normalize_leetspeak("p@ssword")
        self.assertEqual(norm, "password")
        self.assertEqual(len(subs), 1)
        self.assertEqual(subs[0][0], "@")
        self.assertEqual(subs[0][1], "a")

        norm2, subs2 = normalize_leetspeak("P@55w0rd")
        self.assertEqual(norm2, "password")
        self.assertEqual(len(subs2), 4)

        norm3, _ = normalize_leetspeak("4dm1n")
        self.assertEqual(norm3, "admin")

    def test_numerical_sequences(self):
        findings = detect_predictable_sequences("abc123456xyz")
        seq_matches = [f.match_snippet for f in findings if f.category == "sequence"]
        self.assertTrue(any("123456" in m for m in seq_matches))

        rev_findings = detect_predictable_sequences("test987654")
        self.assertTrue(any("987654" in f.match_snippet for f in rev_findings))

    def test_alphabetical_sequences(self):
        findings = detect_predictable_sequences("myabcdefpassword")
        self.assertTrue(any("abcdef" in f.match_snippet for f in findings))

        rev_findings = detect_predictable_sequences("zyxwvut")
        self.assertTrue(any("zyxwvut" in f.match_snippet for f in rev_findings))

    def test_keyboard_walk_detection(self):
        findings = detect_keyboard_walks("qwerty123")
        self.assertTrue(any("qwerty" in f.match_snippet.lower() for f in findings))

        findings_home = detect_keyboard_walks("asdfghjkl")
        self.assertTrue(any("asdfgh" in f.match_snippet.lower() for f in findings_home))

        findings_diag = detect_keyboard_walks("1qaz2wsx")
        self.assertTrue(len(findings_diag) > 0)

    def test_repeated_characters(self):
        findings = detect_repeated_characters("passsword11111")
        repeats = [f for f in findings if f.category == "repetition"]
        self.assertTrue(any(f.match_snippet == "sss" for f in repeats))
        self.assertTrue(any("11111" in f.match_snippet for f in repeats))

    def test_repeated_chunks(self):
        findings = detect_repeated_chunks("abcabc1212")
        chunks = [f for f in findings if f.category == "repeated_chunk"]
        self.assertTrue(any("abc" in f.description for f in chunks))

    def test_audit_patterns_clean_string(self):
        # A pseudo-random mixed string should produce 0 pattern findings
        findings = audit_patterns("K9#mQ$8vL!xZ2@wP")
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
