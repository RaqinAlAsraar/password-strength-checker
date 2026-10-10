"""
Unit Tests for Shannon and Keyspace Entropy Engines.
"""

import math
import unittest

from src.core.entropy import (
    analyze_charset_variety,
    calculate_keyspace_entropy,
    calculate_shannon_entropy,
    evaluate_entropy,
)


class TestEntropyEngine(unittest.TestCase):

    def test_empty_password_entropy(self):
        h, total = calculate_shannon_entropy("")
        self.assertEqual(h, 0.0)
        self.assertEqual(total, 0.0)

        res = evaluate_entropy("")
        self.assertEqual(res.length, 0)
        self.assertEqual(res.keyspace_entropy_bits, 0.0)
        self.assertEqual(res.total_shannon_entropy, 0.0)

    def test_single_character_entropy(self):
        # A single character repeated has Shannon entropy 0 bits
        h, total = calculate_shannon_entropy("aaaaaa")
        self.assertEqual(h, 0.0)
        self.assertEqual(total, 0.0)

    def test_uniform_distribution_shannon_entropy(self):
        # 4 distinct characters each appearing once: p = 1/4 = 0.25
        # H = - 4 * (0.25 * log2(0.25)) = - 4 * (0.25 * -2) = 2.0 bits/char
        h, total = calculate_shannon_entropy("abcd")
        self.assertAlmostEqual(h, 2.0, places=3)
        self.assertAlmostEqual(total, 8.0, places=2)

    def test_variety_detection_lowercase(self):
        v = analyze_charset_variety("hello")
        self.assertTrue(v.has_lower)
        self.assertFalse(v.has_upper)
        self.assertFalse(v.has_digits)
        self.assertFalse(v.has_symbols)
        self.assertEqual(v.pool_size, 26)

    def test_variety_detection_full_pool(self):
        v = analyze_charset_variety("Ab1! ")
        self.assertTrue(v.has_lower)
        self.assertTrue(v.has_upper)
        self.assertTrue(v.has_digits)
        self.assertTrue(v.has_symbols)
        self.assertEqual(v.variety_count, 4)
        self.assertEqual(v.pool_size, 26 + 26 + 10 + 33)  # 95

    def test_keyspace_entropy_calculation(self):
        # 8-char lowercase password: 8 * log2(26) = 8 * 4.7004 = 37.60 bits
        v = analyze_charset_variety("abcdefgh")
        bits, combos = calculate_keyspace_entropy("abcdefgh", v)
        expected = 8 * math.log2(26)
        self.assertAlmostEqual(bits, round(expected, 2), places=1)
        self.assertEqual(combos, 26**8)


if __name__ == "__main__":
    unittest.main()
