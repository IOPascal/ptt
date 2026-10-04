"""Tests for PIN helpers."""
import unittest

from ptt.auth import format_pin, generate_pin, normalize_pin


class PinTest(unittest.TestCase):
    def test_generate_is_six_digits(self):
        for _ in range(20):
            pin = generate_pin()
            self.assertEqual(len(pin), 6)
            self.assertTrue(pin.isdigit())

    def test_generate_varies(self):
        self.assertGreater(len({generate_pin() for _ in range(20)}), 1)

    def test_normalize(self):
        self.assertEqual(normalize_pin("482-913"), "482913")
        self.assertEqual(normalize_pin(" 482 913 "), "482913")
        self.assertEqual(normalize_pin("abc"), "")

    def test_format(self):
        self.assertEqual(format_pin("482913"), "482-913")
        self.assertEqual(format_pin("482-913"), "482-913")
        self.assertEqual(format_pin("1234"), "1234")  # non-6-digit kept as-is


if __name__ == "__main__":
    unittest.main()
