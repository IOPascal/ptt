"""Tests for the framed host banner."""
import unittest

from ptt.host import format_banner, use_color


class BannerTest(unittest.TestCase):
    def test_plain_box_contains_info(self):
        out = format_banner(
            8022,
            ["192.168.1.42"],
            "aa11-bb22-cc33-dd44",
            "SHA256:AB:CD",
            color=False,
            unicode_box=False,
        )
        self.assertIn("aa11-bb22-cc33-dd44", out)
        self.assertIn("192.168.1.42", out)
        self.assertIn("8022", out)
        self.assertNotIn("\x1b[", out)
        lines = out.splitlines()
        self.assertTrue(lines[0].startswith("+") and lines[0].endswith("+"))
        for line in lines:  # frame is symmetric
            self.assertEqual(len(line), len(lines[0]))

    def test_colored_unicode_box(self):
        out = format_banner(
            8022,
            ["192.168.1.42"],
            "aa11-bb22-cc33-dd44",
            "SHA256:AB:CD",
            color=True,
            unicode_box=True,
        )
        self.assertIn("╭", out)
        self.assertIn("╯", out)
        self.assertIn("\x1b[36m", out)  # cyan frame
        self.assertIn("\x1b[92m", out)  # green token
        self.assertIn("aa11-bb22-cc33-dd44", out)


class UseColorTest(unittest.TestCase):
    def test_explicit_modes(self):
        self.assertTrue(use_color("always"))
        self.assertFalse(use_color("never"))


if __name__ == "__main__":
    unittest.main()
