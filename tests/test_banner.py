"""Tests for the framed host banner."""
import unittest

from ptt.host import format_banner, use_color


def _banner(**overrides):
    args = {
        "port": 8022,
        "ips": ["192.168.1.42"],
        "name": "wohnzimmer",
        "secret": "482913",
        "kind": "pin",
        "fingerprint": "SHA256:AB:CD",
        "discover_enabled": True,
    }
    args.update(overrides)
    return format_banner(
        args["port"],
        args["ips"],
        args["name"],
        args["secret"],
        args["kind"],
        args["fingerprint"],
        args["discover_enabled"],
        color=overrides.get("color", False),
        unicode_box=overrides.get("unicode_box", False),
    )


class BannerTest(unittest.TestCase):
    def test_plain_box_contains_info(self):
        out = _banner()
        self.assertIn("482-913", out)  # PIN shown formatted
        self.assertIn("wohnzimmer", out)
        self.assertIn("192.168.1.42", out)
        self.assertIn("ptt connect", out)
        self.assertNotIn("\x1b[", out)
        lines = out.splitlines()
        self.assertTrue(lines[0].startswith("+") and lines[0].endswith("+"))
        for line in lines:  # frame is symmetric
            self.assertEqual(len(line), len(lines[0]))

    def test_token_mode(self):
        out = _banner(secret="aa11-bb22", kind="token")
        self.assertIn("aa11-bb22", out)
        self.assertIn("Token:", out)
        self.assertNotIn("PIN:", out)

    def test_discover_disabled_hint(self):
        out = _banner(discover_enabled=False)
        self.assertIn("deaktiviert", out)

    def test_colored_unicode_box(self):
        out = _banner(color=True, unicode_box=True)
        self.assertIn("╭", out)
        self.assertIn("╯", out)
        self.assertIn("\x1b[36m", out)  # cyan frame
        self.assertIn("\x1b[92m", out)  # green secret
        self.assertIn("482-913", out)


class UseColorTest(unittest.TestCase):
    def test_explicit_modes(self):
        self.assertTrue(use_color("always"))
        self.assertFalse(use_color("never"))


if __name__ == "__main__":
    unittest.main()
