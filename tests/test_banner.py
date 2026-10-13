"""Tests for the framed host banner."""
import os
import unittest
from unittest import mock

from ptt.host import format_banner
from ptt.output import use_color


def _banner(**overrides):
    args = {
        "port": 8022,
        "ips": ["192.168.1.42"],
        "name": "wohnzimmer",
        "secret": "482913",
        "kind": "pin",
        "fingerprint": "SHA256:AB:CD",
        "discover_enabled": True,
        "shell": "/bin/bash",
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
        args["shell"],
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

    def test_shell_row(self):
        out = _banner(shell="/bin/zsh")
        self.assertIn("Shell:", out)
        self.assertIn("/bin/zsh", out)
        lines = out.splitlines()
        for line in lines:
            self.assertEqual(len(line), len(lines[0]))

    def test_discover_disabled_hint(self):
        out = _banner(discover_enabled=False)
        self.assertIn("deaktiviert", out)

    def test_three_ips_all_shown(self):
        out = _banner(ips=["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        self.assertIn("10.0.0.3", out)
        self.assertNotIn("weitere Adressen", out)

    def test_many_ips_collapsed(self):
        out = _banner(
            ips=["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]
        )
        self.assertIn("ptt connect 10.0.0.1", out)
        self.assertNotIn("10.0.0.2", out)
        self.assertIn("+4 weitere Adressen", out)
        lines = out.splitlines()
        for line in lines:
            self.assertEqual(len(line), len(lines[0]))

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

    def test_auto_follows_tty(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch("sys.stdout") as out:
                out.isatty.return_value = True
                self.assertTrue(use_color("auto"))
                out.isatty.return_value = False
                self.assertFalse(use_color("auto"))

    def test_no_color_env_disables(self):
        with mock.patch.dict(os.environ, {"NO_COLOR": "1"}):
            with mock.patch("sys.stdout") as out:
                out.isatty.return_value = True
                self.assertFalse(use_color("auto"))


if __name__ == "__main__":
    unittest.main()
