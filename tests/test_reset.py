"""Tests for `ptt reset`."""
import contextlib
import io
import os
import tempfile
import unittest
from unittest import mock

from ptt.cert import CERT_FILE, KEY_FILE
from ptt.known_hosts import KNOWN_HOSTS_FILE
from ptt.reset import MANAGED_FILES, run_reset


def _seed(directory, names=(CERT_FILE, KEY_FILE, KNOWN_HOSTS_FILE)):
    for name in names:
        with open(os.path.join(directory, name), "w") as handle:
            handle.write("x")


class ResetTest(unittest.TestCase):
    def test_dry_run_deletes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed(tmp)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_reset(data_dir=tmp, dry_run=True)
            self.assertEqual(rc, 0)
            out = buf.getvalue()
            self.assertIn("Vorschau", out)
            self.assertIn("3 Dateien", out)
            for name in MANAGED_FILES:
                self.assertTrue(os.path.exists(os.path.join(tmp, name)))

    def test_yes_deletes_managed_files_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed(tmp)
            keep = os.path.join(tmp, "notizen.txt")
            with open(keep, "w") as handle:
                handle.write("bleibt")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_reset(data_dir=tmp, assume_yes=True)
            self.assertEqual(rc, 0)
            self.assertIn("Zurückgesetzt", buf.getvalue())
            self.assertIn("neu bestätigt", buf.getvalue())
            for name in MANAGED_FILES:
                self.assertFalse(os.path.exists(os.path.join(tmp, name)))
            self.assertTrue(os.path.exists(keep))

    def test_confirm_yes_deletes(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed(tmp, names=(CERT_FILE,))
            buf = io.StringIO()
            with mock.patch("builtins.input", return_value="j"), (
                contextlib.redirect_stdout(buf)
            ):
                rc = run_reset(data_dir=tmp)
            self.assertEqual(rc, 0)
            self.assertIn("1 Datei", buf.getvalue())
            self.assertFalse(
                os.path.exists(os.path.join(tmp, CERT_FILE))
            )

    def test_confirm_no_aborts(self):
        for answer in ("n", "", "nein"):
            with self.subTest(answer=answer):
                with tempfile.TemporaryDirectory() as tmp:
                    _seed(tmp)
                    buf = io.StringIO()
                    with mock.patch(
                        "builtins.input", return_value=answer
                    ), contextlib.redirect_stdout(buf):
                        rc = run_reset(data_dir=tmp)
                    self.assertEqual(rc, 1)
                    self.assertIn("Abgebrochen", buf.getvalue())
                    self.assertTrue(
                        os.path.exists(os.path.join(tmp, CERT_FILE))
                    )

    def test_confirm_eof_aborts(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed(tmp)
            buf = io.StringIO()
            with mock.patch(
                "builtins.input", side_effect=EOFError
            ), contextlib.redirect_stdout(buf):
                rc = run_reset(data_dir=tmp)
            self.assertEqual(rc, 1)
            self.assertTrue(
                os.path.exists(os.path.join(tmp, CERT_FILE))
            )

    def test_empty_dir_nothing_to_do(self):
        with tempfile.TemporaryDirectory() as tmp:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_reset(data_dir=tmp, assume_yes=True)
            self.assertEqual(rc, 0)
            self.assertIn("Nichts zu tun", buf.getvalue())

    @unittest.skipIf(os.name == "nt", "Symlinks brauchen Rechte")
    def test_symlinks_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "echt.pem")
            with open(target, "w") as handle:
                handle.write("x")
            os.symlink(
                target, os.path.join(tmp, CERT_FILE)
            )
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_reset(data_dir=tmp, assume_yes=True)
            self.assertEqual(rc, 0)
            self.assertIn("Symlink", buf.getvalue())
            self.assertTrue(os.path.islink(os.path.join(tmp, CERT_FILE)))
            self.assertTrue(os.path.exists(target))

    def test_delete_error_returns_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed(tmp, names=(CERT_FILE,))
            buf = io.StringIO()
            with mock.patch(
                "ptt.reset._remove",
                side_effect=OSError("verweigert"),
            ), contextlib.redirect_stdout(buf):
                rc = run_reset(data_dir=tmp, assume_yes=True)
            self.assertEqual(rc, 1)
            self.assertIn("verweigert", buf.getvalue())


class ResetCliTest(unittest.TestCase):
    def test_reset_parses(self):
        from ptt.cli import build_parser

        args = build_parser().parse_args(["reset"])
        self.assertEqual(args.command, "reset")
        self.assertFalse(args.yes)
        self.assertFalse(args.dry_run)
        args = build_parser().parse_args(["reset", "--yes"])
        self.assertTrue(args.yes)
        args = build_parser().parse_args(["reset", "--dry-run"])
        self.assertTrue(args.dry_run)

    def test_main_calls_reset(self):
        from ptt.cli import main

        with mock.patch("ptt.cli.run_reset", return_value=0) as m:
            self.assertEqual(main(["reset"]), 0)
        m.assert_called_once_with(assume_yes=False, dry_run=False)
        with mock.patch("ptt.cli.run_reset", return_value=0) as m:
            self.assertEqual(main(["reset", "--yes"]), 0)
        m.assert_called_once_with(assume_yes=True, dry_run=False)


if __name__ == "__main__":
    unittest.main()
