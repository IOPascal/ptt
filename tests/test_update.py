"""Tests for `ptt update` (git pull flow + pip fallback selection)."""
import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from ptt.update import REPO_URL, git_root, run_update


def _git(*args, cwd, check=True):
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=check,
    )


def _commit(repo, filename, content, message):
    with open(os.path.join(repo, filename), "w") as f:
        f.write(content)
    _git("add", filename, cwd=repo)
    _git(
        "-c",
        "user.name=PTT Test",
        "-c",
        "user.email=ptt-test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-m",
        message,
        cwd=repo,
    )


class GitRootTest(unittest.TestCase):
    def test_non_repo_returns_none(self):
        if shutil.which("git") is None:
            self.skipTest("git not available")
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(git_root(tmp))

    def test_no_git_returns_none(self):
        with mock.patch("ptt.update.shutil.which", return_value=None):
            with tempfile.TemporaryDirectory() as tmp:
                self.assertIsNone(git_root(tmp))


class UpdateTest(unittest.TestCase):
    def test_pull_new_commit(self):
        if shutil.which("git") is None:
            self.skipTest("git not available")
        with tempfile.TemporaryDirectory() as tmp:
            origin = os.path.join(tmp, "origin")
            clone = os.path.join(tmp, "clone")
            os.mkdir(origin)
            _git("init", "-b", "main", cwd=origin)
            _commit(origin, "version.txt", "v1\n", "v1")
            subprocess.run(
                ["git", "clone", origin, clone],
                capture_output=True,
                text=True,
                check=True,
            )
            _commit(origin, "version.txt", "v2\n", "v2")

            self.assertEqual(run_update(clone, assume_yes=True), 0)
            with open(os.path.join(clone, "version.txt")) as f:
                self.assertEqual(f.read(), "v2\n")

            # second run: already up to date, still exit 0
            self.assertEqual(run_update(clone, assume_yes=True), 0)

    def _origin_clone(self, tmp):
        origin = os.path.join(tmp, "origin")
        clone = os.path.join(tmp, "clone")
        os.mkdir(origin)
        _git("init", "-b", "main", cwd=origin)
        _commit(origin, "version.txt", "v1\n", "v1")
        subprocess.run(
            ["git", "clone", origin, clone],
            capture_output=True,
            text=True,
            check=True,
        )
        return origin, clone

    def test_preview_shown_and_confirmed(self):
        if shutil.which("git") is None:
            self.skipTest("git not available")
        with tempfile.TemporaryDirectory() as tmp:
            origin, clone = self._origin_clone(tmp)
            _commit(origin, "version.txt", "v2\n", "v2")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                with mock.patch("builtins.input", return_value="j"):
                    self.assertEqual(run_update(clone), 0)
            out = buf.getvalue()
            self.assertIn("Neue Commits", out)
            self.assertIn("v2", out)
            with open(os.path.join(clone, "version.txt")) as f:
                self.assertEqual(f.read(), "v2\n")

    def test_prompt_abort_changes_nothing(self):
        if shutil.which("git") is None:
            self.skipTest("git not available")
        with tempfile.TemporaryDirectory() as tmp:
            origin, clone = self._origin_clone(tmp)
            _commit(origin, "version.txt", "v2\n", "v2")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                with mock.patch("builtins.input", return_value="n"):
                    self.assertEqual(run_update(clone), 1)
            self.assertIn("Abgebrochen", buf.getvalue())
            with open(os.path.join(clone, "version.txt")) as f:
                self.assertEqual(f.read(), "v1\n")

    def test_yes_skips_prompt(self):
        if shutil.which("git") is None:
            self.skipTest("git not available")
        with tempfile.TemporaryDirectory() as tmp:
            origin, clone = self._origin_clone(tmp)
            _commit(origin, "version.txt", "v2\n", "v2")

            def explode(prompt=""):
                raise AssertionError("must not prompt with --yes")

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                with mock.patch("builtins.input", side_effect=explode):
                    self.assertEqual(run_update(clone, assume_yes=True), 0)
            with open(os.path.join(clone, "version.txt")) as f:
                self.assertEqual(f.read(), "v2\n")

    def test_pip_fallback_command(self):
        with (
            mock.patch("ptt.update.shutil.which", return_value="/usr/bin/git"),
            mock.patch("ptt.update.git_root", return_value=None),
            mock.patch("ptt.update.subprocess.run") as m,
        ):
            m.return_value.returncode = 0
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(run_update("/nonexistent", assume_yes=True), 0)
            self.assertIn("pip install", buf.getvalue())
        cmd = m.call_args[0][0]
        self.assertEqual(
            cmd, [sys.executable, "-m", "pip", "install", "--upgrade", f"git+{REPO_URL}"]
        )

    def test_pip_confirm_and_abort(self):
        with (
            mock.patch("ptt.update.shutil.which", return_value="/usr/bin/git"),
            mock.patch("ptt.update.git_root", return_value=None),
            mock.patch("ptt.update.subprocess.run") as m,
        ):
            m.return_value.returncode = 0
            with mock.patch("builtins.input", return_value=""):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    self.assertEqual(run_update("/nonexistent"), 0)
                self.assertIn("Befehl:", buf.getvalue())
            m.reset_mock()
            with mock.patch("builtins.input", return_value="n"):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    self.assertEqual(run_update("/nonexistent"), 1)
            m.assert_not_called()

    def test_no_git_fails_cleanly(self):
        with mock.patch("ptt.update.shutil.which", return_value=None):
            with tempfile.TemporaryDirectory() as tmp:
                self.assertEqual(run_update(tmp), 1)

    def test_dirty_workdir_aborts(self):
        if shutil.which("git") is None:
            self.skipTest("git not available")
        with tempfile.TemporaryDirectory() as tmp:
            origin = os.path.join(tmp, "origin")
            clone = os.path.join(tmp, "clone")
            os.mkdir(origin)
            _git("init", "-b", "main", cwd=origin)
            _commit(origin, "version.txt", "v1\n", "v1")
            subprocess.run(
                ["git", "clone", origin, clone],
                capture_output=True,
                text=True,
                check=True,
            )
            with open(os.path.join(clone, "version.txt"), "w") as f:
                f.write("locally modified\n")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(run_update(clone), 1)
            self.assertIn("lokale Änderungen", buf.getvalue())
            with open(os.path.join(clone, "version.txt")) as f:
                self.assertEqual(f.read(), "locally modified\n")

    def test_pull_timeout_fails_cleanly(self):
        def fake_run(cmd, **kwargs):
            proc = mock.Mock()
            if "pull" in cmd:
                raise subprocess.TimeoutExpired(cmd, 120)
            proc.returncode = 0
            proc.stdout = "abc123" if "rev-parse" in cmd else ""
            return proc

        with (
            mock.patch("ptt.update.shutil.which", return_value="/usr/bin/git"),
            mock.patch("ptt.update.subprocess.run", side_effect=fake_run),
        ):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(run_update("/fake-repo"), 1)
            self.assertIn("Timeout", buf.getvalue())

    def test_pip_timeout_fails_cleanly(self):
        with (
            mock.patch("ptt.update.shutil.which", return_value="/usr/bin/git"),
            mock.patch("ptt.update.git_root", return_value=None),
            mock.patch(
                "ptt.update.subprocess.run",
                side_effect=subprocess.TimeoutExpired("pip", 120),
            ),
        ):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(run_update("/nonexistent", assume_yes=True), 1)
            self.assertIn("Timeout", buf.getvalue())


class ConfirmTest(unittest.TestCase):
    def test_yes_variants(self):
        from ptt.update import _confirm

        for answer in ("", "j", "J", "ja", "y", "yes", "  Ja  "):
            with self.subTest(answer=answer):
                with mock.patch("builtins.input", return_value=answer):
                    self.assertTrue(_confirm("Los?"))

    def test_no_variants(self):
        from ptt.update import _confirm

        for answer in ("n", "nein", "no", "x"):
            with self.subTest(answer=answer):
                with mock.patch("builtins.input", return_value=answer):
                    self.assertFalse(_confirm("Los?"))

    def test_eof_and_interrupt_mean_no(self):
        from ptt.update import _confirm

        for exc in (EOFError(), KeyboardInterrupt()):
            with self.subTest(exc=exc):
                with mock.patch("builtins.input", side_effect=exc):
                    buf = io.StringIO()
                    with contextlib.redirect_stdout(buf):
                        self.assertFalse(_confirm("Los?"))


if __name__ == "__main__":
    unittest.main()
