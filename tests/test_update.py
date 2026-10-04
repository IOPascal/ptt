"""Tests for `ptt update` (git pull flow + pip fallback selection)."""
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

            self.assertEqual(run_update(clone), 0)
            with open(os.path.join(clone, "version.txt")) as f:
                self.assertEqual(f.read(), "v2\n")

            # second run: already up to date, still exit 0
            self.assertEqual(run_update(clone), 0)

    def test_pip_fallback_command(self):
        with (
            mock.patch("ptt.update.shutil.which", return_value="/usr/bin/git"),
            mock.patch("ptt.update.git_root", return_value=None),
            mock.patch("ptt.update.subprocess.run") as m,
        ):
            m.return_value.returncode = 0
            self.assertEqual(run_update("/nonexistent"), 0)
        cmd = m.call_args[0][0]
        self.assertEqual(
            cmd, [sys.executable, "-m", "pip", "install", "--upgrade", f"git+{REPO_URL}"]
        )

    def test_no_git_fails_cleanly(self):
        with mock.patch("ptt.update.shutil.which", return_value=None):
            with tempfile.TemporaryDirectory() as tmp:
                self.assertEqual(run_update(tmp), 1)


if __name__ == "__main__":
    unittest.main()
