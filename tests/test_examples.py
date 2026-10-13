"""Tests for examples/ automation scripts (syntax + one end-to-end run)."""
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

from helpers import _free_tcp_port, wait_for_port
from ptt.cert import ensure_cert
from ptt.host import default_shell, run_host

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(ROOT, "examples")
BASH = shutil.which("bash")
TOKEN = "examples-test-token"


class ExamplesSyntaxTest(unittest.TestCase):
    def _scripts(self):
        return sorted(
            os.path.join(EXAMPLES, name)
            for name in os.listdir(EXAMPLES)
            if name.endswith(".sh")
        )

    @unittest.skipUnless(BASH, "bash fehlt")
    def test_all_scripts_parse(self):
        scripts = self._scripts()
        self.assertGreater(len(scripts), 0)
        for path in scripts:
            with self.subTest(script=os.path.basename(path)):
                proc = subprocess.run(
                    [BASH, "-n", path],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_scripts_are_executable_with_shebang(self):
        for path in self._scripts():
            with self.subTest(script=os.path.basename(path)):
                self.assertTrue(
                    os.access(path, os.X_OK), "nicht ausführbar"
                )
                with open(path, encoding="utf-8") as fh:
                    self.assertTrue(
                        fh.readline().startswith("#!/bin/bash"),
                        "kein Bash-Shebang",
                    )

    def test_readme_documents_automation(self):
        with open(
            os.path.join(ROOT, "README.md"), encoding="utf-8"
        ) as fh:
            readme = fh.read()
        for marker in (
            "## Automatisierung",
            "## Exit-Codes",
            "examples/",
            "--quiet",
            "--timeout",
            "PTT_HOST",
            "PTT_PORT",
            "PTT_TIMEOUT",
            "scan [--json]",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, readme)


class HealthCheckLoopbackTest(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX-only (shim + bash)")
    @unittest.skipUnless(BASH, "bash fehlt")
    def test_health_check_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert_dir = os.path.join(tmp, "certs")
            try:
                ensure_cert(cert_dir)
            except RuntimeError as exc:
                self.skipTest(str(exc))
            home = os.path.join(tmp, "home")
            os.makedirs(home)
            bindir = os.path.join(tmp, "bin")
            os.makedirs(bindir)
            shim = os.path.join(bindir, "ptt")
            with open(shim, "w", encoding="utf-8") as fh:
                fh.write(
                    "#!/bin/sh\nexec %s -m ptt \"$@\"\n" % sys.executable
                )
            os.chmod(shim, 0o755)
            port = _free_tcp_port()
            thread = threading.Thread(
                target=run_host,
                kwargs={
                    "bind": "127.0.0.1",
                    "port": port,
                    "shell": default_shell(),
                    "token": TOKEN,
                    "cert_dir": cert_dir,
                    "once": True,
                    "discover": False,
                },
                daemon=True,
            )
            thread.start()
            wait_for_port(port)
            env = dict(os.environ)
            env["PATH"] = bindir + os.pathsep + env.get("PATH", "")
            env["HOME"] = home
            env["PTT_HOST"] = "127.0.0.1"
            env["PTT_PORT"] = str(port)
            env["PTT_TOKEN"] = TOKEN
            proc = subprocess.run(
                [BASH, os.path.join(EXAMPLES, "health-check.sh"),
                 "echo", "ok"],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=ROOT,
                env=env,
            )
            thread.join(timeout=15)
            self.assertFalse(thread.is_alive())
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("ok", proc.stdout)


if __name__ == "__main__":
    unittest.main()
