"""Tests for the TOFU known-hosts store and its client flow."""
import contextlib
import io
import json
import os
import stat
import tempfile
import threading
import unittest
from unittest import mock

from helpers import _free_tcp_port, wait_for_port
from ptt.cert import ensure_cert
from ptt.client import run_client
from ptt.host import default_shell, run_host
from ptt.known_hosts import get_fingerprint, store_fingerprint

TOKEN = "tofu-test-token-1234"


class StoreTest(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "known_hosts")
            self.assertIsNone(get_fingerprint("h", 8022, path))
            store_fingerprint("h", 8022, "SHA256:AA", path)
            self.assertEqual(get_fingerprint("h", 8022, path), "SHA256:AA")
            # other host/port unaffected
            self.assertIsNone(get_fingerprint("h", 8023, path))
            self.assertIsNone(get_fingerprint("other", 8022, path))

    def test_update_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "known_hosts")
            store_fingerprint("h", 8022, "SHA256:AA", path)
            store_fingerprint("h", 8022, "SHA256:BB", path)
            self.assertEqual(get_fingerprint("h", 8022, path), "SHA256:BB")

    def test_corrupt_file_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "known_hosts")
            with open(path, "w") as f:
                f.write("not json{{{")
            self.assertIsNone(get_fingerprint("h", 8022, path))
            # and storing over it recovers
            store_fingerprint("h", 8022, "SHA256:AA", path)
            self.assertEqual(get_fingerprint("h", 8022, path), "SHA256:AA")

    def test_non_dict_file_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "known_hosts")
            with open(path, "w") as f:
                json.dump(["a", "list"], f)
            self.assertIsNone(get_fingerprint("h", 8022, path))

    @unittest.skipIf(os.name == "nt", "POSIX permissions only")
    def test_restrictive_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "sub", "known_hosts")
            store_fingerprint("h", 8022, "SHA256:AA", path)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    @unittest.skipIf(os.name == "nt", "POSIX permissions only")
    def test_existing_dir_tightened(self):
        with tempfile.TemporaryDirectory() as tmp:
            sub = os.path.join(tmp, "sub")
            os.mkdir(sub, 0o755)
            store_fingerprint("h", 8022, "SHA256:AA", os.path.join(sub, "kh"))
            self.assertEqual(stat.S_IMODE(os.stat(sub).st_mode), 0o700)


class TofuFlowTest(unittest.TestCase):
    def _run_host_once(self, port: int, cert_dir: str) -> threading.Thread:
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
        return thread

    def _connect(self, port: int, fp_file: str) -> tuple[int, str]:
        with (
            mock.patch("ptt.known_hosts.known_hosts_path", return_value=fp_file),
            mock.patch("ptt.client._run_unix", return_value=0),
            mock.patch("ptt.client._run_windows", return_value=0),
        ):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_client("127.0.0.1", port, TOKEN)
            return rc, buf.getvalue()

    def test_store_match_and_mismatch(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as tmp:
            fp_file = os.path.join(tmp, "known_hosts")
            cert_a = os.path.join(tmp, "cert-a")
            cert_b = os.path.join(tmp, "cert-b")
            # Same port for all runs: the TOFU key is host+port.
            port = _free_tcp_port()

            # first contact: stored
            host_thread = self._run_host_once(port, cert_a)
            wait_for_port(port)
            rc, out = self._connect(port, fp_file)
            self.assertEqual(rc, 0)
            self.assertIn("gespeichert", out)
            host_thread.join(timeout=15)
            self.assertFalse(host_thread.is_alive())

            # same cert: matches
            host_thread = self._run_host_once(port, cert_a)
            wait_for_port(port)
            rc, out = self._connect(port, fp_file)
            self.assertEqual(rc, 0)
            self.assertIn("gespeicherten überein", out)
            host_thread.join(timeout=15)
            self.assertFalse(host_thread.is_alive())

            # changed cert: aborted
            host_thread = self._run_host_once(port, cert_b)
            wait_for_port(port)
            rc, out = self._connect(port, fp_file)
            self.assertEqual(rc, 1)
            self.assertIn("GEÄNDERT", out)
            host_thread.join(timeout=15)
            self.assertFalse(host_thread.is_alive())

    def test_store_failure_warns_and_continues(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as tmp:
            fp_file = os.path.join(tmp, "known_hosts")
            port = _free_tcp_port()
            host_thread = self._run_host_once(port, os.path.join(tmp, "certs"))
            wait_for_port(port)
            with mock.patch(
                "ptt.client.store_fingerprint",
                side_effect=OSError("read-only"),
            ):
                rc, out = self._connect(port, fp_file)
            self.assertEqual(rc, 0)
            self.assertIn("nicht gespeichert", out)
            host_thread.join(timeout=15)
            self.assertFalse(host_thread.is_alive())


if __name__ == "__main__":
    unittest.main()
