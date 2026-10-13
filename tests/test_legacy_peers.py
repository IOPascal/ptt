"""Old/foreign peers: clean failures, no tracebacks, no hangs."""
import contextlib
import io
import os
import socket
import sys
import tempfile
import threading
import time
import unittest

from helpers import _free_tcp_port
from ptt.cert import ensure_cert, tls_server_context
from ptt.client import _run_get, _run_put, run_client, run_exec


class LegacyPeerTest(unittest.TestCase):
    def _stub(self, answer):
        """TLS stub answering ``answer`` to the hello (None = close).

        Returns the port; tolerates discovery probes before the client.
        """
        # Keep certs alive for the worker's lifetime.
        self._stub_tmp = tempfile.TemporaryDirectory()
        try:
            cert, key = ensure_cert(self._stub_tmp.name)
        except RuntimeError as exc:
            self._stub_tmp.cleanup()
            del self._stub_tmp
            self.skipTest(str(exc))
        port = _free_tcp_port()
        context = tls_server_context(cert, key)
        ready = threading.Event()

        def _serve():
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", port))
            srv.listen(5)
            ready.set()
            try:
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    srv.settimeout(1.0)
                    try:
                        conn, _ = srv.accept()
                    except socket.timeout:
                        continue
                    try:
                        sock = context.wrap_socket(conn, server_side=True)
                    except OSError:
                        conn.close()
                        continue  # probe or junk
                    try:
                        sock.settimeout(10)
                        data = b""
                        while not data.endswith(b"\n"):
                            chunk = sock.recv(4096)
                            if not chunk:
                                break
                            data += chunk
                        if answer is None:
                            return
                        sock.sendall(answer.encode("utf-8") + b"\n")
                        try:
                            sock.settimeout(15)
                            while sock.recv(1024):
                                pass  # hold until the client leaves
                        except OSError:
                            pass
                    finally:
                        try:
                            sock.close()
                        except OSError:
                            pass
                    return
            finally:
                srv.close()

        worker = threading.Thread(target=_serve, daemon=True)
        worker.start()
        # Deterministic readiness (no TCP probe: exactly one client
        # connection per stub, no probe-vs-client ordering race).
        if not ready.wait(timeout=10):
            raise AssertionError("stub did not start listening")
        self._stub_worker = worker
        return port

    def tearDown(self):
        worker = getattr(self, "_stub_worker", None)
        if worker is not None:
            worker.join(timeout=20)
            del self._stub_worker
        tmp = getattr(self, "_stub_tmp", None)
        if tmp is not None:
            tmp.cleanup()
            del self._stub_tmp

    def test_exec_busy_host_is_clean(self):
        port = self._stub("BUSY")
        buf = io.StringIO()
        start = time.monotonic()
        with contextlib.redirect_stdout(buf):
            rc = run_exec("127.0.0.1", port, "t", argv=["uptime"])
        elapsed = time.monotonic() - start
        self.assertEqual(rc, 1)
        self.assertIn("ausgelastet", buf.getvalue())
        self.assertLess(elapsed, 10)

    def test_connect_busy_host_is_clean(self):
        port = self._stub("BUSY")
        buf = io.StringIO()
        start = time.monotonic()
        with contextlib.redirect_stdout(buf):
            rc = run_client("127.0.0.1", port, "t")
        elapsed = time.monotonic() - start
        self.assertEqual(rc, 1)
        self.assertIn("ausgelastet", buf.getvalue())
        self.assertLess(elapsed, 10)

    def test_garbage_answer_is_clean_denied(self):
        port = self._stub("WAT?")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run_exec("127.0.0.1", port, "t", argv=["uptime"])
        self.assertEqual(rc, 1)
        self.assertIn("Zugriff verweigert", buf.getvalue())

    def test_silent_close_is_clean_failure(self):
        port = self._stub(None)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run_exec("127.0.0.1", port, "t", argv=["uptime"])
        self.assertEqual(rc, 1)
        self.assertIn("Auth fehlgeschlagen", buf.getvalue())

    def test_junk_before_client_is_tolerated(self):
        port = self._stub("DENIED")
        junk = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            junk.sendall(b"\x00\xff-garbage\r\n")
        finally:
            junk.close()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run_exec("127.0.0.1", port, "t", argv=["uptime"])
        self.assertEqual(rc, 1)
        self.assertIn("Zugriff verweigert", buf.getvalue())

    def test_exec_silent_host_times_out(self):
        port = self._stub("OK")
        raw = io.BytesIO()
        wrapper = io.TextIOWrapper(raw, encoding="utf-8")
        self._cap_wrapper = wrapper  # keep alive: GC would close raw
        old = sys.stdout
        sys.stdout = wrapper
        try:
            start = time.monotonic()
            rc = run_exec(
                "127.0.0.1", port, "t", argv=["uptime"], timeout=1
            )
            elapsed = time.monotonic() - start
        finally:
            wrapper.flush()
            sys.stdout = old
        self.assertEqual(rc, 124)
        self.assertIn("Zeitlimit", raw.getvalue().decode("utf-8"))
        self.assertLess(elapsed, 8)

    def test_put_without_alpn_is_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "src.bin")
            with open(src, "wb") as fh:
                fh.write(b"data")
            a, b = socket.socketpair()
            try:
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = _run_put(a, src, "up.bin", False)
            finally:
                b.close()
        self.assertEqual(rc, 1)
        self.assertIn("keinen Datei-Transfer", buf.getvalue())

    def test_get_without_alpn_is_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            local = os.path.join(tmp, "down.bin")
            a, b = socket.socketpair()
            try:
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = _run_get(a, "r.bin", local, False)
            finally:
                b.close()
        self.assertEqual(rc, 1)
        self.assertIn("keinen Datei-Transfer", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
