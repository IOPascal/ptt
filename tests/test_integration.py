"""End-to-end test: real host serving a shell over TLS on loopback."""
import contextlib
import hashlib
import io
import json
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from helpers import (
    _free_tcp_port,
    _free_udp_port,
    echo_and_exit,
    tls_connect,
    wait_for_port,
)
from ptt.cert import ensure_cert
from ptt.client import run_client
from ptt.discover import discover
from ptt.host import _handle_connection, default_shell, run_host
from ptt.protocol import (
    ALPN_TRANSFER,
    FRAME_EXIT,
    FRAME_TACK,
    FRAME_TDATA,
    FRAME_TDONE,
    FRAME_TERR,
    FRAME_TREQ,
    recv_frame,
    recv_line,
    send_frame,
    send_line,
)
from ptt.transfer import decode_tack, encode_treq

TOKEN = "aa11-bb22-cc33-dd44"
MARKER = "PTT_INTEGRATION_OK_4711"


class IntegrationTest(unittest.TestCase):
    def _run_host_once(self, port: int, cert_dir: str, **extra):
        kwargs = {
            "bind": "127.0.0.1",
            "port": port,
            "shell": default_shell(),
            "token": TOKEN,
            "cert_dir": cert_dir,
            "once": True,
            "discover": False,
        }
        kwargs.update(extra)
        thread = threading.Thread(target=run_host, kwargs=kwargs, daemon=True)
        thread.start()
        return thread

    def test_auth_shell_exit(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)  # raises RuntimeError if no openssl/cryptography
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            port = _free_tcp_port()
            host_thread = self._run_host_once(port, cert_dir)
            wait_for_port(port)

            sock = tls_connect(port)
            try:
                send_line(sock, TOKEN)
                self.assertEqual(recv_line(sock).strip(), "OK")
                seen, exit_code = echo_and_exit(sock, MARKER)
                self.assertIn(MARKER.encode(), seen)
                self.assertEqual(exit_code, 0)
            finally:
                sock.close()
            host_thread.join(timeout=15)
            self.assertFalse(host_thread.is_alive())

    def _assert_timeout_exit(self, port: int, host_thread) -> None:
        sock = tls_connect(port)
        try:
            send_line(sock, TOKEN)
            self.assertEqual(recv_line(sock).strip(), "OK")
            exit_code = None
            while exit_code is None:
                ftype, payload = recv_frame(sock)
                if ftype == FRAME_EXIT:
                    (exit_code,) = struct.unpack("!i", payload)
            self.assertEqual(exit_code, 124)
        finally:
            sock.close()
        host_thread.join(timeout=15)
        self.assertFalse(host_thread.is_alive())

    def test_idle_timeout_ends_session(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            port = _free_tcp_port()
            host_thread = self._run_host_once(
                port, cert_dir, idle_timeout=1 / 60
            )
            wait_for_port(port)
            self._assert_timeout_exit(port, host_thread)

    def test_idle_timeout_pipes(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            port = _free_tcp_port()
            with mock.patch("ptt.host.HAVE_PTY", False):
                host_thread = self._run_host_once(
                    port, cert_dir, idle_timeout=1 / 60
                )
                wait_for_port(port)
                self._assert_timeout_exit(port, host_thread)

    def test_max_session_ends_session(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            port = _free_tcp_port()
            host_thread = self._run_host_once(
                port, cert_dir, max_session=1 / 60
            )
            wait_for_port(port)
            self._assert_timeout_exit(port, host_thread)

    def test_session_stats_logged(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            port = _free_tcp_port()
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                host_thread = self._run_host_once(port, cert_dir)
                wait_for_port(port)
                sock = tls_connect(port)
                try:
                    send_line(sock, TOKEN)
                    self.assertEqual(recv_line(sock).strip(), "OK")
                    seen, exit_code = echo_and_exit(sock, MARKER)
                    self.assertIn(MARKER.encode(), seen)
                    self.assertEqual(exit_code, 0)
                finally:
                    sock.close()
                host_thread.join(timeout=15)
                self.assertFalse(host_thread.is_alive())
            log = buf.getvalue()
            match = re.search(
                r"Sitzung mit \S+ beendet \(Dauer \d+ s, (\d+) B up / "
                r"([\d.]+) (\w+) down\)\.",
                log,
            )
            self.assertIsNotNone(match, log)
            up = int(match.group(1))
            factor = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3}
            down = float(match.group(2)) * factor[match.group(3)]
            # echo command must have reached the shell, marker came back
            self.assertGreaterEqual(up, len(f"echo {MARKER}\n".encode()))
            self.assertGreaterEqual(down, len(MARKER.encode()))

    def _run_host_subprocess(self, port: int, cert_dir: str, *extra: str):
        return subprocess.Popen(
            [
                sys.executable, "-m", "ptt", "host",
                "--port", str(port),
                "--no-discover",
                "--cert-dir", cert_dir,
                "--token", TOKEN,
                "--shell", "/bin/bash",
                *extra,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

    def _kill_subprocess(self, proc) -> None:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)

    @unittest.skipIf(sys.platform == "win32", "POSIX signals only")
    def test_sigterm_shuts_down_cleanly(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            port = _free_tcp_port()
            proc = self._run_host_subprocess(port, cert_dir)
            sock = None
            try:
                wait_for_port(port)
                sock = tls_connect(port)
                send_line(sock, TOKEN)
                self.assertEqual(recv_line(sock).strip(), "OK")
                proc.send_signal(signal.SIGTERM)
                out, _ = proc.communicate(timeout=30)
                self.assertEqual(proc.returncode, 0)
                self.assertIn("Host beendet", out)
                # session got a clean EXIT frame before teardown
                sock.settimeout(10)
                code = None
                while code is None:
                    ftype, payload = recv_frame(sock)
                    if ftype == FRAME_EXIT:
                        (code,) = struct.unpack("!i", payload)
                self.assertEqual(code, 0)
            finally:
                if sock is not None:
                    sock.close()
                self._kill_subprocess(proc)

    @unittest.skipIf(sys.platform == "win32", "POSIX signals only")
    def test_double_sigint_aborts_immediately(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            port = _free_tcp_port()
            proc = self._run_host_subprocess(port, cert_dir)
            try:
                wait_for_port(port)
                sock = tls_connect(port)
                try:
                    send_line(sock, TOKEN)
                    self.assertEqual(recv_line(sock).strip(), "OK")
                    proc.send_signal(signal.SIGINT)
                    # cleanup takes seconds (bash ignores SIGTERM),
                    # so the second Ctrl+C lands mid-cleanup
                    time.sleep(0.5)
                    proc.send_signal(signal.SIGINT)
                    proc.communicate(timeout=30)
                    self.assertEqual(proc.returncode, 130)
                finally:
                    sock.close()
            finally:
                self._kill_subprocess(proc)

    def test_keepalive_enabled_on_accept(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            port = _free_tcp_port()
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                with mock.patch(
                    "ptt.host.enable_keepalive"
                ) as ka_mock:
                    host_thread = self._run_host_once(port, cert_dir)
                    wait_for_port(port)
                    sock = tls_connect(port)
                    try:
                        send_line(sock, TOKEN)
                        self.assertEqual(recv_line(sock).strip(), "OK")
                        seen, exit_code = echo_and_exit(sock, MARKER)
                        self.assertIn(MARKER.encode(), seen)
                        self.assertEqual(exit_code, 0)
                    finally:
                        sock.close()
                    host_thread.join(timeout=15)
                    self.assertFalse(host_thread.is_alive())
            ka_mock.assert_called()

    def test_discovery_reports_busy_during_session(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            port = _free_tcp_port()
            dport = _free_udp_port()
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                host_thread = self._run_host_once(
                    port, cert_dir, discover=True, discovery_port=dport
                )
                wait_for_port(port)
                idle = discover(timeout=3.0, target="127.0.0.1", port=dport)
                self.assertEqual(len(idle), 1)
                self.assertFalse(idle[0]["busy"])
                sock = tls_connect(port)
                try:
                    send_line(sock, TOKEN)
                    self.assertEqual(recv_line(sock).strip(), "OK")
                    busy = discover(
                        timeout=3.0, target="127.0.0.1", port=dport
                    )
                    self.assertEqual(len(busy), 1)
                    self.assertTrue(busy[0]["busy"])
                    seen, exit_code = echo_and_exit(sock, MARKER)
                    self.assertIn(MARKER.encode(), seen)
                    self.assertEqual(exit_code, 0)
                finally:
                    sock.close()
                host_thread.join(timeout=15)
                self.assertFalse(host_thread.is_alive())

    def test_aborted_connection_ends_session(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            port = _free_tcp_port()
            host_thread = self._run_host_once(port, cert_dir)
            wait_for_port(port)
            sock = tls_connect(port)
            send_line(sock, TOKEN)
            self.assertEqual(recv_line(sock).strip(), "OK")
            # abort with RST instead of a clean close
            sock.setsockopt(
                socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
            )
            sock.close()
            host_thread.join(timeout=15)
            self.assertFalse(host_thread.is_alive())

    def test_max_sessions_rejects_second_client(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            port = _free_tcp_port()
            proc = subprocess.Popen(
                [
                    sys.executable, "-m", "ptt", "host",
                    "--port", str(port),
                    "--no-discover",
                    "--cert-dir", cert_dir,
                    "--token", TOKEN,
                    "--shell", default_shell(),
                    "--max-sessions", "1",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            sock3 = None
            try:
                wait_for_port(port)
                sock1 = tls_connect(port)
                try:
                    send_line(sock1, TOKEN)
                    self.assertEqual(recv_line(sock1).strip(), "OK")
                    sock2 = tls_connect(port)
                    try:
                        send_line(sock2, TOKEN)
                        self.assertEqual(recv_line(sock2).strip(), "BUSY")
                    finally:
                        sock2.close()
                finally:
                    sock1.close()
                # slot frees up after session 1 ends: retry until accepted
                deadline = time.time() + 25
                accepted = False
                while time.time() < deadline:
                    try:
                        sock3 = tls_connect(port)
                        send_line(sock3, TOKEN)
                        if recv_line(sock3).strip() == "OK":
                            accepted = True
                            break
                    except OSError:
                        pass
                    if sock3 is not None:
                        sock3.close()
                        sock3 = None
                    time.sleep(0.5)
                self.assertTrue(accepted, "slot did not free up")
            finally:
                if sock3 is not None:
                    sock3.close()
                if sys.platform == "win32":
                    proc.terminate()
                    proc.wait(timeout=15)
                else:
                    proc.send_signal(signal.SIGTERM)
                    out, _ = proc.communicate(timeout=30)
                    self.assertEqual(proc.returncode, 0)
                    self.assertIn("abgewiesen", out)
                    self.assertIn("Host beendet", out)

    def test_session_counter_counts_two_sessions(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            port = _free_tcp_port()
            proc = subprocess.Popen(
                [
                    sys.executable, "-m", "ptt", "host",
                    "--port", str(port),
                    "--no-discover",
                    "--cert-dir", cert_dir,
                    "--token", TOKEN,
                    "--shell", default_shell(),
                    "--max-sessions", "5",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            try:
                wait_for_port(port)
                for _ in range(2):
                    sock = tls_connect(port)
                    try:
                        send_line(sock, TOKEN)
                        self.assertEqual(recv_line(sock).strip(), "OK")
                        seen, exit_code = echo_and_exit(sock, MARKER)
                        self.assertIn(MARKER.encode(), seen)
                        self.assertEqual(exit_code, 0)
                    finally:
                        sock.close()
            finally:
                if sys.platform == "win32":
                    proc.terminate()
                    out, _ = proc.communicate(timeout=15)
                else:
                    proc.send_signal(signal.SIGTERM)
                    out, _ = proc.communicate(timeout=30)
                    self.assertEqual(proc.returncode, 0)
            self.assertIn("Max. 5 parallele Sitzungen.", out)
            # totals are sequential no matter how session teardowns overlap
            self.assertIn(", 1 gesamt", out)
            self.assertIn(", 2 gesamt", out)

    def test_put_upload_roundtrip(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            with tempfile.TemporaryDirectory() as root:
                port = _free_tcp_port()
                buf = io.StringIO()
                data = os.urandom(200000)
                with contextlib.redirect_stdout(buf):
                    host_thread = self._run_host_once(
                        port, cert_dir, transfer_dir=root
                    )
                    wait_for_port(port)
                    sock = tls_connect(port, [ALPN_TRANSFER])
                    try:
                        send_line(sock, TOKEN)
                        self.assertEqual(recv_line(sock).strip(), "OK")
                        digest = hashlib.sha256(data).hexdigest()
                        send_frame(
                            sock, FRAME_TREQ,
                            encode_treq(
                                "put", "sub/dir/f.bin", len(data), digest
                            ),
                        )
                        ftype, payload = recv_frame(sock)
                        self.assertEqual(ftype, FRAME_TACK)
                        tack = decode_tack(payload)
                        self.assertTrue(tack["ok"])
                        for off in range(0, len(data), 7000):
                            send_frame(
                                sock, FRAME_TDATA, data[off:off + 7000]
                            )
                        send_frame(
                            sock, FRAME_TDONE,
                            json.dumps({"sha256": digest}).encode("utf-8"),
                        )
                        ftype, payload = recv_frame(sock)
                        self.assertEqual(ftype, FRAME_TDONE)
                        result = json.loads(payload.decode("utf-8"))
                        self.assertTrue(result["ok"])
                    finally:
                        sock.close()
                    host_thread.join(timeout=15)
                    self.assertFalse(host_thread.is_alive())
                target = os.path.join(root, "sub", "dir", "f.bin")
                with open(target, "rb") as fh:
                    self.assertEqual(fh.read(), data)
                leftovers = []
                for _dir, _subs, files in os.walk(root):
                    leftovers += [f for f in files if f.endswith(".ptt-part")]
                self.assertEqual(leftovers, [])
                self.assertIn("Transfer put", buf.getvalue())

    def test_get_download_roundtrip(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            with tempfile.TemporaryDirectory() as root:
                data = os.urandom(150000)
                src = os.path.join(root, "sub", "host.bin")
                os.makedirs(os.path.dirname(src))
                with open(src, "wb") as fh:
                    fh.write(data)
                port = _free_tcp_port()
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    host_thread = self._run_host_once(
                        port, cert_dir, transfer_dir=root
                    )
                    wait_for_port(port)
                    sock = tls_connect(port, [ALPN_TRANSFER])
                    try:
                        send_line(sock, TOKEN)
                        self.assertEqual(recv_line(sock).strip(), "OK")
                        send_frame(
                            sock, FRAME_TREQ,
                            encode_treq("get", "sub/host.bin"),
                        )
                        ftype, payload = recv_frame(sock)
                        self.assertEqual(ftype, FRAME_TACK)
                        tack = decode_tack(payload)
                        self.assertTrue(tack["ok"])
                        self.assertEqual(tack["size"], len(data))
                        chunks = []
                        while True:
                            ftype, payload = recv_frame(sock)
                            if ftype == FRAME_TDATA:
                                chunks.append(payload)
                            elif ftype == FRAME_TDONE:
                                commit = json.loads(payload.decode("utf-8"))
                                break
                        self.assertEqual(b"".join(chunks), data)
                        self.assertEqual(
                            commit["sha256"],
                            hashlib.sha256(data).hexdigest(),
                        )
                        send_frame(
                            sock, FRAME_TDONE,
                            json.dumps({"ok": True}).encode("utf-8"),
                        )
                    finally:
                        sock.close()
                    host_thread.join(timeout=15)
                    self.assertFalse(host_thread.is_alive())
                self.assertIn("Transfer get", buf.getvalue())

    def test_get_missing_file(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            with tempfile.TemporaryDirectory() as root:
                port = _free_tcp_port()
                host_thread = self._run_host_once(
                    port, cert_dir, transfer_dir=root
                )
                wait_for_port(port)
                sock = tls_connect(port, [ALPN_TRANSFER])
                try:
                    send_line(sock, TOKEN)
                    self.assertEqual(recv_line(sock).strip(), "OK")
                    send_frame(
                        sock, FRAME_TREQ, encode_treq("get", "nope.bin")
                    )
                    ftype, payload = recv_frame(sock)
                    self.assertEqual(ftype, FRAME_TERR)
                    self.assertIn("gefunden", payload.decode("utf-8"))
                finally:
                    sock.close()
                host_thread.join(timeout=15)
                self.assertFalse(host_thread.is_alive())

    def _transfer_host(self, port, cert_dir, root, **extra):
        kwargs = {"transfer_dir": root}
        kwargs.update(extra)
        return self._run_host_once(port, cert_dir, **kwargs)

    def test_put_rejected_when_too_big(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            with tempfile.TemporaryDirectory() as root:
                port = _free_tcp_port()
                host_thread = self._transfer_host(
                    port, cert_dir, root, max_transfer_size=100
                )
                wait_for_port(port)
                sock = tls_connect(port, [ALPN_TRANSFER])
                try:
                    send_line(sock, TOKEN)
                    self.assertEqual(recv_line(sock).strip(), "OK")
                    send_frame(
                        sock, FRAME_TREQ, encode_treq("put", "big.bin", 200)
                    )
                    ftype, payload = recv_frame(sock)
                    self.assertEqual(ftype, FRAME_TACK)
                    tack = decode_tack(payload)
                    self.assertFalse(tack["ok"])
                    self.assertIn("zu groß", tack["reason"])
                finally:
                    sock.close()
                host_thread.join(timeout=15)
                self.assertFalse(host_thread.is_alive())
                self.assertEqual(os.listdir(root), [])

    def test_put_stream_overflow_aborts(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            with tempfile.TemporaryDirectory() as root:
                port = _free_tcp_port()
                host_thread = self._transfer_host(
                    port, cert_dir, root, max_transfer_size=100
                )
                wait_for_port(port)
                sock = tls_connect(port, [ALPN_TRANSFER])
                try:
                    send_line(sock, TOKEN)
                    self.assertEqual(recv_line(sock).strip(), "OK")
                    send_frame(
                        sock, FRAME_TREQ, encode_treq("put", "f.bin")
                    )
                    ftype, payload = recv_frame(sock)
                    self.assertEqual(ftype, FRAME_TACK)
                    self.assertTrue(decode_tack(payload)["ok"])
                    send_frame(sock, FRAME_TDATA, b"x" * 150)
                    ftype, payload = recv_frame(sock)
                    self.assertEqual(ftype, FRAME_TDONE)
                    result = json.loads(payload.decode("utf-8"))
                    self.assertFalse(result["ok"])
                    self.assertIn("zu groß", result["reason"])
                finally:
                    sock.close()
                host_thread.join(timeout=15)
                self.assertFalse(host_thread.is_alive())
                self.assertEqual(os.listdir(root), [])

    def test_get_rejected_when_too_big(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            with tempfile.TemporaryDirectory() as root:
                with open(os.path.join(root, "big.bin"), "wb") as fh:
                    fh.write(os.urandom(200))
                port = _free_tcp_port()
                host_thread = self._transfer_host(
                    port, cert_dir, root, max_transfer_size=100
                )
                wait_for_port(port)
                sock = tls_connect(port, [ALPN_TRANSFER])
                try:
                    send_line(sock, TOKEN)
                    self.assertEqual(recv_line(sock).strip(), "OK")
                    send_frame(
                        sock, FRAME_TREQ, encode_treq("get", "big.bin")
                    )
                    ftype, payload = recv_frame(sock)
                    self.assertEqual(ftype, FRAME_TERR)
                    self.assertIn("zu groß", payload.decode("utf-8"))
                finally:
                    sock.close()
                host_thread.join(timeout=15)
                self.assertFalse(host_thread.is_alive())

    def test_transfer_idle_timeout(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            with tempfile.TemporaryDirectory() as root:
                port = _free_tcp_port()
                host_thread = self._transfer_host(
                    port, cert_dir, root, idle_timeout=1 / 60
                )
                wait_for_port(port)
                sock = tls_connect(port, [ALPN_TRANSFER])
                try:
                    send_line(sock, TOKEN)
                    self.assertEqual(recv_line(sock).strip(), "OK")
                    sock.settimeout(10)
                    ftype, payload = recv_frame(sock)
                    self.assertEqual(ftype, FRAME_TERR)
                    self.assertIn("Inaktivität", payload.decode("utf-8"))
                finally:
                    sock.close()
                host_thread.join(timeout=15)
                self.assertFalse(host_thread.is_alive())

    def test_transfer_max_session(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            with tempfile.TemporaryDirectory() as root:
                port = _free_tcp_port()
                host_thread = self._transfer_host(
                    port, cert_dir, root, max_session=1 / 60
                )
                wait_for_port(port)
                sock = tls_connect(port, [ALPN_TRANSFER])
                try:
                    send_line(sock, TOKEN)
                    self.assertEqual(recv_line(sock).strip(), "OK")
                    time.sleep(2.5)
                    sock.settimeout(10)
                    ftype, payload = recv_frame(sock)
                    self.assertEqual(ftype, FRAME_TERR)
                    self.assertIn("Sitzungsdauer", payload.decode("utf-8"))
                finally:
                    sock.close()
                host_thread.join(timeout=15)
                self.assertFalse(host_thread.is_alive())

    def test_put_idle_mid_stream_keeps_part(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            with tempfile.TemporaryDirectory() as root:
                port = _free_tcp_port()
                host_thread = self._transfer_host(
                    port, cert_dir, root, idle_timeout=1 / 60
                )
                wait_for_port(port)
                sock = tls_connect(port, [ALPN_TRANSFER])
                try:
                    send_line(sock, TOKEN)
                    self.assertEqual(recv_line(sock).strip(), "OK")
                    send_frame(
                        sock, FRAME_TREQ, encode_treq("put", "slow.bin")
                    )
                    ftype, payload = recv_frame(sock)
                    self.assertEqual(ftype, FRAME_TACK)
                    send_frame(sock, FRAME_TDATA, b"abc")
                    time.sleep(2.5)
                    sock.settimeout(10)
                    ftype, payload = recv_frame(sock)
                    self.assertEqual(ftype, FRAME_TDONE)
                    result = json.loads(payload.decode("utf-8"))
                    self.assertFalse(result["ok"])
                    self.assertIn("Inaktivität", result["reason"])
                finally:
                    sock.close()
                host_thread.join(timeout=15)
                self.assertFalse(host_thread.is_alive())
                # The prefix survives so a retry can resume it.
                part = os.path.join(root, "slow.bin.ptt-part")
                with open(part, "rb") as fh:
                    self.assertEqual(fh.read(), b"abc")
                self.assertFalse(os.path.exists(os.path.join(root, "slow.bin")))

    def test_put_abort_rst_resumes_on_retry(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        full = b"y" * 100000
        with tempfile.TemporaryDirectory() as cert_dir:
            with tempfile.TemporaryDirectory() as root:
                port = _free_tcp_port()
                part = os.path.join(root, "half.bin.ptt-part")
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    host_thread = self._transfer_host(port, cert_dir, root)
                    wait_for_port(port)
                    sock = tls_connect(port, [ALPN_TRANSFER])
                    send_line(sock, TOKEN)
                    self.assertEqual(recv_line(sock).strip(), "OK")
                    send_frame(
                        sock, FRAME_TREQ,
                        encode_treq("put", "half.bin", 100000),
                    )
                    ftype, payload = recv_frame(sock)
                    self.assertEqual(ftype, FRAME_TACK)
                    send_frame(sock, FRAME_TDATA, b"y" * 50000)
                    # Wait until the server persisted the chunk, so the
                    # RST cannot discard it on the wire.
                    deadline = time.monotonic() + 10
                    while (
                        not os.path.exists(part)
                        or os.path.getsize(part) < 50000
                    ) and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertEqual(os.path.getsize(part), 50000)
                    sock.setsockopt(
                        socket.SOL_SOCKET, socket.SO_LINGER,
                        struct.pack("ii", 1, 0),
                    )
                    sock.close()
                    host_thread.join(timeout=15)
                    self.assertFalse(host_thread.is_alive())
                self.assertIn("fehlgeschlagen", buf.getvalue())
                with open(part, "rb") as fh:
                    self.assertEqual(fh.read(), b"y" * 50000)
                # Retry on a fresh connection resumes at the kept prefix.
                port2 = _free_tcp_port()
                host_thread = self._transfer_host(port2, cert_dir, root)
                wait_for_port(port2)
                sock = tls_connect(port2, [ALPN_TRANSFER])
                try:
                    send_line(sock, TOKEN)
                    self.assertEqual(recv_line(sock).strip(), "OK")
                    send_frame(
                        sock, FRAME_TREQ,
                        encode_treq("put", "half.bin", 100000, resume=True),
                    )
                    ftype, payload = recv_frame(sock)
                    self.assertEqual(ftype, FRAME_TACK)
                    tack = decode_tack(payload)
                    self.assertTrue(tack["ok"])
                    self.assertEqual(tack["offset"], 50000)
                    send_frame(sock, FRAME_TDATA, full[50000:])
                    sha = hashlib.sha256(full).hexdigest()
                    send_frame(
                        sock, FRAME_TDONE,
                        json.dumps({"sha256": sha}).encode(),
                    )
                    sock.settimeout(15)
                    ftype, payload = recv_frame(sock)
                    self.assertEqual(ftype, FRAME_TDONE)
                    result = json.loads(payload.decode("utf-8"))
                    self.assertTrue(result["ok"])
                finally:
                    sock.close()
                host_thread.join(timeout=15)
                self.assertFalse(host_thread.is_alive())
                with open(os.path.join(root, "half.bin"), "rb") as fh:
                    self.assertEqual(fh.read(), full)
                self.assertFalse(os.path.exists(part))

    def test_multi_transfer_batch(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        data_a = os.urandom(30000)
        data_b = os.urandom(40000)
        data_down = os.urandom(25000)
        with tempfile.TemporaryDirectory() as cert_dir:
            with tempfile.TemporaryDirectory() as root:
                with tempfile.TemporaryDirectory() as work:
                    file_a = os.path.join(work, "a.bin")
                    file_b = os.path.join(work, "b.bin")
                    with open(file_a, "wb") as fh:
                        fh.write(data_a)
                    with open(file_b, "wb") as fh:
                        fh.write(data_b)
                    with open(os.path.join(root, "down.bin"), "wb") as fh:
                        fh.write(data_down)
                    port = _free_tcp_port()
                    proc = self._run_host_subprocess(
                        port, cert_dir, "--transfer-dir", root
                    )
                    try:
                        wait_for_port(port)
                        buf = io.StringIO()
                        with contextlib.redirect_stdout(buf):
                            rc = run_client(
                                "127.0.0.1", port, TOKEN,
                                put=[file_a, file_b],
                                get=["down.bin:" + os.path.join(work, "got.bin")],
                            )
                        self.assertEqual(rc, 0)
                        self.assertIn("3/3 Transfers ok", buf.getvalue())
                    finally:
                        proc.send_signal(signal.SIGTERM)
                        try:
                            proc.communicate(timeout=30)
                        except Exception:
                            self._kill_subprocess(proc)
                    with open(os.path.join(root, "a.bin"), "rb") as fh:
                        self.assertEqual(fh.read(), data_a)
                    with open(os.path.join(root, "b.bin"), "rb") as fh:
                        self.assertEqual(fh.read(), data_b)
                    with open(os.path.join(work, "got.bin"), "rb") as fh:
                        self.assertEqual(fh.read(), data_down)

    def test_multi_transfer_batch_partial_failure(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        data_a = os.urandom(20000)
        with tempfile.TemporaryDirectory() as cert_dir:
            with tempfile.TemporaryDirectory() as root:
                with tempfile.TemporaryDirectory() as work:
                    file_a = os.path.join(work, "a.bin")
                    with open(file_a, "wb") as fh:
                        fh.write(data_a)
                    port = _free_tcp_port()
                    proc = self._run_host_subprocess(
                        port, cert_dir, "--transfer-dir", root
                    )
                    try:
                        wait_for_port(port)
                        buf = io.StringIO()
                        with contextlib.redirect_stdout(buf):
                            rc = run_client(
                                "127.0.0.1", port, TOKEN,
                                put=[file_a],
                                get=["missing.bin:" + os.path.join(work, "x.bin")],
                            )
                        self.assertEqual(rc, 1)
                        self.assertIn(
                            "1/2 Transfers ok, 1 fehlgeschlagen",
                            buf.getvalue(),
                        )
                    finally:
                        proc.send_signal(signal.SIGTERM)
                        try:
                            proc.communicate(timeout=30)
                        except Exception:
                            self._kill_subprocess(proc)
                    with open(os.path.join(root, "a.bin"), "rb") as fh:
                        self.assertEqual(fh.read(), data_a)
                    self.assertFalse(
                        os.path.exists(os.path.join(work, "x.bin"))
                    )

    @unittest.skipIf(sys.platform == "win32", "POSIX signals only")
    def test_host_startup_cleans_stale_parts(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            with tempfile.TemporaryDirectory() as root:
                stale = os.path.join(root, "old.bin.ptt-part")
                fresh = os.path.join(root, "new.bin.ptt-part")
                with open(stale, "wb") as fh:
                    fh.write(b"old")
                with open(fresh, "wb") as fh:
                    fh.write(b"new")
                old = time.time() - 25 * 3600
                os.utime(stale, (old, old))
                port = _free_tcp_port()
                proc = self._run_host_subprocess(
                    port, cert_dir, "--transfer-dir", root
                )
                sock = None
                try:
                    wait_for_port(port)
                    # A completed auth proves the accept loop (and the
                    # SIGTERM handlers) are up; SIGTERM before that
                    # would kill the process with -15.
                    sock = tls_connect(port, [ALPN_TRANSFER])
                    send_line(sock, TOKEN)
                    self.assertEqual(recv_line(sock).strip(), "OK")
                    proc.send_signal(signal.SIGTERM)
                    out, _ = proc.communicate(timeout=30)
                    self.assertEqual(proc.returncode, 0)
                    self.assertIn("aufgeräumt", out)
                finally:
                    if sock is not None:
                        sock.close()
                    self._kill_subprocess(proc)
                self.assertFalse(os.path.exists(stale))
                self.assertTrue(os.path.exists(fresh))

    @unittest.skipIf(sys.platform == "win32", "POSIX signals only")
    def test_sigterm_mid_transfer_resumes_on_retry(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        full = b"z" * 1000 + b"q" * (10**7 - 1000)
        with tempfile.TemporaryDirectory() as cert_dir:
            with tempfile.TemporaryDirectory() as root:
                port = _free_tcp_port()
                part = os.path.join(root, "big.bin.ptt-part")
                proc = self._run_host_subprocess(
                    port, cert_dir, "--transfer-dir", root
                )
                sock = None
                try:
                    wait_for_port(port)
                    sock = tls_connect(port, [ALPN_TRANSFER])
                    send_line(sock, TOKEN)
                    self.assertEqual(recv_line(sock).strip(), "OK")
                    send_frame(
                        sock, FRAME_TREQ,
                        encode_treq("put", "big.bin", 10**7),
                    )
                    ftype, payload = recv_frame(sock)
                    self.assertEqual(ftype, FRAME_TACK)
                    send_frame(sock, FRAME_TDATA, b"z" * 1000)
                    # Order matters: SIGTERM must hit after the server
                    # persisted the chunk, not instead of reading it.
                    deadline = time.monotonic() + 10
                    while (
                        not os.path.exists(part)
                        or os.path.getsize(part) < 1000
                    ) and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertEqual(os.path.getsize(part), 1000)
                    proc.send_signal(signal.SIGTERM)
                    sock.settimeout(15)
                    ftype, payload = recv_frame(sock)
                    self.assertEqual(ftype, FRAME_TDONE)
                    result = json.loads(payload.decode("utf-8"))
                    self.assertFalse(result["ok"])
                    out, _ = proc.communicate(timeout=30)
                    self.assertEqual(proc.returncode, 0)
                    self.assertIn("fährt herunter", out)
                    self.assertIn("Host beendet", out)
                finally:
                    if sock is not None:
                        sock.close()
                    self._kill_subprocess(proc)
                with open(part, "rb") as fh:
                    self.assertEqual(fh.read(), b"z" * 1000)
                # Restarted host resumes the interrupted upload.
                port2 = _free_tcp_port()
                proc2 = self._run_host_subprocess(
                    port2, cert_dir, "--transfer-dir", root
                )
                sock2 = None
                try:
                    wait_for_port(port2)
                    sock2 = tls_connect(port2, [ALPN_TRANSFER])
                    send_line(sock2, TOKEN)
                    self.assertEqual(recv_line(sock2).strip(), "OK")
                    send_frame(
                        sock2, FRAME_TREQ,
                        encode_treq("put", "big.bin", 10**7, resume=True),
                    )
                    ftype, payload = recv_frame(sock2)
                    self.assertEqual(ftype, FRAME_TACK)
                    tack = decode_tack(payload)
                    self.assertTrue(tack["ok"])
                    self.assertEqual(tack["offset"], 1000)
                    for off in range(1000, len(full), 65536):
                        send_frame(sock2, FRAME_TDATA, full[off:off + 65536])
                    sha = hashlib.sha256(full).hexdigest()
                    send_frame(
                        sock2, FRAME_TDONE,
                        json.dumps({"sha256": sha}).encode(),
                    )
                    sock2.settimeout(30)
                    ftype, payload = recv_frame(sock2)
                    self.assertEqual(ftype, FRAME_TDONE)
                    result = json.loads(payload.decode("utf-8"))
                    self.assertTrue(result["ok"])
                finally:
                    if sock2 is not None:
                        sock2.close()
                    self._kill_subprocess(proc2)
                with open(os.path.join(root, "big.bin"), "rb") as fh:
                    self.assertEqual(fh.read(), full)
                self.assertFalse(os.path.exists(part))

    @unittest.skipIf(sys.platform == "win32", "POSIX signals only")
    def test_sigterm_mid_transfer_once_keeps_part(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            with tempfile.TemporaryDirectory() as root:
                port = _free_tcp_port()
                proc = self._run_host_subprocess(
                    port, cert_dir, "--transfer-dir", root, "--once"
                )
                sock = None
                try:
                    wait_for_port(port)
                    sock = tls_connect(port, [ALPN_TRANSFER])
                    send_line(sock, TOKEN)
                    self.assertEqual(recv_line(sock).strip(), "OK")
                    send_frame(
                        sock, FRAME_TREQ,
                        encode_treq("put", "big.bin", 10**7),
                    )
                    ftype, payload = recv_frame(sock)
                    self.assertEqual(ftype, FRAME_TACK)
                    proc.send_signal(signal.SIGTERM)
                    sock.settimeout(15)
                    ftype, payload = recv_frame(sock)
                    self.assertEqual(ftype, FRAME_TERR)
                    self.assertIn("fährt herunter", payload.decode("utf-8"))
                    out, _ = proc.communicate(timeout=30)
                    self.assertEqual(proc.returncode, 0)
                    self.assertIn("Host beendet", out)
                finally:
                    if sock is not None:
                        sock.close()
                    self._kill_subprocess(proc)
                # SIGTERM may strike before or after the server opened the
                # part file; either residue is harmless for a retry.
                part = os.path.join(root, "big.bin.ptt-part")
                if os.path.exists(part):
                    self.assertEqual(os.path.getsize(part), 0)
                self.assertFalse(
                    os.path.exists(os.path.join(root, "big.bin"))
                )

    def test_put_symlink_escape_rejected(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            with tempfile.TemporaryDirectory() as root:
                with tempfile.TemporaryDirectory() as outside:
                    link = os.path.join(root, "link")
                    try:
                        os.symlink(outside, link)
                    except OSError as exc:
                        self.skipTest(f"no symlinks: {exc}")
                    port = _free_tcp_port()
                    host_thread = self._transfer_host(port, cert_dir, root)
                    wait_for_port(port)
                    sock = tls_connect(port, [ALPN_TRANSFER])
                    try:
                        send_line(sock, TOKEN)
                        self.assertEqual(recv_line(sock).strip(), "OK")
                        send_frame(
                            sock, FRAME_TREQ,
                            encode_treq("put", "link/evil.bin", 3),
                        )
                        ftype, payload = recv_frame(sock)
                        self.assertEqual(ftype, FRAME_TERR)
                        self.assertIn("Pfad", payload.decode("utf-8"))
                    finally:
                        sock.close()
                    host_thread.join(timeout=15)
                    self.assertFalse(host_thread.is_alive())
                    self.assertEqual(os.listdir(outside), [])

    def test_put_rejects_bad_path(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            with tempfile.TemporaryDirectory() as root:
                port = _free_tcp_port()
                host_thread = self._run_host_once(
                    port, cert_dir, transfer_dir=root
                )
                wait_for_port(port)
                sock = tls_connect(port, [ALPN_TRANSFER])
                try:
                    send_line(sock, TOKEN)
                    self.assertEqual(recv_line(sock).strip(), "OK")
                    send_frame(
                        sock, FRAME_TREQ, encode_treq("put", "../evil", 3)
                    )
                    ftype, payload = recv_frame(sock)
                    self.assertEqual(ftype, FRAME_TERR)
                    self.assertIn("Pfad", payload.decode("utf-8"))
                finally:
                    sock.close()
                host_thread.join(timeout=15)
                self.assertFalse(host_thread.is_alive())
                self.assertEqual(os.listdir(root), [])

    def test_max_session_pipes(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            port = _free_tcp_port()
            with mock.patch("ptt.host.HAVE_PTY", False):
                host_thread = self._run_host_once(
                    port, cert_dir, max_session=1 / 60
                )
                wait_for_port(port)
                self._assert_timeout_exit(port, host_thread)

    def test_pipes_fallback_shell_exit(self):
        """Exercise _serve_pipes (the non-PTY path) on any platform."""
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            port = _free_tcp_port()
            with mock.patch("ptt.host.HAVE_PTY", False):
                host_thread = self._run_host_once(port, cert_dir)
                wait_for_port(port)

                sock = tls_connect(port)
                try:
                    send_line(sock, TOKEN)
                    self.assertEqual(recv_line(sock).strip(), "OK")
                    seen, exit_code = echo_and_exit(sock, MARKER)
                    self.assertIn(MARKER.encode(), seen)
                    self.assertEqual(exit_code, 0)
                finally:
                    sock.close()
                host_thread.join(timeout=15)
                self.assertFalse(host_thread.is_alive())

    def test_denied_logs_no_secret(self):
        """Neither the wrong nor the real secret may appear in host output."""
        canary = "CANARY-ptt-secret-9876"
        real = "real-token-xyz-12345"
        a, b = socket.socketpair()
        try:
            send_line(b, canary)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                result = _handle_connection(
                    a, default_shell(), real, "token", False, {}
                )
            self.assertFalse(result)
            self.assertEqual(recv_line(b).strip(), "DENIED")
            self.assertNotIn(canary, buf.getvalue())
            self.assertNotIn(real, buf.getvalue())
        finally:
            a.close()
            b.close()

    def test_wrong_token_denied(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            port = _free_tcp_port()
            host_thread = self._run_host_once(port, cert_dir)
            wait_for_port(port)

            sock = tls_connect(port)
            try:
                send_line(sock, "wrong-token")
                self.assertEqual(recv_line(sock).strip(), "DENIED")
            finally:
                sock.close()
            host_thread.join(timeout=15)
            self.assertFalse(host_thread.is_alive())

    def test_pin_auth_with_dashes(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            port = _free_tcp_port()
            host_thread = self._run_host_once(
                port, cert_dir, token=None, pin="123456"
            )
            wait_for_port(port)

            sock = tls_connect(port)
            try:
                send_line(sock, "123-456")
                self.assertEqual(recv_line(sock).strip(), "OK")
                seen, exit_code = echo_and_exit(sock, MARKER)
                self.assertIn(MARKER.encode(), seen)
                self.assertEqual(exit_code, 0)
            finally:
                sock.close()
            host_thread.join(timeout=15)
            self.assertFalse(host_thread.is_alive())

    def test_wrong_pin_denied(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            port = _free_tcp_port()
            host_thread = self._run_host_once(
                port, cert_dir, token=None, pin="123456"
            )
            wait_for_port(port)

            sock = tls_connect(port)
            try:
                send_line(sock, "000000")
                self.assertEqual(recv_line(sock).strip(), "DENIED")
            finally:
                sock.close()
            host_thread.join(timeout=15)
            self.assertFalse(host_thread.is_alive())

    def test_discovery_finds_host(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            port = _free_tcp_port()
            udp_port = _free_udp_port()
            host_thread = self._run_host_once(
                port, cert_dir, discover=True, discovery_port=udp_port,
                name="testbox",
            )
            wait_for_port(port)

            found = discover(timeout=2.0, target="127.0.0.1", port=udp_port)
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0]["name"], "testbox")
            self.assertEqual(found[0]["port"], port)
            self.assertEqual(found[0]["auth"], "token")
            self.assertTrue(found[0]["fingerprint"].startswith("SHA256:"))

            # complete a session so the --once host shuts down
            sock = tls_connect(port)
            try:
                send_line(sock, TOKEN)
                self.assertEqual(recv_line(sock).strip(), "OK")
                echo_and_exit(sock, MARKER)
            finally:
                sock.close()
            host_thread.join(timeout=15)
            self.assertFalse(host_thread.is_alive())


if __name__ == "__main__":
    unittest.main()
