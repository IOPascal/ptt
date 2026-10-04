"""End-to-end test: real host serving a shell over TLS on loopback."""
import socket
import ssl
import struct
import tempfile
import threading
import time
import unittest

from ptt.cert import ensure_cert
from ptt.discover import discover
from ptt.host import default_shell, run_host
from ptt.protocol import (
    FRAME_EXIT,
    FRAME_RESIZE,
    FRAME_STDIN,
    FRAME_STDOUT,
    recv_frame,
    recv_line,
    send_frame,
    send_line,
)

TOKEN = "aa11-bb22-cc33-dd44"
MARKER = "PTT_INTEGRATION_OK_4711"


def _free_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _tls_connect(port: int):
    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    sock = context.wrap_socket(raw, server_hostname="127.0.0.1")
    sock.settimeout(10)
    return sock


def _wait_for_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            probe = socket.create_connection(("127.0.0.1", port), timeout=1)
            probe.close()
            return
        except OSError:
            time.sleep(0.1)
    raise AssertionError("host did not start listening")


def _free_udp_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _echo_and_exit(sock, marker: str):
    """Run `echo <marker>` then `exit`; returns (output, exit_code)."""
    send_frame(sock, FRAME_RESIZE, struct.pack("!HH", 80, 24))
    send_frame(sock, FRAME_STDIN, f"echo {marker}\n".encode())
    seen = b""
    exit_code = None
    while exit_code is None:
        ftype, payload = recv_frame(sock)
        if ftype == FRAME_STDOUT:
            seen += payload
            if marker.encode() in seen:
                send_frame(sock, FRAME_STDIN, b"exit\n")
        elif ftype == FRAME_EXIT:
            (exit_code,) = struct.unpack("!i", payload)
    return seen, exit_code


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
            port = _free_port()
            host_thread = self._run_host_once(port, cert_dir)
            _wait_for_port(port)

            sock = _tls_connect(port)
            try:
                send_line(sock, TOKEN)
                self.assertEqual(recv_line(sock).strip(), "OK")
                send_frame(sock, FRAME_RESIZE, struct.pack("!HH", 80, 24))
                send_frame(sock, FRAME_STDIN, f"echo {MARKER}\n".encode())
                seen = b""
                exit_code = None
                while exit_code is None:
                    ftype, payload = recv_frame(sock)
                    if ftype == FRAME_STDOUT:
                        seen += payload
                        if MARKER.encode() in seen:
                            send_frame(sock, FRAME_STDIN, b"exit\n")
                    elif ftype == FRAME_EXIT:
                        (exit_code,) = struct.unpack("!i", payload)
                self.assertIn(MARKER.encode(), seen)
                self.assertEqual(exit_code, 0)
            finally:
                sock.close()
            host_thread.join(timeout=15)
            self.assertFalse(host_thread.is_alive())

    def test_wrong_token_denied(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            port = _free_port()
            host_thread = self._run_host_once(port, cert_dir)
            _wait_for_port(port)

            sock = _tls_connect(port)
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
            port = _free_port()
            host_thread = self._run_host_once(
                port, cert_dir, token=None, pin="123456"
            )
            _wait_for_port(port)

            sock = _tls_connect(port)
            try:
                send_line(sock, "123-456")
                self.assertEqual(recv_line(sock).strip(), "OK")
                seen, exit_code = _echo_and_exit(sock, MARKER)
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
            port = _free_port()
            host_thread = self._run_host_once(
                port, cert_dir, token=None, pin="123456"
            )
            _wait_for_port(port)

            sock = _tls_connect(port)
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
            port = _free_port()
            udp_port = _free_udp_port()
            host_thread = self._run_host_once(
                port, cert_dir, discover=True, discovery_port=udp_port,
                name="testbox",
            )
            _wait_for_port(port)

            found = discover(timeout=2.0, target="127.0.0.1", port=udp_port)
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0]["name"], "testbox")
            self.assertEqual(found[0]["port"], port)
            self.assertEqual(found[0]["auth"], "token")
            self.assertTrue(found[0]["fingerprint"].startswith("SHA256:"))

            # complete a session so the --once host shuts down
            sock = _tls_connect(port)
            try:
                send_line(sock, TOKEN)
                self.assertEqual(recv_line(sock).strip(), "OK")
                _echo_and_exit(sock, MARKER)
            finally:
                sock.close()
            host_thread.join(timeout=15)
            self.assertFalse(host_thread.is_alive())


if __name__ == "__main__":
    unittest.main()
