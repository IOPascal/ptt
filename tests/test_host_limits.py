"""Tests for the per-IP brute-force brake."""
import contextlib
import io
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

from helpers import _free_tcp_port, tls_connect
from ptt.cert import ensure_cert
from ptt.protocol import recv_line, send_line
from ptt.host import (
    PIN_MAX_FAILURES,
    PIN_WINDOW_SECONDS,
    _backoff_delay,
    _failures_for,
    _handle_connection,
    _locked_out,
    _lockout_wait,
    SessionResult,
    default_shell,
    run_host,
)

T0 = 1_000_000.0


def _fail_n(failures, ip, n, at=T0):
    with mock.patch("ptt.host.time.time", return_value=at):
        for _ in range(n):
            _failures_for(failures, ip).append(at)


class LockoutTest(unittest.TestCase):
    def test_threshold(self):
        failures: dict = {}
        _fail_n(failures, "10.0.0.1", PIN_MAX_FAILURES - 1)
        with mock.patch("ptt.host.time.time", return_value=T0):
            self.assertFalse(_locked_out(failures, "10.0.0.1"))
        _fail_n(failures, "10.0.0.1", 1)
        with mock.patch("ptt.host.time.time", return_value=T0):
            self.assertTrue(_locked_out(failures, "10.0.0.1"))

    def test_per_ip_isolation(self):
        failures: dict = {}
        _fail_n(failures, "10.0.0.1", PIN_MAX_FAILURES)
        with mock.patch("ptt.host.time.time", return_value=T0):
            self.assertTrue(_locked_out(failures, "10.0.0.1"))
            self.assertFalse(_locked_out(failures, "10.0.0.2"))
            self.assertEqual(_lockout_wait(failures, "10.0.0.2"), 0.0)

    def test_window_expiry(self):
        failures: dict = {}
        _fail_n(failures, "10.0.0.1", PIN_MAX_FAILURES)
        with mock.patch(
            "ptt.host.time.time", return_value=T0 + PIN_WINDOW_SECONDS + 1
        ):
            self.assertFalse(_locked_out(failures, "10.0.0.1"))
            self.assertEqual(_lockout_wait(failures, "10.0.0.1"), 0.0)

    def test_wait_counts_down(self):
        failures: dict = {}
        _fail_n(failures, "10.0.0.1", PIN_MAX_FAILURES)
        with mock.patch("ptt.host.time.time", return_value=T0):
            self.assertAlmostEqual(
                _lockout_wait(failures, "10.0.0.1"), PIN_WINDOW_SECONDS
            )
        with mock.patch("ptt.host.time.time", return_value=T0 + 10):
            self.assertAlmostEqual(
                _lockout_wait(failures, "10.0.0.1"), PIN_WINDOW_SECONDS - 10
            )


class BackoffTest(unittest.TestCase):
    def test_delay_sequence(self):
        with mock.patch("ptt.host.random.uniform", return_value=0.0):
            self.assertEqual(_backoff_delay(1), 1.0)
            self.assertEqual(_backoff_delay(2), 2.0)
            self.assertEqual(_backoff_delay(3), 4.0)
            self.assertEqual(_backoff_delay(6), 30.0)  # 2**5 capped
            self.assertEqual(_backoff_delay(10), 30.0)

    def test_jitter_added(self):
        with mock.patch("ptt.host.random.uniform", return_value=0.5):
            self.assertEqual(_backoff_delay(1), 1.5)

    def test_failed_auth_sleeps(self):
        a, b = socket.socketpair()
        try:
            send_line(b, "wrong-secret")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                with mock.patch("ptt.host.time.sleep") as sleep_mock:
                    result = _handle_connection(
                        a, default_shell(), "real-secret", "token", False, {}
                    )
            self.assertFalse(result)
            self.assertEqual(recv_line(b).strip(), "DENIED")
            sleep_mock.assert_called_once()
            delay = sleep_mock.call_args[0][0]
            self.assertGreaterEqual(delay, 1.0)
            self.assertLessEqual(delay, 1.5)
        finally:
            a.close()
            b.close()

    def test_success_resets_failures(self):
        a, b = socket.socketpair()
        try:
            failures = {"?": [1000.0, 1001.0]}
            send_line(b, "real-secret")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                stats = SessionResult("ended", 10, 20, 1.5)
                with (
                    mock.patch(
                        "ptt.host._serve_pty", return_value=stats
                    ),
                    mock.patch(
                        "ptt.host._serve_pipes", return_value=stats
                    ),
                    mock.patch("ptt.host.time.sleep") as sleep_mock,
                ):
                    result = _handle_connection(
                        a, default_shell(), "real-secret", "token", False, failures
                    )
            self.assertTrue(result)
            self.assertEqual(recv_line(b).strip(), "OK")
            sleep_mock.assert_not_called()
            self.assertNotIn("?", failures)
        finally:
            a.close()
            b.close()


class VerbosePhaseTest(unittest.TestCase):
    def test_denied_logs_phases_when_verbose(self):
        a, b = socket.socketpair()
        try:
            send_line(b, "wrong-secret")
            out, err = io.StringIO(), io.StringIO()
            with (
                contextlib.redirect_stdout(out),
                contextlib.redirect_stderr(err),
                mock.patch("ptt.host.time.sleep"),
            ):
                result = _handle_connection(
                    a, default_shell(), "real-secret", "token", False, {},
                    verbose=True,
                )
            self.assertFalse(result)
            self.assertEqual(recv_line(b).strip(), "DENIED")
            phases = err.getvalue()
            self.assertLess(
                phases.index("Hello empfangen"),
                phases.index("Auth abgelehnt"),
            )
        finally:
            a.close()
            b.close()

    def test_denied_silent_by_default(self):
        a, b = socket.socketpair()
        try:
            send_line(b, "wrong-secret")
            out, err = io.StringIO(), io.StringIO()
            with (
                contextlib.redirect_stdout(out),
                contextlib.redirect_stderr(err),
                mock.patch("ptt.host.time.sleep"),
            ):
                result = _handle_connection(
                    a, default_shell(), "real-secret", "token", False, {}
                )
            self.assertFalse(result)
            self.assertEqual(recv_line(b).strip(), "DENIED")
            self.assertEqual(err.getvalue(), "")
        finally:
            a.close()
            b.close()

    def test_exec_ok_logs_phases(self):
        a, b = socket.socketpair()
        try:
            send_line(b, "EXEC tok echo hi")
            out, err = io.StringIO(), io.StringIO()
            stats = SessionResult("ended", 10, 20, 1.5)
            with (
                contextlib.redirect_stdout(out),
                contextlib.redirect_stderr(err),
                mock.patch(
                    "ptt.host._serve_exec", return_value=stats
                ),
            ):
                result = _handle_connection(
                    a, default_shell(), "tok", "token", False, {},
                    verbose=True,
                )
            self.assertTrue(result)
            self.assertEqual(recv_line(b).strip(), "OK")
            phases = err.getvalue()
            markers = [
                "Hello empfangen", "Auth ok (token)", "Modus: exec",
                "Sitzung beendet (ended",
            ]
            positions = [phases.index(marker) for marker in markers]
            self.assertEqual(positions, sorted(positions))
        finally:
            a.close()
            b.close()


class HandshakeTimeoutTest(unittest.TestCase):
    def test_half_open_connection_times_out(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            port = _free_tcp_port()
            with mock.patch("ptt.host.AUTH_TIMEOUT", 0.3):
                thread = threading.Thread(
                    target=run_host,
                    kwargs={
                        "bind": "127.0.0.1",
                        "port": port,
                        "shell": default_shell(),
                        "token": "t" * 20,
                        "cert_dir": cert_dir,
                        "once": True,
                        "discover": False,
                    },
                    daemon=True,
                )
                thread.start()
                # No wait_for_port here: its probe would add noise to the
                # handshake-failure log, so the first working connect IS the
                # probe. (Failed handshakes don't end a --once host.)
                deadline = time.time() + 10
                probe = None
                while time.time() < deadline:
                    try:
                        probe = socket.create_connection(
                            ("127.0.0.1", port), timeout=1
                        )
                        break
                    except OSError:
                        time.sleep(0.1)
                self.assertIsNotNone(probe, "host did not start listening")
                assert probe is not None
                probe.settimeout(10)
                start = time.monotonic()
                data = probe.recv(1)  # server closes after handshake timeout
                elapsed = time.monotonic() - start
                probe.close()
                self.assertEqual(data, b"")
                self.assertLess(elapsed, 5)
                # A failed handshake is no session: the --once host keeps
                # listening, so shut it down with a denied auth attempt.
                sock = tls_connect(port)
                try:
                    send_line(sock, "wrong-token")
                    self.assertEqual(recv_line(sock).strip(), "DENIED")
                finally:
                    sock.close()
                thread.join(timeout=15)
                self.assertFalse(thread.is_alive())


class BindErrorTest(unittest.TestCase):
    def test_busy_port_exits_1_with_hint(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        try:
            port = blocker.getsockname()[1]
            with tempfile.TemporaryDirectory() as cert_dir:
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    with self.assertRaises(SystemExit) as ctx:
                        run_host(
                            bind="127.0.0.1",
                            port=port,
                            shell=default_shell(),
                            token="t" * 20,
                            cert_dir=cert_dir,
                            once=True,
                            discover=False,
                        )
                self.assertEqual(ctx.exception.code, 1)
                self.assertIn("Start fehlgeschlagen", buf.getvalue())
                self.assertIn("--port", buf.getvalue())
        finally:
            blocker.close()

    def test_missing_cert_backend_exits_1(self):
        with mock.patch(
            "ptt.host.ensure_cert",
            side_effect=RuntimeError("Kein 'openssl'-Programm gefunden."),
        ):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                with self.assertRaises(SystemExit) as ctx:
                    run_host(
                        bind="127.0.0.1",
                        port=1,
                        shell=default_shell(),
                        token="t" * 20,
                        cert_dir="/nonexistent-cert-dir-ptt",
                        once=True,
                        discover=False,
                    )
            self.assertEqual(ctx.exception.code, 1)
            self.assertIn("openssl", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
