"""Tests for client error paths (no tracebacks on network/TTY failures)."""
import contextlib
import io
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from helpers import _free_tcp_port, wait_for_port
from ptt.cert import ensure_cert
from ptt.client import (
    _connect_with_retry,
    _discover_with_progress,
    _prompt_hidden,
    _prompt_pin,
    _read_loop,
    _run_get,
    _run_put,
    _run_unix,
    run_client,
    run_exec,
    run_scan,
)
from ptt.host import default_shell, run_host
from ptt.output import TIMEOUT_EXIT_CODE
from ptt.protocol import FRAME_STDOUT, send_frame

TOKEN = "client-error-token-1"

try:
    import termios  # noqa: F401
except ImportError:
    termios = None


class PromptTest(unittest.TestCase):
    def test_hidden_prompt_errors_return_none(self):
        for exc in (EOFError(), OSError("x"), ValueError("x")):
            with self.subTest(exc=exc), mock.patch(
                "getpass.getpass", side_effect=exc
            ):
                self.assertIsNone(_prompt_hidden("Token: "))

    def test_pin_prompt_errors_return_none(self):
        for exc in (EOFError(), OSError("x"), ValueError("x")):
            with self.subTest(exc=exc), mock.patch(
                "builtins.input", side_effect=exc
            ):
                self.assertIsNone(_prompt_pin())

    def test_interrupt_propagates_from_prompts(self):
        with mock.patch("getpass.getpass", side_effect=KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt):
                _prompt_hidden("Token: ")
        with mock.patch("builtins.input", side_effect=KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt):
                _prompt_pin()

    def test_pin_prompt_enforces_length(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with mock.patch("builtins.input", side_effect=["12345", "123-456"]):
                self.assertEqual(_prompt_pin(), "123-456")

    def test_pin_prompt_gives_up_after_3_tries(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with mock.patch("builtins.input", return_value="12"):
                self.assertIsNone(_prompt_pin())


class RunClientErrorTest(unittest.TestCase):
    def test_keepalive_enabled_on_connect(self):
        raw = mock.MagicMock()
        with (
            mock.patch("socket.create_connection", return_value=raw),
            mock.patch("ptt.client.tls_client_context") as tls_mock,
            mock.patch("ptt.client.enable_keepalive") as ka_mock,
        ):
            tls_mock.return_value.wrap_socket.side_effect = OSError("nope")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_client("127.0.0.1", 8022, "token")
        self.assertEqual(rc, 1)
        ka_mock.assert_called_once_with(raw)

    def test_retry_connects_to_late_host(self):
        port = _free_tcp_port()

        def late_listener():
            time.sleep(2)
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", port))
            srv.listen(1)
            try:
                conn, _ = srv.accept()
                time.sleep(1)
                conn.close()
            except OSError:
                pass
            finally:
                srv.close()

        thread = threading.Thread(target=late_listener, daemon=True)
        thread.start()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            sock = _connect_with_retry(
                "127.0.0.1", port, retry=5, retry_delay=0.5, color=False
            )
        self.assertIsNotNone(sock)
        sock.close()
        # No assertion on retry chatter: on some stacks (Windows
        # loopback drops SYNs instead of refusing) the first attempt
        # stays pending until the late listener appears and then
        # succeeds silently. Eventual success is the contract here.

    def test_retry_gives_up(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            sock = _connect_with_retry(
                "127.0.0.1", _free_tcp_port(), retry=2, retry_delay=0.1,
                color=False,
            )
        self.assertIsNone(sock)
        out = buf.getvalue()
        self.assertIn("3 Versuche fehlgeschlagen.", out)
        self.assertIn("Nächster Schritt", out)

    def test_no_retry_single_attempt(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            sock = _connect_with_retry(
                "127.0.0.1", _free_tcp_port(), retry=0, retry_delay=2.0,
                color=False,
            )
        self.assertIsNone(sock)
        out = buf.getvalue()
        self.assertIn("Keine Verbindung", out)
        self.assertNotIn("Versuche fehlgeschlagen", out)

    def test_put_missing_file_returns_1_without_network(self):
        with mock.patch(
            "socket.create_connection",
            side_effect=AssertionError("must not connect"),
        ):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_client(
                    "127.0.0.1", 1, "token",
                    put="/nonexistent-ptt-put-file",
                )
        self.assertEqual(rc, 1)
        self.assertIn("Datei nicht gefunden", buf.getvalue())

    def test_get_bad_remote_name_returns_1_without_network(self):
        for get in ("..", "sub/..", "sub/"):
            with self.subTest(get=get):
                with mock.patch(
                    "socket.create_connection",
                    side_effect=AssertionError("must not connect"),
                ):
                    buf = io.StringIO()
                    with contextlib.redirect_stdout(buf):
                        rc = run_client("127.0.0.1", 1, "token", get=get)
                self.assertEqual(rc, 1)
                self.assertIn("Ungültiger Remote-Name", buf.getvalue())

    def test_connection_failure_returns_1(self):
        with mock.patch(
            "socket.create_connection", side_effect=OSError("refused")
        ):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_client("127.0.0.1", 1, "token")
        self.assertEqual(rc, 1)
        self.assertIn("Keine Verbindung", buf.getvalue())
        self.assertIn("Nächster Schritt", buf.getvalue())

    def test_no_hosts_abort_is_quiet(self):
        with (
            mock.patch("ptt.client.discover", return_value=[]),
            mock.patch("builtins.input", return_value="a"),
        ):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_client(None, 8022, "token")
        self.assertEqual(rc, 1)
        out = buf.getvalue()
        self.assertIn("Keine PTT-Hosts", out)
        self.assertNotIn("Nächster Schritt", out)

    def test_no_hosts_exhausted_shows_next_step(self):
        with (
            mock.patch("ptt.client.discover", return_value=[]),
            mock.patch("builtins.input", side_effect=["w", "w"]),
        ):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_client(None, 8022, "token")
        self.assertEqual(rc, 1)
        out = buf.getvalue()
        self.assertEqual(out.count("Keine PTT-Hosts"), 3)
        self.assertIn("Nächster Schritt", out)

    def test_retry_then_ip_connects_directly(self):
        with (
            mock.patch("ptt.client.discover", return_value=[]),
            mock.patch("builtins.input", side_effect=["i", "10.9.9.9"]),
            mock.patch(
                "socket.create_connection", side_effect=OSError("refused")
            ),
        ):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_client(None, 8022, "token")
        self.assertEqual(rc, 1)
        self.assertIn("Verbinde mit 10.9.9.9:8022", buf.getvalue())

    def test_retry_finds_host(self):
        found = [
            {
                "name": "box",
                "address": "10.1.2.3",
                "port": 8022,
                "fingerprint": "SHA256:AA",
                "auth": "pin",
            }
        ]
        with (
            mock.patch("ptt.client.discover", side_effect=[[], found]),
            mock.patch("builtins.input", return_value="w"),
            mock.patch(
                "socket.create_connection", side_effect=OSError("refused")
            ),
        ):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_client(None, 8022, "token")
        self.assertEqual(rc, 1)
        self.assertIn("Verbinde mit 10.1.2.3:8022", buf.getvalue())


class RetryPromptTest(unittest.TestCase):
    def test_retry_variants(self):
        from ptt.client import _prompt_retry

        for answer, want in (("", "retry"), ("w", "retry"), ("i", "ip"),
                             ("a", "abort"), ("n", "abort")):
            with self.subTest(answer=answer):
                with mock.patch("builtins.input", return_value=answer):
                    self.assertEqual(_prompt_retry(), want)

    def test_retry_invalid_then_valid(self):
        from ptt.client import _prompt_retry

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with mock.patch("builtins.input", side_effect=["x", "i"]):
                self.assertEqual(_prompt_retry(), "ip")

    def test_retry_eof_aborts(self):
        from ptt.client import _prompt_retry

        with mock.patch("builtins.input", side_effect=EOFError):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(_prompt_retry(), "abort")

    def test_address_prompt(self):
        from ptt.client import _prompt_address

        with mock.patch("builtins.input", return_value="  10.0.0.5  "):
            self.assertEqual(_prompt_address(), "10.0.0.5")
        with mock.patch("builtins.input", side_effect=EOFError):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertIsNone(_prompt_address())
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with mock.patch("builtins.input", return_value=""):
                self.assertIsNone(_prompt_address())

    def test_interrupt_during_discovery_returns_130(self):
        with mock.patch(
            "ptt.client.discover", side_effect=KeyboardInterrupt()
        ):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_client(None, 8022, "token")
        self.assertEqual(rc, 130)
        self.assertIn("Abgebrochen", buf.getvalue())

    def test_discover_with_progress_returns_hosts_quietly(self):
        hosts = [{"name": "a"}]
        with mock.patch("ptt.client.discover", return_value=hosts) as m:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(_discover_with_progress(timeout=0.1), hosts)
            self.assertEqual(buf.getvalue(), "")
        m.assert_called_once_with(timeout=0.1)

    def test_tls_error_has_next_step(self):
        with (
            mock.patch("socket.create_connection") as connect_mock,
            mock.patch("ptt.client.tls_client_context") as ctx_mock,
        ):
            ctx_mock.return_value.wrap_socket.side_effect = OSError("boom")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_client("127.0.0.1", 8022, "token")
        connect_mock.return_value.close.assert_called_once()
        self.assertEqual(rc, 1)
        out = buf.getvalue()
        self.assertIn("TLS-Fehler", out)
        self.assertIn("Nächster Schritt", out)


class LoopbackMessageTest(unittest.TestCase):
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
                # Short pre-auth wait: stale probes may wedge the
                # single-threaded accept loop until this timeout.
                "auth_timeout": 3,
            },
            daemon=True,
        )
        thread.start()
        return thread

    def _need_backend(self) -> None:
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))

    def test_denied_has_next_step(self):
        self._need_backend()
        with tempfile.TemporaryDirectory() as tmp:
            fp_file = f"{tmp}/known_hosts"
            port = _free_tcp_port()
            host_thread = self._run_host_once(port, f"{tmp}/certs")
            wait_for_port(port)
            with mock.patch(
                "ptt.known_hosts.known_hosts_path", return_value=fp_file
            ):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = run_client("127.0.0.1", port, "wrong-token")
            self.assertEqual(rc, 1)
            out = buf.getvalue()
            self.assertIn("Zugriff verweigert", out)
            self.assertIn("Nächster Schritt", out)
            host_thread.join(timeout=15)
            self.assertFalse(host_thread.is_alive())

    def test_discovery_mismatch_has_next_step(self):
        self._need_backend()
        with tempfile.TemporaryDirectory() as tmp:
            port = _free_tcp_port()
            forged = [
                {
                    "name": "spoof",
                    "address": "127.0.0.1",
                    "port": port,
                    "fingerprint": "SHA256:00:FORGED",
                    "auth": "token",
                }
            ]
            host_thread = self._run_host_once(port, f"{tmp}/certs")
            wait_for_port(port)
            with mock.patch("ptt.client.discover", return_value=forged):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = run_client(None, port, TOKEN)
            self.assertEqual(rc, 1)
            out = buf.getvalue()
            self.assertIn("NICHT mit der Ankündigung", out)
            self.assertIn("Nächster Schritt", out)
            host_thread.join(timeout=15)
            self.assertFalse(host_thread.is_alive())

    def test_prompt_abort_returns_130(self):
        self._need_backend()
        with tempfile.TemporaryDirectory() as tmp:
            fp_file = f"{tmp}/known_hosts"
            port = _free_tcp_port()
            host_thread = self._run_host_once(port, f"{tmp}/certs")
            wait_for_port(port)
            with (
                mock.patch(
                    "ptt.known_hosts.known_hosts_path", return_value=fp_file
                ),
                mock.patch("getpass.getpass", side_effect=KeyboardInterrupt()),
            ):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = run_client("127.0.0.1", port, None)
            self.assertEqual(rc, 130)
            self.assertIn("Abgebrochen", buf.getvalue())
            host_thread.join(timeout=15)
            self.assertFalse(host_thread.is_alive())

    def test_auth_interrupted_has_next_step(self):
        self._need_backend()
        with tempfile.TemporaryDirectory() as tmp:
            fp_file = f"{tmp}/known_hosts"
            port = _free_tcp_port()
            host_thread = self._run_host_once(port, f"{tmp}/certs")
            wait_for_port(port)
            with (
                mock.patch(
                    "ptt.known_hosts.known_hosts_path", return_value=fp_file
                ),
                mock.patch(
                    "ptt.client.send_line", side_effect=OSError("boom")
                ),
            ):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = run_client("127.0.0.1", port, TOKEN)
            self.assertEqual(rc, 1)
            out = buf.getvalue()
            self.assertIn("Auth fehlgeschlagen", out)
            self.assertIn("Nächster Schritt", out)
            host_thread.join(timeout=15)
            self.assertFalse(host_thread.is_alive())


@unittest.skipIf(termios is None, "POSIX TTY only")
class UnixRunnerTest(unittest.TestCase):
    def test_no_tty_returns_2(self):
        with mock.patch("sys.stdin") as stdin:
            stdin.isatty.return_value = False
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = _run_unix(object())
        self.assertEqual(rc, 2)
        self.assertIn("kein Terminal", buf.getvalue())

    def test_broken_stdin_returns_1(self):
        with mock.patch("sys.stdin") as stdin:
            stdin.isatty.return_value = True
            stdin.fileno.side_effect = ValueError("closed")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = _run_unix(object())
        self.assertEqual(rc, 1)
        self.assertIn("Terminalfehler", buf.getvalue())


class ReadLoopErrorTest(unittest.TestCase):
    def test_closed_output_sets_code_1(self):
        a, b = socket.socketpair()
        out = io.BytesIO()
        out.close()
        result = {"code": 0}
        done = threading.Event()

        def peer():
            try:
                send_frame(b, FRAME_STDOUT, b"x")
            finally:
                b.close()

        thread = threading.Thread(target=peer)
        thread.start()
        _read_loop(a, out, result, done)
        thread.join(timeout=10)
        a.close()
        self.assertEqual(result["code"], 1)
        self.assertTrue(done.is_set())


class MultiTransferTest(unittest.TestCase):
    def test_runs_puts_then_gets_in_order(self):
        calls = []

        def fake(host, port, token, color_mode, retry, retry_delay,
                 put, get, fresh, deadline=None, _found=None, _out=None,
                 verbose=False):
            calls.append((put, get, fresh))
            return 0

        buf = io.StringIO()
        with (
            mock.patch("ptt.client._run_client", side_effect=fake),
            contextlib.redirect_stdout(buf),
        ):
            rc = run_client(
                "h", 8022, "t", put=["a", "b"], get=["c"], fresh=True,
            )
        self.assertEqual(rc, 0)
        self.assertEqual(
            calls,
            [("a", None, True), ("b", None, True), (None, "c", True)],
        )
        out = buf.getvalue()
        self.assertIn("Transfer 1/3: --put a", out)
        self.assertIn("Transfer 2/3: --put b", out)
        self.assertIn("Transfer 3/3: --get c", out)
        self.assertIn("3/3 Transfers ok", out)

    def test_failure_continues_and_sets_exit_1(self):
        results = iter([0, 1, 0])

        def fake(host, port, token, color_mode, retry, retry_delay,
                 put, get, fresh, deadline=None, _found=None, _out=None,
                 verbose=False):
            return next(results)

        buf = io.StringIO()
        with (
            mock.patch("ptt.client._run_client", side_effect=fake),
            contextlib.redirect_stdout(buf),
        ):
            rc = run_client("h", 8022, "t", put=["a", "b", "c"])
        self.assertEqual(rc, 1)
        self.assertIn("2/3 Transfers ok, 1 fehlgeschlagen", buf.getvalue())

    def test_single_string_still_single_call(self):
        with mock.patch(
            "ptt.client._run_client", return_value=0
        ) as m:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_client("h", 8022, "t", put="a")
        self.assertEqual(rc, 0)
        m.assert_called_once_with(
            "h", 8022, "t", "auto", 0, 2.0, "a", None, False,
            deadline=None, _out=None, verbose=False,
        )
        self.assertNotIn("Transfer 1/1", buf.getvalue())

    def test_search_runs_once_for_batch(self):
        found = ("found-host", 9999, "fp", "token")
        with (
            mock.patch(
                "ptt.client._search_interactive", return_value=found
            ) as search,
            mock.patch(
                "ptt.client._run_client", return_value=0
            ) as run,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            rc = run_client(None, 8022, "t", put=["a", "b"])
        self.assertEqual(rc, 0)
        search.assert_called_once_with(8022, mock.ANY)
        self.assertEqual(run.call_count, 2)
        for call in run.call_args_list:
            self.assertEqual(call.args[0], "found-host")
            self.assertEqual(call.kwargs["_found"], found)

    def test_aborted_search_aborts_batch(self):
        with (
            mock.patch(
                "ptt.client._search_interactive", return_value=None
            ),
            mock.patch("ptt.client._run_client") as run,
        ):
            rc = run_client(None, 8022, "t", put=["a", "b"])
        self.assertEqual(rc, 1)
        run.assert_not_called()


class TimeoutTest(unittest.TestCase):
    def _blackhole(self):
        """Listening socket that accepts and then never speaks."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def _hold():
            try:
                conn, _ = srv.accept()
                try:
                    conn.settimeout(10)
                    try:
                        # Swallow everything (e.g. TLS ClientHello),
                        # never answer; ends at client close.
                        while conn.recv(65536):
                            pass
                    except OSError:
                        pass
                finally:
                    conn.close()
            except OSError:
                pass
            finally:
                srv.close()

        worker = threading.Thread(target=_hold, daemon=True)
        worker.start()
        return port, worker

    def test_connect_blackhole_times_out(self):
        port, worker = self._blackhole()
        buf = io.StringIO()
        start = time.monotonic()
        with contextlib.redirect_stdout(buf):
            rc = run_client("127.0.0.1", port, "t", timeout=1)
        elapsed = time.monotonic() - start
        worker.join(timeout=12)
        self.assertEqual(rc, 124)
        self.assertIn("Zeitlimit", buf.getvalue())
        self.assertLess(elapsed, 8)

    def test_exec_blackhole_times_out(self):
        port, worker = self._blackhole()
        buf = io.StringIO()
        start = time.monotonic()
        with contextlib.redirect_stdout(buf):
            rc = run_exec(
                "127.0.0.1", port, "t", argv=["uptime"], timeout=1
            )
        elapsed = time.monotonic() - start
        worker.join(timeout=12)
        self.assertEqual(rc, 124)
        self.assertIn("Zeitlimit", buf.getvalue())
        self.assertLess(elapsed, 8)

    def test_retry_loop_aborts_on_deadline(self):
        buf = io.StringIO()
        start = time.monotonic()
        with contextlib.redirect_stdout(buf):
            with self.assertRaises(TimeoutError):
                _connect_with_retry(
                    "127.0.0.1", 1, retry=100, retry_delay=30,
                    color=False,
                    deadline=time.monotonic() + 0.5,
                )
        elapsed = time.monotonic() - start
        self.assertIn("Zeitlimit", buf.getvalue())
        self.assertLess(elapsed, 10)

    def test_expired_deadline_skips_connect(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with self.assertRaises(TimeoutError):
                _connect_with_retry(
                    "127.0.0.1", 1, retry=0, retry_delay=0,
                    color=False,
                    deadline=time.monotonic() - 1,
                )
        self.assertIn("Zeitlimit", buf.getvalue())

    def test_refused_with_timeout_stays_1(self):
        with mock.patch(
            "socket.create_connection", side_effect=OSError("refused")
        ):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_client("127.0.0.1", 1, "token", timeout=30)
        self.assertEqual(rc, 1)
        self.assertIn("Keine Verbindung", buf.getvalue())

    def test_attempt_timeout_before_deadline_retries(self):
        with mock.patch(
            "socket.create_connection",
            side_effect=socket.timeout("timed out"),
        ):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_client("127.0.0.1", 1, "token", timeout=30)
        self.assertEqual(rc, 1)
        out = buf.getvalue()
        self.assertIn("Keine Verbindung", out)
        self.assertIn("timed out", out)

    def test_attempt_timeout_at_deadline_is_124(self):
        with mock.patch(
            "socket.create_connection",
            side_effect=socket.timeout("timed out"),
        ):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_client("127.0.0.1", 1, "token", timeout=0.1)
        self.assertEqual(rc, 124)
        self.assertIn("Zeitlimit", buf.getvalue())

    def test_put_timeout_returns_124(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "src.bin")
            with open(src, "wb") as fh:
                fh.write(b"data")
            a, b = socket.socketpair()
            try:
                buf = io.StringIO()
                with (
                    mock.patch(
                        "ptt.client.wants_transfer", return_value=True
                    ),
                    contextlib.redirect_stdout(buf),
                ):
                    rc = _run_put(
                        a, src, "up.bin", False,
                        deadline=time.monotonic() - 1,
                    )
            finally:
                b.close()
        self.assertEqual(rc, 124)
        out = buf.getvalue()
        self.assertIn("Zeitlimit", out)
        self.assertIn("--timeout", out)

    def test_get_timeout_returns_124(self):
        with tempfile.TemporaryDirectory() as tmp:
            local = os.path.join(tmp, "down.bin")
            a, b = socket.socketpair()
            try:
                buf = io.StringIO()
                with (
                    mock.patch(
                        "ptt.client.wants_transfer", return_value=True
                    ),
                    contextlib.redirect_stdout(buf),
                ):
                    rc = _run_get(
                        a, "r.bin", local, False,
                        deadline=time.monotonic() - 1,
                    )
            finally:
                b.close()
        self.assertEqual(rc, 124)
        out = buf.getvalue()
        self.assertIn("Zeitlimit", out)
        self.assertIn("--timeout", out)


class QuietTest(unittest.TestCase):
    def _stdio(self):
        """Capture stdout (bytes, with .buffer) and stderr (text)."""
        raw_out = io.BytesIO()
        wrapper = io.TextIOWrapper(raw_out, encoding="utf-8")
        err_buf = io.StringIO()
        self._quiet_wrapper = wrapper  # keep alive: GC would close raw_out
        return raw_out, wrapper, err_buf

    def test_quiet_reroutes_prints_to_stderr(self):
        seen = {}

        def fake(*args, **kwargs):
            seen["out"] = kwargs.get("_out")
            seen["is_stderr"] = sys.stdout is sys.stderr
            print("status-line")
            return 0

        raw_out, wrapper, err_buf = self._stdio()
        old = sys.stdout
        sys.stdout = wrapper
        try:
            with (
                mock.patch("ptt.client._run_client", side_effect=fake),
                contextlib.redirect_stderr(err_buf),
            ):
                rc = run_client("h", 8022, "t", quiet=True)
        finally:
            wrapper.flush()
            sys.stdout = old
        self.assertEqual(rc, 0)
        self.assertIs(seen["out"], raw_out)
        self.assertTrue(seen["is_stderr"])
        self.assertIn("status-line", err_buf.getvalue())
        self.assertEqual(raw_out.getvalue(), b"")

    def test_loud_passes_no_out_stream(self):
        seen = {}

        def fake(*args, **kwargs):
            seen["out"] = kwargs.get("_out")
            seen["is_stderr"] = sys.stdout is sys.stderr
            return 0

        raw_out, wrapper, err_buf = self._stdio()
        old = sys.stdout
        sys.stdout = wrapper
        try:
            with (
                mock.patch("ptt.client._run_client", side_effect=fake),
                contextlib.redirect_stderr(err_buf),
            ):
                rc = run_client("h", 8022, "t")
        finally:
            wrapper.flush()
            sys.stdout = old
        self.assertEqual(rc, 0)
        self.assertIsNone(seen["out"])
        self.assertFalse(seen["is_stderr"])


class ExitCodeTest(unittest.TestCase):
    def test_timeout_code_matches_gnu_timeout(self):
        self.assertEqual(TIMEOUT_EXIT_CODE, 124)

    def test_interrupted_connect_returns_130(self):
        with mock.patch(
            "ptt.client._run_client", side_effect=KeyboardInterrupt
        ):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_client("127.0.0.1", 8022, "t")
        self.assertEqual(rc, 130)
        self.assertIn("Abgebrochen", buf.getvalue())

    def test_interrupted_exec_returns_130(self):
        with mock.patch(
            "ptt.client._run_client", side_effect=KeyboardInterrupt
        ):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_exec("127.0.0.1", 8022, "t", argv=["uptime"])
        self.assertEqual(rc, 130)
        self.assertIn("Abgebrochen", buf.getvalue())


class ScanTest(unittest.TestCase):
    HOSTS = [
        {
            "name": "wohnzimmer",
            "address": "192.168.1.42",
            "port": 8022,
            "fingerprint": "SHA256:AA:BB:CC:DD",
            "auth": "token",
            "busy": False,
        },
        {
            "name": "keller",
            "address": "192.168.1.43",
            "port": 8022,
            "fingerprint": "SHA256:11:22:33:44",
            "auth": "pin",
            "busy": True,
        },
    ]

    def test_human_lists_hosts(self):
        buf = io.StringIO()
        with (
            mock.patch("ptt.client.discover", return_value=self.HOSTS),
            contextlib.redirect_stdout(buf),
        ):
            rc = run_scan("never")
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("1) wohnzimmer (192.168.1.42, TOKEN,", out)
        self.assertIn("SHA256:AA:...:DD", out)
        self.assertIn("2) keller (192.168.1.43, PIN,", out)
        self.assertIn("(belegt)", out)

    def test_json_parses(self):
        import json

        buf = io.StringIO()
        with (
            mock.patch("ptt.client.discover", return_value=self.HOSTS),
            contextlib.redirect_stdout(buf),
        ):
            rc = run_scan("never", as_json=True)
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(buf.getvalue()), self.HOSTS)

    def test_empty_human(self):
        buf = io.StringIO()
        with (
            mock.patch("ptt.client.discover", return_value=[]),
            contextlib.redirect_stdout(buf),
        ):
            rc = run_scan("never")
        self.assertEqual(rc, 0)
        self.assertIn("Keine Hosts", buf.getvalue())

    def test_empty_json(self):
        import json

        buf = io.StringIO()
        with (
            mock.patch("ptt.client.discover", return_value=[]),
            contextlib.redirect_stdout(buf),
        ):
            rc = run_scan("never", as_json=True)
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(buf.getvalue()), [])


if __name__ == "__main__":
    unittest.main()
