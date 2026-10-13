"""Tests for `ptt exec` (hello parsing, serving, client session, loopback)."""
import contextlib
import io
import os
import signal
import socket
import struct
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

from helpers import _free_tcp_port, wait_for_port
from ptt.cert import ensure_cert
from ptt.client import _run_exec_session, run_exec
from ptt.host import _exit_code_from_returncode, _parse_hello, _serve_exec
from ptt.protocol import (
    FRAME_EXIT,
    FRAME_STDIN,
    FRAME_STDOUT,
    recv_frame,
    send_frame,
)

TOKEN = "exec-test-token-42"


class HelloParseTest(unittest.TestCase):
    def test_plain_token(self):
        self.assertEqual(_parse_hello("tok", "token", "tok"), (True, None))

    def test_plain_pin(self):
        self.assertEqual(
            _parse_hello("482 913", "pin", "482913"), (True, None)
        )

    def test_wrong_secret(self):
        self.assertEqual(_parse_hello("nope", "token", "tok"), (False, None))

    def test_exec_token(self):
        authed, argv = _parse_hello(
            "EXEC tok echo 'hi there'", "token", "tok"
        )
        self.assertTrue(authed)
        self.assertEqual(argv, ["echo", "hi there"])

    def test_exec_pin(self):
        authed, argv = _parse_hello("EXEC 482913 uptime", "pin", "482913")
        self.assertTrue(authed)
        self.assertEqual(argv, ["uptime"])

    def test_exec_token_with_spaces(self):
        authed, argv = _parse_hello(
            "EXEC my tok echo ok", "token", "my tok"
        )
        self.assertTrue(authed)
        self.assertEqual(argv, ["echo", "ok"])

    def test_exec_wrong_secret(self):
        self.assertEqual(
            _parse_hello("EXEC nope echo ok", "token", "tok"), (False, None)
        )

    def test_exec_without_argv_denied(self):
        self.assertEqual(
            _parse_hello("EXEC tok", "token", "tok"), (False, None)
        )
        self.assertEqual(
            _parse_hello("EXEC tok   ", "token", "tok"), (False, None)
        )

    def test_exec_bad_quoting_denied(self):
        self.assertEqual(
            _parse_hello("EXEC tok echo 'oops", "token", "tok"),
            (False, None),
        )

    def test_legacy_exec_prefixed_token_still_shell(self):
        # A token that literally starts with "EXEC " keeps working
        # as a plain shell secret (fallback comparison).
        self.assertEqual(
            _parse_hello("EXEC foo", "token", "EXEC foo"), (True, None)
        )

    def test_bare_exec_word_is_plain_secret(self):
        self.assertEqual(
            _parse_hello("EXEC", "token", "EXEC"), (True, None)
        )
        self.assertEqual(
            _parse_hello("EXEC", "token", "tok"), (False, None)
        )


class ExitCodeMapTest(unittest.TestCase):
    def test_normal_codes_pass_through(self):
        self.assertEqual(_exit_code_from_returncode(0), 0)
        self.assertEqual(_exit_code_from_returncode(3), 3)

    def test_signal_death_maps_to_128_plus_signo(self):
        self.assertEqual(_exit_code_from_returncode(-9), 137)
        self.assertEqual(_exit_code_from_returncode(-15), 143)


class ServeExecTest(unittest.TestCase):
    def _run(self, argv):
        a, b = socket.socketpair()
        result = {}
        worker = threading.Thread(
            target=lambda: result.setdefault(
                "res", _serve_exec(b, argv)
            ),
            daemon=True,
        )
        worker.start()
        try:
            out = bytearray()
            code = None
            while True:
                ftype, payload = recv_frame(a)
                if ftype == FRAME_STDOUT:
                    out += payload
                elif ftype == FRAME_EXIT:
                    code = struct.unpack("!i", payload)[0]
                    break
        finally:
            a.close()
            worker.join(timeout=10)
            b.close()
        return bytes(out), code, result["res"]

    def test_echo(self):
        out, code, res = self._run(
            [sys.executable, "-c", "print('exec-ok')"]
        )
        self.assertEqual(code, 0)
        self.assertIn(b"exec-ok", out)
        self.assertEqual(res.reason, "ended")

    def test_exit_code_passes_through(self):
        _out, code, _res = self._run(
            [sys.executable, "-c", "import sys; sys.exit(3)"]
        )
        self.assertEqual(code, 3)

    def test_umlaut_output(self):
        out, code, _res = self._run(
            [sys.executable, "-c", "print('Grüße')"]
        )
        self.assertEqual(code, 0)
        self.assertIn("Grüße".encode("utf-8"), out)

    def test_stderr_is_merged(self):
        out, code, _res = self._run(
            [sys.executable, "-c", "import sys; sys.stderr.write('err-x')"]
        )
        self.assertEqual(code, 0)
        self.assertIn(b"err-x", out)

    def test_unknown_program_gives_127(self):
        _out, code, res = self._run(["ptt-no-such-program-xyz"])
        self.assertEqual(code, 127)
        self.assertEqual(res.reason, "ended")

    @unittest.skipIf(os.name == "nt", "POSIX signals only")
    def test_signal_death_gives_128_plus_signo(self):
        _out, code, res = self._run(
            [
                sys.executable, "-c",
                "import os, signal; "
                "os.kill(os.getpid(), signal.SIGTERM)",
            ]
        )
        self.assertEqual(code, 128 + signal.SIGTERM)
        self.assertEqual(res.reason, "ended")

    def test_empty_argv_raises(self):
        a, b = socket.socketpair()
        try:
            with self.assertRaises(ValueError):
                _serve_exec(b, [])
        finally:
            a.close()
            b.close()

    def test_stdin_piping_with_eof_marker(self):
        argv = [
            sys.executable, "-c",
            "import sys; sys.stdout.write(sys.stdin.read())",
        ]
        a, b = socket.socketpair()
        worker = threading.Thread(
            target=_serve_exec, args=(b, argv), daemon=True
        )
        worker.start()
        try:
            send_frame(a, FRAME_STDIN, b"hello-")
            send_frame(a, FRAME_STDIN, b"pipe")
            send_frame(a, FRAME_STDIN, b"")  # EOF marker
            out = bytearray()
            code = None
            while True:
                ftype, payload = recv_frame(a)
                if ftype == FRAME_STDOUT:
                    out += payload
                elif ftype == FRAME_EXIT:
                    code = struct.unpack("!i", payload)[0]
                    break
        finally:
            a.close()
            worker.join(timeout=10)
            b.close()
        self.assertEqual(code, 0)
        self.assertEqual(bytes(out), b"hello-pipe")


class ExecSessionTest(unittest.TestCase):
    def _captured_stdout(self):
        raw = io.BytesIO()
        wrapper = io.TextIOWrapper(raw, encoding="utf-8")
        # Keep the wrapper alive past the block: its GC would close raw.
        self._cap_wrapper = wrapper

        @contextlib.contextmanager
        def _ctx():
            old = sys.stdout
            sys.stdout = wrapper
            try:
                yield raw
            finally:
                wrapper.flush()
                sys.stdout = old

        return _ctx()

    def _empty_stdin(self):
        return mock.patch.object(
            sys, "stdin", types.SimpleNamespace(buffer=io.BytesIO(b""))
        )

    def test_stdout_and_exit_code(self):
        a, b = socket.socketpair()
        try:
            send_frame(b, FRAME_STDOUT, "Grüße".encode("utf-8"))
            send_frame(b, FRAME_EXIT, struct.pack("!i", 5))
            b.close()
            with self._captured_stdout() as raw, self._empty_stdin():
                code = _run_exec_session(a, False)
        finally:
            a.close()
        self.assertEqual(code, 5)
        self.assertIn("Grüße".encode("utf-8"), raw.getvalue())

    def test_abort_gives_1_with_message(self):
        a, b = socket.socketpair()
        b.close()  # EOF before EXIT
        try:
            with self._captured_stdout() as raw, self._empty_stdin():
                code = _run_exec_session(a, False)
        finally:
            a.close()
        self.assertEqual(code, 1)
        self.assertIn("abgebrochen", raw.getvalue().decode("utf-8"))

    def test_expired_deadline_returns_124(self):
        a, b = socket.socketpair()
        try:
            with self._captured_stdout() as raw, self._empty_stdin():
                code = _run_exec_session(
                    a, False, deadline=time.monotonic() - 1
                )
        finally:
            a.close()
            b.close()
        self.assertEqual(code, 124)
        self.assertIn("Zeitlimit", raw.getvalue().decode("utf-8"))

    def test_explicit_out_stream_gets_payload(self):
        a, b = socket.socketpair()
        try:
            send_frame(b, FRAME_STDOUT, b"payload-x")
            send_frame(b, FRAME_EXIT, struct.pack("!i", 0))
            b.close()
            payload = io.BytesIO()
            with self._captured_stdout() as raw, self._empty_stdin():
                code = _run_exec_session(a, False, _out=payload)
        finally:
            a.close()
        self.assertEqual(code, 0)
        self.assertEqual(payload.getvalue(), b"payload-x")
        self.assertEqual(raw.getvalue(), b"")


class ExecStdinTest(unittest.TestCase):
    def _fake_stdin(self, data: bytes):
        return mock.patch.object(
            sys, "stdin", types.SimpleNamespace(buffer=io.BytesIO(data))
        )

    def _captured_stdout(self):
        raw = io.BytesIO()
        wrapper = io.TextIOWrapper(raw, encoding="utf-8")
        self._cap_wrapper = wrapper

        @contextlib.contextmanager
        def _ctx():
            old = sys.stdout
            sys.stdout = wrapper
            try:
                yield raw
            finally:
                wrapper.flush()
                sys.stdout = old

        return _ctx()

    def test_pipes_data_then_eof(self):
        a, b = socket.socketpair()
        seen = {"data": bytearray(), "eof": False}

        def _stub():
            try:
                while True:
                    ftype, payload = recv_frame(b)
                    if ftype != FRAME_STDIN:
                        continue
                    if not payload:
                        seen["eof"] = True
                        break
                    seen["data"] += payload
                send_frame(b, FRAME_STDOUT, b"stub-out")
                send_frame(b, FRAME_EXIT, struct.pack("!i", 0))
            except (OSError, ValueError):
                pass

        worker = threading.Thread(target=_stub, daemon=True)
        worker.start()
        try:
            with self._captured_stdout() as raw, self._fake_stdin(b"piped-data"):
                code = _run_exec_session(a, False)
        finally:
            a.close()
            worker.join(timeout=10)
            b.close()
        self.assertEqual(code, 0)
        self.assertIn(b"stub-out", raw.getvalue())
        self.assertEqual(bytes(seen["data"]), b"piped-data")
        self.assertTrue(seen["eof"])

    def test_empty_stdin_sends_only_eof(self):
        a, b = socket.socketpair()
        frames = []

        def _stub():
            try:
                while True:
                    ftype, payload = recv_frame(b)
                    if ftype != FRAME_STDIN:
                        continue
                    frames.append(payload)
                    if not payload:
                        break
                send_frame(b, FRAME_EXIT, struct.pack("!i", 0))
            except (OSError, ValueError):
                pass

        worker = threading.Thread(target=_stub, daemon=True)
        worker.start()
        try:
            with self._captured_stdout() as raw, self._fake_stdin(b""):
                code = _run_exec_session(a, False)
        finally:
            a.close()
            worker.join(timeout=10)
            b.close()
        self.assertEqual(code, 0)
        self.assertEqual(frames, [b""])


class ExecLoopbackTest(unittest.TestCase):
    def _run_host_once(self, port, cert_dir):
        from ptt.host import default_shell, run_host

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

    def _exec(self, argv, token=TOKEN, stdin_data: bytes = b""):
        code, out, _err = self._exec_streams(
            argv, token=token, stdin_data=stdin_data
        )
        return code, out

    def _exec_streams(
        self, argv, token=TOKEN, stdin_data: bytes = b"", quiet=False,
        verbose=False,
    ):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            port = _free_tcp_port()
            thread = self._run_host_once(port, cert_dir)
            wait_for_port(port)
            raw = io.BytesIO()
            wrapper = io.TextIOWrapper(raw, encoding="utf-8")
            self._loop_wrapper = wrapper  # keep alive: GC would close raw
            old = sys.stdout
            sys.stdout = wrapper
            fake_stdin = types.SimpleNamespace(
                buffer=io.BytesIO(stdin_data)
            )
            err_buf = io.StringIO()
            with (
                mock.patch.object(sys, "stdin", fake_stdin),
                contextlib.redirect_stderr(err_buf),
            ):
                try:
                    code = run_exec(
                        "127.0.0.1", port, token, "never", argv=argv,
                        quiet=quiet, verbose=verbose,
                    )
                finally:
                    wrapper.flush()
                    sys.stdout = old
            thread.join(timeout=15)
            self.assertFalse(thread.is_alive())
            return code, raw.getvalue(), err_buf.getvalue()

    def test_echo(self):
        code, out = self._exec(
            [sys.executable, "-c", "print('exec-ok')"]
        )
        self.assertEqual(code, 0)
        self.assertIn(b"exec-ok", out)

    def test_exit_code_3(self):
        code, _out = self._exec(
            [sys.executable, "-c", "import sys; sys.exit(3)"]
        )
        self.assertEqual(code, 3)

    def test_umlauts(self):
        code, out = self._exec([sys.executable, "-c", "print('Grüße')"])
        self.assertEqual(code, 0)
        self.assertIn("Grüße".encode("utf-8"), out)

    def test_unknown_program_127(self):
        code, _out = self._exec(["ptt-no-such-program-xyz"])
        self.assertEqual(code, 127)

    def test_wrong_token_denied(self):
        code, out = self._exec(
            [sys.executable, "-c", "print('x')"], token="wrong-token"
        )
        self.assertEqual(code, 1)
        self.assertIn("Zugriff verweigert", out.decode("utf-8"))

    def test_quiet_stdout_is_payload_only(self):
        code, out, err = self._exec_streams(
            [sys.executable, "-c", "print('quiet-ok')"], quiet=True
        )
        self.assertEqual(code, 0)
        self.assertEqual(out, "quiet-ok\n".encode("utf-8"))
        self.assertIn("Verbinde mit", err)

    def test_quiet_denied_goes_to_stderr(self):
        code, out, err = self._exec_streams(
            [sys.executable, "-c", "print('x')"],
            token="wrong-token",
            quiet=True,
        )
        self.assertEqual(code, 1)
        self.assertEqual(out, b"")
        self.assertIn("Zugriff verweigert", err)

    def test_verbose_phases_in_order(self):
        code, _out, err = self._exec_streams(
            [sys.executable, "-c", "print('v-ok')"], verbose=True
        )
        self.assertEqual(code, 0)
        phases = [
            "TCP verbunden", "TLS-Handshake", "Host geprüft",
            "Auth ok", "Modus: exec",
        ]
        positions = [err.index(phase) for phase in phases]
        self.assertEqual(positions, sorted(positions))

    def test_default_is_silent_on_stderr(self):
        code, _out, err = self._exec_streams(
            [sys.executable, "-c", "print('v-ok')"]
        )
        self.assertEqual(code, 0)
        self.assertEqual(err, "")

    def test_overlong_command_rejected(self):
        code, out = self._exec(
            [sys.executable, "-c", "x = '" + "y" * 2000 + "'"]
        )
        self.assertEqual(code, 2)
        self.assertIn("zu lang", out.decode("utf-8"))

    def test_empty_argv_rejected(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = run_exec("127.0.0.1", 1, TOKEN, "never", argv=[])
        self.assertEqual(code, 2)
        self.assertIn("braucht einen Befehl", buf.getvalue())

    def test_piped_stdin_loopback(self):
        code, out = self._exec(
            [
                sys.executable, "-c",
                "import sys; print('got:' + sys.stdin.read())",
            ],
            stdin_data="pipe-in".encode("utf-8"),
        )
        self.assertEqual(code, 0)
        self.assertIn("got:pipe-in".encode("utf-8"), out)

    def test_empty_stdin_loopback(self):
        code, out = self._exec(
            [sys.executable, "-c", "print('no-stdin-ok')"],
            stdin_data=b"",
        )
        self.assertEqual(code, 0)
        self.assertIn(b"no-stdin-ok", out)


if __name__ == "__main__":
    unittest.main()
