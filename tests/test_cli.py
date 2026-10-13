"""Smoke tests for the CLI parser."""
import contextlib
import io
import os
import tempfile
import unittest
from unittest import mock

from ptt.cli import (
    _parse_timeout,
    _resolve_opt,
    _resolve_token,
    _warn_short_token,
    build_parser,
    main,
)
from ptt.host import DEFAULT_PORT, _validate_shell, default_shell, run_host


class ParserTest(unittest.TestCase):
    def setUp(self):
        self.parser = build_parser()

    def test_host_defaults(self):
        args = self.parser.parse_args(["host"])
        self.assertEqual(args.command, "host")
        self.assertEqual(args.bind, "0.0.0.0")
        self.assertIsNone(args.port)  # resolved in main(): CLI > PTT_PORT
        self.assertIsNone(args.shell)
        self.assertIsNone(args.token)
        self.assertIsNone(args.token_file)
        self.assertIsNone(args.cert_dir)
        self.assertFalse(args.once)
        self.assertEqual(args.color, "auto")
        self.assertIsNone(args.name)
        self.assertIsNone(args.pin)
        self.assertTrue(args.discover)
        self.assertEqual(args.idle_timeout, 0.0)
        self.assertEqual(args.max_session, 0.0)
        self.assertEqual(args.max_sessions, 1)
        self.assertIsNone(args.transfer_dir)
        self.assertEqual(args.max_transfer_size, 0)

    def test_host_options(self):
        args = self.parser.parse_args(
            [
                "host",
                "--bind", "127.0.0.1",
                "--port", "9999",
                "--shell", "/bin/sh",
                "--token", "secret",
                "--cert-dir", "/tmp/certs",
                "--once",
                "--color", "never",
                "--name", "box",
                "--pin", "123456",
                "--no-discover",
            ]
        )
        self.assertEqual(args.bind, "127.0.0.1")
        self.assertEqual(args.port, 9999)
        self.assertEqual(args.shell, "/bin/sh")
        self.assertEqual(args.token, "secret")
        self.assertEqual(args.cert_dir, "/tmp/certs")
        self.assertTrue(args.once)
        self.assertEqual(args.color, "never")
        self.assertEqual(args.name, "box")
        self.assertEqual(args.pin, "123456")
        self.assertFalse(args.discover)

    def test_connect_defaults(self):
        args = self.parser.parse_args(["connect"])
        self.assertEqual(args.command, "connect")
        self.assertIsNone(args.host)
        self.assertIsNone(args.port)  # resolved in main(): CLI > PTT_PORT
        self.assertEqual(args.color, "auto")
        self.assertIsNone(args.token)
        self.assertIsNone(args.token_file)
        self.assertEqual(args.retry, 0)
        self.assertEqual(args.retry_delay, 2.0)
        self.assertIsNone(args.put)
        self.assertIsNone(args.get)

    def test_connect_retry_options(self):
        args = self.parser.parse_args(
            ["connect", "h", "--retry", "3", "--retry-delay", "0.5"]
        )
        self.assertEqual(args.retry, 3)
        self.assertEqual(args.retry_delay, 0.5)

    def test_put_and_transfer_dir_options(self):
        args = self.parser.parse_args(["connect", "h", "--put", "f.bin:neu"])
        self.assertEqual(args.put, ["f.bin:neu"])
        args = self.parser.parse_args(["host", "--transfer-dir", "/tmp/x"])
        self.assertEqual(args.transfer_dir, "/tmp/x")

    def test_get_option(self):
        args = self.parser.parse_args(["connect", "h", "--get", "r.bin:l"])
        self.assertEqual(args.get, ["r.bin:l"])

    def test_put_get_repeatable_and_mixed(self):
        args = self.parser.parse_args(
            ["connect", "h", "--put", "a", "--get", "b", "--put", "c"]
        )
        self.assertEqual(args.put, ["a", "c"])
        self.assertEqual(args.get, ["b"])

    def test_fresh_option(self):
        args = self.parser.parse_args(["connect", "h", "--put", "f"])
        self.assertEqual(args.fresh, False)
        self.assertEqual(args.put, ["f"])
        args = self.parser.parse_args(["connect", "h", "--put", "f", "--fresh"])
        self.assertEqual(args.fresh, True)

    def test_exec_option(self):
        args = self.parser.parse_args(["exec", "h", "uptime", "now"])
        self.assertEqual(args.host, "h")
        self.assertEqual(args.argv, ["uptime", "now"])
        self.assertEqual(args.retry, 0)
        # Options work after the host (connect-style); dashed command
        # args need the `--` separator.
        args = self.parser.parse_args(["exec", "h", "--", "echo", "-n", "x"])
        self.assertEqual(args.argv, ["echo", "-n", "x"])
        args = self.parser.parse_args(["exec", "h", "--port", "9999", "echo"])
        self.assertEqual(args.port, 9999)
        self.assertEqual(args.argv, ["echo"])
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            with self.assertRaises(SystemExit) as ctx:
                self.parser.parse_args(["exec"])
        self.assertEqual(ctx.exception.code, 2)

    def test_exec_without_command_rejected(self):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            with self.assertRaises(SystemExit) as ctx:
                main(["exec", "h"])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("BEFEHL", buf.getvalue())

    def test_timeout_option(self):
        args = self.parser.parse_args(["connect", "h"])
        self.assertIsNone(args.timeout)  # resolved in main(): CLI > PTT_TIMEOUT
        args = self.parser.parse_args(["connect", "h", "--timeout", "12.5"])
        self.assertEqual(args.timeout, 12.5)
        args = self.parser.parse_args(["exec", "h", "--timeout", "3", "uptime"])
        self.assertEqual(args.timeout, 3.0)

    def test_timeout_negative_rejected(self):
        for argv in (
            ["connect", "h", "--timeout", "-1"],
            ["exec", "h", "--timeout", "-1", "uptime"],
        ):
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                with self.assertRaises(SystemExit) as ctx:
                    main(argv)
            self.assertEqual(ctx.exception.code, 2)
            self.assertIn("--timeout", buf.getvalue())

    def test_scan_option(self):
        args = self.parser.parse_args(["scan"])
        self.assertEqual(args.json, False)
        args = self.parser.parse_args(["scan", "--json"])
        self.assertEqual(args.json, True)

    def test_scan_dispatched(self):
        with mock.patch("ptt.cli.run_scan", return_value=0) as m:
            self.assertEqual(main(["scan", "--json"]), 0)
        m.assert_called_once_with(color_mode="auto", as_json=True)

    def test_max_transfer_size_option(self):
        args = self.parser.parse_args(["host", "--max-transfer-size", "10M"])
        self.assertEqual(args.max_transfer_size, 10 * 1024**2)
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            with self.assertRaises(SystemExit) as ctx:
                self.parser.parse_args(["host", "--max-transfer-size", "xx"])
        self.assertEqual(ctx.exception.code, 2)

    def test_hosts_reject_negative_transfer_size(self):
        with self.assertRaisesRegex(ValueError, "transfer-size"):
            run_host(
                bind="127.0.0.1",
                port=1,
                shell=default_shell(),
                token="t" * 20,
                cert_dir="/nonexistent-cert-dir-ptt",
                max_transfer_size=-1,
            )

    def test_put_and_get_mixed_passed_as_lists(self):
        with (
            mock.patch.dict(os.environ, {"PTT_TOKEN": "env-token"}),
            mock.patch("ptt.cli.run_client", return_value=0) as m,
        ):
            self.assertEqual(
                main(["connect", "h", "--put", "a", "--get", "b"]),
                0,
            )
        m.assert_called_once_with(
            "h", 8022, "env-token", "auto",
            retry=0, retry_delay=2.0, put=["a"], get=["b"], fresh=False,
            timeout=0, quiet=False, verbose=False,
        )

    def test_fresh_needs_put_or_get(self):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            with self.assertRaises(SystemExit) as ctx:
                main(["connect", "h", "--fresh"])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("--fresh", buf.getvalue())

    def test_bad_transfer_dir_rejected(self):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            with self.assertRaises(SystemExit) as ctx:
                main(
                    [
                        "host",
                        "--token",
                        "t" * 20,
                        "--transfer-dir",
                        "/nonexistent-dir-ptt",
                    ]
                )
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("transfer-dir", buf.getvalue())

    def test_negative_retry_rejected(self):
        for argv in (
            ["connect", "h", "--retry", "-1"],
            ["connect", "h", "--retry-delay", "-1"],
        ):
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                with self.assertRaises(SystemExit) as ctx:
                    main(argv)
            self.assertEqual(ctx.exception.code, 2)

    def test_connect_color_option(self):
        args = self.parser.parse_args(["connect", "h", "--color", "never"])
        self.assertEqual(args.color, "never")

    def test_quiet_option(self):
        args = self.parser.parse_args(["connect", "h"])
        self.assertFalse(args.quiet)
        args = self.parser.parse_args(["connect", "h", "--quiet"])
        self.assertTrue(args.quiet)
        args = self.parser.parse_args(["exec", "h", "--quiet", "uptime"])
        self.assertTrue(args.quiet)
        self.assertEqual(args.argv, ["uptime"])

    def test_verbose_option(self):
        args = self.parser.parse_args(["connect", "h"])
        self.assertFalse(args.verbose)
        args = self.parser.parse_args(["connect", "h", "--verbose"])
        self.assertTrue(args.verbose)
        args = self.parser.parse_args(["exec", "h", "--verbose", "uptime"])
        self.assertTrue(args.verbose)
        args = self.parser.parse_args(["host", "--verbose"])
        self.assertTrue(args.verbose)

    def test_connect_options(self):
        args = self.parser.parse_args(
            ["connect", "192.168.1.5", "--port", "9999", "--token", "t"]
        )
        self.assertEqual(args.host, "192.168.1.5")
        self.assertEqual(args.port, 9999)
        self.assertEqual(args.token, "t")

    def test_update_parses(self):
        args = self.parser.parse_args(["update"])
        self.assertEqual(args.command, "update")
        self.assertFalse(args.yes)
        args = self.parser.parse_args(["update", "--yes"])
        self.assertTrue(args.yes)

    def test_bad_ports_rejected(self):
        for argv in (
            ["host", "--port", "0"],
            ["host", "--port", "70000"],
            ["host", "--port", "abc"],
            ["connect", "127.0.0.1", "--port", "-1"],
        ):
            with self.subTest(argv=argv):
                buf = io.StringIO()
                with contextlib.redirect_stderr(buf):
                    with self.assertRaises(SystemExit) as ctx:
                        self.parser.parse_args(argv)
                self.assertEqual(ctx.exception.code, 2)

    def test_hosts_reject_bad_shell(self):
        with self.assertRaises(ValueError):
            run_host(
                bind="127.0.0.1",
                port=1,
                shell="/nonexistent-shell-ptt",
                token="t" * 20,
                cert_dir="/nonexistent-cert-dir-ptt",
            )

    def test_hosts_reject_bad_pin(self):
        for pin in ("123", "12345", "1" * 13, "ab"):
            with self.subTest(pin=pin):
                with self.assertRaisesRegex(ValueError, "6 bis 12"):
                    run_host(
                        bind="127.0.0.1",
                        port=1,
                        shell=default_shell(),
                        token=None,
                        cert_dir="/nonexistent-cert-dir-ptt",
                        pin=pin,
                    )

    def test_validate_shell_accepts_default(self):
        _validate_shell(default_shell())  # must not raise

    def test_token_file_option_parses(self):
        args = self.parser.parse_args(["connect", "h", "--token-file", "t.txt"])
        self.assertEqual(args.token_file, "t.txt")

    def test_idle_timeout_option(self):
        args = self.parser.parse_args(["host", "--idle-timeout", "5"])
        self.assertEqual(args.idle_timeout, 5.0)

    def test_negative_idle_timeout_rejected(self):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            with self.assertRaises(SystemExit) as ctx:
                main(["host", "--idle-timeout", "-1"])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("idle-timeout", buf.getvalue())

    def test_max_session_option(self):
        args = self.parser.parse_args(["host", "--max-session", "30"])
        self.assertEqual(args.max_session, 30.0)

    def test_max_sessions_option(self):
        args = self.parser.parse_args(["host", "--max-sessions", "5"])
        self.assertEqual(args.max_sessions, 5)
        args = self.parser.parse_args(["host", "--max-sessions", "0"])
        self.assertEqual(args.max_sessions, 0)

    def test_negative_max_sessions_rejected(self):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            with self.assertRaises(SystemExit) as ctx:
                main(["host", "--max-sessions", "-1"])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("max-sessions", buf.getvalue())

    def test_negative_max_session_rejected(self):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            with self.assertRaises(SystemExit) as ctx:
                main(["host", "--max-session", "-2"])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("max-session", buf.getvalue())

    def _help_text(self, argv: list) -> str:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with self.assertRaises(SystemExit) as ctx:
                self.parser.parse_args(argv)
        self.assertEqual(ctx.exception.code, 0)
        return buf.getvalue()

    def test_help_exits_zero(self):
        self.assertIn("Listen-Port", self._help_text(["host", "--help"]))

    def test_main_help_shows_examples(self):
        out = self._help_text(["--help"])
        self.assertIn("Beispiele:", out)
        self.assertIn("ptt connect", out)
        self.assertIn("ptt host", out)
        self.assertIn("ptt update", out)

    def test_connect_help_explains_search_vs_direct(self):
        out = self._help_text(["connect", "--help"])
        self.assertIn("suchen", out)
        self.assertIn("direkt", out)


class ResolveTokenTest(unittest.TestCase):
    def test_none_when_nothing_given(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(_resolve_token(None, None))

    def test_flag_wins_and_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "t.txt")
            with open(path, "w") as f:
                f.write("from-file\n")
            with mock.patch.dict(os.environ, {"PTT_TOKEN": "from-env"}):
                buf = io.StringIO()
                with contextlib.redirect_stderr(buf):
                    token = _resolve_token("from-flag", path)
        self.assertEqual(token, "from-flag")
        self.assertIn("ps", buf.getvalue())

    def test_env_before_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "t.txt")
            with open(path, "w") as f:
                f.write("from-file\n")
            with mock.patch.dict(os.environ, {"PTT_TOKEN": "from-env"}):
                self.assertEqual(_resolve_token(None, path), "from-env")

    def test_file_content_stripped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "t.txt")
            with open(path, "w") as f:
                f.write("  secret-123\n")
            with mock.patch.dict(os.environ, {}, clear=True):
                self.assertEqual(_resolve_token(None, path), "secret-123")

    def test_missing_file_raises(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                _resolve_token(None, "/nonexistent-token-file-ptt")

    def test_empty_file_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "t.txt")
            with open(path, "w") as f:
                f.write("  \n")
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaises(ValueError):
                    _resolve_token(None, path)


class WarnShortTokenTest(unittest.TestCase):
    def _warned(self, token):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            _warn_short_token(token)
        return buf.getvalue()

    def test_short_token_warns(self):
        self.assertIn("kurz", self._warned("short"))

    def test_long_token_silent(self):
        self.assertEqual(self._warned("x" * 16), "")

    def test_none_silent(self):
        self.assertEqual(self._warned(None), "")

    def test_host_main_warns_for_short_token(self):
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch("ptt.cli.run_host"),
        ):
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                main(["host", "--token", "short", "--no-discover"])
        self.assertIn("kurz", buf.getvalue())

    def test_connect_main_stays_silent_for_pin(self):
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch("ptt.cli.run_client", return_value=0),
        ):
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                main(["connect", "h", "--token", "123456"])
        self.assertNotIn("kurz", buf.getvalue())


class MainWiringTest(unittest.TestCase):
    def test_connect_passes_resolved_token(self):
        with (
            mock.patch.dict(os.environ, {"PTT_TOKEN": "env-token"}),
            mock.patch("ptt.cli.run_client", return_value=0) as m,
        ):
            self.assertEqual(
                main(["connect", "example", "--port", "9999", "--color", "never"]),
                0,
            )
        m.assert_called_once_with(
            "example", 9999, "env-token", "never",
            retry=0, retry_delay=2.0, put=None, get=None, fresh=False,
            timeout=0, quiet=False, verbose=False,
        )

    def test_exec_passed_to_run_exec(self):
        with (
            mock.patch.dict(os.environ, {"PTT_TOKEN": "env-token"}),
            mock.patch("ptt.cli.run_exec", return_value=3) as m,
        ):
            self.assertEqual(
                main(["exec", "example", "uptime"]),
                3,
            )
        m.assert_called_once_with(
            "example", 8022, "env-token", "auto",
            retry=0, retry_delay=2.0, argv=["uptime"], timeout=0,
            quiet=False, verbose=False,
        )

    def test_timeout_passed_to_client(self):
        with (
            mock.patch.dict(os.environ, {"PTT_TOKEN": "env-token"}),
            mock.patch("ptt.cli.run_client", return_value=0) as m,
        ):
            self.assertEqual(
                main(["connect", "example", "--timeout", "5"]),
                0,
            )
        m.assert_called_once_with(
            "example", 8022, "env-token", "auto",
            retry=0, retry_delay=2.0, put=None, get=None, fresh=False,
            timeout=5.0, quiet=False, verbose=False,
        )

    def test_timeout_passed_to_run_exec(self):
        with (
            mock.patch.dict(os.environ, {"PTT_TOKEN": "env-token"}),
            mock.patch("ptt.cli.run_exec", return_value=0) as m,
        ):
            self.assertEqual(
                main(["exec", "example", "--timeout", "2.5", "uptime"]),
                0,
            )
        m.assert_called_once_with(
            "example", 8022, "env-token", "auto",
            retry=0, retry_delay=2.0, argv=["uptime"], timeout=2.5,
            quiet=False, verbose=False,
        )

    def test_fresh_passed_to_client(self):
        with (
            mock.patch.dict(os.environ, {"PTT_TOKEN": "env-token"}),
            mock.patch("ptt.cli.run_client", return_value=0) as m,
        ):
            self.assertEqual(
                main([
                    "connect", "example", "--put", "f.bin", "--fresh",
                ]),
                0,
            )
        m.assert_called_once_with(
            "example", 8022, "env-token", "auto",
            retry=0, retry_delay=2.0, put=["f.bin"], get=None, fresh=True,
            timeout=0, quiet=False, verbose=False,
        )

    def test_quiet_passed_to_client(self):
        with (
            mock.patch.dict(os.environ, {"PTT_TOKEN": "env-token"}),
            mock.patch("ptt.cli.run_client", return_value=0) as m,
        ):
            self.assertEqual(
                main(["connect", "example", "--quiet"]),
                0,
            )
        m.assert_called_once_with(
            "example", 8022, "env-token", "auto",
            retry=0, retry_delay=2.0, put=None, get=None, fresh=False,
            timeout=0, quiet=True, verbose=False,
        )

    def test_quiet_passed_to_run_exec(self):
        with (
            mock.patch.dict(os.environ, {"PTT_TOKEN": "env-token"}),
            mock.patch("ptt.cli.run_exec", return_value=0) as m,
        ):
            self.assertEqual(
                main(["exec", "example", "--quiet", "uptime"]),
                0,
            )
        m.assert_called_once_with(
            "example", 8022, "env-token", "auto",
            retry=0, retry_delay=2.0, argv=["uptime"], timeout=0,
            quiet=True, verbose=False,
        )

    def test_verbose_passed_to_client(self):
        with (
            mock.patch.dict(os.environ, {"PTT_TOKEN": "env-token"}),
            mock.patch("ptt.cli.run_client", return_value=0) as m,
        ):
            self.assertEqual(
                main(["connect", "example", "--verbose"]),
                0,
            )
        m.assert_called_once_with(
            "example", 8022, "env-token", "auto",
            retry=0, retry_delay=2.0, put=None, get=None, fresh=False,
            timeout=0, quiet=False, verbose=True,
        )

    def test_verbose_passed_to_run_exec(self):
        with (
            mock.patch.dict(os.environ, {"PTT_TOKEN": "env-token"}),
            mock.patch("ptt.cli.run_exec", return_value=0) as m,
        ):
            self.assertEqual(
                main(["exec", "example", "--verbose", "uptime"]),
                0,
            )
        m.assert_called_once_with(
            "example", 8022, "env-token", "auto",
            retry=0, retry_delay=2.0, argv=["uptime"], timeout=0,
            quiet=False, verbose=True,
        )

    def test_verbose_passed_to_run_host(self):
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch("ptt.cli.run_host") as m,
        ):
            self.assertEqual(
                main(["host", "--no-discover", "--verbose"]), 0
            )
        self.assertTrue(m.call_args.kwargs["verbose"])

    def test_host_passes_resolved_token(self):
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch("ptt.cli.run_host") as m,
        ):
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                self.assertEqual(
                    main(["host", "--token", "flag-token", "--no-discover"]), 0
                )
        self.assertIn("ps", buf.getvalue())
        self.assertEqual(m.call_args.kwargs["token"], "flag-token")


class ResolveOptTest(unittest.TestCase):
    def setUp(self):
        self.parser = build_parser()

    def test_cli_wins_over_env(self):
        with mock.patch.dict(os.environ, {"PTT_X": "from-env"}):
            self.assertEqual(
                _resolve_opt("cli", "PTT_X", None, "dflt", self.parser),
                "cli",
            )

    def test_env_used_when_no_cli(self):
        with mock.patch.dict(os.environ, {"PTT_X": "  from-env  "}):
            self.assertEqual(
                _resolve_opt(None, "PTT_X", None, "dflt", self.parser),
                "from-env",
            )

    def test_default_when_nothing_set(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                _resolve_opt(None, "PTT_X", None, "dflt", self.parser),
                "dflt",
            )

    def test_empty_env_counts_as_unset(self):
        for raw in ("", "   "):
            with (
                self.subTest(raw=raw),
                mock.patch.dict(os.environ, {"PTT_X": raw}),
            ):
                self.assertEqual(
                    _resolve_opt(None, "PTT_X", None, "dflt", self.parser),
                    "dflt",
                )

    def test_parse_applies_to_env(self):
        with mock.patch.dict(os.environ, {"PTT_X": "42"}):
            self.assertEqual(
                _resolve_opt(None, "PTT_X", int, 0, self.parser), 42
            )

    def test_bad_env_fails_with_exit_2(self):
        buf = io.StringIO()
        with (
            mock.patch.dict(os.environ, {"PTT_X": "abc"}),
            contextlib.redirect_stderr(buf),
        ):
            with self.assertRaises(SystemExit) as ctx:
                _resolve_opt(None, "PTT_X", int, 0, self.parser)
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("PTT_X", buf.getvalue())

    def test_parse_timeout_values(self):
        self.assertEqual(_parse_timeout("12.5"), 12.5)
        self.assertEqual(_parse_timeout("0"), 0.0)
        for raw in ("-1", "xyz"):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    _parse_timeout(raw)


class EnvFallbackTest(unittest.TestCase):
    def test_connect_uses_env(self):
        env = {"PTT_HOST": "envhost", "PTT_PORT": "9999", "PTT_TIMEOUT": "7.5"}
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("ptt.cli.run_client", return_value=0) as m,
        ):
            self.assertEqual(main(["connect"]), 0)
        m.assert_called_once_with(
            "envhost", 9999, None, "auto",
            retry=0, retry_delay=2.0, put=None, get=None, fresh=False,
            timeout=7.5, quiet=False, verbose=False,
        )

    def test_cli_wins_over_env(self):
        env = {"PTT_HOST": "envhost", "PTT_PORT": "9999", "PTT_TIMEOUT": "7.5"}
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("ptt.cli.run_client", return_value=0) as m,
        ):
            self.assertEqual(
                main([
                    "connect", "clihost", "--port", "1111", "--timeout", "3",
                ]),
                0,
            )
        m.assert_called_once_with(
            "clihost", 1111, None, "auto",
            retry=0, retry_delay=2.0, put=None, get=None, fresh=False,
            timeout=3.0, quiet=False, verbose=False,
        )

    def test_empty_env_means_default(self):
        env = {"PTT_HOST": " ", "PTT_PORT": "", "PTT_TIMEOUT": "  "}
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("ptt.cli.run_client", return_value=0) as m,
        ):
            self.assertEqual(main(["connect"]), 0)
        m.assert_called_once_with(
            None, DEFAULT_PORT, None, "auto",
            retry=0, retry_delay=2.0, put=None, get=None, fresh=False,
            timeout=0, quiet=False, verbose=False,
        )

    def test_bad_port_env_rejected(self):
        for raw in ("abc", "0", "99999"):
            with self.subTest(raw=raw):
                buf = io.StringIO()
                with (
                    mock.patch.dict(
                        os.environ, {"PTT_PORT": raw}, clear=True
                    ),
                    contextlib.redirect_stderr(buf),
                ):
                    with self.assertRaises(SystemExit) as ctx:
                        main(["connect", "h"])
                self.assertEqual(ctx.exception.code, 2)
                self.assertIn("PTT_PORT", buf.getvalue())

    def test_bad_timeout_env_rejected(self):
        for raw in ("xyz", "-1"):
            with self.subTest(raw=raw):
                buf = io.StringIO()
                with (
                    mock.patch.dict(
                        os.environ, {"PTT_TIMEOUT": raw}, clear=True
                    ),
                    contextlib.redirect_stderr(buf),
                ):
                    with self.assertRaises(SystemExit) as ctx:
                        main(["connect", "h"])
                self.assertEqual(ctx.exception.code, 2)
                self.assertIn("PTT_TIMEOUT", buf.getvalue())

    def test_exec_honors_port_and_timeout_env(self):
        env = {"PTT_PORT": "9999", "PTT_TIMEOUT": "7.5"}
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("ptt.cli.run_exec", return_value=0) as m,
        ):
            self.assertEqual(main(["exec", "h", "uptime"]), 0)
        m.assert_called_once_with(
            "h", 9999, None, "auto",
            retry=0, retry_delay=2.0, argv=["uptime"], timeout=7.5,
            quiet=False, verbose=False,
        )

    def test_exec_ignores_env_host(self):
        # PTT_HOST is connect-only: a positional HOST plus a positional
        # BEFEHL leaves no unambiguous room for it.
        with (
            mock.patch.dict(os.environ, {"PTT_HOST": "envhost"}, clear=True),
            mock.patch("ptt.cli.run_exec", return_value=0) as m,
        ):
            self.assertEqual(main(["exec", "clihost", "uptime"]), 0)
        m.assert_called_once_with(
            "clihost", DEFAULT_PORT, None, "auto",
            retry=0, retry_delay=2.0, argv=["uptime"], timeout=0,
            quiet=False, verbose=False,
        )

    def test_host_honors_port_env(self):
        with (
            mock.patch.dict(os.environ, {"PTT_PORT": "9999"}, clear=True),
            mock.patch("ptt.cli.run_host") as m,
        ):
            self.assertEqual(main(["host", "--no-discover"]), 0)
        self.assertEqual(m.call_args.kwargs["port"], 9999)

    def test_host_cli_port_wins_over_env(self):
        with (
            mock.patch.dict(os.environ, {"PTT_PORT": "9999"}, clear=True),
            mock.patch("ptt.cli.run_host") as m,
        ):
            self.assertEqual(
                main(["host", "--no-discover", "--port", "1111"]), 0
            )
        self.assertEqual(m.call_args.kwargs["port"], 1111)


if __name__ == "__main__":
    unittest.main()
