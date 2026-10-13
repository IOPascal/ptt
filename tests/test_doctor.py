"""Tests for `ptt doctor`."""
import contextlib
import datetime
import io
import os
import shutil
import socket
import sys
import tempfile
import unittest
from unittest import mock

from ptt.cert import CERT_FILE, KEY_FILE, ensure_cert
from ptt.doctor import (
    CHECKS,
    FIXES,
    _captured_bytes,
    _cert_expiry,
    _free_tcp_port,
    _isolated_home,
    list_checks,
    redact,
    render_report,
    run_checks,
    run_checks_detailed,
    run_doctor,
    run_fix,
    run_report,
    run_self_test,
)
from ptt.host import DEFAULT_PORT


class DoctorTest(unittest.TestCase):
    def test_runs_and_reports_python(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run_doctor()
        self.assertIn(rc, (0, 1))
        out = buf.getvalue()
        self.assertIn("Python", out)
        self.assertIn("PTT-Diagnose", out)

    def test_check_structure(self):
        with tempfile.TemporaryDirectory() as tmp:
            results = run_checks(cert_dir=os.path.join(tmp, "ptt"))
        self.assertEqual(len(results), len(CHECKS))
        for status, message in results:
            self.assertIn(status, ("OK", "WARN", "FAIL"))
            self.assertTrue(message)

    def test_busy_tcp_port_warns(self):
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            blocker.bind(("127.0.0.1", DEFAULT_PORT))
        except OSError:
            self.skipTest(f"port {DEFAULT_PORT} already busy")
        blocker.listen(1)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                results = run_checks_detailed(
                    cert_dir=os.path.join(tmp, "ptt")
                )
        finally:
            blocker.close()
        ports = [c for c in results if c["id"] == "ports"]
        self.assertEqual(len(ports), 1)
        self.assertIn("belegt", ports[0]["message"])

    def test_missing_shell_warns(self):
        with mock.patch(
            "ptt.doctor.default_shell", return_value="/nonexistent-sh-ptt"
        ):
            with tempfile.TemporaryDirectory() as tmp:
                results = run_checks(cert_dir=os.path.join(tmp, "ptt"))
        shells = [message for _, message in results if "sh-ptt" in message]
        self.assertEqual(len(shells), 1)

    def test_no_tls_backend_warns(self):
        with (
            mock.patch("ptt.doctor.shutil.which", return_value=None),
            mock.patch.dict(sys.modules, {"cryptography": None}),
        ):
            with tempfile.TemporaryDirectory() as tmp:
                results = run_checks(cert_dir=os.path.join(tmp, "ptt"))
        backends = [s for s, m in results if "cryptography" in m or "openssl" in m]
        self.assertTrue(backends)
        self.assertTrue(all(status == "WARN" for status in backends))

    def test_invalid_cert_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert_dir = os.path.join(tmp, "ptt")
            os.mkdir(cert_dir)
            with open(os.path.join(cert_dir, "ptt-cert.pem"), "wb") as f:
                f.write(b"broken")
            with open(os.path.join(cert_dir, "ptt-key.pem"), "wb") as f:
                f.write(b"broken")
            results = run_checks(cert_dir=cert_dir)
        certs = [(s, m) for s, m in results if "Zertifikat" in m and "Verzeichnis" not in m]
        self.assertEqual(len(certs), 1)
        self.assertEqual(certs[0][0], "WARN")


class NetCheckTest(unittest.TestCase):
    def _by_id(self, cert_dir=None):
        with tempfile.TemporaryDirectory() as tmp:
            detailed = run_checks_detailed(
                cert_dir=cert_dir or os.path.join(tmp, "ptt")
            )
        return {c["id"]: c for c in detailed}

    def test_tcp_loopback_ok(self):
        check = self._by_id()["net-tcp"]
        self.assertEqual(check["status"], "OK")

    def test_tcp_failure_is_fail(self):
        with mock.patch(
            "socket.socket", side_effect=OSError("net down")
        ):
            check = self._by_id()["net-tcp"]
        self.assertEqual(check["status"], "FAIL")
        self.assertIn("Loopback", check["message"])

    def test_udp_real_run_never_crashes(self):
        check = self._by_id()["net-udp"]
        self.assertIn(check["status"], ("OK", "WARN"))

    def test_udp_success_message(self):
        with mock.patch("socket.socket") as sock_cls:
            sock_cls.return_value.accept.return_value = (mock.Mock(), None)
            check = self._by_id()["net-udp"]
        sock_cls.return_value.sendto.assert_called_once()
        self.assertEqual(check["status"], "OK")
        self.assertIn("Suche", check["message"])

    def test_udp_failure_warns_with_direct_hint(self):
        with mock.patch(
            "socket.socket", side_effect=OSError("no route")
        ):
            check = self._by_id()["net-udp"]
        self.assertEqual(check["status"], "WARN")
        self.assertIn("ptt connect <ip>", check["message"])


class TlsCheckTest(unittest.TestCase):
    def _by_id(self, cert_dir):
        detailed = run_checks_detailed(cert_dir=cert_dir)
        return {c["id"]: c for c in detailed}

    def _fresh_certs(self, tmp):
        try:
            return ensure_cert(os.path.join(tmp, "certs"))
        except RuntimeError as exc:
            self.skipTest(str(exc))

    def test_expiry_fresh_cert_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert, _key = self._fresh_certs(tmp)
            check = self._by_id(os.path.dirname(cert))["cert-expiry"]
        self.assertEqual(check["status"], "OK")
        self.assertIn("Tage", check["message"])

    def test_expiry_soon_warns(self):
        soon = datetime.datetime.now(datetime.timezone.utc)
        soon += datetime.timedelta(days=5, minutes=5)
        with tempfile.TemporaryDirectory() as tmp:
            cert, _key = self._fresh_certs(tmp)
            with mock.patch(
                "ptt.doctor._cert_expiry", return_value=soon
            ):
                check = self._by_id(os.path.dirname(cert))["cert-expiry"]
        self.assertEqual(check["status"], "WARN")
        self.assertIn("5 Tagen", check["message"])

    def test_expiry_past_warns(self):
        past = datetime.datetime.now(datetime.timezone.utc)
        past -= datetime.timedelta(days=1)
        with tempfile.TemporaryDirectory() as tmp:
            cert, _key = self._fresh_certs(tmp)
            with mock.patch(
                "ptt.doctor._cert_expiry", return_value=past
            ):
                check = self._by_id(os.path.dirname(cert))["cert-expiry"]
        self.assertEqual(check["status"], "WARN")
        self.assertIn("abgelaufen", check["message"])

    def test_expiry_unparseable_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert, _key = self._fresh_certs(tmp)
            with mock.patch(
                "ptt.doctor._cert_expiry", return_value=None
            ):
                check = self._by_id(os.path.dirname(cert))["cert-expiry"]
        self.assertEqual(check["status"], "WARN")
        self.assertIn("nicht prüfbar", check["message"])

    def test_expiry_missing_cert_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            check = self._by_id(os.path.join(tmp, "nix"))["cert-expiry"]
        self.assertEqual(check["status"], "OK")

    def test_cert_expiry_parses_real_cert(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert, _key = self._fresh_certs(tmp)
            end = _cert_expiry(cert)
        if end is None:
            self.skipTest("weder openssl noch cryptography")
        now = datetime.datetime.now(datetime.timezone.utc)
        self.assertGreater(end, now)
        self.assertLess((end - now).days, 400)

    def test_cert_expiry_garbage_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.pem")
            with open(path, "wb") as fh:
                fh.write(b"kein-pem")
            self.assertIsNone(_cert_expiry(path))

    def test_cert_key_fresh_pair_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert, _key = self._fresh_certs(tmp)
            check = self._by_id(os.path.dirname(cert))["cert-key"]
        self.assertEqual(check["status"], "OK")

    def test_cert_key_crossed_pair_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert_a, _key_a = self._fresh_certs(tmp)
            other = os.path.join(tmp, "other")
            os.mkdir(other)
            _cert_b, key_b = self._fresh_certs(other)
            mixed = os.path.join(tmp, "mixed")
            os.mkdir(mixed)
            shutil.copy(cert_a, os.path.join(mixed, CERT_FILE))
            shutil.copy(key_b, os.path.join(mixed, KEY_FILE))
            check = self._by_id(mixed)["cert-key"]
        self.assertEqual(check["status"], "FAIL")
        self.assertIn("nicht zusammen", check["message"])

    def test_cert_key_missing_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            check = self._by_id(os.path.join(tmp, "nix"))["cert-key"]
        self.assertEqual(check["status"], "OK")

    def test_cert_key_half_missing_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert, _key = self._fresh_certs(tmp)
            lonely = os.path.join(tmp, "lonely")
            os.mkdir(lonely)
            shutil.copy(cert, os.path.join(lonely, CERT_FILE))
            check = self._by_id(lonely)["cert-key"]
        self.assertEqual(check["status"], "FAIL")
        self.assertIn("fehlt", check["message"])

    def test_cert_key_garbage_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            broken = os.path.join(tmp, "broken")
            os.mkdir(broken)
            for name in (CERT_FILE, KEY_FILE):
                with open(os.path.join(broken, name), "wb") as fh:
                    fh.write(b"kaputt")
            check = self._by_id(broken)["cert-key"]
        self.assertEqual(check["status"], "FAIL")
        self.assertIn("nicht ladbar", check["message"])


class FixTest(unittest.TestCase):
    def _mode(self, path):
        import stat

        return stat.S_IMODE(os.stat(path).st_mode)

    def _broken_home(self, tmp):
        home = os.path.join(tmp, "ptt")
        os.mkdir(home, 0o755)
        sub = os.path.join(home, "sub")
        os.mkdir(sub, 0o755)
        files = []
        for name in ("a.bin", "sub/b.bin"):
            path = os.path.join(home, name)
            with open(path, "wb") as fh:
                fh.write(b"x")
            os.chmod(path, 0o644)
            files.append(path)
        return home, files

    @unittest.skipIf(os.name == "nt", "POSIX-Modi")
    def test_fix_corrects_perms(self):
        with tempfile.TemporaryDirectory() as tmp:
            home, files = self._broken_home(tmp)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_fix(cert_dir=home)
            self.assertEqual(rc, 0)
            self.assertIn("FIXED", buf.getvalue())
            self.assertEqual(self._mode(home), 0o700)
            for path in files:
                with self.subTest(path=path):
                    self.assertEqual(self._mode(path), 0o600)
            # Re-check is green now.
            detailed = run_checks_detailed(cert_dir=home)
            by_id = {c["id"]: c for c in detailed}
            self.assertEqual(by_id["cert-dir"]["status"], "OK")

    @unittest.skipIf(os.name == "nt", "POSIX-Modi")
    def test_second_run_is_idle(self):
        with tempfile.TemporaryDirectory() as tmp:
            home, _files = self._broken_home(tmp)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(run_fix(cert_dir=home), 0)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_fix(cert_dir=home)
            self.assertEqual(rc, 0)
            out = buf.getvalue()
            self.assertIn("korrekt", out)
            self.assertNotIn("FIXED", out)

    @unittest.skipIf(os.name == "nt", "POSIX-Modi")
    def test_dry_run_changes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            home, files = self._broken_home(tmp)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_fix(cert_dir=home, dry_run=True)
            self.assertEqual(rc, 0)
            out = buf.getvalue()
            self.assertIn("Vorschau", out)
            self.assertIn("TODO", out)
            self.assertEqual(self._mode(home), 0o755)
            for path in files:
                self.assertEqual(self._mode(path), 0o644)

    def test_missing_dir_is_idle(self):
        with tempfile.TemporaryDirectory() as tmp:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_fix(cert_dir=os.path.join(tmp, "nix"))
            self.assertEqual(rc, 0)
            self.assertIn("nichts zu tun", buf.getvalue())

    @unittest.skipIf(os.name == "nt", "POSIX-Modi")
    def test_chmod_failure_is_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            home, _files = self._broken_home(tmp)
            buf = io.StringIO()
            with (
                mock.patch("os.chmod", side_effect=OSError("deny")),
                contextlib.redirect_stdout(buf),
            ):
                rc = run_fix(cert_dir=home)
            self.assertEqual(rc, 1)
            self.assertIn("FAIL", buf.getvalue())

    @unittest.skipIf(os.name == "nt", "POSIX fix path only")
    def test_symlinks_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            home, _files = self._broken_home(tmp)
            link = os.path.join(home, "link.bin")
            try:
                os.symlink(os.path.join(home, "a.bin"), link)
            except OSError:
                self.skipTest("Symlinks nicht möglich")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_fix(cert_dir=home)
            self.assertEqual(rc, 0)
            self.assertIn("übersprungen", buf.getvalue())
            self.assertTrue(os.path.islink(link))

    def test_windows_reports_nothing_to_do(self):
        buf = io.StringIO()
        with (
            mock.patch("os.name", "nt"),
            contextlib.redirect_stdout(buf),
        ):
            rc = run_fix(cert_dir="/nonexistent-ptt-fix")
        self.assertEqual(rc, 0)
        self.assertIn("Windows", buf.getvalue())

    def test_fix_registry_shape(self):
        ids = [fix_id for fix_id, _, _ in FIXES]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(ids))


class TransferCheckTest(unittest.TestCase):
    def _by_id(self, target):
        with mock.patch("os.getcwd", return_value=target):
            with tempfile.TemporaryDirectory() as tmp:
                detailed = run_checks_detailed(
                    cert_dir=os.path.join(tmp, "ptt")
                )
        return {c["id"]: c for c in detailed}

    def test_transfer_dir_writable_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            check = self._by_id(tmp)["transfer-dir"]
        self.assertEqual(check["status"], "OK")
        self.assertIn(os.path.basename(tmp), check["message"])

    @unittest.skipIf(os.name == "nt", "POSIX-Modi")
    def test_transfer_dir_readonly_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp, 0o555)
            try:
                check = self._by_id(tmp)["transfer-dir"]
            finally:
                os.chmod(tmp, 0o755)
        self.assertEqual(check["status"], "FAIL")

    def test_transfer_dir_missing_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            check = self._by_id(os.path.join(tmp, "nix"))["transfer-dir"]
        self.assertEqual(check["status"], "FAIL")

    def test_transfer_dir_getcwd_error_fails(self):
        with mock.patch("os.getcwd", side_effect=OSError("weg")):
            with tempfile.TemporaryDirectory() as tmp:
                detailed = run_checks_detailed(
                    cert_dir=os.path.join(tmp, "ptt")
                )
        by_id = {c["id"]: c for c in detailed}
        self.assertEqual(by_id["transfer-dir"]["status"], "FAIL")

    def test_disk_space_ok(self):
        usage = mock.Mock(total=10 * 1024**3, free=5 * 1024**3)
        with (
            mock.patch("os.getcwd", return_value="/tmp"),
            mock.patch("shutil.disk_usage", return_value=usage),
        ):
            with tempfile.TemporaryDirectory() as tmp:
                detailed = run_checks_detailed(
                    cert_dir=os.path.join(tmp, "ptt")
                )
        check = {c["id"]: c for c in detailed}["disk-space"]
        self.assertEqual(check["status"], "OK")
        self.assertIn("5.0 GB", check["message"])

    def test_disk_space_low_warns(self):
        usage = mock.Mock(total=10 * 1024**3, free=50 * 1024**2)
        with (
            mock.patch("os.getcwd", return_value="/tmp"),
            mock.patch("shutil.disk_usage", return_value=usage),
        ):
            with tempfile.TemporaryDirectory() as tmp:
                detailed = run_checks_detailed(
                    cert_dir=os.path.join(tmp, "ptt")
                )
        check = {c["id"]: c for c in detailed}["disk-space"]
        self.assertEqual(check["status"], "WARN")
        self.assertIn("50.0 MB", check["message"])

    def test_disk_space_error_warns(self):
        with (
            mock.patch("os.getcwd", return_value="/tmp"),
            mock.patch(
                "shutil.disk_usage", side_effect=OSError("weg")
            ),
        ):
            with tempfile.TemporaryDirectory() as tmp:
                detailed = run_checks_detailed(
                    cert_dir=os.path.join(tmp, "ptt")
                )
        check = {c["id"]: c for c in detailed}["disk-space"]
        self.assertEqual(check["status"], "WARN")
        self.assertIn("nicht prüfbar", check["message"])

    def test_stale_parts_none_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            check = self._by_id(tmp)["stale-parts"]
        self.assertEqual(check["status"], "OK")
        self.assertIn("keine", check["message"])

    def test_stale_parts_counted_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("a.ptt-part", "b.ptt-part", "c.bin"):
                with open(os.path.join(tmp, name), "wb") as fh:
                    fh.write(b"x")
            check = self._by_id(tmp)["stale-parts"]
        self.assertEqual(check["status"], "OK")
        self.assertIn("2 Teil-Dateien", check["message"])

    def test_stale_parts_error_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            check = self._by_id(os.path.join(tmp, "nix"))["stale-parts"]
        self.assertEqual(check["status"], "WARN")


class CheckRegistryTest(unittest.TestCase):
    def test_ids_unique_and_stable_order(self):
        ids = [check_id for check_id, _, _, _ in CHECKS]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(check_id for check_id in ids))
        with tempfile.TemporaryDirectory() as tmp:
            detailed = run_checks_detailed(cert_dir=os.path.join(tmp, "ptt"))
        self.assertEqual([c["id"] for c in detailed], ids)

    def test_titles_present(self):
        for check_id, title, _, _ in CHECKS:
            with self.subTest(id=check_id):
                self.assertTrue(title)

    def test_hints_present(self):
        for check_id, _, _, hint in CHECKS:
            with self.subTest(id=check_id):
                self.assertTrue(hint)
                self.assertTrue(
                    hint.endswith("."),
                    f"Hinweis ohne Punkt ({check_id}): {hint!r}",
                )

    def test_tuple_view_matches_detailed(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert_dir = os.path.join(tmp, "ptt")
            tuples = run_checks(cert_dir=cert_dir)
            detailed = run_checks_detailed(cert_dir=cert_dir)
        self.assertEqual(len(tuples), len(CHECKS))
        for (status, message), check in zip(tuples, detailed):
            self.assertEqual(status, check["status"])
            self.assertEqual(message, check["message"])

    def test_registry_is_data_driven(self):
        extra = [
            ("injected", "Injiziert", lambda d: ("OK", "da"), "Hinweis!"),
        ]
        with mock.patch("ptt.doctor.CHECKS", CHECKS + extra):
            with tempfile.TemporaryDirectory() as tmp:
                detailed = run_checks_detailed(
                    cert_dir=os.path.join(tmp, "ptt")
                )
        self.assertEqual(detailed[-1]["id"], "injected")
        self.assertEqual(detailed[-1]["message"], "da")
        self.assertEqual(detailed[-1]["hint"], "Hinweis!")

    def test_json_carries_id_and_title(self):
        import json

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            run_doctor(as_json=True)
        doc = json.loads(buf.getvalue())
        ids = [check_id for check_id, _, _, _ in CHECKS]
        self.assertEqual([c["id"] for c in doc["checks"]], ids)
        for check in doc["checks"]:
            self.assertIn("title", check)
            self.assertTrue(check["title"])


class DoctorCliTest(unittest.TestCase):
    def test_doctor_parses(self):
        from ptt.cli import build_parser

        args = build_parser().parse_args(["doctor"])
        self.assertEqual(args.command, "doctor")
        self.assertEqual(args.json, False)
        args = build_parser().parse_args(["doctor", "--json"])
        self.assertEqual(args.json, True)

    def test_help_mentions_exit_code(self):
        from ptt.cli import build_parser

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with self.assertRaises(SystemExit) as ctx:
                build_parser().parse_args(["doctor", "--help"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("Exit", buf.getvalue())

    def test_main_calls_doctor(self):
        from ptt.cli import main

        with mock.patch("ptt.cli.run_doctor", return_value=0) as m:
            self.assertEqual(main(["doctor"]), 0)
        m.assert_called_once_with(
            as_json=False, self_test=False, only=None
        )
        with mock.patch("ptt.cli.run_doctor", return_value=0) as m:
            self.assertEqual(main(["doctor", "--json"]), 0)
        m.assert_called_once_with(
            as_json=True, self_test=False, only=None
        )

    def test_fix_options_parse(self):
        from ptt.cli import build_parser

        args = build_parser().parse_args(["doctor", "--fix"])
        self.assertTrue(args.fix)
        self.assertFalse(args.dry_run)
        args = build_parser().parse_args(["doctor", "--fix", "--dry-run"])
        self.assertTrue(args.dry_run)

    def test_self_test_parses(self):
        from ptt.cli import build_parser

        args = build_parser().parse_args(["doctor", "--self-test"])
        self.assertTrue(args.self_test)
        args = build_parser().parse_args(["doctor"])
        self.assertFalse(args.self_test)

    def test_main_calls_self_test(self):
        from ptt.cli import main

        with mock.patch("ptt.cli.run_doctor", return_value=0) as m:
            self.assertEqual(main(["doctor", "--self-test"]), 0)
        m.assert_called_once_with(
            as_json=False, self_test=True, only=None
        )
        with mock.patch("ptt.cli.run_doctor", return_value=0) as m:
            self.assertEqual(
                main(["doctor", "--self-test", "--json"]), 0
            )
        m.assert_called_once_with(
            as_json=True, self_test=True, only=None
        )

    def test_fix_and_self_test_rejected(self):
        from ptt.cli import main

        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            with self.assertRaises(SystemExit) as ctx:
                main(["doctor", "--fix", "--self-test"])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("--self-test", buf.getvalue())

    def test_main_calls_fix(self):
        from ptt.cli import main

        with mock.patch("ptt.cli.run_fix", return_value=0) as m:
            self.assertEqual(main(["doctor", "--fix"]), 0)
        m.assert_called_once_with(dry_run=False)
        with mock.patch("ptt.cli.run_fix", return_value=0) as m:
            self.assertEqual(main(["doctor", "--fix", "--dry-run"]), 0)
        m.assert_called_once_with(dry_run=True)

    def test_dry_run_without_fix_rejected(self):
        from ptt.cli import main

        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            with self.assertRaises(SystemExit) as ctx:
                main(["doctor", "--dry-run"])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("--fix", buf.getvalue())


class DoctorJsonTest(unittest.TestCase):
    def test_json_parses_with_structure(self):
        import json

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run_doctor()
        self.assertIn(rc, (0, 1))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc_json = run_doctor(as_json=True)
        self.assertEqual(rc_json, rc)
        doc = json.loads(buf.getvalue())
        self.assertIn("checks", doc)
        self.assertIn("fails", doc)
        self.assertIn("warns", doc)
        self.assertTrue(doc["checks"])
        for check in doc["checks"]:
            self.assertIn(check["status"], ("OK", "WARN", "FAIL"))
            self.assertIsInstance(check["message"], str)
        fails = sum(1 for c in doc["checks"] if c["status"] == "FAIL")
        self.assertEqual(doc["fails"], fails)
        self.assertEqual(rc_json, 1 if fails else 0)

    def test_json_uses_cert_dir(self):
        import json

        with tempfile.TemporaryDirectory() as tmp:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                run_doctor(cert_dir=tmp, as_json=True)
            doc = json.loads(buf.getvalue())
            blob = json.dumps(doc, ensure_ascii=False)
            self.assertIn(os.path.basename(tmp), blob)


class SelfTestHelpersTest(unittest.TestCase):
    def test_free_tcp_port_is_bindable(self):
        port = _free_tcp_port()
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("127.0.0.1", port))
        finally:
            probe.close()

    def test_isolated_home_points_and_restores(self):
        old_home = os.environ.get("HOME")
        old_profile = os.environ.get("USERPROFILE")
        with tempfile.TemporaryDirectory() as tmp:
            with _isolated_home(tmp):
                self.assertEqual(os.environ.get("HOME"), tmp)
                self.assertEqual(os.environ.get("USERPROFILE"), tmp)
            self.assertEqual(os.environ.get("HOME"), old_home)
            self.assertEqual(os.environ.get("USERPROFILE"), old_profile)

    def test_capture_stays_readable_after_block(self):
        # Regression: the exhausted generator used to GC the
        # TextIOWrapper, closing the buffer before getvalue().
        with _captured_bytes() as raw:
            print("hello-capture")
        self.assertIn(b"hello-capture", raw.getvalue())

    def test_capture_keeps_stdout_buffer(self):
        with _captured_bytes() as raw:
            sys.stdout.buffer.write(b"raw-bytes\n")
            sys.stdout.buffer.flush()
        self.assertIn(b"raw-bytes", raw.getvalue())


class SelfTestTimeoutTest(unittest.TestCase):
    def test_hanging_steps_yield_timeout_row(self):
        import threading

        import ptt.doctor as doctor_mod

        gate = threading.Event()
        steps = lambda: (gate.wait(30), [])[1]  # noqa: E731
        with mock.patch.object(
            doctor_mod, "_self_test_steps", side_effect=steps
        ), mock.patch.object(doctor_mod, "SELF_TEST_TIMEOUT", 0.05):
            rows = run_self_test()
        gate.set()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], "self-timeout")
        self.assertEqual(rows[0]["status"], "FAIL")
        self.assertIn("abgebrochen", rows[0]["message"])


class SelfTestWiringTest(unittest.TestCase):
    def test_run_doctor_self_test_uses_steps(self):
        rows = [
            {
                "id": "self-cert",
                "title": "Selbsttest: Zertifikat",
                "status": "OK",
                "message": "Test-Zertifikat erzeugt",
            }
        ]
        buf = io.StringIO()
        with mock.patch(
            "ptt.doctor.run_self_test", return_value=rows
        ), contextlib.redirect_stdout(buf):
            rc = run_doctor(self_test=True)
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("PTT-Selbsttest", out)
        self.assertIn("Test-Zertifikat erzeugt", out)

    def test_run_doctor_self_test_fail_returns_1(self):
        rows = [
            {
                "id": "self-exec",
                "title": "Selbsttest: exec",
                "status": "FAIL",
                "message": "exec scheitert (Exit 1)",
            }
        ]
        buf = io.StringIO()
        with mock.patch(
            "ptt.doctor.run_self_test", return_value=rows
        ), contextlib.redirect_stdout(buf):
            rc = run_doctor(self_test=True)
        self.assertEqual(rc, 1)
        self.assertIn("Problem", buf.getvalue())

    def test_run_doctor_self_test_json_shape(self):
        import json

        rows = [
            {
                "id": "self-put",
                "title": "Selbsttest: Upload",
                "status": "OK",
                "message": "Upload ok",
            }
        ]
        buf = io.StringIO()
        with mock.patch(
            "ptt.doctor.run_self_test", return_value=rows
        ), contextlib.redirect_stdout(buf):
            rc = run_doctor(self_test=True, as_json=True)
        self.assertEqual(rc, 0)
        doc = json.loads(buf.getvalue())
        self.assertEqual(doc["fails"], 0)
        self.assertEqual(doc["checks"][0]["id"], "self-put")


class SelfTestLiveTest(unittest.TestCase):
    def test_full_self_test_all_green(self):
        rows = run_self_test()
        self.assertEqual(
            [row["id"] for row in rows],
            ["self-cert", "self-exec", "self-put", "self-get"],
        )
        for row in rows:
            self.assertEqual(row["status"], "OK")
            self.assertTrue(row["title"])
            self.assertTrue(row["message"])
            self.assertIn("hint", row)


class CheckFilterTest(unittest.TestCase):
    def test_only_runs_subset_in_registry_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            detailed = run_checks_detailed(
                cert_dir=os.path.join(tmp, "ptt"),
                only=["shell", "python"],
            )
        self.assertEqual(
            [c["id"] for c in detailed], ["python", "shell"]
        )

    def test_only_dedupes(self):
        with tempfile.TemporaryDirectory() as tmp:
            detailed = run_checks_detailed(
                cert_dir=os.path.join(tmp, "ptt"),
                only=["shell", "shell"],
            )
        self.assertEqual([c["id"] for c in detailed], ["shell"])

    def test_run_doctor_passes_only_through(self):
        with mock.patch(
            "ptt.doctor.run_checks_detailed", return_value=[]
        ) as m:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                run_doctor(only=["shell"])
        m.assert_called_once_with(None, only=["shell"])

    def test_run_doctor_only_none_runs_all(self):
        with mock.patch(
            "ptt.doctor.run_checks_detailed", return_value=[]
        ) as m:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                run_doctor()
        m.assert_called_once_with(None, only=None)


class HintOutputTest(unittest.TestCase):
    ROWS = [
        {
            "id": "a",
            "title": "A",
            "status": "OK",
            "message": "alles gut",
            "hint": "ungenutzt",
        },
        {
            "id": "b",
            "title": "B",
            "status": "WARN",
            "message": "wackelt",
            "hint": "festziehen",
        },
        {
            "id": "c",
            "title": "C",
            "status": "FAIL",
            "message": "kaputt",
            "hint": "reparieren",
        },
    ]

    def test_hints_printed_for_warn_and_fail_only(self):
        buf = io.StringIO()
        with mock.patch(
            "ptt.doctor.run_checks_detailed",
            return_value=[dict(r) for r in self.ROWS],
        ), contextlib.redirect_stdout(buf):
            rc = run_doctor()
        self.assertEqual(rc, 1)
        out = buf.getvalue()
        self.assertIn("Hinweis: festziehen", out)
        self.assertIn("Hinweis: reparieren", out)
        self.assertNotIn("ungenutzt", out)

    def test_json_carries_hint(self):
        import json

        buf = io.StringIO()
        with mock.patch(
            "ptt.doctor.run_checks_detailed",
            return_value=[dict(r) for r in self.ROWS],
        ), contextlib.redirect_stdout(buf):
            run_doctor(as_json=True)
        doc = json.loads(buf.getvalue())
        hints = [c["hint"] for c in doc["checks"]]
        self.assertEqual(hints, ["ungenutzt", "festziehen", "reparieren"])

    def test_missing_hint_key_tolerated(self):
        rows = [
            {k: v for k, v in row.items() if k != "hint"}
            for row in self.ROWS
        ]
        buf = io.StringIO()
        with mock.patch(
            "ptt.doctor.run_checks_detailed", return_value=rows
        ), contextlib.redirect_stdout(buf):
            rc = run_doctor()
        self.assertEqual(rc, 1)
        self.assertNotIn("Hinweis:", buf.getvalue())


class ListChecksTest(unittest.TestCase):
    def test_list_text_names_every_id(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = list_checks()
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        for check_id, _, _, _ in CHECKS:
            self.assertIn(check_id, out)
        self.assertIn("--check", out)

    def test_list_json_shape(self):
        import json

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = list_checks(as_json=True)
        self.assertEqual(rc, 0)
        doc = json.loads(buf.getvalue())
        self.assertEqual(len(doc), len(CHECKS))
        for entry, (check_id, title, _, hint) in zip(doc, CHECKS):
            self.assertEqual(entry["id"], check_id)
            self.assertEqual(entry["title"], title)
            self.assertEqual(entry["hint"], hint)


class CheckCliTest(unittest.TestCase):
    def test_check_parses(self):
        from ptt.cli import build_parser

        args = build_parser().parse_args(["doctor", "--check", "shell"])
        self.assertEqual(args.check, "shell")
        args = build_parser().parse_args(["doctor"])
        self.assertIsNone(args.check)

    def test_list_parses(self):
        from ptt.cli import build_parser

        args = build_parser().parse_args(["doctor", "--list"])
        self.assertTrue(args.list)
        args = build_parser().parse_args(["doctor"])
        self.assertFalse(args.list)

    def test_main_passes_only_in_registry_order(self):
        from ptt.cli import main

        with mock.patch("ptt.cli.run_doctor", return_value=0) as m:
            self.assertEqual(
                main(["doctor", "--check", "shell,python,shell"]), 0
            )
        m.assert_called_once_with(
            as_json=False, self_test=False, only=["python", "shell"]
        )

    def test_main_rejects_unknown_check(self):
        from ptt.cli import main

        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            with self.assertRaises(SystemExit) as ctx:
                main(["doctor", "--check", "shell,nosuch"])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("unbekannte Prüfung: nosuch", buf.getvalue())

    def test_main_rejects_empty_check(self):
        from ptt.cli import main

        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            with self.assertRaises(SystemExit) as ctx:
                main(["doctor", "--check", " , "])
        self.assertEqual(ctx.exception.code, 2)

    def test_main_calls_list_checks(self):
        from ptt.cli import main

        with mock.patch("ptt.cli.list_checks", return_value=0) as m:
            self.assertEqual(main(["doctor", "--list"]), 0)
        m.assert_called_once_with(as_json=False)
        with mock.patch("ptt.cli.list_checks", return_value=0) as m:
            self.assertEqual(main(["doctor", "--list", "--json"]), 0)
        m.assert_called_once_with(as_json=True)

    def test_list_exclusions_rejected(self):
        from ptt.cli import main

        for extra in (
            ["--fix"], ["--self-test"], ["--check", "shell"], ["--report"]
        ):
            with self.subTest(extra=extra):
                buf = io.StringIO()
                with contextlib.redirect_stderr(buf):
                    with self.assertRaises(SystemExit) as ctx:
                        main(["doctor", "--list"] + extra)
                self.assertEqual(ctx.exception.code, 2)

    def test_check_exclusions_rejected(self):
        from ptt.cli import main

        for extra in (["--fix"], ["--self-test"]):
            with self.subTest(extra=extra):
                buf = io.StringIO()
                with contextlib.redirect_stderr(buf):
                    with self.assertRaises(SystemExit) as ctx:
                        main(["doctor", "--check", "shell"] + extra)
                self.assertEqual(ctx.exception.code, 2)


class RedactTest(unittest.TestCase):
    def test_home_becomes_tilde(self):
        home = os.path.expanduser("~")
        if home in ("~", "/"):
            self.skipTest("no distinct home dir")
        self.assertEqual(
            redact(f"liegt in {home}/daten"), "liegt in ~/daten"
        )

    def test_lan_ips_scrubbed(self):
        text = redact("von 192.168.1.42 und 10.0.0.7 an")
        self.assertEqual(text, "von <ip> und <ip> an")

    def test_loopback_kept(self):
        text = redact("auf 127.0.0.1:8022 lauschen")
        self.assertIn("127.0.0.1", text)
        self.assertNotIn("<ip>", text)

    def test_bad_octets_kept(self):
        self.assertIn("999.1.1.1", redact("weg 999.1.1.1 hin"))
        self.assertIn("1.2.3", redact("Version 1.2.3 ok"))


class ReportTest(unittest.TestCase):
    ROWS = [
        {
            "id": "a",
            "title": "A",
            "status": "OK",
            "message": "alles gut",
            "hint": "ungenutzt",
        },
        {
            "id": "b",
            "title": "B",
            "status": "FAIL",
            "message": "kaputt",
            "hint": "reparieren",
        },
    ]

    def test_render_shape(self):
        from ptt import __version__

        body = render_report([dict(r) for r in self.ROWS])
        self.assertIn("# PTT-Diagnosebericht", body)
        self.assertIn(f"- PTT: {__version__}", body)
        self.assertIn("- Python: ", body)
        self.assertIn("- System: ", body)
        self.assertIn("- Datum (UTC): ", body)
        self.assertIn("- Ergebnis: 1 Fehler, 0 Warnungen", body)
        self.assertIn("- [OK] a: alles gut", body)
        self.assertIn("- [FAIL] b: kaputt", body)
        self.assertIn("Hinweis: reparieren", body)
        self.assertNotIn("ungenutzt", body)
        self.assertIn("entfernt", body)

    def test_render_scrubs_home_and_ip(self):
        home = os.path.expanduser("~")
        rows = [
            {
                "id": "x",
                "title": "X",
                "status": "WARN",
                "message": f"in {home}/p bei 192.168.0.5",
                "hint": "hinweis",
            }
        ]
        body = render_report(rows)
        if home not in ("~", "/"):
            self.assertNotIn(home, body)
            self.assertIn("~/p", body)
        self.assertNotIn("192.168.0.5", body)
        self.assertIn("<ip>", body)

    def test_run_report_stdout_rc(self):
        buf = io.StringIO()
        with mock.patch(
            "ptt.doctor.run_checks_detailed",
            return_value=[dict(r) for r in self.ROWS],
        ), contextlib.redirect_stdout(buf):
            rc = run_report()
        self.assertEqual(rc, 1)
        self.assertIn("# PTT-Diagnosebericht", buf.getvalue())

    def test_run_report_stdout_ok(self):
        buf = io.StringIO()
        with mock.patch(
            "ptt.doctor.run_checks_detailed",
            return_value=[dict(self.ROWS[0])],
        ), contextlib.redirect_stdout(buf):
            rc = run_report(path="-")
        self.assertEqual(rc, 0)

    def test_run_report_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bericht.md")
            buf = io.StringIO()
            with mock.patch(
                "ptt.doctor.run_checks_detailed",
                return_value=[dict(r) for r in self.ROWS],
            ), contextlib.redirect_stdout(buf):
                rc = run_report(path=path)
            self.assertEqual(rc, 1)
            self.assertIn("Bericht geschrieben", buf.getvalue())
            with open(path, encoding="utf-8") as handle:
                self.assertIn("# PTT-Diagnosebericht", handle.read())

    def test_run_report_file_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "fehlt", "bericht.md")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_report(path=path)
            self.assertEqual(rc, 1)
            self.assertIn("Bericht scheitert", buf.getvalue())


class ReportCliTest(unittest.TestCase):
    def test_report_parses(self):
        from ptt.cli import build_parser

        args = build_parser().parse_args(["doctor", "--report"])
        self.assertEqual(args.report, "-")
        args = build_parser().parse_args(
            ["doctor", "--report", "r.md"]
        )
        self.assertEqual(args.report, "r.md")
        args = build_parser().parse_args(["doctor"])
        self.assertIsNone(args.report)

    def test_main_calls_run_report(self):
        from ptt.cli import main

        with mock.patch("ptt.cli.run_report", return_value=0) as m:
            self.assertEqual(main(["doctor", "--report"]), 0)
        m.assert_called_once_with(path="-")
        with mock.patch("ptt.cli.run_report", return_value=0) as m:
            self.assertEqual(
                main(["doctor", "--report", "r.md"]), 0
            )
        m.assert_called_once_with(path="r.md")

    def test_report_exclusions_rejected(self):
        from ptt.cli import main

        for extra in (
            ["--fix"],
            ["--self-test"],
            ["--check", "shell"],
            ["--json"],
            ["--list"],
        ):
            with self.subTest(extra=extra):
                buf = io.StringIO()
                with contextlib.redirect_stderr(buf):
                    with self.assertRaises(SystemExit) as ctx:
                        main(["doctor", "--report"] + extra)
                self.assertEqual(ctx.exception.code, 2)


class DoctorDocsTest(unittest.TestCase):
    FLAGS = (
        "--json",
        "--fix",
        "--dry-run",
        "--self-test",
        "--list",
        "--check",
        "--report",
    )

    def test_readme_documents_every_doctor_flag(self):
        root = os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        )
        with open(
            os.path.join(root, "README.md"), encoding="utf-8"
        ) as handle:
            readme = handle.read()
        self.assertIn("## Diagnose", readme)
        for flag in self.FLAGS:
            with self.subTest(flag=flag):
                self.assertIn(flag, readme)

    def test_changelog_covers_diagnose_line(self):
        root = os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        )
        with open(
            os.path.join(root, "CHANGELOG.md"), encoding="utf-8"
        ) as handle:
            changelog = handle.read()
        for minor in range(11):
            version = f"0.10.{minor}"
            with self.subTest(version=version):
                self.assertIn(f"## {version}", changelog)


if __name__ == "__main__":
    unittest.main()
