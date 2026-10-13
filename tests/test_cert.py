"""Tests for certificate validation, atomic writes and permissions."""
from __future__ import annotations

import contextlib
import datetime
import io
import os
import shutil
import ssl
import stat
import subprocess
import tempfile
import unittest

from ptt.cert import (
    CERT_DAYS,
    CERT_FILE,
    KEY_FILE,
    _atomic_write,
    _pem_files_valid,
    cert_fingerprint,
    ensure_cert,
    ensure_data_dir,
    secure_write,
    tls_client_context,
    tls_server_context,
)


def _backend_available() -> bool:
    try:
        with tempfile.TemporaryDirectory() as tmp:
            ensure_cert(tmp)
    except RuntimeError:
        return False
    return True


class PemValidationTest(unittest.TestCase):
    def test_missing_files_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(
                _pem_files_valid(
                    os.path.join(tmp, CERT_FILE), os.path.join(tmp, KEY_FILE)
                )
            )

    def test_garbage_files_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert = os.path.join(tmp, CERT_FILE)
            key = os.path.join(tmp, KEY_FILE)
            with open(cert, "wb") as f:
                f.write(b"not a cert")
            with open(key, "wb") as f:
                f.write(b"not a key")
            self.assertFalse(_pem_files_valid(cert, key))

    def test_wrong_key_rejected(self):
        if not _backend_available():
            self.skipTest("no openssl/cryptography")
        with tempfile.TemporaryDirectory() as tmp:
            cert_path, key_path = ensure_cert(tmp)
            with open(key_path, "wb") as f:
                f.write(b"-----BEGIN FAKE-----\nAAAA\n")
            self.assertFalse(_pem_files_valid(cert_path, key_path))

    def test_broken_pair_regenerated_with_hint(self):
        if not _backend_available():
            self.skipTest("no openssl/cryptography")
        with tempfile.TemporaryDirectory() as tmp:
            cert_path = os.path.join(tmp, CERT_FILE)
            key_path = os.path.join(tmp, KEY_FILE)
            with open(cert_path, "wb") as f:
                f.write(b"broken")
            with open(key_path, "wb") as f:
                f.write(b"broken")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                cert2, key2 = ensure_cert(tmp)
            self.assertEqual((cert2, key2), (cert_path, key_path))
            self.assertIn("erzeuge neu", buf.getvalue())
            self.assertTrue(_pem_files_valid(cert_path, key_path))
            self.assertTrue(cert_fingerprint(cert_path).startswith("SHA256:"))

    def test_half_pair_regenerated_with_hint(self):
        if not _backend_available():
            self.skipTest("no openssl/cryptography")
        with tempfile.TemporaryDirectory() as tmp:
            cert_path = os.path.join(tmp, CERT_FILE)
            with open(cert_path, "wb") as f:
                f.write(b"lonely")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                ensure_cert(tmp)
            self.assertIn("unvollständig", buf.getvalue())
            self.assertTrue(
                _pem_files_valid(cert_path, os.path.join(tmp, KEY_FILE))
            )

    def test_valid_pair_reused_silently(self):
        if not _backend_available():
            self.skipTest("no openssl/cryptography")
        with tempfile.TemporaryDirectory() as tmp:
            ensure_cert(tmp)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                ensure_cert(tmp)
            self.assertEqual(buf.getvalue(), "")


@unittest.skipIf(os.name == "nt", "POSIX permissions only")
class PermissionTest(unittest.TestCase):
    def test_restrictive_permissions(self):
        if not _backend_available():
            self.skipTest("no openssl/cryptography")
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "ptt")
            cert_path, key_path = ensure_cert(target)
            self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(key_path).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(cert_path).st_mode), 0o644)
            self.assertTrue(cert_path.endswith(CERT_FILE))

    def test_existing_dir_tightened(self):
        if not _backend_available():
            self.skipTest("no openssl/cryptography")
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "ptt")
            os.mkdir(target, 0o755)
            ensure_cert(target)
            self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o700)

    def test_secure_write_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            secret = os.path.join(tmp, "s.bin")
            public = os.path.join(tmp, "p.bin")
            secure_write(secret, b"x")
            secure_write(public, b"y", 0o644)
            self.assertEqual(stat.S_IMODE(os.stat(secret).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(public).st_mode), 0o644)
            with open(secret, "rb") as f:
                self.assertEqual(f.read(), b"x")

    def test_ensure_data_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "sub", "ptt")
            self.assertEqual(ensure_data_dir(target), target)
            self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o700)
            os.chmod(target, 0o755)
            ensure_data_dir(target)
            self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o700)


class TlsContextTest(unittest.TestCase):
    def test_client_context(self):
        context = tls_client_context()
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)
        self.assertFalse(context.check_hostname)

    def test_server_context(self):
        if not _backend_available():
            self.skipTest("no openssl/cryptography")
        with tempfile.TemporaryDirectory() as tmp:
            cert_path, key_path = ensure_cert(tmp)
            context = tls_server_context(cert_path, key_path)
            self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)


def _cert_facts(cert_path: str) -> tuple[list[str], int] | None:
    """(SAN DNS names, validity days) via cryptography or openssl CLI."""
    try:
        from cryptography import x509
    except ImportError:
        x509 = None  # type: ignore[assignment]
    if x509 is not None:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        sans = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
        before = getattr(cert, "not_valid_before_utc", None)
        after = getattr(cert, "not_valid_after_utc", None)
        if before is None or after is None:  # cryptography < 42
            before, after = cert.not_valid_before, cert.not_valid_after
        days = (after - before).days
        return list(sans), days
    if shutil.which("openssl") is None:
        return None
    proc = subprocess.run(
        ["openssl", "x509", "-in", cert_path, "-noout", "-ext", "subjectAltName"],
        capture_output=True,
        text=True,
        check=True,
    )
    sans = [
        part.strip().removeprefix("DNS:")
        for part in proc.stdout.replace("\n", "").split(":", 1)[-1].split(",")
        if part.strip().startswith("DNS:")
    ]
    proc = subprocess.run(
        ["openssl", "x509", "-in", cert_path, "-noout", "-dates"],
        capture_output=True,
        text=True,
        check=True,
    )
    stamps = {}
    for line in proc.stdout.splitlines():
        key, _, value = line.partition("=")
        stamps[key.strip()] = value.strip().removesuffix(" GMT")
    fmt = "%b %d %H:%M:%S %Y"
    before = datetime.datetime.strptime(stamps["notBefore"], fmt)
    after = datetime.datetime.strptime(stamps["notAfter"], fmt)
    return sans, (after - before).days


class CertContentTest(unittest.TestCase):
    def test_san_and_lifetime(self):
        if not _backend_available():
            self.skipTest("no openssl/cryptography")
        with tempfile.TemporaryDirectory() as tmp:
            cert_path, _ = ensure_cert(tmp)
            facts = _cert_facts(cert_path)
        if facts is None:
            self.skipTest("no cert parser (cryptography/openssl) available")
        sans, days = facts
        self.assertIn("localhost", sans)
        self.assertEqual(days, CERT_DAYS)


class AtomicWriteTest(unittest.TestCase):
    def test_content_and_no_leftovers(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "f.bin")
            _atomic_write(path, b"data-123")
            with open(path, "rb") as f:
                self.assertEqual(f.read(), b"data-123")
            self.assertEqual(os.listdir(tmp), ["f.bin"])


if __name__ == "__main__":
    unittest.main()
