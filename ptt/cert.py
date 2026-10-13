"""Self-signed TLS certificates for PTT host mode.

The host generates one self-signed certificate (reused across runs) so the
tunnel is always TLS-encrypted. Clients do not verify the CA chain (there is
none) -- authentication happens via the token, and both sides display the
SHA256 fingerprint so the user can compare it manually (TOFU).
"""
from __future__ import annotations

import base64
import hashlib
import os
import socket
import ssl
import subprocess

from .protocol import ALPN_SHELL, ALPN_TRANSFER

CERT_FILE = "ptt-cert.pem"
KEY_FILE = "ptt-key.pem"
CERT_DAYS = 397


def tls_server_context(cert_path: str, key_path: str) -> ssl.SSLContext:
    """TLS server context: TLS 1.2+ with the host certificate."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_path, key_path)
    if ssl.HAS_ALPN:
        context.set_alpn_protocols([ALPN_SHELL, ALPN_TRANSFER])
    return context


def tls_client_context(alpn: list[str] | None = None) -> ssl.SSLContext:
    """TLS client context: TLS 1.2+, no CA check (TOFU via fingerprint).

    ``alpn`` optionally offers a session mode (e.g. file transfer);
    the default offers nothing and negotiates a shell like before.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if alpn and ssl.HAS_ALPN:
        context.set_alpn_protocols(list(alpn))
    return context


def _san_names() -> list[str]:
    """DNS names for the SAN extension (localhost + local hostname)."""
    names = ["localhost"]
    try:
        host = socket.gethostname()
    except OSError:
        return names
    if host and all(ch.isalnum() or ch in ".-" for ch in host):
        names.append(host)
    return names


def default_cert_dir() -> str:
    return os.path.join(os.path.expanduser("~"), ".ptt")


def _chmod(path: str, mode: int) -> None:
    """chmod on POSIX, no-op on Windows (no POSIX permission bits)."""
    if os.name != "nt":
        os.chmod(path, mode)


def ensure_data_dir(directory: str) -> str:
    """Create ``directory`` with 0700 (tightening existing dirs)."""
    os.makedirs(directory, mode=0o700, exist_ok=True)
    _chmod(directory, 0o700)
    return directory


def secure_write(path: str, data: bytes, mode: int = 0o600) -> None:
    """Atomically write ``data`` to ``path`` with restrictive ``mode``."""
    _atomic_write(path, data)
    _chmod(path, mode)


def _pem_files_valid(cert_path: str, key_path: str) -> bool:
    """True when both PEM files exist and parse."""
    try:
        with open(key_path, "rb") as f:
            key_pem = f.read()
        if b"PRIVATE KEY" not in key_pem:
            return False
        cert_fingerprint(cert_path)  # raises when the cert is unreadable
        return True
    except (OSError, ValueError):
        return False


def ensure_cert(cert_dir: str | None = None) -> tuple[str, str]:
    """Return (cert_path, key_path), generating a self-signed cert if needed."""
    directory = ensure_data_dir(cert_dir or default_cert_dir())
    cert_path = os.path.join(directory, CERT_FILE)
    key_path = os.path.join(directory, KEY_FILE)
    if os.path.exists(cert_path) and os.path.exists(key_path):
        if _pem_files_valid(cert_path, key_path):
            return cert_path, key_path
        print("[*] Zertifikat ungültig, erzeuge neu ...")
    elif os.path.exists(cert_path) or os.path.exists(key_path):
        print("[*] Zertifikat unvollständig, erzeuge neu ...")
    try:
        _generate_with_openssl(cert_path, key_path)
    except (OSError, subprocess.CalledProcessError):
        _generate_with_cryptography(cert_path, key_path)
    return cert_path, key_path


def _atomic_write(path: str, data: bytes) -> None:
    """Write ``data`` to ``path`` via temp file + replace (crash-safe)."""
    tmp = f"{path}.tmp-{os.getpid()}"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def _write_private_key(key_path: str, pem_bytes: bytes) -> None:
    secure_write(key_path, pem_bytes)


def _write_cert(cert_path: str, pem_bytes: bytes) -> None:
    secure_write(cert_path, pem_bytes, 0o644)


def _generate_with_openssl(cert_path: str, key_path: str) -> None:
    tmp_cert = f"{cert_path}.tmp-{os.getpid()}"
    tmp_key = f"{key_path}.tmp-{os.getpid()}"
    san = "subjectAltName=" + ",".join(f"DNS:{n}" for n in _san_names())
    try:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", tmp_key, "-out", tmp_cert,
                "-days", str(CERT_DAYS), "-nodes",
                "-subj", "/CN=PTT-Private-Terminal-Tunnel",
                "-addext", san,
            ],
            check=True,
            capture_output=True,
        )
    except BaseException:
        for tmp in (tmp_cert, tmp_key):
            try:
                os.unlink(tmp)
            except OSError:
                pass
        raise
    os.replace(tmp_key, key_path)
    os.replace(tmp_cert, cert_path)
    _chmod(key_path, 0o600)
    _chmod(cert_path, 0o644)


def _generate_with_cryptography(cert_path: str, key_path: str) -> None:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError as exc:
        raise RuntimeError(
            "Kein 'openssl'-Programm gefunden und Python-Paket 'cryptography' "
            "nicht installiert. Bitte openssl installieren oder "
            "'pip install cryptography' ausführen."
        ) from exc
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "PTT-Private-Terminal-Tunnel")]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=CERT_DAYS))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(n) for n in _san_names()]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    _write_private_key(
        key_path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ),
    )
    _write_cert(cert_path, cert.public_bytes(serialization.Encoding.PEM))


def _format_fingerprint(digest: bytes) -> str:
    return "SHA256:" + ":".join(f"{b:02X}" for b in digest)


def cert_fingerprint(cert_path: str) -> str:
    """SHA256 fingerprint of a PEM certificate file."""
    with open(cert_path, "rb") as f:
        pem = f.read()
    b64 = b"".join(
        line.strip() for line in pem.splitlines() if not line.startswith(b"-----")
    )
    der = base64.b64decode(b64)
    return _format_fingerprint(hashlib.sha256(der).digest())


def peer_fingerprint(sock) -> str:
    """SHA256 fingerprint of the TLS peer certificate."""
    der = sock.getpeercert(binary_form=True)
    if not der:
        return "(kein Zertifikat)"
    return _format_fingerprint(hashlib.sha256(der).digest())
