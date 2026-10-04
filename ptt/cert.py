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
import subprocess

CERT_FILE = "ptt-cert.pem"
KEY_FILE = "ptt-key.pem"


def default_cert_dir() -> str:
    return os.path.join(os.path.expanduser("~"), ".ptt")


def ensure_cert(cert_dir: str | None = None) -> tuple[str, str]:
    """Return (cert_path, key_path), generating a self-signed cert if needed."""
    directory = cert_dir or default_cert_dir()
    os.makedirs(directory, exist_ok=True)
    cert_path = os.path.join(directory, CERT_FILE)
    key_path = os.path.join(directory, KEY_FILE)
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path
    try:
        _generate_with_openssl(cert_path, key_path)
    except (OSError, subprocess.CalledProcessError):
        _generate_with_cryptography(cert_path, key_path)
    return cert_path, key_path


def _generate_with_openssl(cert_path: str, key_path: str) -> None:
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", "825", "-nodes",
            "-subj", "/CN=PTT-Private-Terminal-Tunnel",
        ],
        check=True,
        capture_output=True,
    )
    os.chmod(key_path, 0o600)


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
        .not_valid_after(now + datetime.timedelta(days=825))
        .sign(key, hashes.SHA256())
    )
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
    os.chmod(key_path, 0o600)
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


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
