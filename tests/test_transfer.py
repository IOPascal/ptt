"""Tests for transfer negotiation (ALPN modes + request codecs)."""
import contextlib
import hashlib
import io
import json
import os
import socket
import ssl
import tempfile
import threading
import time
import unittest
from unittest import mock

from ptt.cert import ensure_cert, tls_client_context, tls_server_context
from ptt.client import _TransferProgress, _split_get_arg, _split_put_arg
from ptt.protocol import (
    ALPN_TRANSFER,
    FRAME_TACK,
    FRAME_TDATA,
    FRAME_TDONE,
    FRAME_TREQ,
    recv_frame,
    send_frame,
)
from ptt.transfer import (
    TransferError,
    TransferTimeoutError,
    _TransferLimits,
    _bad_part,
    _clamp_offset,
    _serve_get,
    _serve_put,
    _target_path,
    _win_part_ok,
    cleanup_stale_parts,
    decode_tack,
    decode_treq,
    encode_tack,
    encode_treq,
    get_file,
    parse_size,
    put_file,
    wants_transfer,
)

SHA = "ab" * 32


class TreqCodecTest(unittest.TestCase):
    def test_roundtrip(self):
        for op in ("put", "get"):
            payload = encode_treq(op, "a/b.txt", size=12, sha256=SHA)
            self.assertEqual(
                decode_treq(payload),
                {
                    "op": op,
                    "path": "a/b.txt",
                    "size": 12,
                    "sha256": SHA,
                    "resume": False,
                    "offset": 0,
                },
            )

    def test_roundtrip_minimal(self):
        payload = encode_treq("get", "f.bin")
        self.assertEqual(
            decode_treq(payload),
            {
                "op": "get",
                "path": "f.bin",
                "size": None,
                "sha256": None,
                "resume": False,
                "offset": 0,
            },
        )

    def test_roundtrip_resume(self):
        payload = encode_treq("get", "f.bin", resume=True, offset=70000)
        self.assertEqual(
            decode_treq(payload),
            {
                "op": "get",
                "path": "f.bin",
                "size": None,
                "sha256": None,
                "resume": True,
                "offset": 70000,
            },
        )

    def test_legacy_payload_defaults(self):
        # Peers from 0.8.6 and older send no resume/offset fields.
        payload = json.dumps({"op": "put", "path": "f"}).encode()
        self.assertEqual(
            decode_treq(payload),
            {
                "op": "put",
                "path": "f",
                "size": None,
                "sha256": None,
                "resume": False,
                "offset": 0,
            },
        )

    def test_encode_rejects_bad_input(self):
        for kwargs in (
            {"op": "post", "path": "f"},
            {"op": "put", "path": ""},
            {"op": "put", "path": "x" * 1025},
            {"op": "put", "path": "f", "size": -1},
            {"op": "put", "path": "f", "size": True},
            {"op": "put", "path": "f", "sha256": "zz"},
            {"op": "put", "path": "f", "sha256": "ab" * 31},
            {"op": "put", "path": "f", "resume": "yes"},
            {"op": "put", "path": "f", "offset": -1},
            {"op": "put", "path": "f", "offset": True},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    encode_treq(**kwargs)

    def test_decode_rejects_malformed(self):
        bad = [
            b"not json",
            b"[1, 2]",
            b"\xff\xfe",
            json.dumps({"op": "put"}).encode(),
            json.dumps({"op": "put", "path": ""}).encode(),
            json.dumps({"op": "put", "path": "x" * 1025}).encode(),
            json.dumps({"op": "move", "path": "f"}).encode(),
            json.dumps({"op": "put", "path": "f", "size": -3}).encode(),
            json.dumps({"op": "put", "path": "f", "size": "5"}).encode(),
            json.dumps({"op": "put", "path": "f", "sha256": "nope"}).encode(),
            json.dumps({"op": "put", "path": "f", "resume": 1}).encode(),
            json.dumps({"op": "put", "path": "f", "offset": -2}).encode(),
            json.dumps({"op": "put", "path": "f", "offset": "7"}).encode(),
        ]
        for payload in bad:
            with self.subTest(payload=payload[:30]):
                self.assertIsNone(decode_treq(payload))


class TackCodecTest(unittest.TestCase):
    def test_roundtrip(self):
        payload = encode_tack(True, size=99)
        self.assertEqual(
            decode_tack(payload),
            {"ok": True, "reason": "", "size": 99, "offset": 0},
        )
        payload = encode_tack(False, reason="voll")
        self.assertEqual(
            decode_tack(payload),
            {"ok": False, "reason": "voll", "size": None, "offset": 0},
        )

    def test_roundtrip_offset(self):
        payload = encode_tack(True, size=99, offset=40)
        self.assertEqual(
            decode_tack(payload),
            {"ok": True, "reason": "", "size": 99, "offset": 40},
        )

    def test_legacy_payload_defaults(self):
        payload = json.dumps({"ok": True, "reason": ""}).encode()
        self.assertEqual(
            decode_tack(payload),
            {"ok": True, "reason": "", "size": None, "offset": 0},
        )

    def test_encode_rejects_bad_input(self):
        for kwargs in (
            {"ok": "yes"},
            {"ok": True, "reason": 5},
            {"ok": True, "size": -1},
            {"ok": True, "offset": -1},
            {"ok": True, "offset": "4"},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    encode_tack(**kwargs)

    def test_decode_rejects_malformed(self):
        bad = [
            b"not json",
            b"true",
            json.dumps({"ok": 1}).encode(),
            json.dumps({"ok": True, "reason": 7}).encode(),
            json.dumps({"ok": True, "size": -2}).encode(),
            json.dumps({}).encode(),
        ]
        for payload in bad:
            with self.subTest(payload=payload[:20]):
                self.assertIsNone(decode_tack(payload))


class AlpnTest(unittest.TestCase):
    def _tls_pair(self, cert_dir, client_alpn, legacy_server=False):
        cert_path, key_path = ensure_cert(cert_dir)
        if legacy_server:
            server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            server_ctx.load_cert_chain(cert_path, key_path)
        else:
            server_ctx = tls_server_context(cert_path, key_path)
        client_ctx = tls_client_context(client_alpn)
        a, b = socket.socketpair()
        outcome = {}

        def serve():
            try:
                outcome["server"] = server_ctx.wrap_socket(a, server_side=True)
            except OSError as exc:
                outcome["error"] = exc

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            client = client_ctx.wrap_socket(b, server_hostname="localhost")
        except OSError:
            a.close()
            b.close()
            thread.join(timeout=10)
            raise
        thread.join(timeout=10)
        self.assertIn("server", outcome)
        return outcome["server"], client

    def test_transfer_mode_negotiated(self):
        if not ssl.HAS_ALPN:
            self.skipTest("TLS stack without ALPN")
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            server, client = self._tls_pair(cert_dir, [ALPN_TRANSFER])
            try:
                self.assertEqual(
                    server.selected_alpn_protocol(), ALPN_TRANSFER
                )
                self.assertEqual(
                    client.selected_alpn_protocol(), ALPN_TRANSFER
                )
                self.assertTrue(wants_transfer(server))
                self.assertTrue(wants_transfer(client))
            finally:
                server.close()
                client.close()

    def test_no_offer_means_shell(self):
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            server, client = self._tls_pair(cert_dir, None)
            try:
                self.assertIsNone(server.selected_alpn_protocol())
                self.assertIsNone(client.selected_alpn_protocol())
                self.assertFalse(wants_transfer(server))
                self.assertFalse(wants_transfer(client))
            finally:
                server.close()
                client.close()

    def test_legacy_server_offers_nothing(self):
        if not ssl.HAS_ALPN:
            self.skipTest("TLS stack without ALPN")
        try:
            with tempfile.TemporaryDirectory() as cert_dir:
                ensure_cert(cert_dir)
        except RuntimeError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as cert_dir:
            server, client = self._tls_pair(
                cert_dir, [ALPN_TRANSFER], legacy_server=True
            )
            try:
                self.assertIsNone(client.selected_alpn_protocol())
                self.assertFalse(wants_transfer(client))
            finally:
                server.close()
                client.close()


class PutArgTest(unittest.TestCase):
    def test_existing_path_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "f.bin")
            with open(src, "wb") as fh:
                fh.write(b"x")
            self.assertEqual(_split_put_arg(src), (src, None))

    def test_name_split(self):
        self.assertEqual(_split_put_arg("plain"), ("plain", None))
        self.assertEqual(_split_put_arg("a:b"), ("a", "b"))
        self.assertEqual(_split_put_arg("a:b:c"), ("a:b", "c"))
        self.assertEqual(_split_put_arg("a:"), ("a:", None))
        # drive path, not FILE:NAME
        self.assertEqual(_split_put_arg("C:\\x"), ("C:\\x", None))


class ParseSizeTest(unittest.TestCase):
    def test_values(self):
        self.assertEqual(parse_size("0"), 0)
        self.assertEqual(parse_size("1024"), 1024)
        self.assertEqual(parse_size("100K"), 100 * 1024)
        self.assertEqual(parse_size("100k"), 100 * 1024)
        self.assertEqual(parse_size("1.5M"), int(1.5 * 1024**2))
        self.assertEqual(parse_size("2G"), 2 * 1024**3)
        self.assertEqual(parse_size(" 10M "), 10 * 1024**2)

    def test_invalid(self):
        for bad in ("", "x", "K", "-5", "-1M", "inf", "1.2.3"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    parse_size(bad)


class TransferLimitsTest(unittest.TestCase):
    def test_disabled(self):
        lim = _TransferLimits()
        self.assertIsNone(lim.hit())
        self.assertFalse(lim.too_big(10**12))

    def test_hit(self):
        lim = _TransferLimits(max_size=100, idle_seconds=5, max_seconds=50)
        self.assertIsNone(lim.hit())
        self.assertTrue(lim.too_big(101))
        self.assertFalse(lim.too_big(100))
        self.assertIn("100 B", lim.too_big_reason())
        lim.last_active -= 10
        self.assertEqual(lim.hit(), "idle")
        lim.touch()
        self.assertIsNone(lim.hit())
        lim.started -= 60
        self.assertEqual(lim.hit(), "expired")


class GetArgTest(unittest.TestCase):
    def test_split(self):
        self.assertEqual(_split_get_arg("f"), ("f", None))
        self.assertEqual(_split_get_arg("a:b"), ("a", "b"))
        self.assertEqual(_split_get_arg("a:b:c"), ("a:b", "c"))
        self.assertEqual(_split_get_arg("a:"), ("a:", None))
        self.assertEqual(_split_get_arg(":x"), ("", "x"))

    def test_drive_paths(self):
        self.assertEqual(_split_get_arg("C:\\out"), ("C:\\out", None))
        self.assertEqual(_split_get_arg("r:C:\\out"), ("r", "C:\\out"))
        self.assertEqual(_split_get_arg("r:C:/out"), ("r", "C:/out"))


class TargetPathTest(unittest.TestCase):
    def test_inside(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(
                _target_path(root, "f.txt"), os.path.join(root, "f.txt")
            )
            self.assertEqual(
                _target_path(root, "sub/dir/f"),
                os.path.join(root, "sub", "dir", "f"),
            )

    def test_escape_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            for bad in (
                "", "../x", "a/../../x", "/abs/path", ".", "a\x00b",
            ):
                with self.subTest(bad=bad):
                    self.assertIsNone(_target_path(root, bad))

    def test_symlink_escape_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            link = os.path.join(root, "link")
            try:
                os.symlink("/etc", link)
            except OSError as exc:
                self.skipTest(f"no symlinks: {exc}")
            self.assertIsNone(_target_path(root, "link/hostname"))

    @unittest.skipIf(os.name == "nt", "POSIX-only: colon is legal")
    def test_colon_allowed_on_posix(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(
                _target_path(root, "12:30.log"),
                os.path.join(root, "12:30.log"),
            )

    def test_win_part_ok(self):
        for bad in (
            "C:foo", "f:stream", "CON", "con.txt", "com1", "lpt9.log",
            "AUX", "nul", "file ", "file.",
        ):
            with self.subTest(bad=bad):
                self.assertFalse(_win_part_ok(bad))
        for good in ("ok.txt", ".", "console", "com10", "my aux"):
            with self.subTest(good=good):
                self.assertTrue(_win_part_ok(good))

    @unittest.skipUnless(os.name == "nt", "Windows-only attack vectors")
    def test_windows_attacks_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            for bad in (
                "C:foo",
                "f:stream",
                "CON",
                "con.txt",
                "com1",
                "lpt9.log",
                "AUX",
                "file ",
                "file.",
                "sub\\..\\x",
            ):
                with self.subTest(bad=bad):
                    self.assertIsNone(_target_path(root, bad))
            self.assertEqual(
                _target_path(root, "sub\\ok.txt"),
                os.path.join(root, "sub\\ok.txt"),
            )


class PutFileTest(unittest.TestCase):
    def _stub_ok(self, sock, collected):
        ftype, payload = recv_frame(sock)
        assert ftype == FRAME_TREQ
        collected["req"] = decode_treq(payload)
        send_frame(sock, FRAME_TACK, encode_tack(True))
        chunks = []
        while True:
            ftype, payload = recv_frame(sock)
            if ftype == FRAME_TDATA:
                chunks.append(payload)
            elif ftype == FRAME_TDONE:
                collected["commit"] = json.loads(payload.decode("utf-8"))
                break
        collected["data"] = b"".join(chunks)
        send_frame(sock, FRAME_TDONE, json.dumps({"ok": True}).encode())

    def test_roundtrip(self):
        data = os.urandom(150000)
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "src.bin")
            with open(src, "wb") as fh:
                fh.write(data)
            a, b = socket.socketpair()
            collected = {}
            worker = threading.Thread(
                target=self._stub_ok, args=(b, collected), daemon=True
            )
            worker.start()
            try:
                progress = []
                sent = put_file(
                    a, src, "up.bin",
                    on_progress=lambda s, t: progress.append((s, t)),
                )
            finally:
                a.close()
            worker.join(timeout=10)
            b.close()
        self.assertEqual(sent, len(data))
        self.assertEqual(collected["data"], data)
        self.assertEqual(collected["req"]["op"], "put")
        self.assertEqual(collected["req"]["path"], "up.bin")
        self.assertEqual(collected["req"]["size"], len(data))
        self.assertEqual(
            collected["req"]["sha256"], hashlib.sha256(data).hexdigest()
        )
        self.assertTrue(progress)
        self.assertEqual(progress[-1], (len(data), len(data)))

    def test_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "src.bin")
            with open(src, "wb") as fh:
                fh.write(b"data")
            a, b = socket.socketpair()

            def stub():
                try:
                    recv_frame(b)
                    send_frame(b, FRAME_TACK, encode_tack(False, "nein"))
                except OSError:
                    pass
                finally:
                    b.close()

            worker = threading.Thread(target=stub, daemon=True)
            worker.start()
            try:
                with self.assertRaisesRegex(TransferError, "nein"):
                    put_file(a, src, "up.bin")
            finally:
                a.close()
            worker.join(timeout=10)

    def test_eof(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "src.bin")
            with open(src, "wb") as fh:
                fh.write(b"data")
            a, b = socket.socketpair()
            b.close()
            try:
                with self.assertRaises(TransferError):
                    put_file(a, src, "up.bin")
            finally:
                a.close()

    def test_missing_local(self):
        a, b = socket.socketpair()
        try:
            with self.assertRaisesRegex(TransferError, "nicht lesbar"):
                put_file(a, "/nonexistent-ptt-put-src", "x")
        finally:
            a.close()
            b.close()

    def test_directory_local(self):
        a, b = socket.socketpair()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                with self.assertRaisesRegex(TransferError, "Verzeichnis"):
                    put_file(a, tmp, "x")
        finally:
            a.close()
            b.close()

    def test_abort_propagates(self):
        data = os.urandom(150000)
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "src.bin")
            with open(src, "wb") as fh:
                fh.write(data)
            a, b = socket.socketpair()
            collected = {}
            worker = threading.Thread(
                target=self._stub_ok, args=(b, collected), daemon=True
            )
            worker.start()

            def abort(sent, total):
                raise KeyboardInterrupt()

            try:
                with self.assertRaises(KeyboardInterrupt):
                    put_file(a, src, "up.bin", on_progress=abort)
            finally:
                a.close()
            worker.join(timeout=10)
            b.close()

    def test_bad_remote(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "src.bin")
            with open(src, "wb") as fh:
                fh.write(b"data")
            a, b = socket.socketpair()
            try:
                with self.assertRaises(TransferError):
                    put_file(a, src, "")
            finally:
                a.close()
                b.close()


class GetFileTest(unittest.TestCase):
    def _stub_ok(self, sock, data, collected):
        ftype, payload = recv_frame(sock)
        assert ftype == FRAME_TREQ
        collected["req"] = decode_treq(payload)
        send_frame(sock, FRAME_TACK, encode_tack(True, size=len(data)))
        for off in range(0, len(data), 5000):
            send_frame(sock, FRAME_TDATA, data[off:off + 5000])
        sha = hashlib.sha256(data).hexdigest()
        send_frame(
            sock, FRAME_TDONE, json.dumps({"sha256": sha}).encode("utf-8")
        )
        ftype, payload = recv_frame(sock)
        collected["result"] = json.loads(payload.decode("utf-8"))

    def test_roundtrip(self):
        data = os.urandom(120000)
        with tempfile.TemporaryDirectory() as tmp:
            local = os.path.join(tmp, "down.bin")
            a, b = socket.socketpair()
            collected = {}
            worker = threading.Thread(
                target=self._stub_ok, args=(b, data, collected), daemon=True
            )
            worker.start()
            try:
                progress = []
                received = get_file(
                    a, "sub/remote.bin", local,
                    on_progress=lambda s, t: progress.append((s, t)),
                )
            finally:
                a.close()
            worker.join(timeout=10)
            b.close()
            with open(local, "rb") as fh:
                self.assertEqual(fh.read(), data)
            self.assertEqual(
                [f for f in os.listdir(tmp) if f.endswith(".ptt-part")], []
            )
        self.assertEqual(received, len(data))
        self.assertEqual(collected["req"]["op"], "get")
        self.assertEqual(collected["req"]["path"], "sub/remote.bin")
        self.assertTrue(collected["result"]["ok"])
        self.assertTrue(progress)
        self.assertEqual(progress[-1], (len(data), len(data)))

    def test_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            local = os.path.join(tmp, "down.bin")
            a, b = socket.socketpair()

            def stub():
                try:
                    recv_frame(b)
                    send_frame(b, FRAME_TACK, encode_tack(False, "nope"))
                except OSError:
                    pass
                finally:
                    b.close()

            worker = threading.Thread(target=stub, daemon=True)
            worker.start()
            try:
                with self.assertRaisesRegex(TransferError, "nope"):
                    get_file(a, "r.bin", local)
            finally:
                a.close()
            worker.join(timeout=10)
            self.assertFalse(os.path.exists(local))
            self.assertFalse(os.path.exists(local + ".ptt-part"))

    def test_bad_checksum(self):
        data = os.urandom(10000)
        with tempfile.TemporaryDirectory() as tmp:
            local = os.path.join(tmp, "down.bin")
            a, b = socket.socketpair()

            def stub():
                try:
                    recv_frame(b)
                    send_frame(
                        b, FRAME_TACK, encode_tack(True, size=len(data))
                    )
                    send_frame(b, FRAME_TDATA, data)
                    send_frame(
                        b, FRAME_TDONE,
                        json.dumps({"sha256": "00" * 32}).encode("utf-8"),
                    )
                    recv_frame(b)  # result
                except OSError:
                    pass
                finally:
                    b.close()

            worker = threading.Thread(target=stub, daemon=True)
            worker.start()
            try:
                with self.assertRaisesRegex(TransferError, "Prüfsumme"):
                    get_file(a, "r.bin", local)
            finally:
                a.close()
            worker.join(timeout=10)
            self.assertFalse(os.path.exists(local))
            self.assertFalse(os.path.exists(local + ".ptt-part"))

    def test_unwritable_target(self):
        a, b = socket.socketpair()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                with self.assertRaisesRegex(TransferError, "schreibbar"):
                    get_file(a, "r.bin", os.path.join(tmp, "nodir", "f"))
        finally:
            a.close()
            b.close()

    def test_abort_keeps_part_for_resume(self):
        data = os.urandom(120000)
        with tempfile.TemporaryDirectory() as tmp:
            local = os.path.join(tmp, "down.bin")
            a, b = socket.socketpair()
            collected = {}
            worker = threading.Thread(
                target=self._stub_ok, args=(b, data, collected), daemon=True
            )
            worker.start()

            def abort(sent, total):
                raise KeyboardInterrupt()

            try:
                with self.assertRaises(KeyboardInterrupt):
                    get_file(a, "r.bin", local, on_progress=abort)
            finally:
                a.close()
            worker.join(timeout=10)
            b.close()
            self.assertFalse(os.path.exists(local))
            part = local + ".ptt-part"
            self.assertTrue(os.path.exists(part))
            with open(part, "rb") as fh:
                prefix = fh.read()
            self.assertTrue(prefix)
            self.assertEqual(prefix, data[:len(prefix)])

    def test_checksum_failure_deletes_part(self):
        data = os.urandom(20000)
        bad = bytearray(data)
        bad[100] ^= 0xFF

        def _stub_corrupt(sock):
            ftype, _payload = recv_frame(sock)
            assert ftype == FRAME_TREQ
            send_frame(sock, FRAME_TACK, encode_tack(True, size=len(data)))
            send_frame(sock, FRAME_TDATA, bytes(bad))
            sha = hashlib.sha256(data).hexdigest()
            send_frame(
                sock, FRAME_TDONE, json.dumps({"sha256": sha}).encode()
            )
            try:
                recv_frame(sock)  # client result
            except (OSError, ValueError):
                pass

        with tempfile.TemporaryDirectory() as tmp:
            local = os.path.join(tmp, "down.bin")
            a, b = socket.socketpair()
            worker = threading.Thread(
                target=_stub_corrupt, args=(b,), daemon=True
            )
            worker.start()
            try:
                with self.assertRaisesRegex(TransferError, "Prüfsumme"):
                    get_file(a, "r.bin", local)
            finally:
                a.close()
            worker.join(timeout=10)
            b.close()
            self.assertFalse(os.path.exists(local))
            self.assertFalse(os.path.exists(local + ".ptt-part"))

    def test_local_dir_target(self):
        data = b"dir-target-data"
        with tempfile.TemporaryDirectory() as tmp:
            a, b = socket.socketpair()
            collected = {}
            worker = threading.Thread(
                target=self._stub_ok, args=(b, data, collected), daemon=True
            )
            worker.start()
            try:
                received = get_file(a, "sub/r.bin", tmp + os.sep)
            finally:
                a.close()
            worker.join(timeout=10)
            b.close()
            with open(os.path.join(tmp, "r.bin"), "rb") as fh:
                self.assertEqual(fh.read(), data)
        self.assertEqual(received, len(data))


class ProgressTest(unittest.TestCase):
    def _tty_bar(self, buf, **kwargs):
        buf.isatty = lambda: True
        with mock.patch(
            "shutil.get_terminal_size",
            return_value=os.terminal_size((100, 24)),
        ):
            with contextlib.redirect_stdout(buf):
                return _TransferProgress(**kwargs)

    def test_bar_renders_percent(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            bar = self._tty_bar(buf, min_interval=0)
            bar(50, 100)
            bar(100, 100)
            bar.finish()
        out = buf.getvalue()
        self.assertIn("\r[" + "#" * 15 + "-" * 15 + "]", out)
        self.assertIn("100.0%", out)
        self.assertIn("/s", out)
        self.assertTrue(out.endswith("\n"))

    def test_unknown_total_shows_bytes(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            bar = self._tty_bar(buf, min_interval=0)
            bar(2048, None)
            bar.finish()
        out = buf.getvalue()
        self.assertIn("2.0 KB", out)
        self.assertNotIn("%", out)

    def test_throttled(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            bar = self._tty_bar(buf, min_interval=3600)
            bar(10, 100)
            bar(20, 100)
            bar(30, 100)
            bar.finish()
        # first update plus forced final line
        self.assertEqual(buf.getvalue().count("\r"), 2)

    def test_first_update_renders_on_fresh_boot(self):
        # Regression: shown=0.0 throttled the first update away when
        # monotonic() was still tiny (fresh CI runners); the bar
        # must always render its first update (CI: 1 != 2).
        buf = io.StringIO()
        with mock.patch("time.monotonic", return_value=100.0):
            with contextlib.redirect_stdout(buf):
                bar = self._tty_bar(buf, min_interval=3600)
                bar(10, 100)
        self.assertEqual(buf.getvalue().count("\r"), 1)

    def test_silent_without_tty(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            bar = _TransferProgress()
            bar(50, 100)
            bar.finish()
        self.assertEqual(buf.getvalue(), "")


class ResumeHelperTest(unittest.TestCase):
    def test_clamp_offset(self):
        self.assertEqual(_clamp_offset(5, 10), 5)
        self.assertEqual(_clamp_offset(0, 10), 0)
        self.assertEqual(_clamp_offset(-3, 10), 0)
        self.assertEqual(_clamp_offset(99, 10), 10)
        self.assertEqual(_clamp_offset(10, 10), 10)
        self.assertEqual(_clamp_offset("x", 10), 0)
        self.assertEqual(_clamp_offset(None, 10), 0)
        self.assertEqual(_clamp_offset(None, None), 0)
        self.assertEqual(_clamp_offset(7, None), 7)

    def test_bad_part(self):
        for reason in (
            "Prüfsumme falsch",
            "mehr Daten als angekündigt",
            "unvollständig (3 von 9 B)",
            "Datei zu groß (max. 1.0 MB)",
            "ungültiger Pfad",
            "ungültige Antwort",
        ):
            with self.subTest(reason=reason):
                self.assertTrue(_bad_part(reason))
        for reason in (
            "Verbindung abgebrochen",
            "Verbindung abgebrochen: EOF",
            "Host fährt herunter",
            "abgebrochen",
            "keine Antwort vom Host",
            "keine Bestätigung vom Host",
            "Inaktivität",
        ):
            with self.subTest(reason=reason):
                self.assertFalse(_bad_part(reason))


class PutResumeTest(unittest.TestCase):
    def test_client_seeks_to_server_offset(self):
        data = os.urandom(150000)
        offset = 5000
        collected = {}

        def _stub_resume(sock):
            ftype, payload = recv_frame(sock)
            assert ftype == FRAME_TREQ
            collected["req"] = decode_treq(payload)
            send_frame(
                sock, FRAME_TACK, encode_tack(True, offset=offset)
            )
            chunks = []
            while True:
                ftype, payload = recv_frame(sock)
                if ftype == FRAME_TDATA:
                    chunks.append(payload)
                elif ftype == FRAME_TDONE:
                    collected["commit"] = json.loads(
                        payload.decode("utf-8")
                    )
                    break
            collected["data"] = b"".join(chunks)
            send_frame(
                sock, FRAME_TDONE, json.dumps({"ok": True}).encode()
            )

        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "src.bin")
            with open(src, "wb") as fh:
                fh.write(data)
            a, b = socket.socketpair()
            worker = threading.Thread(
                target=_stub_resume, args=(b,), daemon=True
            )
            worker.start()
            try:
                resumed = []
                sent = put_file(
                    a, src, "up.bin",
                    on_resume=lambda o, t: resumed.append((o, t)),
                )
            finally:
                a.close()
            worker.join(timeout=10)
            b.close()
        self.assertEqual(sent, len(data))
        self.assertEqual(collected["data"], data[offset:])
        self.assertEqual(resumed, [(offset, len(data))])
        self.assertEqual(collected["req"]["resume"], True)
        self.assertEqual(
            collected["commit"]["sha256"], hashlib.sha256(data).hexdigest()
        )


class GetResumeTest(unittest.TestCase):
    def _stub_honors_offset(self, sock, data, collected):
        ftype, payload = recv_frame(sock)
        assert ftype == FRAME_TREQ
        req = decode_treq(payload)
        collected["req"] = req
        start = req["offset"] if req["resume"] else 0
        send_frame(
            sock, FRAME_TACK, encode_tack(True, size=len(data), offset=start)
        )
        for off in range(start, len(data), 5000):
            send_frame(sock, FRAME_TDATA, data[off:off + 5000])
        sha = hashlib.sha256(data).hexdigest()
        send_frame(
            sock, FRAME_TDONE, json.dumps({"sha256": sha}).encode("utf-8")
        )
        ftype, payload = recv_frame(sock)
        collected["result"] = json.loads(payload.decode("utf-8"))

    def test_client_continues_local_part(self):
        data = os.urandom(120000)
        prefix = 7000
        with tempfile.TemporaryDirectory() as tmp:
            local = os.path.join(tmp, "down.bin")
            with open(local + ".ptt-part", "wb") as fh:
                fh.write(data[:prefix])
            a, b = socket.socketpair()
            collected = {}
            worker = threading.Thread(
                target=self._stub_honors_offset,
                args=(b, data, collected),
                daemon=True,
            )
            worker.start()
            try:
                resumed = []
                received = get_file(
                    a, "r.bin", local,
                    on_resume=lambda o, t: resumed.append((o, t)),
                )
            finally:
                a.close()
            worker.join(timeout=10)
            b.close()
            with open(local, "rb") as fh:
                self.assertEqual(fh.read(), data)
            self.assertFalse(os.path.exists(local + ".ptt-part"))
        self.assertEqual(received, len(data))
        self.assertEqual(resumed, [(prefix, len(data))])
        self.assertEqual(collected["req"]["offset"], prefix)
        self.assertEqual(collected["result"], {"ok": True, "reason": ""})

    def test_client_restarts_when_server_grants_zero(self):
        data = os.urandom(30000)

        def _stub_legacy(sock):
            # Old server: ignores resume, streams the whole file.
            ftype, _payload = recv_frame(sock)
            assert ftype == FRAME_TREQ
            send_frame(sock, FRAME_TACK, encode_tack(True, size=len(data)))
            send_frame(sock, FRAME_TDATA, data)
            sha = hashlib.sha256(data).hexdigest()
            send_frame(
                sock, FRAME_TDONE, json.dumps({"sha256": sha}).encode()
            )
            try:
                recv_frame(sock)  # client result
            except (OSError, ValueError):
                pass

        with tempfile.TemporaryDirectory() as tmp:
            local = os.path.join(tmp, "down.bin")
            with open(local + ".ptt-part", "wb") as fh:
                fh.write(b"stale-prefix-bytes")
            a, b = socket.socketpair()
            worker = threading.Thread(
                target=_stub_legacy, args=(b,), daemon=True
            )
            worker.start()
            try:
                resumed = []
                received = get_file(
                    a, "r.bin", local,
                    on_resume=lambda o, t: resumed.append((o, t)),
                )
            finally:
                a.close()
            worker.join(timeout=10)
            b.close()
            with open(local, "rb") as fh:
                self.assertEqual(fh.read(), data)
        self.assertEqual(received, len(data))
        self.assertEqual(resumed, [])


class ServeResumeTest(unittest.TestCase):
    def _marks(self):
        return ("[+]", "[x]", "[i]")

    def test_put_server_grants_offset_and_verifies(self):
        data = os.urandom(90000)
        prefix = 9000
        sha = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            part = os.path.join(tmp, "up.bin.ptt-part")
            with open(part, "wb") as fh:
                fh.write(data[:prefix])
            req = decode_treq(
                encode_treq("put", "up.bin", len(data), sha, resume=True)
            )
            a, b = socket.socketpair()
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                worker = threading.Thread(
                    target=_serve_put,
                    args=(b, tmp, req, "peer", self._marks(), None,
                          _TransferLimits(0, 0, 0)),
                    daemon=True,
                )
                worker.start()
                try:
                    ftype, payload = recv_frame(a)
                    self.assertEqual(ftype, FRAME_TACK)
                    tack = decode_tack(payload)
                    self.assertTrue(tack["ok"])
                    self.assertEqual(tack["offset"], prefix)
                    send_frame(a, FRAME_TDATA, data[prefix:])
                    send_frame(
                        a, FRAME_TDONE,
                        json.dumps({"sha256": sha}).encode(),
                    )
                    ftype, payload = recv_frame(a)
                    self.assertEqual(ftype, FRAME_TDONE)
                    result = json.loads(payload.decode("utf-8"))
                    self.assertTrue(result["ok"])
                finally:
                    a.close()
                worker.join(timeout=10)
                b.close()
            with open(os.path.join(tmp, "up.bin"), "rb") as fh:
                self.assertEqual(fh.read(), data)
            self.assertFalse(os.path.exists(part))

    def test_put_server_keeps_part_on_abort(self):
        data = os.urandom(40000)
        sha = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            req = decode_treq(
                encode_treq("put", "up.bin", len(data), sha, resume=True)
            )
            a, b = socket.socketpair()
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                worker = threading.Thread(
                    target=_serve_put,
                    args=(b, tmp, req, "peer", self._marks(), None,
                          _TransferLimits(0, 0, 0)),
                    daemon=True,
                )
                worker.start()
                ftype, payload = recv_frame(a)
                self.assertEqual(ftype, FRAME_TACK)
                send_frame(a, FRAME_TDATA, data[:5000])
                a.close()  # abort mid-upload
                worker.join(timeout=10)
                b.close()
            part = os.path.join(tmp, "up.bin.ptt-part")
            self.assertTrue(os.path.exists(part))
            with open(part, "rb") as fh:
                self.assertEqual(fh.read(), data[:5000])
            self.assertFalse(os.path.exists(os.path.join(tmp, "up.bin")))

    def test_put_server_deletes_part_on_checksum_mismatch(self):
        data = os.urandom(40000)
        bad = bytearray(data)
        bad[10] ^= 0xFF
        sha = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            req = decode_treq(
                encode_treq("put", "up.bin", len(data), sha, resume=True)
            )
            a, b = socket.socketpair()
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                worker = threading.Thread(
                    target=_serve_put,
                    args=(b, tmp, req, "peer", self._marks(), None,
                          _TransferLimits(0, 0, 0)),
                    daemon=True,
                )
                worker.start()
                try:
                    ftype, _payload = recv_frame(a)
                    self.assertEqual(ftype, FRAME_TACK)
                    send_frame(a, FRAME_TDATA, bytes(bad))
                    send_frame(
                        a, FRAME_TDONE,
                        json.dumps({"sha256": sha}).encode(),
                    )
                    ftype, payload = recv_frame(a)
                    result = json.loads(payload.decode("utf-8"))
                    self.assertFalse(result["ok"])
                finally:
                    a.close()
                worker.join(timeout=10)
                b.close()
            self.assertFalse(
                os.path.exists(os.path.join(tmp, "up.bin.ptt-part"))
            )
            self.assertFalse(os.path.exists(os.path.join(tmp, "up.bin")))

    def test_get_server_seeks_to_client_offset(self):
        data = os.urandom(80000)
        start = 6000
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "f.bin"), "wb") as fh:
                fh.write(data)
            req = decode_treq(
                encode_treq("get", "f.bin", resume=True, offset=start)
            )
            a, b = socket.socketpair()
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                worker = threading.Thread(
                    target=_serve_get,
                    args=(b, tmp, req, "peer", self._marks(), None,
                          _TransferLimits(0, 0, 0)),
                    daemon=True,
                )
                worker.start()
                try:
                    ftype, payload = recv_frame(a)
                    self.assertEqual(ftype, FRAME_TACK)
                    tack = decode_tack(payload)
                    self.assertEqual(tack["offset"], start)
                    self.assertEqual(tack["size"], len(data))
                    chunks = []
                    while True:
                        ftype, payload = recv_frame(a)
                        if ftype == FRAME_TDATA:
                            chunks.append(payload)
                        elif ftype == FRAME_TDONE:
                            commit = json.loads(payload.decode("utf-8"))
                            break
                    send_frame(
                        a, FRAME_TDONE,
                        json.dumps({"ok": True, "reason": ""}).encode(),
                    )
                finally:
                    a.close()
                worker.join(timeout=10)
                b.close()
            self.assertEqual(b"".join(chunks), data[start:])
            self.assertEqual(
                commit["sha256"], hashlib.sha256(data).hexdigest()
            )


class CleanupTest(unittest.TestCase):
    def _touch(self, path, age_seconds):
        with open(path, "wb") as fh:
            fh.write(b"x")
        old = time.time() - age_seconds
        os.utime(path, (old, old))

    def test_removes_only_stale_parts(self):
        with tempfile.TemporaryDirectory() as tmp:
            stale = os.path.join(tmp, "a.bin.ptt-part")
            fresh = os.path.join(tmp, "b.bin.ptt-part")
            other = os.path.join(tmp, "c.bin")
            sub = os.path.join(tmp, "sub")
            os.mkdir(sub)
            nested = os.path.join(sub, "d.bin.ptt-part")
            self._touch(stale, 100000)
            self._touch(fresh, 10)
            self._touch(other, 100000)
            self._touch(nested, 100000)
            removed = cleanup_stale_parts(tmp, max_age=1000)
            self.assertEqual(removed, 2)
            self.assertFalse(os.path.exists(stale))
            self.assertFalse(os.path.exists(nested))
            self.assertTrue(os.path.exists(fresh))
            self.assertTrue(os.path.exists(other))

    def test_missing_root_returns_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(
                cleanup_stale_parts(os.path.join(tmp, "nope")), 0
            )

    def test_symlink_part_is_skipped(self):
        if not hasattr(os, "symlink"):
            self.skipTest("no symlinks")
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "real.bin")
            with open(target, "wb") as fh:
                fh.write(b"data")
            link = os.path.join(tmp, "evil.ptt-part")
            try:
                os.symlink(target, link)
            except OSError:
                self.skipTest("cannot create symlinks")
            removed = cleanup_stale_parts(tmp, max_age=0)
            self.assertEqual(removed, 0)
            self.assertTrue(os.path.islink(link))
            self.assertTrue(os.path.exists(target))


class FreshTest(unittest.TestCase):
    def test_put_fresh_sends_no_resume(self):
        data = os.urandom(30000)
        collected = {}

        def _stub(sock):
            ftype, payload = recv_frame(sock)
            assert ftype == FRAME_TREQ
            collected["req"] = decode_treq(payload)
            send_frame(sock, FRAME_TACK, encode_tack(True))
            chunks = []
            while True:
                ftype, payload = recv_frame(sock)
                if ftype == FRAME_TDATA:
                    chunks.append(payload)
                elif ftype == FRAME_TDONE:
                    break
            collected["data"] = b"".join(chunks)
            send_frame(
                sock, FRAME_TDONE, json.dumps({"ok": True}).encode()
            )

        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "src.bin")
            with open(src, "wb") as fh:
                fh.write(data)
            a, b = socket.socketpair()
            worker = threading.Thread(
                target=_stub, args=(b,), daemon=True
            )
            worker.start()
            try:
                resumed = []
                sent = put_file(
                    a, src, "up.bin", fresh=True,
                    on_resume=lambda o, t: resumed.append((o, t)),
                )
            finally:
                a.close()
            worker.join(timeout=10)
            b.close()
        self.assertEqual(sent, len(data))
        self.assertEqual(collected["data"], data)
        self.assertEqual(collected["req"]["resume"], False)
        self.assertEqual(collected["req"]["offset"], 0)
        self.assertEqual(resumed, [])

    def test_get_fresh_discards_local_part(self):
        data = os.urandom(30000)

        def _stub_legacy(sock):
            ftype, payload = recv_frame(sock)
            assert ftype == FRAME_TREQ
            collected["req"] = decode_treq(payload)
            send_frame(sock, FRAME_TACK, encode_tack(True, size=len(data)))
            send_frame(sock, FRAME_TDATA, data)
            sha = hashlib.sha256(data).hexdigest()
            send_frame(
                sock, FRAME_TDONE, json.dumps({"sha256": sha}).encode()
            )
            try:
                recv_frame(sock)  # client result
            except (OSError, ValueError):
                pass

        collected = {}
        with tempfile.TemporaryDirectory() as tmp:
            local = os.path.join(tmp, "down.bin")
            with open(local + ".ptt-part", "wb") as fh:
                fh.write(b"stale-bytes")
            a, b = socket.socketpair()
            worker = threading.Thread(
                target=_stub_legacy, args=(b,), daemon=True
            )
            worker.start()
            try:
                resumed = []
                received = get_file(
                    a, "r.bin", local, fresh=True,
                    on_resume=lambda o, t: resumed.append((o, t)),
                )
            finally:
                a.close()
            worker.join(timeout=10)
            b.close()
            with open(local, "rb") as fh:
                self.assertEqual(fh.read(), data)
        self.assertEqual(received, len(data))
        self.assertEqual(collected["req"]["resume"], False)
        self.assertEqual(resumed, [])


class TransferTimeoutTest(unittest.TestCase):
    def test_put_expired_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "src.bin")
            with open(src, "wb") as fh:
                fh.write(b"data")
            a, b = socket.socketpair()
            try:
                with self.assertRaisesRegex(TransferTimeoutError, "Zeitlimit"):
                    put_file(a, src, "up.bin", deadline=time.monotonic() - 1)
            finally:
                a.close()
                b.close()

    def test_get_expired_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            local = os.path.join(tmp, "down.bin")
            a, b = socket.socketpair()
            try:
                with self.assertRaisesRegex(TransferTimeoutError, "Zeitlimit"):
                    get_file(
                        a, "r.bin", local, deadline=time.monotonic() - 1
                    )
            finally:
                a.close()
                b.close()

    def test_put_tack_stall_times_out(self):
        def _stub(sock):
            try:
                recv_frame(sock)  # TREQ
                recv_frame(sock)  # never comes; ends at client close
            except (OSError, ValueError):
                pass

        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "src.bin")
            with open(src, "wb") as fh:
                fh.write(os.urandom(1000))
            a, b = socket.socketpair()
            worker = threading.Thread(
                target=_stub, args=(b,), daemon=True
            )
            worker.start()
            try:
                start = time.monotonic()
                with self.assertRaisesRegex(TransferTimeoutError, "Zeitlimit"):
                    put_file(
                        a, src, "up.bin",
                        deadline=time.monotonic() + 1,
                    )
                self.assertLess(time.monotonic() - start, 4)
            finally:
                a.close()
                worker.join(timeout=10)
                b.close()

    def test_get_mid_stream_stall_times_out_and_keeps_part(self):
        data = os.urandom(60000)

        def _stub(sock):
            try:
                recv_frame(sock)  # TREQ
                send_frame(
                    sock, FRAME_TACK, encode_tack(True, size=len(data))
                )
                send_frame(sock, FRAME_TDATA, data[:5000])
                recv_frame(sock)  # client result or close
            except (OSError, ValueError):
                pass

        with tempfile.TemporaryDirectory() as tmp:
            local = os.path.join(tmp, "down.bin")
            a, b = socket.socketpair()
            worker = threading.Thread(
                target=_stub, args=(b,), daemon=True
            )
            worker.start()
            try:
                start = time.monotonic()
                with self.assertRaisesRegex(TransferTimeoutError, "Zeitlimit"):
                    get_file(
                        a, "r.bin", local,
                        deadline=time.monotonic() + 1,
                    )
                self.assertLess(time.monotonic() - start, 4)
            finally:
                a.close()
                worker.join(timeout=10)
                b.close()
            part = local + ".ptt-part"
            self.assertTrue(os.path.exists(part))
            with open(part, "rb") as fh:
                self.assertEqual(fh.read(), data[:5000])


if __name__ == "__main__":
    unittest.main()
