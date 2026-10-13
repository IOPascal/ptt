"""Unit tests for the PTT wire protocol."""
import io
import socket
import struct
import sys
import threading
import unittest

from ptt.client import _read_loop
from ptt.protocol import (
    FRAME_EXIT,
    FRAME_RESIZE,
    FRAME_STDIN,
    FRAME_STDOUT,
    MAX_UNKNOWN_FRAMES,
    UnknownFrameError,
    enable_keepalive,
    recv_frame,
    recv_line,
    send_exit,
    send_frame,
    send_line,
)


class FrameTest(unittest.TestCase):
    def test_roundtrip(self):
        a, b = socket.socketpair()
        try:
            send_frame(a, FRAME_STDIN, b"hello")
            self.assertEqual(recv_frame(b), (FRAME_STDIN, b"hello"))
        finally:
            a.close()
            b.close()

    def test_all_frame_types(self):
        a, b = socket.socketpair()
        try:
            for ftype in (FRAME_STDIN, FRAME_STDOUT, FRAME_RESIZE, FRAME_EXIT):
                send_frame(a, ftype, bytes([ftype]) * 100)
            for ftype in (FRAME_STDIN, FRAME_STDOUT, FRAME_RESIZE, FRAME_EXIT):
                self.assertEqual(recv_frame(b), (ftype, bytes([ftype]) * 100))
        finally:
            a.close()
            b.close()

    def test_empty_payload(self):
        a, b = socket.socketpair()
        try:
            send_frame(a, FRAME_STDOUT, b"")
            self.assertEqual(recv_frame(b), (FRAME_STDOUT, b""))
        finally:
            a.close()
            b.close()

    def test_large_payload(self):
        import threading

        a, b = socket.socketpair()
        try:
            payload = bytes(range(256)) * 2000  # ~512 KiB
            errors: list = []

            def sender():
                try:
                    send_frame(a, FRAME_STDOUT, payload)
                except OSError as exc:  # pragma: no cover
                    errors.append(exc)

            thread = threading.Thread(target=sender)
            thread.start()
            self.assertEqual(recv_frame(b), (FRAME_STDOUT, payload))
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
        finally:
            a.close()
            b.close()

    def test_oversized_payload_rejected(self):
        a, b = socket.socketpair()
        try:
            with self.assertRaises(ValueError):
                send_frame(a, FRAME_STDOUT, b"x" * (1024 * 1024 + 1))
        finally:
            a.close()
            b.close()

    def test_send_exit_roundtrip(self):
        a, b = socket.socketpair()
        try:
            send_exit(a, 42)
            ftype, payload = recv_frame(b)
            self.assertEqual(ftype, FRAME_EXIT)
            (code,) = struct.unpack("!i", payload)
            self.assertEqual(code, 42)
        finally:
            a.close()
            b.close()

    def test_closed_connection_raises(self):
        a, b = socket.socketpair()
        a.close()
        try:
            with self.assertRaises(ConnectionError):
                recv_frame(b)
        finally:
            b.close()


class LineTest(unittest.TestCase):
    def test_roundtrip(self):
        a, b = socket.socketpair()
        try:
            send_line(a, "3fa2-9c1d-77b0-e4f5")
            self.assertEqual(recv_line(b), "3fa2-9c1d-77b0-e4f5")
        finally:
            a.close()
            b.close()

    def test_crlf_tolerated(self):
        a, b = socket.socketpair()
        try:
            a.sendall(b"secret\r\n")
            self.assertEqual(recv_line(b), "secret")
        finally:
            a.close()
            b.close()


class UnknownFrameTest(unittest.TestCase):
    def _send_raw(self, sock, ftype: int, payload: bytes = b""):
        sock.sendall(struct.pack("!BI", ftype, len(payload)) + payload)

    def test_unknown_type_raises(self):
        a, b = socket.socketpair()
        try:
            self._send_raw(a, 0xFF)
            with self.assertRaises(UnknownFrameError):
                recv_frame(b)
        finally:
            a.close()
            b.close()

    def test_unknown_is_connection_error(self):
        self.assertTrue(issubclass(UnknownFrameError, ConnectionError))

    def test_read_loop_tolerates_few_unknown(self):
        a, b = socket.socketpair()
        out, result, done = io.BytesIO(), {"code": 0}, threading.Event()

        def peer():
            try:
                for _ in range(3):
                    self._send_raw(b, 0xFF)
                send_exit(b, 0)
            finally:
                b.close()

        thread = threading.Thread(target=peer)
        thread.start()
        _read_loop(a, out, result, done)
        thread.join(timeout=10)
        a.close()
        self.assertTrue(done.is_set())
        self.assertEqual(result["code"], 0)

    def test_read_loop_aborts_at_threshold(self):
        a, b = socket.socketpair()
        out, result, done = io.BytesIO(), {"code": 0}, threading.Event()

        def peer():
            try:
                for _ in range(MAX_UNKNOWN_FRAMES + 2):
                    self._send_raw(b, 0xFF)
            finally:
                b.close()

        thread = threading.Thread(target=peer)
        thread.start()
        _read_loop(a, out, result, done)
        thread.join(timeout=10)
        a.close()
        self.assertTrue(done.is_set())
        self.assertEqual(result["code"], 1)


class KeepaliveTest(unittest.TestCase):
    def test_enable_keepalive_sets_option(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        try:
            cli = socket.create_connection(srv.getsockname(), timeout=5)
            conn, _ = srv.accept()
            try:
                enable_keepalive(cli)
                self.assertNotEqual(
                    cli.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE), 0
                )
                idle = getattr(socket, "TCP_KEEPIDLE", None)
                if sys.platform.startswith("linux") and idle is not None:
                    self.assertEqual(
                        cli.getsockopt(socket.IPPROTO_TCP, idle), 60
                    )
            finally:
                cli.close()
                conn.close()
        finally:
            srv.close()

    def test_enable_keepalive_fails_soft(self):
        closed = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        closed.close()
        enable_keepalive(closed)  # must not raise


if __name__ == "__main__":
    unittest.main()
