"""Unit tests for the PTT wire protocol."""
import socket
import unittest

from ptt.protocol import (
    FRAME_EXIT,
    FRAME_RESIZE,
    FRAME_STDIN,
    FRAME_STDOUT,
    recv_frame,
    recv_line,
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


if __name__ == "__main__":
    unittest.main()
