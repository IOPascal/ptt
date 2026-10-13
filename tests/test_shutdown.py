"""Unit tests for host shutdown signal handlers."""
import signal
import threading
import unittest
from unittest import mock

from ptt.host import (
    _install_shutdown_handlers,
    _make_sigint_handler,
    _on_sigterm,
    _restore_shutdown_handlers,
)


class ShutdownHandlerTest(unittest.TestCase):
    def test_sigterm_raises_keyboard_interrupt(self):
        with self.assertRaises(KeyboardInterrupt):
            _on_sigterm(signal.SIGTERM, None)

    def test_sigint_first_raises_second_exits(self):
        handler = _make_sigint_handler()
        with self.assertRaises(KeyboardInterrupt):
            handler(signal.SIGINT, None)
        with mock.patch("os._exit") as mock_exit:
            handler(signal.SIGINT, None)
        mock_exit.assert_called_once_with(130)

    def test_install_skipped_in_worker_thread(self):
        before_term = signal.getsignal(signal.SIGTERM)
        before_int = signal.getsignal(signal.SIGINT)
        results = []
        worker = threading.Thread(
            target=lambda: results.append(_install_shutdown_handlers())
        )
        worker.start()
        worker.join(timeout=10)
        self.assertEqual(results, [None])
        self.assertIs(signal.getsignal(signal.SIGTERM), before_term)
        self.assertIs(signal.getsignal(signal.SIGINT), before_int)

    def test_install_and_restore_in_main_thread(self):
        before_term = signal.getsignal(signal.SIGTERM)
        before_int = signal.getsignal(signal.SIGINT)
        old = _install_shutdown_handlers()
        try:
            self.assertIsNotNone(old)
            self.assertIs(signal.getsignal(signal.SIGTERM), _on_sigterm)
            current_int = signal.getsignal(signal.SIGINT)
            self.assertTrue(callable(current_int))
            self.assertIsNot(current_int, before_int)
        finally:
            _restore_shutdown_handlers(old)
        self.assertIs(signal.getsignal(signal.SIGTERM), before_term)
        self.assertIs(signal.getsignal(signal.SIGINT), before_int)

    def test_restore_none_is_noop(self):
        _restore_shutdown_handlers(None)


if __name__ == "__main__":
    unittest.main()
