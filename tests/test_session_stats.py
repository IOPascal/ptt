"""Unit tests for session stats formatting."""
import contextlib
import io
import time
import unittest

from ptt.output import format_bytes, format_duration, log_phase


class FormatStatsTest(unittest.TestCase):
    def testformat_bytes(self):
        self.assertEqual(format_bytes(0), "0 B")
        self.assertEqual(format_bytes(33), "33 B")
        self.assertEqual(format_bytes(1023), "1023 B")
        self.assertEqual(format_bytes(1024), "1.0 KB")
        self.assertEqual(format_bytes(1536), "1.5 KB")
        self.assertEqual(format_bytes(1024**2), "1.0 MB")
        self.assertEqual(format_bytes(1024**3), "1.0 GB")

    def testformat_duration(self):
        self.assertEqual(format_duration(0.4), "0 s")
        self.assertEqual(format_duration(12), "12 s")
        self.assertEqual(format_duration(60), "1 min")
        self.assertEqual(format_duration(185), "3 min 5 s")
        self.assertEqual(format_duration(3600), "1 h 0 min")
        self.assertEqual(format_duration(3900), "1 h 5 min")


class LogPhaseTest(unittest.TestCase):
    def test_silent_when_not_verbose(self):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            log_phase(False, time.monotonic(), "nichts")
        self.assertEqual(buf.getvalue(), "")

    def test_timestamped_line_when_verbose(self):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            log_phase(True, time.monotonic(), "TCP verbunden")
        self.assertRegex(buf.getvalue(), r"\[\+\d+\.\d\ds\] TCP verbunden\n")


if __name__ == "__main__":
    unittest.main()
