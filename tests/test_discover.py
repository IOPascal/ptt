"""Tests for LAN discovery and host picking."""
import contextlib
import io
import json
import time
import unittest
from unittest import mock

from helpers import _free_udp_port
from ptt.client import _short_fingerprint, pick_host
from ptt.discover import (
    MAX_FINGERPRINT_LEN,
    MAX_HOSTS,
    _store_reply,
    discover,
    make_reply,
    parse_reply,
    start_responder,
)


class ParseReplyTest(unittest.TestCase):
    def _reply(self, **overrides):
        info = {
            "ptt": 1,
            "name": "wohnzimmer",
            "port": 8022,
            "fingerprint": "SHA256:AA:BB",
            "auth": "pin",
        }
        info.update(overrides)
        return json.dumps(info).encode("utf-8")

    def test_valid(self):
        info = parse_reply(self._reply(), "192.168.1.5")
        self.assertEqual(
            info,
            {
                "name": "wohnzimmer",
                "address": "192.168.1.5",
                "port": 8022,
                "fingerprint": "SHA256:AA:BB",
                "auth": "pin",
                "busy": False,
            },
        )

    def test_busy_flag(self):
        info = parse_reply(self._reply(busy=True), "192.168.1.5")
        self.assertTrue(info["busy"])
        # old hosts send no flag: treated as available
        info = parse_reply(self._reply(), "192.168.1.5")
        self.assertFalse(info["busy"])

    def test_extra_keys_ignored(self):
        # Foreign/future hosts may send unknown keys: tolerated.
        info = parse_reply(
            self._reply(version="9.9", features=["x"], extra={"a": 1}),
            "192.168.1.5",
        )
        self.assertEqual(info["name"], "wohnzimmer")
        self.assertEqual(info["port"], 8022)
        self.assertNotIn("version", info)

    def test_make_reply_roundtrip(self):
        info = parse_reply(
            make_reply("box", 8022, "SHA256:AA:BB", "token", busy=True),
            "10.0.0.2",
        )
        self.assertEqual(info["name"], "box")
        self.assertTrue(info["busy"])

    def test_invalid_replies_ignored(self):
        for bad in (
            b"not json",
            b"[1, 2]",
            self._reply(port=99999),
            self._reply(port="x"),
            self._reply(fingerprint="nope"),
            self._reply(fingerprint="SHA256:" + "A" * MAX_FINGERPRINT_LEN),
            self._reply(auth="password"),
            self._reply(name=None),
            json.dumps({"name": "x"}).encode("utf-8"),
        ):
            self.assertIsNone(parse_reply(bad, "192.168.1.5"))

    def test_control_chars_stripped_from_name(self):
        info = parse_reply(self._reply(name="ab\x00\x1bc\n"), "192.168.1.5")
        assert info is not None
        self.assertEqual(info["name"], "abc")

    def test_blank_name_falls_back_to_address(self):
        info = parse_reply(self._reply(name="\x00\x07"), "192.168.1.5")
        assert info is not None
        self.assertEqual(info["name"], "192.168.1.5")


class StoreReplyTest(unittest.TestCase):
    def _info(self, n: int) -> dict:
        return {
            "name": f"h{n}",
            "address": "127.0.0.1",
            "port": 8022,
            "fingerprint": f"SHA256:{n:04d}",
            "auth": "pin",
        }

    def test_bounded_to_max_hosts(self):
        found: dict = {}
        for n in range(MAX_HOSTS + 20):
            _store_reply(found, self._info(n))
        self.assertEqual(len(found), MAX_HOSTS)

    def test_existing_entry_still_updated_at_cap(self):
        found: dict = {}
        for n in range(MAX_HOSTS):
            _store_reply(found, self._info(n))
        updated = self._info(0)
        updated["name"] = "renamed"
        _store_reply(found, updated)
        self.assertEqual(len(found), MAX_HOSTS)
        self.assertEqual(found["SHA256:0000"]["name"], "renamed")


class DiscoverRoundtripTest(unittest.TestCase):
    def test_responder_answers(self):
        port = _free_udp_port()
        stop, thread = start_responder(8022, "testbox", "SHA256:AA:BB", "pin", port)
        time.sleep(0.3)  # let the responder bind before the single request
        try:
            found = discover(timeout=2.0, target="127.0.0.1", port=port)
        finally:
            stop.set()
            thread.join(timeout=5)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["name"], "testbox")
        self.assertEqual(found[0]["address"], "127.0.0.1")
        self.assertEqual(found[0]["port"], 8022)
        self.assertEqual(found[0]["auth"], "pin")

    def test_nothing_found(self):
        found = discover(timeout=0.5, target="127.0.0.1", port=_free_udp_port())
        self.assertEqual(found, [])

    def test_responder_reports_live_busy(self):
        port = _free_udp_port()
        state = {"busy": False}
        stop, thread = start_responder(
            8022, "testbox", "SHA256:AA:BB", "pin", port,
            busy=lambda: state["busy"],
        )
        time.sleep(0.3)
        try:
            found = discover(timeout=2.0, target="127.0.0.1", port=port)
            self.assertEqual(len(found), 1)
            self.assertFalse(found[0]["busy"])
            state["busy"] = True
            found = discover(timeout=2.0, target="127.0.0.1", port=port)
            self.assertEqual(len(found), 1)
            self.assertTrue(found[0]["busy"])
        finally:
            stop.set()
            thread.join(timeout=5)


class PickHostTest(unittest.TestCase):
    def test_single_host_auto(self):
        hosts = [
            {
                "name": "a",
                "address": "1.2.3.4",
                "port": 8022,
                "fingerprint": "SHA256:X",
                "auth": "pin",
            }
        ]
        with mock.patch("builtins.input") as m:
            self.assertEqual(pick_host(hosts), hosts[0])
            m.assert_not_called()

    def test_choose_by_number(self):
        hosts = [
            {
                "name": "a",
                "address": "1.1.1.1",
                "port": 8022,
                "fingerprint": "SHA256:AA:11:BB",
                "auth": "pin",
            },
            {
                "name": "b",
                "address": "2.2.2.2",
                "port": 8022,
                "fingerprint": "SHA256:CC:22:DD",
                "auth": "token",
            },
        ]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with mock.patch("builtins.input", side_effect=["x", "2"]):
                self.assertEqual(pick_host(hosts), hosts[1])
        out = buf.getvalue()
        self.assertIn("LAN-Suche", out)
        self.assertIn("SHA256:AA:...:BB", out)
        self.assertIn("SHA256:CC:...:DD", out)
        self.assertIn("PIN", out)
        self.assertIn("TOKEN", out)

    def test_busy_hosts_marked(self):
        hosts = [
            {
                "name": "a",
                "address": "1.2.3.4",
                "port": 8022,
                "fingerprint": "SHA256:X",
                "auth": "pin",
                "busy": True,
            },
            {
                "name": "b",
                "address": "1.2.3.5",
                "port": 8022,
                "fingerprint": "SHA256:Y",
                "auth": "pin",
                "busy": False,
            },
        ]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with mock.patch("builtins.input", return_value="2"):
                self.assertEqual(pick_host(hosts), hosts[1])
        out = buf.getvalue()
        self.assertIn("a (1.2.3.4, PIN, SHA256:X) (belegt)", out)
        self.assertNotIn("b (1.2.3.5, PIN, SHA256:Y) (belegt)", out)

    def test_abort_on_eof(self):
        hosts = [{"name": "a", "address": "1.1.1.1"}, {"name": "b", "address": "2.2.2.2"}]
        with mock.patch("builtins.input", side_effect=EOFError):
            self.assertIsNone(pick_host(hosts))

    def test_interrupt_propagates(self):
        hosts = [{"name": "a", "address": "1.1.1.1"}, {"name": "b", "address": "2.2.2.2"}]
        with mock.patch("builtins.input", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    pick_host(hosts)


class ShortFingerprintTest(unittest.TestCase):
    def test_long_abbreviated(self):
        self.assertEqual(
            _short_fingerprint("SHA256:AB:CD:EF"), "SHA256:AB:...:EF"
        )

    def test_short_kept(self):
        self.assertEqual(_short_fingerprint("SHA256:X"), "SHA256:X")

    def test_empty_becomes_question_mark(self):
        self.assertEqual(_short_fingerprint(""), "?")


if __name__ == "__main__":
    unittest.main()
