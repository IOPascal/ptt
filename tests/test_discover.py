"""Tests for LAN discovery and host picking."""
import json
import socket
import time
import unittest
from unittest import mock

from ptt.client import pick_host
from ptt.discover import discover, parse_reply, start_responder


def _free_udp_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


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
            },
        )

    def test_invalid_replies_ignored(self):
        for bad in (
            b"not json",
            b"[1, 2]",
            self._reply(port=99999),
            self._reply(port="x"),
            self._reply(fingerprint="nope"),
            self._reply(auth="password"),
            self._reply(name=None),
            json.dumps({"name": "x"}).encode("utf-8"),
        ):
            self.assertIsNone(parse_reply(bad, "192.168.1.5"))


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
            {"name": "a", "address": "1.1.1.1"},
            {"name": "b", "address": "2.2.2.2"},
        ]
        with mock.patch("builtins.input", side_effect=["x", "2"]):
            self.assertEqual(pick_host(hosts), hosts[1])

    def test_abort_on_eof(self):
        hosts = [{"name": "a", "address": "1.1.1.1"}, {"name": "b", "address": "2.2.2.2"}]
        with mock.patch("builtins.input", side_effect=EOFError):
            self.assertIsNone(pick_host(hosts))


if __name__ == "__main__":
    unittest.main()
