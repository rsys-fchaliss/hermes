"""Tests for scripts.mrf.connectivity."""

import socket
import unittest
from unittest.mock import patch, MagicMock

from scripts.mrf.connectivity import (
    ConnectivityResult,
    format_result,
    test_connectivity as run_connectivity_test,
    main,
)


class TestConnectivityResult(unittest.TestCase):
    def test_default_values(self):
        r = ConnectivityResult(host="10.0.0.1", port=8080)
        self.assertFalse(r.success)
        self.assertFalse(r.tcp_reachable)
        self.assertFalse(r.api_reachable)
        self.assertIsNone(r.latency_ms)
        self.assertEqual(r.errors, [])


class TestTestConnectivity(unittest.TestCase):
    @patch("scripts.mrf.connectivity.MRFClient")
    @patch("scripts.mrf.connectivity._probe_tcp")
    def test_success_when_both_pass(self, mock_probe, MockClient):
        mock_probe.return_value = (True, None)
        MockClient.return_value.get.return_value = {"status": "ok"}

        result = run_connectivity_test(host="10.0.0.1")

        self.assertTrue(result.success)
        self.assertTrue(result.tcp_reachable)
        self.assertTrue(result.api_reachable)
        self.assertIsNotNone(result.latency_ms)

    @patch("scripts.mrf.connectivity._probe_tcp")
    def test_failure_when_tcp_fails(self, mock_probe):
        mock_probe.return_value = (False, "Connection refused")

        result = run_connectivity_test(host="10.0.0.1")

        self.assertFalse(result.success)
        self.assertFalse(result.tcp_reachable)
        self.assertFalse(result.api_reachable)
        self.assertIn("TCP", result.errors[0])

    @patch("scripts.mrf.connectivity.MRFClient")
    @patch("scripts.mrf.connectivity._probe_tcp")
    def test_failure_when_api_fails(self, mock_probe, MockClient):
        mock_probe.return_value = (True, None)
        MockClient.return_value.get.side_effect = ConnectionError("HTTP 503")

        result = run_connectivity_test(host="10.0.0.1")

        self.assertFalse(result.success)
        self.assertTrue(result.tcp_reachable)
        self.assertFalse(result.api_reachable)
        self.assertIn("API", result.errors[0])


class TestProbeTcp(unittest.TestCase):
    @patch("scripts.mrf.connectivity.socket.create_connection")
    def test_success(self, mock_conn):
        mock_conn.return_value.__enter__ = lambda s: s
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        from scripts.mrf.connectivity import _probe_tcp
        ok, err = _probe_tcp("localhost", 9999, 5)
        self.assertTrue(ok)
        self.assertIsNone(err)

    @patch("scripts.mrf.connectivity.socket.create_connection")
    def test_failure(self, mock_conn):
        mock_conn.side_effect = OSError("Connection refused")
        from scripts.mrf.connectivity import _probe_tcp
        ok, err = _probe_tcp("localhost", 9999, 5)
        self.assertFalse(ok)
        self.assertIsNotNone(err)


class TestFormatResult(unittest.TestCase):
    def test_pass_label_when_success(self):
        r = ConnectivityResult(host="h", port=8080, success=True, tcp_reachable=True, api_reachable=True, latency_ms=3.5)
        output = format_result(r)
        self.assertIn("PASS", output)
        self.assertIn("3.5", output)

    def test_fail_label_when_not_success(self):
        r = ConnectivityResult(host="h", port=8080, errors=["TCP: refused"])
        output = format_result(r)
        self.assertIn("FAIL", output)
        self.assertIn("TCP: refused", output)


class TestConnectivityMain(unittest.TestCase):
    @patch("scripts.mrf.connectivity.test_connectivity")
    def test_returns_zero_on_success(self, mock_test):
        mock_test.return_value = ConnectivityResult(
            host="localhost", port=8080, success=True
        )
        rc = main(["--host", "localhost"])
        self.assertEqual(rc, 0)

    @patch("scripts.mrf.connectivity.test_connectivity")
    def test_returns_one_on_failure(self, mock_test):
        mock_test.return_value = ConnectivityResult(
            host="localhost", port=8080, success=False
        )
        rc = main(["--host", "localhost"])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
