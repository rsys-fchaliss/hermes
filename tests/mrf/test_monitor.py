"""Tests for scripts.mrf.monitor."""

import time
import unittest
from unittest.mock import patch

from scripts.mrf.monitor import format_metrics, get_metrics, poll_metrics, main


class TestGetMetrics(unittest.TestCase):
    @patch("scripts.mrf.monitor.MRFClient")
    def test_returns_metrics_dict(self, MockClient):
        MockClient.return_value.get.return_value = {
            "active_sessions": 3,
            "cpu_usage_pct": 20.5,
        }
        result = get_metrics()
        self.assertIn("active_sessions", result)
        MockClient.return_value.get.assert_called_once_with("/api/v1/metrics")

    @patch("scripts.mrf.monitor.MRFClient")
    def test_propagates_connection_error(self, MockClient):
        MockClient.return_value.get.side_effect = ConnectionError("refused")
        with self.assertRaises(ConnectionError):
            get_metrics()


class TestPollMetrics(unittest.TestCase):
    @patch("scripts.mrf.monitor.time.sleep", return_value=None)
    @patch("scripts.mrf.monitor.get_metrics")
    def test_collects_requested_count(self, mock_get, mock_sleep):
        mock_get.return_value = {"active_sessions": 1}
        results = list(poll_metrics(count=3, interval=1.0))
        self.assertEqual(len(results), 3)

    @patch("scripts.mrf.monitor.time.sleep", return_value=None)
    @patch("scripts.mrf.monitor.get_metrics")
    def test_each_snapshot_has_timestamp(self, mock_get, mock_sleep):
        mock_get.return_value = {"active_sessions": 0}
        results = list(poll_metrics(count=2, interval=0.1))
        for r in results:
            self.assertIn("timestamp", r)
            self.assertIsInstance(r["timestamp"], float)


class TestFormatMetrics(unittest.TestCase):
    def test_contains_expected_keys(self):
        metrics = {
            "active_sessions": 5,
            "cpu_usage_pct": 15.0,
            "timestamp": time.time(),
        }
        output = format_metrics(metrics)
        self.assertIn("active_sessions", output)
        self.assertIn("cpu_usage_pct", output)

    def test_header_present(self):
        output = format_metrics({"timestamp": time.time()})
        self.assertIn("MRF Metrics", output)


class TestMonitorMain(unittest.TestCase):
    @patch("scripts.mrf.monitor.get_metrics")
    def test_single_snapshot_returns_zero(self, mock_get):
        mock_get.return_value = {"active_sessions": 1}
        rc = main(["--host", "localhost"])
        self.assertEqual(rc, 0)

    @patch("scripts.mrf.monitor.get_metrics")
    def test_connection_error_returns_one(self, mock_get):
        mock_get.side_effect = ConnectionError("unreachable")
        rc = main(["--host", "localhost"])
        self.assertEqual(rc, 1)

    @patch("scripts.mrf.monitor.get_metrics")
    def test_json_output(self, mock_get):
        mock_get.return_value = {"active_sessions": 2}
        rc = main(["--host", "localhost", "--json"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
