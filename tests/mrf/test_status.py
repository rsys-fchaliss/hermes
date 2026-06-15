"""Tests for scripts.mrf.status."""

import unittest
from unittest.mock import patch

from scripts.mrf.status import check_status, format_status, main


class TestCheckStatus(unittest.TestCase):
    @patch("scripts.mrf.status.MRFClient")
    def test_returns_status_dict(self, MockClient):
        MockClient.return_value.get.return_value = {
            "state": "running",
            "uptime": 3600,
            "active_sessions": 5,
            "version": "1.2.3",
        }
        result = check_status(host="10.0.0.1")
        self.assertEqual(result["state"], "running")
        MockClient.return_value.get.assert_called_once_with("/api/v1/status")

    @patch("scripts.mrf.status.MRFClient")
    def test_propagates_connection_error(self, MockClient):
        MockClient.return_value.get.side_effect = ConnectionError("refused")
        with self.assertRaises(ConnectionError):
            check_status()


class TestFormatStatus(unittest.TestCase):
    def test_output_contains_keys(self):
        status = {"state": "running", "uptime": 120, "active_sessions": 2}
        output = format_status(status)
        self.assertIn("state", output)
        self.assertIn("running", output)
        self.assertIn("active_sessions", output)

    def test_header_present(self):
        output = format_status({})
        self.assertIn("MRF Status", output)


class TestStatusMain(unittest.TestCase):
    @patch("scripts.mrf.status.check_status")
    def test_returns_zero_for_running(self, mock_check):
        mock_check.return_value = {"state": "running"}
        rc = main(["--host", "localhost"])
        self.assertEqual(rc, 0)

    @patch("scripts.mrf.status.check_status")
    def test_returns_nonzero_for_stopped(self, mock_check):
        mock_check.return_value = {"state": "stopped"}
        rc = main(["--host", "localhost"])
        self.assertNotEqual(rc, 0)

    @patch("scripts.mrf.status.check_status")
    def test_returns_one_on_connection_error(self, mock_check):
        mock_check.side_effect = ConnectionError("unreachable")
        rc = main(["--host", "10.0.0.1"])
        self.assertEqual(rc, 1)

    @patch("scripts.mrf.status.check_status")
    def test_json_output_flag(self, mock_check):
        mock_check.return_value = {"state": "active"}
        rc = main(["--host", "localhost", "--json"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
