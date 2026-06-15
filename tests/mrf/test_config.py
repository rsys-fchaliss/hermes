"""Tests for scripts.mrf.config."""

import unittest
from unittest.mock import patch

from scripts.mrf.config import get_config, reset_config, set_config, main


class TestGetConfig(unittest.TestCase):
    @patch("scripts.mrf.config.MRFClient")
    def test_returns_full_config(self, MockClient):
        full = {"max_sessions": 100, "codec": "opus"}
        MockClient.return_value.get.return_value = full
        result = get_config()
        self.assertEqual(result, full)

    @patch("scripts.mrf.config.MRFClient")
    def test_returns_single_key(self, MockClient):
        full = {"max_sessions": 100, "codec": "opus"}
        MockClient.return_value.get.return_value = full
        result = get_config(key="codec")
        self.assertEqual(result, {"codec": "opus"})

    @patch("scripts.mrf.config.MRFClient")
    def test_raises_key_error_for_missing_key(self, MockClient):
        MockClient.return_value.get.return_value = {"max_sessions": 100}
        with self.assertRaises(KeyError):
            get_config(key="nonexistent")

    @patch("scripts.mrf.config.MRFClient")
    def test_propagates_connection_error(self, MockClient):
        MockClient.return_value.get.side_effect = ConnectionError("refused")
        with self.assertRaises(ConnectionError):
            get_config()


class TestSetConfig(unittest.TestCase):
    @patch("scripts.mrf.config.MRFClient")
    def test_calls_put_with_correct_payload(self, MockClient):
        MockClient.return_value.put.return_value = {"max_sessions": 200}
        result = set_config("max_sessions", 200)
        self.assertEqual(result, {"max_sessions": 200})
        MockClient.return_value.put.assert_called_once_with(
            "/api/v1/config", {"max_sessions": 200}
        )


class TestResetConfig(unittest.TestCase):
    @patch("scripts.mrf.config.MRFClient")
    def test_calls_post_reset(self, MockClient):
        MockClient.return_value.post.return_value = {"max_sessions": 50}
        result = reset_config()
        MockClient.return_value.post.assert_called_once_with("/api/v1/config/reset", {})
        self.assertIn("max_sessions", result)


class TestConfigMain(unittest.TestCase):
    @patch("scripts.mrf.config.get_config")
    def test_get_command_returns_zero(self, mock_get):
        mock_get.return_value = {"max_sessions": 100}
        rc = main(["--host", "localhost", "get"])
        self.assertEqual(rc, 0)

    @patch("scripts.mrf.config.set_config")
    def test_set_command_with_json_value(self, mock_set):
        mock_set.return_value = {"max_sessions": 200}
        rc = main(["--host", "localhost", "set", "--key", "max_sessions", "--value", "200"])
        self.assertEqual(rc, 0)
        mock_set.assert_called_once()
        _, kwargs = mock_set.call_args
        self.assertEqual(kwargs.get("value") or mock_set.call_args[0][1], 200)

    @patch("scripts.mrf.config.get_config")
    def test_returns_one_on_error(self, mock_get):
        mock_get.side_effect = ConnectionError("unreachable")
        rc = main(["--host", "localhost", "get"])
        self.assertEqual(rc, 1)

    @patch("scripts.mrf.config.reset_config")
    def test_reset_command(self, mock_reset):
        mock_reset.return_value = {}
        rc = main(["--host", "localhost", "reset"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
