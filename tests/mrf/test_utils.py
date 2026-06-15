"""Tests for scripts.mrf.utils."""

import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

from scripts.mrf.utils import (
    MRFClient,
    load_config,
    save_config,
    setup_logging,
)


class TestSetupLogging(unittest.TestCase):
    def test_returns_logger(self):
        import logging
        logger = setup_logging("DEBUG")
        self.assertIsInstance(logger, logging.Logger)

    def test_with_log_file(self):
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as fh:
            log_path = fh.name
        try:
            setup_logging("INFO", log_file=log_path)
            self.assertTrue(os.path.exists(log_path))
        finally:
            os.unlink(log_path)


class TestLoadSaveConfig(unittest.TestCase):
    def test_round_trip(self):
        cfg = {"host": "10.0.0.1", "port": 8080, "max_sessions": 100}
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False
        ) as fh:
            path = fh.name
        try:
            save_config(cfg, path)
            loaded = load_config(path)
            self.assertEqual(loaded, cfg)
        finally:
            os.unlink(path)

    def test_load_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            load_config("/nonexistent/path/config.json")

    def test_load_invalid_json(self):
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False
        ) as fh:
            fh.write("not valid json {{")
            path = fh.name
        try:
            with self.assertRaises(json.JSONDecodeError):
                load_config(path)
        finally:
            os.unlink(path)


class TestMRFClient(unittest.TestCase):
    def _make_client(self, **kwargs):
        return MRFClient(host="localhost", port=9999, timeout=5, **kwargs)

    @patch("scripts.mrf.utils.urlopen")
    def test_get_success(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"state": "running"}'
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = self._make_client()
        result = client.get("/api/v1/status")
        self.assertEqual(result, {"state": "running"})

    @patch("scripts.mrf.utils.urlopen")
    def test_post_success(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"ok": true}'
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = self._make_client()
        result = client.post("/api/v1/config/reset", {})
        self.assertEqual(result, {"ok": True})

    @patch("scripts.mrf.utils.urlopen")
    def test_http_error_raises_connection_error(self, mock_urlopen):
        mock_urlopen.side_effect = HTTPError(
            url="http://localhost:9999/api/v1/status",
            code=503,
            msg="Service Unavailable",
            hdrs=None,
            fp=None,
        )
        client = self._make_client()
        with self.assertRaises(ConnectionError):
            client.get("/api/v1/status")

    @patch("scripts.mrf.utils.urlopen")
    def test_url_error_raises_connection_error(self, mock_urlopen):
        mock_urlopen.side_effect = URLError("Connection refused")
        client = self._make_client()
        with self.assertRaises(ConnectionError):
            client.get("/api/v1/status")

    @patch("scripts.mrf.utils.urlopen")
    def test_empty_response_returns_empty_dict(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = b""
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = self._make_client()
        result = client.delete("/api/v1/sessions/123")
        self.assertEqual(result, {})

    def test_auth_token_included_in_headers(self):
        token = "secret-token"
        client = MRFClient(auth_token=token)
        headers = client._headers()
        self.assertIn("Authorization", headers)
        self.assertIn(token, headers["Authorization"])

    def test_no_auth_token_omits_authorization_header(self):
        client = MRFClient()
        headers = client._headers()
        self.assertNotIn("Authorization", headers)


if __name__ == "__main__":
    unittest.main()
