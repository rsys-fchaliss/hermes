"""Shared utilities for MRF management scripts."""

import json
import logging
import os
import sys
from typing import Any, Dict, Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin


DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "mrf_config.json")
DEFAULT_MRF_HOST = "localhost"
DEFAULT_MRF_PORT = 8080
DEFAULT_TIMEOUT = 10


def setup_logging(level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """Configure and return a logger for MRF utilities.

    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file: Optional path to a log file. Logs to stdout if not provided.

    Returns:
        Configured Logger instance.
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    handlers: list = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
    )
    return logging.getLogger("mrf")


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load MRF configuration from a JSON file.

    Args:
        config_path: Path to the JSON config file. Defaults to mrf_config.json
                     in the same directory as this module.

    Returns:
        Dictionary of configuration values.

    Raises:
        FileNotFoundError: If the config file does not exist.
        json.JSONDecodeError: If the config file contains invalid JSON.
    """
    path = config_path or DEFAULT_CONFIG_PATH
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def save_config(config: Dict[str, Any], config_path: Optional[str] = None) -> None:
    """Persist MRF configuration to a JSON file.

    Args:
        config: Configuration dictionary to save.
        config_path: Destination path. Defaults to mrf_config.json.
    """
    path = config_path or DEFAULT_CONFIG_PATH
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(config, fh, indent=2)


class MRFClient:
    """HTTP client for communicating with an MRF management API.

    Args:
        host: Hostname or IP address of the MRF node.
        port: TCP port of the MRF management API.
        timeout: Socket timeout in seconds.
        auth_token: Optional ****** for authenticated endpoints.
    """

    def __init__(
        self,
        host: str = DEFAULT_MRF_HOST,
        port: int = DEFAULT_MRF_PORT,
        timeout: int = DEFAULT_TIMEOUT,
        auth_token: Optional[str] = None,
    ) -> None:
        self.base_url = f"http://{host}:{port}"
        self.timeout = timeout
        self._auth_token = auth_token
        self._logger = logging.getLogger("mrf.client")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._auth_token:
            headers["Authorization"] = "Bearer " + self._auth_token
        return headers

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Send an HTTP request and return the parsed JSON response.

        Args:
            method: HTTP verb (GET, POST, PUT, DELETE).
            path: URL path relative to base_url.
            body: Optional request body, serialised as JSON.

        Returns:
            Parsed JSON response as a dictionary.

        Raises:
            ConnectionError: On network or HTTP errors.
        """
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        data = json.dumps(body).encode("utf-8") if body else None
        req = Request(url, data=data, headers=self._headers(), method=method)
        self._logger.debug("%s %s", method, url)
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except HTTPError as exc:
            raise ConnectionError(f"HTTP {exc.code} {exc.reason} for {url}") from exc
        except URLError as exc:
            raise ConnectionError(f"URL error for {url}: {exc.reason}") from exc

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, path: str) -> Dict[str, Any]:
        return self._request("GET", path)

    def post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("POST", path, body)

    def put(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("PUT", path, body)

    def delete(self, path: str) -> Dict[str, Any]:
        return self._request("DELETE", path)
