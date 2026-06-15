"""MRF configuration management utilities.

Usage (CLI)::

    # Show current configuration
    python -m scripts.mrf.config get --host 192.168.1.10

    # Update a configuration key
    python -m scripts.mrf.config set --host 192.168.1.10 --key max_sessions --value 200

Usage (library)::

    from scripts.mrf.config import get_config, set_config
    cfg = get_config(host="192.168.1.10")
    set_config(host="192.168.1.10", key="max_sessions", value=200)
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, Optional

from .utils import MRFClient, setup_logging


def get_config(
    host: str = "localhost",
    port: int = 8080,
    timeout: int = 10,
    auth_token: Optional[str] = None,
    key: Optional[str] = None,
) -> Dict[str, Any]:
    """Retrieve the active configuration from an MRF node.

    Args:
        host: Hostname or IP address of the MRF node.
        port: Management API port.
        timeout: Request timeout in seconds.
        auth_token: Optional ******
        key: If provided, return only the value for this configuration key.

    Returns:
        Full configuration dictionary, or a single-entry dict when *key* is given.

    Raises:
        ConnectionError: If the MRF node is unreachable.
        KeyError: If *key* is provided but does not exist in the configuration.
    """
    client = MRFClient(host=host, port=port, timeout=timeout, auth_token=auth_token)
    config = client.get("/api/v1/config")
    if key is not None:
        if key not in config:
            raise KeyError(f"Configuration key '{key}' not found")
        return {key: config[key]}
    return config


def set_config(
    key: str,
    value: Any,
    host: str = "localhost",
    port: int = 8080,
    timeout: int = 10,
    auth_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Update a single configuration key on the MRF node.

    Args:
        key: Configuration key to update.
        value: New value for the key.
        host: Hostname or IP address of the MRF node.
        port: Management API port.
        timeout: Request timeout in seconds.
        auth_token: Optional ******

    Returns:
        The updated configuration as returned by the API.

    Raises:
        ConnectionError: If the MRF node is unreachable.
    """
    client = MRFClient(host=host, port=port, timeout=timeout, auth_token=auth_token)
    return client.put("/api/v1/config", {key: value})


def reset_config(
    host: str = "localhost",
    port: int = 8080,
    timeout: int = 10,
    auth_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Reset the MRF node configuration to factory defaults.

    Args:
        host: Hostname or IP address of the MRF node.
        port: Management API port.
        timeout: Request timeout in seconds.
        auth_token: Optional ******

    Returns:
        The default configuration as returned by the API.

    Raises:
        ConnectionError: If the MRF node is unreachable.
    """
    client = MRFClient(host=host, port=port, timeout=timeout, auth_token=auth_token)
    return client.post("/api/v1/config/reset", {})


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Manage MRF node configuration."
    )
    parser.add_argument("--host", default="localhost", help="MRF hostname or IP")
    parser.add_argument("--port", type=int, default=8080, help="Management API port")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (seconds)")
    parser.add_argument("--token", default=None, help="****** token")
    parser.add_argument(
        "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"]
    )

    sub = parser.add_subparsers(dest="command", required=True)

    get_p = sub.add_parser("get", help="Retrieve configuration")
    get_p.add_argument("--key", default=None, help="Specific config key to retrieve")

    set_p = sub.add_parser("set", help="Update a configuration key")
    set_p.add_argument("--key", required=True, help="Configuration key")
    set_p.add_argument("--value", required=True, help="New value (JSON-decoded)")

    sub.add_parser("reset", help="Reset configuration to defaults")

    return parser.parse_args(argv)


def main(argv: Optional[list] = None) -> int:
    """Entry point for the config CLI tool."""
    args = _parse_args(argv)
    logger = setup_logging(args.log_level)
    common = dict(host=args.host, port=args.port, timeout=args.timeout, auth_token=args.token)

    try:
        if args.command == "get":
            result = get_config(**common, key=args.key)
        elif args.command == "set":
            try:
                value: Any = json.loads(args.value)
            except json.JSONDecodeError:
                value = args.value
            result = set_config(key=args.key, value=value, **common)
        else:  # reset
            result = reset_config(**common)
    except (ConnectionError, KeyError) as exc:
        logger.error("%s", exc)
        return 1

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
