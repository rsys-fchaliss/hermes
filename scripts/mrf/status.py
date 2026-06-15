"""MRF health and status utilities.

Usage (CLI)::

    python -m scripts.mrf.status --host 192.168.1.10 --port 8080

Usage (library)::

    from scripts.mrf.status import check_status
    info = check_status(host="192.168.1.10")
    print(info)
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, Optional

from .utils import MRFClient, setup_logging


def check_status(
    host: str = "localhost",
    port: int = 8080,
    timeout: int = 10,
    auth_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Query the MRF node and return its current status.

    Args:
        host: Hostname or IP address of the MRF node.
        port: Management API port.
        timeout: Request timeout in seconds.
        auth_token: Optional ******

    Returns:
        Dictionary containing status fields such as ``state``, ``uptime``,
        ``active_sessions``, and ``version``.

    Raises:
        ConnectionError: If the MRF node is unreachable.
    """
    client = MRFClient(host=host, port=port, timeout=timeout, auth_token=auth_token)
    return client.get("/api/v1/status")


def format_status(status: Dict[str, Any]) -> str:
    """Return a human-readable string representation of MRF status.

    Args:
        status: Status dictionary returned by :func:`check_status`.

    Returns:
        Multi-line formatted string.
    """
    lines = ["MRF Status"]
    lines.append("-" * 40)
    for key, value in status.items():
        lines.append(f"  {key:<20}: {value}")
    return "\n".join(lines)


def _parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check the health and status of an MRF node."
    )
    parser.add_argument("--host", default="localhost", help="MRF hostname or IP")
    parser.add_argument("--port", type=int, default=8080, help="Management API port")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (seconds)")
    parser.add_argument("--token", default=None, help="****** token")
    parser.add_argument(
        "--json", dest="output_json", action="store_true", help="Output raw JSON"
    )
    parser.add_argument(
        "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"]
    )
    return parser.parse_args(argv)


def main(argv: Optional[list] = None) -> int:
    """Entry point for the status CLI tool."""
    args = _parse_args(argv)
    logger = setup_logging(args.log_level)

    try:
        status = check_status(
            host=args.host,
            port=args.port,
            timeout=args.timeout,
            auth_token=args.token,
        )
    except ConnectionError as exc:
        logger.error("Failed to retrieve MRF status: %s", exc)
        return 1

    if args.output_json:
        print(json.dumps(status, indent=2))
    else:
        print(format_status(status))

    state = status.get("state", "").lower()
    return 0 if state in ("running", "active", "ok") else 2


if __name__ == "__main__":
    sys.exit(main())
