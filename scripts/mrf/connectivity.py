"""MRF connectivity testing utilities.

Usage (CLI)::

    python -m scripts.mrf.connectivity --host 192.168.1.10 --port 8080

Usage (library)::

    from scripts.mrf.connectivity import test_connectivity, ConnectivityResult
    result = test_connectivity(host="192.168.1.10")
    if result.success:
        print("MRF is reachable")
"""

from __future__ import annotations

import argparse
import socket
import sys
import time
from dataclasses import dataclass, field
from typing import List, Optional

from .utils import MRFClient, setup_logging


@dataclass
class ConnectivityResult:
    """Aggregated results from an MRF connectivity probe.

    Attributes:
        host: Target hostname or IP.
        port: Target TCP port.
        success: ``True`` if all checks passed.
        tcp_reachable: ``True`` if a raw TCP connection was established.
        api_reachable: ``True`` if the management API responded with HTTP 200.
        latency_ms: Round-trip latency of the API health check in milliseconds.
        errors: List of error messages encountered during testing.
    """

    host: str
    port: int
    success: bool = False
    tcp_reachable: bool = False
    api_reachable: bool = False
    latency_ms: Optional[float] = None
    errors: List[str] = field(default_factory=list)


def _probe_tcp(host: str, port: int, timeout: int) -> tuple[bool, Optional[str]]:
    """Attempt a raw TCP connection to *host*:*port*.

    Returns:
        Tuple of (success, error_message).
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, None
    except OSError as exc:
        return False, str(exc)


def test_connectivity(
    host: str = "localhost",
    port: int = 8080,
    timeout: int = 10,
    auth_token: Optional[str] = None,
) -> ConnectivityResult:
    """Run a suite of connectivity checks against an MRF node.

    The function performs two checks in order:

    1. **TCP reachability** – verifies the management port accepts connections.
    2. **API health check** – sends a GET request to ``/api/v1/health`` and
       measures round-trip latency.

    Args:
        host: Hostname or IP address of the MRF node.
        port: Management API port.
        timeout: Socket / HTTP timeout in seconds.
        auth_token: Optional ******

    Returns:
        :class:`ConnectivityResult` summarising all checks.
    """
    result = ConnectivityResult(host=host, port=port)

    # --- TCP probe ---
    tcp_ok, tcp_err = _probe_tcp(host, port, timeout)
    result.tcp_reachable = tcp_ok
    if tcp_err:
        result.errors.append(f"TCP: {tcp_err}")

    if tcp_ok:
        # --- API health probe ---
        client = MRFClient(host=host, port=port, timeout=timeout, auth_token=auth_token)
        t0 = time.monotonic()
        try:
            client.get("/api/v1/health")
            result.latency_ms = (time.monotonic() - t0) * 1000
            result.api_reachable = True
        except ConnectionError as exc:
            result.errors.append(f"API: {exc}")

    result.success = result.tcp_reachable and result.api_reachable
    return result


def format_result(result: ConnectivityResult) -> str:
    """Return a human-readable summary of a :class:`ConnectivityResult`.

    Args:
        result: The connectivity test result.

    Returns:
        Multi-line formatted string.
    """
    status = "PASS" if result.success else "FAIL"
    lines = [
        f"Connectivity Test  [{result.host}:{result.port}]  {status}",
        "-" * 50,
        f"  TCP reachable : {'YES' if result.tcp_reachable else 'NO'}",
        f"  API reachable : {'YES' if result.api_reachable else 'NO'}",
    ]
    if result.latency_ms is not None:
        lines.append(f"  Latency       : {result.latency_ms:.1f} ms")
    if result.errors:
        lines.append("  Errors:")
        for err in result.errors:
            lines.append(f"    - {err}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Test connectivity to an MRF node.")
    parser.add_argument("--host", default="localhost", help="MRF hostname or IP")
    parser.add_argument("--port", type=int, default=8080, help="Management API port")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (seconds)")
    parser.add_argument("--token", default=None, help="****** token")
    parser.add_argument(
        "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"]
    )
    return parser.parse_args(argv)


def main(argv: Optional[list] = None) -> int:
    """Entry point for the connectivity CLI tool."""
    args = _parse_args(argv)
    setup_logging(args.log_level)

    result = test_connectivity(
        host=args.host,
        port=args.port,
        timeout=args.timeout,
        auth_token=args.token,
    )
    print(format_result(result))
    return 0 if result.success else 1


if __name__ == "__main__":
    sys.exit(main())
