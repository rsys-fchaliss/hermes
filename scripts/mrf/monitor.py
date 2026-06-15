"""MRF metrics monitoring utilities.

Usage (CLI)::

    # Display a snapshot of current metrics
    python -m scripts.mrf.monitor --host 192.168.1.10

    # Poll metrics every 5 seconds
    python -m scripts.mrf.monitor --host 192.168.1.10 --interval 5

Usage (library)::

    from scripts.mrf.monitor import get_metrics, poll_metrics
    snapshot = get_metrics(host="192.168.1.10")
    for snapshot in poll_metrics(host="192.168.1.10", interval=5, count=10):
        print(snapshot)
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any, Dict, Generator, Optional

from .utils import MRFClient, setup_logging


# Metric keys expected from the MRF API
METRIC_KEYS = (
    "active_sessions",
    "total_sessions",
    "cpu_usage_pct",
    "mem_usage_pct",
    "packets_sent",
    "packets_recv",
    "errors",
)


def get_metrics(
    host: str = "localhost",
    port: int = 8080,
    timeout: int = 10,
    auth_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch a single metrics snapshot from the MRF node.

    Args:
        host: Hostname or IP address of the MRF node.
        port: Management API port.
        timeout: Request timeout in seconds.
        auth_token: Optional ******

    Returns:
        Dictionary containing current MRF metrics.

    Raises:
        ConnectionError: If the MRF node is unreachable.
    """
    client = MRFClient(host=host, port=port, timeout=timeout, auth_token=auth_token)
    return client.get("/api/v1/metrics")


def poll_metrics(
    host: str = "localhost",
    port: int = 8080,
    timeout: int = 10,
    auth_token: Optional[str] = None,
    interval: float = 5.0,
    count: Optional[int] = None,
) -> Generator[Dict[str, Any], None, None]:
    """Continuously poll MRF metrics and yield each snapshot.

    Args:
        host: Hostname or IP address of the MRF node.
        port: Management API port.
        timeout: Request timeout in seconds.
        auth_token: Optional ******
        interval: Seconds between polls.
        count: Number of snapshots to collect (``None`` = run indefinitely).

    Yields:
        Metrics dictionaries, each augmented with a ``timestamp`` field
        (Unix epoch as a float).
    """
    collected = 0
    while count is None or collected < count:
        snapshot = get_metrics(host=host, port=port, timeout=timeout, auth_token=auth_token)
        snapshot["timestamp"] = time.time()
        yield snapshot
        collected += 1
        if count is None or collected < count:
            time.sleep(interval)


def format_metrics(metrics: Dict[str, Any]) -> str:
    """Return a human-readable summary of an MRF metrics snapshot.

    Args:
        metrics: Metrics dictionary returned by :func:`get_metrics`.

    Returns:
        Multi-line formatted string.
    """
    ts = metrics.get("timestamp", time.time())
    lines = [f"MRF Metrics  [{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))}]"]
    lines.append("-" * 40)
    for key in METRIC_KEYS:
        if key in metrics:
            lines.append(f"  {key:<25}: {metrics[key]}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Monitor MRF node metrics.")
    parser.add_argument("--host", default="localhost", help="MRF hostname or IP")
    parser.add_argument("--port", type=int, default=8080, help="Management API port")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (seconds)")
    parser.add_argument("--token", default=None, help="****** token")
    parser.add_argument(
        "--interval", type=float, default=0.0,
        help="Poll interval in seconds (0 = single snapshot)",
    )
    parser.add_argument(
        "--count", type=int, default=None,
        help="Number of snapshots to collect when --interval > 0",
    )
    parser.add_argument(
        "--json", dest="output_json", action="store_true", help="Output raw JSON"
    )
    parser.add_argument(
        "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"]
    )
    return parser.parse_args(argv)


def main(argv: Optional[list] = None) -> int:
    """Entry point for the monitor CLI tool."""
    args = _parse_args(argv)
    logger = setup_logging(args.log_level)
    common = dict(host=args.host, port=args.port, timeout=args.timeout, auth_token=args.token)

    try:
        if args.interval > 0:
            for snapshot in poll_metrics(**common, interval=args.interval, count=args.count):
                if args.output_json:
                    print(json.dumps(snapshot))
                else:
                    print(format_metrics(snapshot))
        else:
            snapshot = get_metrics(**common)
            if args.output_json:
                print(json.dumps(snapshot, indent=2))
            else:
                print(format_metrics(snapshot))
    except ConnectionError as exc:
        logger.error("Failed to retrieve metrics: %s", exc)
        return 1
    except KeyboardInterrupt:
        pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
