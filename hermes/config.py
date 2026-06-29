import os
import yaml
import argparse


def load_yaml_config(config_path: str) -> dict:
    """Load configuration from a YAML file."""
    if not os.path.isfile(config_path):
        return {}
    with open(config_path, "r") as f:
        data = yaml.safe_load(f)
    return data if data else {}


def parse_cli_args(args=None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Extract closed CVEs from container build logs"
    )
    parser.add_argument("--product", help="Product name")
    parser.add_argument("--version", help="Project version")
    parser.add_argument("--input", help="Path to ZIP file containing build logs")
    parser.add_argument("--output", help="Output CSV file path (default: closed-cves.csv)")
    parser.add_argument(
        "--config",
        default="hermes.yaml",
        help="Path to YAML config file (default: hermes.yaml)",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=None,
        help="Delay in seconds between API requests (default: 0.5)",
    )
    parser.add_argument(
        "--distro-filter",
        choices=["rocky", "alpine"],
        default=None,
        help="Only process containers of this distro type",
    )
    parser.add_argument(
        "--skip-enrichment",
        action="store_true",
        help="Skip OSV.dev metadata enrichment",
    )
    return parser.parse_args(args)


def build_config(cli_args: argparse.Namespace) -> dict:
    """Merge YAML config and CLI args. YAML takes priority."""
    yaml_config = load_yaml_config(cli_args.config)

    config = {
        "product": yaml_config.get("product") or cli_args.product,
        "project_version": yaml_config.get("project_version") or cli_args.version,
        "input": yaml_config.get("input") or cli_args.input,
        "output": yaml_config.get("output") or cli_args.output or "closed-cves.csv",
        "rate_limit": yaml_config.get("rate_limit") or cli_args.rate_limit or 0.5,
        "distro_filter": yaml_config.get("distro_filter") or cli_args.distro_filter,
        "skip_enrichment": yaml_config.get("skip_enrichment") or cli_args.skip_enrichment or False,
    }
    return config


def validate_config(config: dict) -> list:
    """Validate that required config fields are present. Returns list of errors."""
    errors = []
    if not config.get("product"):
        errors.append("Missing required field: product (set in hermes.yaml or via --product)")
    if not config.get("input"):
        errors.append("Missing required field: input (set in hermes.yaml or via --input)")
    return errors
