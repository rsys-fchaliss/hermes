# hermes

Utility scripts for managing and monitoring a **Media Resource Function (MRF)** node.

## Requirements

Python 3.8 or later.  No third-party packages are required — all modules rely
only on the Python standard library.

## Quick start

```bash
# Clone the repository and enter the project directory
git clone https://github.com/rsys-fchaliss/hermes.git
cd hermes
```

## Scripts overview

All scripts live under `scripts/mrf/` and can be run directly as modules
(`python -m scripts.mrf.<module>`) or imported as a library.

| Module | Description |
|---|---|
| `status` | Query the health and current state of an MRF node |
| `config` | Read and update MRF configuration via the management API |
| `monitor` | Poll and display real-time MRF metrics |
| `connectivity` | Probe TCP and API reachability of an MRF node |
| `utils` | Shared helpers: HTTP client, config I/O, logging setup |

## Usage

### Status check

```bash
python -m scripts.mrf.status --host 192.168.1.10 --port 8080
python -m scripts.mrf.status --host 192.168.1.10 --json
```

### Configuration management

```bash
# Show full configuration
python -m scripts.mrf.config --host 192.168.1.10 get

# Show a single key
python -m scripts.mrf.config --host 192.168.1.10 get --key max_sessions

# Update a key
python -m scripts.mrf.config --host 192.168.1.10 set --key max_sessions --value 200

# Reset to defaults
python -m scripts.mrf.config --host 192.168.1.10 reset
```

### Metrics monitoring

```bash
# Single snapshot
python -m scripts.mrf.monitor --host 192.168.1.10

# Poll every 5 seconds
python -m scripts.mrf.monitor --host 192.168.1.10 --interval 5

# Poll 10 times and emit JSON
python -m scripts.mrf.monitor --host 192.168.1.10 --interval 5 --count 10 --json
```

### Connectivity test

```bash
python -m scripts.mrf.connectivity --host 192.168.1.10 --port 8080
```

## Library usage

```python
from scripts.mrf import check_status, get_config, get_metrics, test_connectivity

# Check node health
status = check_status(host="192.168.1.10")
print(status["state"])

# Fetch config
cfg = get_config(host="192.168.1.10", key="max_sessions")

# Get metrics snapshot
metrics = get_metrics(host="192.168.1.10")

# Test reachability
result = test_connectivity(host="192.168.1.10")
print("Reachable:", result.success)
```

## Running tests

```bash
python -m pytest tests/ -v
```
