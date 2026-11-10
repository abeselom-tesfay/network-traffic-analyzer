
# Network Traffic Analyzer

A Python command-line application for analyzing network traffic records, computing traffic statistics, detecting potentially suspicious activity, and exporting reports.

## Features

- Load and validate network traffic from CSV files.
- Compute packet counts, byte totals, packet-size statistics, and protocol distributions.
- Identify high-volume traffic from individual source IP addresses.
- Identify potential port scanning using distinct destination-port counts.
- Configure detection thresholds through command-line arguments.
- Export analysis results to JSON and CSV.
- Build distributable Python packages using Poetry.
- Run automated tests using pytest.

## Technology Stack

- Python 3.13
- Poetry for dependency management, versioning, and packaging
- pandas for tabular data processing
- NumPy for statistical calculations
- Rich for terminal output
- pytest for automated testing

## Project Structure

```text
network-traffic-analyzer/
├── data/
│   └── sample_traffic.csv
├── src/
│   └── network_traffic_analyzer/
│       ├── __init__.py
│       ├── analyzer.py
│       ├── detector.py
│       ├── reporter.py
│       └── cli.py
├── tests/
│   ├── __init__.py
│   ├── test_analyzer.py
│   └── test_detector.py
├── .gitignore
├── poetry.lock
├── pyproject.toml
└── README.md
```

## Prerequisites

Install Python 3.13 and Poetry 2.x.

Check the installed versions:

```bash
python --version
poetry --version
```

## Installation

Clone the repository:

```bash
git clone https://github.com/abeselom-tesfay/network-traffic-analyzer.git
cd network-traffic-analyzer
```

Install the project and its locked dependencies:

```bash
poetry install
```

Poetry creates or uses an isolated virtual environment and installs the application, its runtime dependencies, and its development dependencies.

## Running the Application

Analyze the included sample dataset:

```bash
poetry run network-traffic-analyzer data/sample_traffic.csv
```

Use custom detection thresholds and an output directory:

```bash
poetry run network-traffic-analyzer data/sample_traffic.csv --volume-threshold 100 --port-threshold 10 --output reports/custom
```

Display command-line help:

```bash
poetry run network-traffic-analyzer --help
```

Display the application version:

```bash
poetry run network-traffic-analyzer --version
```

## Input CSV Format

Input files must contain the following columns:

| Column | Description |
|---|---|
| timestamp | Packet timestamp |
| source_ip | Source IPv4 or IPv6 address |
| destination_ip | Destination IPv4 or IPv6 address |
| protocol | Network protocol |
| source_port | Source port number |
| destination_port | Destination port number |
| packet_size | Packet size in bytes |

Example:

```csv
timestamp,source_ip,destination_ip,protocol,source_port,destination_port,packet_size
2026-11-10 10:00:00,192.168.1.10,10.0.0.1,TCP,50000,80,1024
2026-11-10 10:00:01,192.168.1.20,10.0.0.2,UDP,51000,53,512
```

## Anomaly Detection

The application implements two configurable detection rules.

**High-volume traffic:** A source IP is flagged when its packet count exceeds the configured volume threshold.

**Potential port scanning:** A source IP is flagged when the number of distinct destination ports it contacts exceeds the configured port threshold.

Default thresholds:

- High-volume detection: more than 100 packets per source IP.
- Port-scanning detection: more than 10 distinct destination ports per source IP.

These are illustrative heuristic rules, not definitive evidence of malicious activity. The application does not perform live packet capture.

## Output Reports

The application generates:

- `reports/traffic_report.json`: Traffic statistics and detected alerts.
- `reports/alerts.csv`: Tabular alert records.

Use `--output` to change the destination directory.

Generated reports are excluded from Git.

## Automated Testing

Run the complete test suite:

```bash
poetry run pytest -q
```

Run detailed tests:

```bash
poetry run pytest -v
```

The test suite covers CSV loading and validation, traffic statistics, detection thresholds, port-scanning behavior, and invalid inputs.

## Build Automation and Packaging

Poetry manages project dependencies, package metadata, versions, and distribution builds.

Validate the project configuration:

```bash
poetry check
```

Build the application:

```bash
poetry build
```

The build generates two distribution formats:

```text
dist/
├── network_traffic_analyzer-0.1.0-py3-none-any.whl
└── network_traffic_analyzer-0.1.0.tar.gz
```

The wheel is an installable Python package, while the source distribution contains the source package.

Python source files are packaged rather than compiled into a native executable.

## Independent Wheel Installation

To test the built package outside Poetry's development environment, create a separate virtual environment.

On Windows with Python 3.13:

```bash
py -3.13 -m venv .venv-wheel-test
source .venv-wheel-test/Scripts/activate
```

Install the generated wheel:

```bash
python -m pip install dist/network_traffic_analyzer-0.1.0-py3-none-any.whl
```

Run the installed application:

```bash
network-traffic-analyzer data/sample_traffic.csv
```

Deactivate the environment:

```bash
deactivate
```

The independent wheel installation has been successfully verified on Windows with Python 3.13.

## Version Management

Poetry maintains the project version in `pyproject.toml`.

Display the current version:

```bash
poetry version
```

Increment the patch version when preparing a new release:

```bash
poetry version patch
```

Reinstall and rebuild after a version change:

```bash
poetry install
poetry build
```

The CLI obtains its version from installed package metadata, avoiding a hardcoded version number.

## Dependency Reproducibility

The project includes:

- `pyproject.toml`, defining package metadata and dependency constraints.
- `poetry.lock`, recording resolved dependencies for Poetry-managed installations.

Install the locked dependencies using:

```bash
poetry install
```

A separate `pip install` of the wheel resolves dependencies using the constraints embedded in the package metadata rather than the Poetry lockfile.

## Repository

https://github.com/abeselom-tesfay/network-traffic-analyzer
