
"""Automated tests for network traffic loading and analysis."""

import csv
from pathlib import Path

import pytest

from network_traffic_analyzer.analyzer import (
    analyze_traffic,
    load_traffic,
)


COLUMNS = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "protocol",
    "source_port",
    "destination_port",
    "packet_size",
]


def write_traffic_csv(path: Path, rows: list[list]) -> Path:
    """Create a temporary traffic CSV file for testing."""
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(COLUMNS)
        writer.writerows(rows)
    return path


def sample_row() -> list:
    """Return a valid network traffic record."""
    return [
        "2026-11-10 10:00:00",
        "192.168.1.10",
        "10.0.0.1",
        "TCP",
        50000,
        80,
        1024,
    ]


def test_load_valid_traffic(tmp_path: Path) -> None:
    """Valid traffic records should load correctly."""
    path = write_traffic_csv(tmp_path / "valid.csv", [sample_row()])

    data = load_traffic(path)

    assert len(data) == 1
    assert data.iloc[0]["source_ip"] == "192.168.1.10"
    assert data.iloc[0]["packet_size"] == 1024


def test_missing_file_raises_error(tmp_path: Path) -> None:
    """A nonexistent CSV file should raise FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        load_traffic(tmp_path / "missing.csv")


def test_empty_csv_raises_error(tmp_path: Path) -> None:
    """A CSV containing only headers should be rejected."""
    path = write_traffic_csv(tmp_path / "empty.csv", [])

    with pytest.raises(ValueError, match="no records"):
        load_traffic(path)


def test_missing_columns_raises_error(tmp_path: Path) -> None:
    """CSV files missing required columns should be rejected."""
    path = tmp_path / "missing_columns.csv"
    path.write_text("timestamp,source_ip\n2026-11-10,192.168.1.10\n")

    with pytest.raises(ValueError, match="Missing required columns"):
        load_traffic(path)


def test_invalid_ip_raises_error(tmp_path: Path) -> None:
    """Invalid IP addresses should be rejected."""
    row = sample_row()
    row[1] = "999.999.999.999"

    path = write_traffic_csv(tmp_path / "invalid_ip.csv", [row])

    with pytest.raises(ValueError):
        load_traffic(path)


def test_negative_packet_size_raises_error(tmp_path: Path) -> None:
    """Negative packet sizes should be rejected."""
    row = sample_row()
    row[6] = -100

    path = write_traffic_csv(tmp_path / "negative.csv", [row])

    with pytest.raises(ValueError, match="cannot contain negatives"):
        load_traffic(path)


def test_invalid_port_raises_error(tmp_path: Path) -> None:
    """Port numbers greater than 65535 should be rejected."""
    row = sample_row()
    row[5] = 70000

    path = write_traffic_csv(tmp_path / "invalid_port.csv", [row])

    with pytest.raises(ValueError, match="valid port range"):
        load_traffic(path)


def test_analyze_traffic_statistics(tmp_path: Path) -> None:
    """Traffic statistics should match the supplied records."""
    first = sample_row()

    second = [
        "2026-11-10 10:00:01",
        "192.168.1.20",
        "10.0.0.2",
        "UDP",
        51000,
        53,
        512,
    ]

    path = write_traffic_csv(tmp_path / "statistics.csv", [first, second])

    data = load_traffic(path)
    statistics = analyze_traffic(data)

    assert statistics["total_packets"] == 2
    assert statistics["total_bytes"] == 1536
    assert statistics["average_packet_size"] == 768.0
    assert statistics["min_packet_size"] == 512
    assert statistics["max_packet_size"] == 1024
    assert statistics["unique_source_ips"] == 2
    assert statistics["unique_destination_ips"] == 2
    assert statistics["protocol_distribution"] == {"TCP": 1, "UDP": 1}
