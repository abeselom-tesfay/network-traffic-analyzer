
"""Automated tests for network traffic anomaly detection."""

import pandas as pd
import pytest

from network_traffic_analyzer.detector import (
    detect_high_volume,
    detect_port_scanning,
    detect_suspicious_activity,
)


def test_high_volume_detection() -> None:
    """Detect a source exceeding the packet-count threshold."""
    data = pd.DataFrame(
        {
            "source_ip": ["192.168.1.10"] * 120
            + ["192.168.1.20"] * 5,
            "destination_port": [80] * 125,
        }
    )

    alerts = detect_high_volume(data, threshold=100)

    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "192.168.1.10"
    assert alerts[0]["packet_count"] == 120
    assert alerts[0]["alert_type"] == "HIGH_VOLUME"


def test_high_volume_threshold_boundary() -> None:
    """Exactly 100 packets must not trigger an alert."""
    data = pd.DataFrame(
        {
            "source_ip": ["192.168.1.10"] * 100,
            "destination_port": [80] * 100,
        }
    )

    assert detect_high_volume(data, threshold=100) == []


def test_port_scanning_detection() -> None:
    """Detect a source contacting many distinct destination ports."""
    data = pd.DataFrame(
        {
            "source_ip": ["192.168.1.20"] * 15,
            "destination_port": list(range(20, 35)),
        }
    )

    alerts = detect_port_scanning(data, threshold=10)

    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "192.168.1.20"
    assert alerts[0]["unique_destination_ports"] == 15
    assert alerts[0]["alert_type"] == "POTENTIAL_PORT_SCAN"


def test_port_scanning_threshold_boundary() -> None:
    """Exactly 10 distinct ports must not trigger an alert."""
    data = pd.DataFrame(
        {
            "source_ip": ["192.168.1.20"] * 10,
            "destination_port": list(range(20, 30)),
        }
    )

    assert detect_port_scanning(data, threshold=10) == []


def test_repeated_ports_are_counted_once() -> None:
    """Repeated connections to one port are not a port scan."""
    data = pd.DataFrame(
        {
            "source_ip": ["192.168.1.20"] * 20,
            "destination_port": [80] * 20,
        }
    )

    assert detect_port_scanning(data, threshold=10) == []


def test_combined_detection() -> None:
    """Both detection algorithms should produce their respective alerts."""
    data = pd.DataFrame(
        {
            "source_ip": ["192.168.1.10"] * 120
            + ["192.168.1.20"] * 15,
            "destination_port": [80] * 120
            + list(range(20, 35)),
        }
    )

    alerts = detect_suspicious_activity(
        data,
        volume_threshold=100,
        port_threshold=10,
    )

    assert len(alerts) == 2
    assert {alert["alert_type"] for alert in alerts} == {
        "HIGH_VOLUME",
        "POTENTIAL_PORT_SCAN",
    }


@pytest.mark.parametrize("threshold", [0, -1, -10])
def test_invalid_volume_threshold(threshold: int) -> None:
    """Reject zero and negative packet-count thresholds."""
    data = pd.DataFrame(
        {
            "source_ip": ["192.168.1.10"],
            "destination_port": [80],
        }
    )

    with pytest.raises(ValueError, match="positive integer"):
        detect_high_volume(data, threshold=threshold)


@pytest.mark.parametrize("threshold", [0, -1, -10])
def test_invalid_port_threshold(threshold: int) -> None:
    """Reject zero and negative destination-port thresholds."""
    data = pd.DataFrame(
        {
            "source_ip": ["192.168.1.10"],
            "destination_port": [80],
        }
    )

    with pytest.raises(ValueError, match="positive integer"):
        detect_port_scanning(data, threshold=threshold)
