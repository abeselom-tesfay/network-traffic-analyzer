
"""Detect potentially suspicious patterns in network traffic."""

import pandas as pd


def detect_high_volume(
    data: pd.DataFrame,
    threshold: int = 100,
) -> list[dict]:
    """Identify source IPs exceeding a packet-count threshold."""
    if threshold < 1:
        raise ValueError("Threshold must be a positive integer.")

    packet_counts = data.groupby("source_ip").size()

    suspicious = packet_counts[packet_counts > threshold]

    return [
        {
            "source_ip": str(ip),
            "packet_count": int(count),
            "threshold": threshold,
            "alert_type": "HIGH_VOLUME",
        }
        for ip, count in suspicious.items()
    ]


def detect_port_scanning(
    data: pd.DataFrame,
    threshold: int = 10,
) -> list[dict]:
    """Identify source IPs contacting many distinct destination ports."""
    if threshold < 1:
        raise ValueError("Threshold must be a positive integer.")

    port_counts = (
        data.groupby("source_ip")["destination_port"]
        .nunique()
    )

    suspicious = port_counts[port_counts > threshold]

    return [
        {
            "source_ip": str(ip),
            "unique_destination_ports": int(count),
            "threshold": threshold,
            "alert_type": "POTENTIAL_PORT_SCAN",
        }
        for ip, count in suspicious.items()
    ]


def detect_suspicious_activity(
    data: pd.DataFrame,
    volume_threshold: int = 100,
    port_threshold: int = 10,
) -> list[dict]:
    """Run all supported suspicious traffic detection rules."""
    alerts = []

    alerts.extend(
        detect_high_volume(data, threshold=volume_threshold)
    )

    alerts.extend(
        detect_port_scanning(data, threshold=port_threshold)
    )

    return alerts
