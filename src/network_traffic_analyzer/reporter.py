
"""Export network traffic analysis reports."""

import json
from pathlib import Path

import pandas as pd


def export_json(
    statistics: dict,
    alerts: list[dict],
    output_path: str | Path,
) -> Path:
    """Export traffic statistics and alerts as a JSON report."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "statistics": statistics,
        "alerts": alerts,
        "total_alerts": len(alerts),
    }

    with path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, allow_nan=False)

    return path


def export_csv(
    alerts: list[dict],
    output_path: str | Path,
) -> Path:
    """Export suspicious activity alerts as a CSV report."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    columns = [
        "source_ip",
        "alert_type",
        "packet_count",
        "unique_destination_ports",
        "threshold",
    ]

    data = pd.DataFrame(alerts).reindex(columns=columns)
    data.to_csv(path, index=False)

    return path
