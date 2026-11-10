
"""Load and analyze network traffic records from CSV files."""

from pathlib import Path
import ipaddress

import numpy as np
import pandas as pd


REQUIRED_COLUMNS = {
    "timestamp",
    "source_ip",
    "destination_ip",
    "protocol",
    "source_port",
    "destination_port",
    "packet_size",
}


def load_traffic(file_path: str | Path) -> pd.DataFrame:
    """Load a CSV file and validate its network traffic records."""
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"Traffic file not found: {path}")

    data = pd.read_csv(path)

    missing = REQUIRED_COLUMNS - set(data.columns)
    if missing:
        raise ValueError(
            f"Missing required columns: {', '.join(sorted(missing))}"
        )

    if data.empty:
        raise ValueError("The traffic file contains no records.")

    data["timestamp"] = pd.to_datetime(data["timestamp"], errors="raise")

    for column in ("source_ip", "destination_ip"):
        data[column] = data[column].map(
            lambda value: str(ipaddress.ip_address(value))
        )

    data["protocol"] = data["protocol"].astype(str).str.upper().str.strip()

    if data["protocol"].eq("").any():
        raise ValueError("Protocol values cannot be empty.")

    for column in ("source_port", "destination_port", "packet_size"):
        data[column] = pd.to_numeric(data[column], errors="raise")

        if data[column].isna().any():
            raise ValueError(f"Column {column} contains missing values.")

        if not np.isfinite(data[column].to_numpy(dtype=float)).all():
            raise ValueError(f"Column {column} contains non-finite values.")

        if (data[column] % 1 != 0).any():
            raise ValueError(f"Column {column} must contain integers.")

        if (data[column] < 0).any():
            raise ValueError(f"Column {column} cannot contain negatives.")

    for column in ("source_port", "destination_port"):
        if (data[column] > 65535).any():
            raise ValueError(f"Column {column} exceeds the valid port range.")

    data["packet_size"] = data["packet_size"].astype("int64")
    data["source_port"] = data["source_port"].astype("int64")
    data["destination_port"] = data["destination_port"].astype("int64")

    return data


def analyze_traffic(data: pd.DataFrame) -> dict:
    """Calculate descriptive network traffic statistics."""
    if data.empty:
        raise ValueError("Cannot analyze an empty dataset.")

    packet_sizes = data["packet_size"].to_numpy(dtype=np.int64)

    return {
        "total_packets": int(len(data)),
        "total_bytes": int(data["packet_size"].sum()),
        "average_packet_size": float(np.mean(packet_sizes)),
        "min_packet_size": int(np.min(packet_sizes)),
        "max_packet_size": int(np.max(packet_sizes)),
        "unique_source_ips": int(data["source_ip"].nunique()),
        "unique_destination_ips": int(data["destination_ip"].nunique()),
        "protocol_distribution": {
            str(key): int(value)
            for key, value in data["protocol"].value_counts().items()
        },
        "top_source_ips": {
            str(key): int(value)
            for key, value in data["source_ip"].value_counts().head(5).items()
        },
        "top_destination_ports": {
            str(key): int(value)
            for key, value in data["destination_port"]
            .value_counts()
            .head(5)
            .items()
        },
    }
