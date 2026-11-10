
"""Command-line interface for the Network Traffic Analyzer."""

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from network_traffic_analyzer.analyzer import (
    analyze_traffic,
    load_traffic,
)
from network_traffic_analyzer.detector import detect_suspicious_activity
from network_traffic_analyzer.reporter import export_csv, export_json


console = Console()


def create_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Analyze network traffic and detect suspicious patterns."
    )

    parser.add_argument(
        "input",
        type=Path,
        help="Path to the network traffic CSV file.",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports"),
        help="Directory for generated reports (default: reports).",
    )

    parser.add_argument(
        "--volume-threshold",
        type=int,
        default=100,
        help="Packet-count threshold for high-volume alerts.",
    )

    parser.add_argument(
        "--port-threshold",
        type=int,
        default=10,
        help="Distinct destination-port threshold for scan alerts.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0",
    )

    return parser


def display_statistics(statistics: dict) -> None:
    """Display network traffic statistics in a formatted table."""
    table = Table(title="Network Traffic Statistics")

    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    metrics = [
        ("Total packets", statistics["total_packets"]),
        ("Total bytes", statistics["total_bytes"]),
        ("Average packet size", f'{statistics["average_packet_size"]:.2f}'),
        ("Minimum packet size", statistics["min_packet_size"]),
        ("Maximum packet size", statistics["max_packet_size"]),
        ("Unique source IPs", statistics["unique_source_ips"]),
        ("Unique destination IPs", statistics["unique_destination_ips"]),
    ]

    for name, value in metrics:
        table.add_row(name, str(value))

    console.print(table)

    console.print("\n[bold]Protocol Distribution[/bold]")
    for protocol, count in statistics["protocol_distribution"].items():
        console.print(f"  {protocol}: {count}")


def main() -> int:
    """Run the network traffic analysis application."""
    parser = create_parser()
    args = parser.parse_args()

    if args.volume_threshold < 1 or args.port_threshold < 1:
        parser.error("Detection thresholds must be positive integers.")

    try:
        console.print("[bold blue]Network Traffic Analyzer[/bold blue]")

        data = load_traffic(args.input)
        statistics = analyze_traffic(data)

        alerts = detect_suspicious_activity(
            data,
            volume_threshold=args.volume_threshold,
            port_threshold=args.port_threshold,
        )

        display_statistics(statistics)

        console.print(
            f"\n[bold yellow]Suspicious activity alerts: "
            f"{len(alerts)}[/bold yellow]"
        )

        for alert in alerts:
            console.print(
                f"  [{alert['alert_type']}] {alert['source_ip']}"
            )

        json_path = export_json(
            statistics,
            alerts,
            args.output / "traffic_report.json",
        )

        csv_path = export_csv(
            alerts,
            args.output / "alerts.csv",
        )

        console.print("\n[bold green]Reports generated:[/bold green]")
        console.print(f"  JSON: {json_path}")
        console.print(f"  CSV:  {csv_path}")

        return 0

    except (FileNotFoundError, ValueError, OSError) as error:
        console.print(f"[bold red]Error:[/bold red] {error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
