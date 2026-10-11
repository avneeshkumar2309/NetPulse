"""
JSON and CSV export utilities for NetPulse scan results.
"""

import json
import csv
from typing import Any
from pathlib import Path


def export_to_json(scan_result: Any, filepath: str) -> str:
    """Export scan results as clean JSON."""
    data = scan_result.to_dict()
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return str(path.resolve())


def export_to_csv(scan_result: Any, filepath: str) -> str:
    """Export scan results into a flattened CSV format."""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)

    fields = [
        "ip",
        "hostname",
        "mac",
        "vendor",
        "os_guess",
        "host_risk_grade",
        "host_risk_score",
        "port",
        "protocol",
        "service",
        "port_state",
        "latency_ms",
        "risk_level",
        "banner",
        "recommendation"
    ]

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        for host in scan_result.hosts:
            if not host.open_ports:
                # Write row for host with no open ports
                writer.writerow({
                    "ip": host.ip,
                    "hostname": host.hostname or "",
                    "mac": host.mac or "",
                    "vendor": host.vendor or "",
                    "os_guess": host.os_guess or "",
                    "host_risk_grade": host.risk_grade,
                    "host_risk_score": host.risk_score,
                    "port": "",
                    "protocol": "",
                    "service": "",
                    "port_state": "none",
                    "latency_ms": "",
                    "risk_level": "Info",
                    "banner": "",
                    "recommendation": ""
                })
            else:
                for p in host.open_ports:
                    writer.writerow({
                        "ip": host.ip,
                        "hostname": host.hostname or "",
                        "mac": host.mac or "",
                        "vendor": host.vendor or "",
                        "os_guess": host.os_guess or "",
                        "host_risk_grade": host.risk_grade,
                        "host_risk_score": host.risk_score,
                        "port": p.port,
                        "protocol": p.protocol,
                        "service": p.service,
                        "port_state": p.state,
                        "latency_ms": f"{p.latency_ms:.1f}" if p.latency_ms is not None else "",
                        "risk_level": p.risk_level,
                        "banner": p.banner or "",
                        "recommendation": p.recommendation or ""
                    })

    return str(path.resolve())
