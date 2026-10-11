"""
Console output and Rich TUI dashboard rendering for NetPulse.
"""

import sys
from typing import Any

# Ensure UTF-8 output on Windows consoles if supported
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    RICH_AVAILABLE = True
    console = Console(safe_box=True)
except ImportError:
    RICH_AVAILABLE = False
    console = None


def print_banner():
    """Display NetPulse ASCII banner."""
    banner_text = r"""
 _   _      _   ____        _             
| \ | | ___| |_|  _ \ _   _| |___  ___    
|  \| |/ _ \ __| |_) | | | | / __|/ _ \   
| |\  |  __/ |_|  __/| |_| | \__ \  __/   
|_| \_|\___|\__|_|    \__,_|_|___/\___|   
  Next-Gen Intelligent Network Scanner v1.0
"""
    if RICH_AVAILABLE:
        console.print(f"[bold cyan]{banner_text}[/bold cyan]")
    else:
        print(banner_text)


def print_scan_header(target: str, ports_summary: str, engine: str):
    """Print the initiation parameters of the scan."""
    if RICH_AVAILABLE:
        content = (
            f"[bold green]Target:[/bold green] {target}\n"
            f"[bold green]Ports:[/bold green] {ports_summary}\n"
            f"[bold green]Engine:[/bold green] {engine}"
        )
        console.print(Panel(content, title="[bold white]Scan Parameters[/bold white]", border_style="cyan"))
    else:
        print(f"[*] Target: {target} | Ports: {ports_summary} | Engine: {engine}")


def get_severity_style(severity: str) -> str:
    styles = {
        "Critical": "bold white on red",
        "High": "bold red",
        "Medium": "bold yellow",
        "Low": "cyan",
        "Info": "green"
    }
    return styles.get(severity, "white")


def print_scan_summary(scan_result: Any):
    """
    Render comprehensive, structured terminal results for a completed scan.
    """
    if not RICH_AVAILABLE:
        _print_plain_summary(scan_result)
        return

    # 1. Hosts Overview Table
    hosts_table = Table(title="[+] Discovered Hosts & Device Inventory", header_style="bold magenta")
    hosts_table.add_column("IP Address", style="bold cyan")
    hosts_table.add_column("Hostname", style="green")
    hosts_table.add_column("MAC / Hardware Vendor", style="yellow")
    hosts_table.add_column("OS Detection", style="blue")
    hosts_table.add_column("Open Ports", style="bold white")
    hosts_table.add_column("Risk Grade", justify="center")

    grade_colors = {"A": "[bold green]A (Safe)[/bold green]", "B": "[green]B (Good)[/green]", "C": "[yellow]C (Warn)[/yellow]", "D": "[red]D (Poor)[/red]", "F": "[bold red]F (Critical)[/bold red]"}

    for host in scan_result.hosts:
        vendor_display = host.vendor if host.vendor else ("Known MAC" if host.mac else "N/A")
        if host.mac:
            vendor_display = f"{host.mac}\n({vendor_display})"
        
        hostname_display = host.hostname if host.hostname else "-"
        os_display = host.os_guess if host.os_guess else "Unknown"
        open_ports_str = ", ".join(str(p.port) for p in host.open_ports) or "[dim]None[/dim]"
        grade_str = grade_colors.get(host.risk_grade, host.risk_grade)

        hosts_table.add_row(
            host.ip,
            hostname_display,
            vendor_display,
            os_display,
            open_ports_str,
            grade_str
        )

    console.print()
    console.print(hosts_table)

    # 2. Detailed Port & Service Table for Each Host
    for host in scan_result.hosts:
        if not host.open_ports:
            continue

        port_table = Table(title=f"[+] Service Details & Risk Analysis for {host.ip}", header_style="bold cyan")
        port_table.add_column("Port", justify="right", style="bold white")
        port_table.add_column("Service", style="green")
        port_table.add_column("Latency", justify="right", style="dim")
        port_table.add_column("Banner / Fingerprint", style="italic")
        port_table.add_column("Severity", justify="center")
        port_table.add_column("Remediation / Hardening", style="white")

        for p in host.open_ports:
            sev_badge = f"[{get_severity_style(p.risk_level)}] {p.risk_level.upper()} [/{get_severity_style(p.risk_level)}]"
            banner_display = p.banner if p.banner else "[dim]No banner[/dim]"
            latency_display = f"{p.latency_ms:.1f}ms" if p.latency_ms is not None else "-"
            rec_display = p.recommendation if p.recommendation else "-"

            port_table.add_row(
                str(p.port),
                p.service,
                latency_display,
                banner_display,
                sev_badge,
                rec_display
            )

        console.print()
        console.print(port_table)

    # 3. Overall Network Security Posture Panel
    score = scan_result.network_posture_score
    grade = scan_result.network_posture_grade
    summary_text = (
        f"[bold]Target:[/bold] {scan_result.target}\n"
        f"[bold]Total Live Hosts:[/bold] {len(scan_result.hosts)}\n"
        f"[bold]Elapsed Time:[/bold] {scan_result.duration_seconds}s\n"
        f"[bold]Engine:[/bold] {scan_result.engine_used}\n"
        f"[bold]Security Posture Score:[/bold] {score}/100 (Grade: {grade_colors.get(grade, grade)})"
    )

    border_color = "green" if grade in ["A", "B"] else ("yellow" if grade == "C" else "red")
    console.print()
    console.print(Panel(summary_text, title="[bold white][*] Network Audit Summary[/bold white]", border_style=border_color))


def _print_plain_summary(scan_result: Any):
    """Fallback plain text summary when Rich is not available."""
    print("\n" + "=" * 60)
    print(f"NETPULSE SCAN REPORT: {scan_result.target}")
    print(f"Hosts Scanned: {len(scan_result.hosts)} | Time: {scan_result.duration_seconds}s | Posture: Grade {scan_result.network_posture_grade}")
    print("=" * 60)

    for host in scan_result.hosts:
        print(f"\n[+] Host: {host.ip} | Hostname: {host.hostname or 'None'} | MAC: {host.mac or 'N/A'}")
        if host.vendor:
            print(f"    Vendor: {host.vendor}")
        if host.os_guess:
            print(f"    OS Guess: {host.os_guess}")
        print(f"    Security Score: {host.risk_score}/100 (Grade {host.risk_grade})")

        if host.open_ports:
            print("    Open Ports:")
            for p in host.open_ports:
                print(f"      - Port {p.port}/TCP ({p.service}) [{p.risk_level}] - {p.banner or 'No banner'}")
                if p.recommendation:
                    print(f"        Action: {p.recommendation}")
        else:
            print("    No open ports discovered in scanned range.")
