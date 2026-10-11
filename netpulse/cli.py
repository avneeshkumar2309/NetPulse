"""
NetPulse Command Line Interface.
Provides subcommands: scan, watch, oui, and list-profiles.
"""

import asyncio
import sys
from pathlib import Path
import click

# Ensure UTF-8 output on Windows consoles if supported
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from .reporting.console import print_banner, print_scan_header, print_scan_summary, RICH_AVAILABLE
from .engine.hybrid import HybridScanner
from .engine.async_scanner import PORT_PROFILES
from .fingerprint.oui import lookup_mac_vendor
from .reporting.json_export import export_to_json, export_to_csv
from .reporting.topology_html import generate_topology_html
from .watcher.monitor import SubnetWatcher

if RICH_AVAILABLE:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    console = Console(safe_box=True)
else:
    console = None


@click.group()
@click.version_option("1.0.0", prog_name="NetPulse")
def main():
    """NetPulse - Next-Generation Intelligent Network Scanner & Security Analyzer."""
    pass


@main.command()
@click.argument("target")
@click.option("-p", "--ports", default="top-100", help="Ports to scan: 'top-20', 'top-100', 'web', 'databases', '1-1000', or '80,443' (default: top-100)")
@click.option("-t", "--timeout", default=1.0, type=float, help="Connection timeout in seconds (default: 1.0)")
@click.option("-c", "--concurrency", default=400, type=int, help="Max async socket concurrency (default: 400)")
@click.option("--raw/--no-raw", default=False, help="Prefer raw Scapy packet engine if elevated (default: auto)")
@click.option("-o", "--output", default=None, help="Export results to file (.json, .csv, or .html)")
@click.option("--html", is_flag=True, help="Automatically generate interactive HTML network topology report")
@click.option("--no-fingerprint", is_flag=True, help="Disable service banner and TLS fingerprinting")
@click.option("--no-risk", is_flag=True, help="Disable security risk assessment")
def scan(
    target: str,
    ports: str,
    timeout: float,
    concurrency: int,
    raw: bool,
    output: str,
    html: bool,
    no_fingerprint: bool,
    no_risk: bool
):
    """Scan a target IP, hostname, or CIDR network range (e.g., 192.168.1.1 or 192.168.1.0/24)."""
    print_banner()
    print_scan_header(target=target, ports_summary=ports, engine="Elevated Raw" if raw else "High-Speed Async Sockets")

    scanner = HybridScanner(
        timeout=timeout,
        max_concurrency=concurrency,
        prefer_raw=raw
    )

    async def run_scan():
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console
            ) as progress:
                task_id = progress.add_task("[cyan]Initiating scan...", total=100)

                def update_cb(desc: str, current: int, total: int):
                    progress.update(task_id, description=f"[cyan]{desc}", completed=current, total=max(total, 1))

                return await scanner.scan(
                    target=target,
                    ports=ports,
                    enrich_fingerprint=not no_fingerprint,
                    enrich_risk=not no_risk,
                    progress_callback=update_cb
                )
        else:
            return await scanner.scan(
                target=target,
                ports=ports,
                enrich_fingerprint=not no_fingerprint,
                enrich_risk=not no_risk
            )

    try:
        scan_result = asyncio.run(run_scan())
    except KeyboardInterrupt:
        if RICH_AVAILABLE:
            console.print("\n[bold red][!] Scan aborted by user.[/bold red]")
        else:
            print("\n[!] Scan aborted by user.")
        sys.exit(130)
    except Exception as e:
        if RICH_AVAILABLE:
            console.print(f"\n[bold red][!] Scan failed: {e}[/bold red]")
        else:
            print(f"\n[!] Scan failed: {e}")
        sys.exit(1)

    # Render terminal output
    print_scan_summary(scan_result)

    # Automatically generate HTML topology if --html flag passed or output ends with .html
    html_target_path = None
    if html:
        clean_target = target.replace("/", "_").replace(":", "_")
        html_target_path = f"netpulse_report_{clean_target}.html"

    if output:
        out_lower = output.lower()
        if out_lower.endswith(".json"):
            saved = export_to_json(scan_result, output)
            _print_exported("JSON", saved)
        elif out_lower.endswith(".csv"):
            saved = export_to_csv(scan_result, output)
            _print_exported("CSV", saved)
        elif out_lower.endswith(".html"):
            saved = generate_topology_html(scan_result, output)
            _print_exported("Interactive HTML Topology", saved)
        else:
            # Default to JSON
            saved = export_to_json(scan_result, output)
            _print_exported("JSON", saved)

    if html_target_path and not (output and output.lower().endswith(".html")):
        saved = generate_topology_html(scan_result, html_target_path)
        _print_exported("Interactive HTML Topology Map", saved)


def _print_exported(fmt: str, path: str):
    if RICH_AVAILABLE:
        console.print(f"\n[bold green][+][/bold green] [bold white]{fmt} report saved to:[/bold white] [cyan]{path}[/cyan]")
    else:
        print(f"\n[+] {fmt} report saved to: {path}")


@main.command()
@click.argument("subnet")
@click.option("-i", "--interval", default=15, type=int, help="Rescan interval in seconds (default: 15)")
def watch(subnet: str, interval: int):
    """Continuously monitor a subnet and alert when rogue devices join or MACs change."""
    print_banner()
    if RICH_AVAILABLE:
        console.print(f"[bold yellow][*] Starting Subnet Watcher on {subnet} (Interval: {interval}s)...[/bold yellow]")
        console.print("[dim]Press Ctrl+C to stop watching.[/dim]\n")
    else:
        print(f"[*] Starting Subnet Watcher on {subnet} (Interval: {interval}s)...")

    def alert_handler(event_type: str, msg: str, data: dict):
        if RICH_AVAILABLE:
            if event_type == "NEW_DEVICE_DETECTED":
                console.print(f"[bold red][ALERT] {msg}[/bold red]")
            elif event_type == "BASELINE_ESTABLISHED":
                console.print(f"[bold green][OK] {msg}[/bold green]")
            elif event_type == "IP_CHANGED":
                console.print(f"[bold yellow][WARN] {msg}[/bold yellow]")
            else:
                console.print(f"[*] {msg}")
        else:
            print(f"[{event_type}] {msg}")

    watcher = SubnetWatcher(subnet=subnet, interval=interval, alert_callback=alert_handler)

    try:
        asyncio.run(watcher.start())
    except KeyboardInterrupt:
        watcher.stop()
        if RICH_AVAILABLE:
            console.print("\n[bold cyan]Watcher stopped cleanly.[/bold cyan]")
        else:
            print("\nWatcher stopped.")


@main.command()
@click.argument("mac")
def oui(mac: str):
    """Look up hardware vendor from MAC address."""
    vendor = lookup_mac_vendor(mac)
    if RICH_AVAILABLE:
        console.print(f"\n[bold green]MAC Address:[/bold green] {mac}")
        console.print(f"[bold green]Manufacturer / Vendor:[/bold green] [bold yellow]{vendor or 'Unknown'}[/bold yellow]\n")
    else:
        print(f"MAC: {mac} -> Vendor: {vendor or 'Unknown'}")


@main.command(name="list-profiles")
def list_profiles():
    """List all pre-configured port profile presets."""
    if RICH_AVAILABLE:
        from rich.table import Table
        t = Table(title="NetPulse Port Profiles", header_style="bold cyan")
        t.add_column("Profile Name", style="bold green")
        t.add_column("Port Count", justify="right")
        t.add_column("Ports Preview", style="dim")

        for name, ports in PORT_PROFILES.items():
            preview = ", ".join(str(p) for p in ports[:12])
            if len(ports) > 12:
                preview += f"... (+{len(ports)-12} more)"
            t.add_row(name, str(len(ports)), preview)
        console.print()
        console.print(t)
    else:
        print("\nAvailable Port Profiles:")
        for name, ports in PORT_PROFILES.items():
            print(f"  - {name} ({len(ports)} ports)")


if __name__ == "__main__":
    main()
