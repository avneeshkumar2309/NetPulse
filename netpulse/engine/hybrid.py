"""
Hybrid Scanner Coordinator: Bridges Async and Raw packet engines,
manages target orchestration, and glues scanning, fingerprinting, and risk analysis.
"""

import asyncio
import ipaddress
import socket
import time
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Callable, Any, Union

from .async_scanner import AsyncPortScanner, AsyncSubnetScanner, parse_ports
from .raw_scanner import RawScanner, SCAPY_AVAILABLE, RawEngineUnavailableError


@dataclass
class PortResult:
    port: int
    protocol: str = "tcp"
    state: str = "closed"
    service: str = "unknown"
    banner: Optional[str] = None
    latency_ms: Optional[float] = None
    risk_level: str = "Info"
    recommendation: Optional[str] = None


@dataclass
class HostResult:
    ip: str
    status: str = "up"
    mac: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    os_guess: Optional[str] = None
    ports: List[PortResult] = field(default_factory=list)
    risk_score: int = 100  # 0 to 100
    risk_grade: str = "A"  # A, B, C, D, F
    issues: List[Dict[str, str]] = field(default_factory=list)

    @property
    def open_ports(self) -> List[PortResult]:
        return [p for p in self.ports if p.state == "open"]


@dataclass
class ScanResult:
    target: str
    scan_type: str
    engine_used: str
    timestamp: str
    duration_seconds: float
    total_hosts_scanned: int
    hosts: List[HostResult] = field(default_factory=list)
    network_posture_score: int = 100
    network_posture_grade: str = "A"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class HybridScanner:
    """
    Intelligent scanner coordinating async and raw engines.
    """

    def __init__(
        self,
        timeout: float = 1.0,
        max_concurrency: int = 400,
        prefer_raw: bool = False
    ):
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self.prefer_raw = prefer_raw
        self.raw_engine = RawScanner(timeout=timeout)
        self.async_port_engine = AsyncPortScanner(timeout=timeout, max_concurrency=max_concurrency)
        self.async_subnet_engine = AsyncSubnetScanner(timeout=timeout, max_concurrency=max_concurrency)

    def determine_target_type(self, target: str) -> str:
        """Return 'ip', 'network', or 'hostname'."""
        target = target.strip()
        try:
            ipaddress.ip_address(target)
            return "ip"
        except ValueError:
            pass

        try:
            ipaddress.ip_network(target, strict=False)
            return "network"
        except ValueError:
            pass

        return "hostname"

    async def scan(
        self,
        target: str,
        ports: Union[str, List[int]] = "top-100",
        enrich_fingerprint: bool = True,
        enrich_risk: bool = True,
        progress_callback: Optional[Callable[[str, int, int], None]] = None
    ) -> ScanResult:
        """
        Orchestrate end-to-end scan of single target or subnet.
        """
        from ..fingerprint.oui import lookup_mac_vendor
        from ..fingerprint.discovery import resolve_host_identity
        from ..fingerprint.banners import inspect_service_banner
        from ..analyzer.posture import evaluate_host_security

        start_time = time.perf_counter()
        timestamp = datetime.now().isoformat()
        port_list = parse_ports(ports)
        target_type = self.determine_target_type(target)

        hosts_to_scan: List[Dict[str, Optional[str]]] = []
        engine_used = "async-sockets"

        # 1. Discover target hosts
        if target_type == "network":
            # Subnet scan: try ARP sweep if raw is preferred/available
            arp_success = False
            if self.prefer_raw and self.raw_engine.available and self.raw_engine.is_elevated():
                try:
                    if progress_callback:
                        progress_callback("Running Raw ARP Subnet Sweep...", 0, 100)
                    arp_clients = self.raw_engine.arp_scan(target)
                    hosts_to_scan = [{"ip": c["ip"], "mac": c["mac"]} for c in arp_clients]
                    engine_used = "raw-arp + async-ports"
                    arp_success = True
                except Exception:
                    arp_success = False

            if not arp_success:
                if progress_callback:
                    progress_callback("Sweeping Subnet via Async TCP Probes...", 0, 100)
                live_ips = await self.async_subnet_engine.sweep_subnet(
                    target,
                    progress_callback=lambda c, t: progress_callback(f"Sweeping Subnet ({c}/{t} IPs)", c, t) if progress_callback else None
                )
                hosts_to_scan = [{"ip": ip, "mac": None} for ip in live_ips]
                engine_used = "async-sweep + async-ports"

        elif target_type == "hostname":
            try:
                resolved_ip = socket.gethostbyname(target)
                hosts_to_scan = [{"ip": resolved_ip, "mac": None}]
            except socket.gaierror as e:
                raise ValueError(f"Could not resolve hostname {target}: {e}")
        else:
            # Single IP
            hosts_to_scan = [{"ip": target, "mac": None}]

        # 2. Port scan & fingerprint each host
        host_results: List[HostResult] = []
        total_hosts = len(hosts_to_scan)

        for idx, hinfo in enumerate(hosts_to_scan, 1):
            ip = hinfo["ip"]
            mac = hinfo.get("mac")

            if progress_callback:
                progress_callback(f"Scanning Host {ip} ({idx}/{total_hosts})", idx, total_hosts)

            # Perform async port scan
            raw_ports = await self.async_port_engine.scan_ports(
                ip,
                port_list,
                progress_callback=lambda c, t: progress_callback(f"Port Scan {ip} ({c}/{t})", c, t) if progress_callback else None
            )

            port_results: List[PortResult] = []
            for rp in raw_ports:
                if rp.state == "open":
                    # Deep banner grabbing if enabled
                    banner_info = rp.banner
                    if enrich_fingerprint:
                        banner_info = await inspect_service_banner(ip, rp.port, initial_banner=rp.banner)

                    port_results.append(PortResult(
                        port=rp.port,
                        protocol="tcp",
                        state=rp.state,
                        service=rp.service_guess,
                        banner=banner_info,
                        latency_ms=rp.latency_ms
                    ))

            # Host identity resolution
            hostname = None
            vendor = None
            os_guess = None

            if enrich_fingerprint:
                # OUI MAC lookup
                if mac:
                    vendor = lookup_mac_vendor(mac)
                
                # Active identity resolution (Reverse DNS, NetBIOS, mDNS)
                identity = await resolve_host_identity(ip)
                hostname = identity.get("hostname")
                if not vendor and identity.get("vendor"):
                    vendor = identity.get("vendor")
                os_guess = identity.get("os_guess")

            host_res = HostResult(
                ip=ip,
                mac=mac,
                vendor=vendor,
                hostname=hostname,
                os_guess=os_guess,
                ports=port_results
            )

            # Security risk evaluation
            if enrich_risk:
                evaluate_host_security(host_res)

            host_results.append(host_res)

        # 3. Aggregate network posture
        avg_score = 100
        if host_results:
            avg_score = int(sum(h.risk_score for h in host_results) / len(host_results))

        def score_to_grade(score: int) -> str:
            if score >= 90:
                return "A"
            if score >= 80:
                return "B"
            if score >= 70:
                return "C"
            if score >= 60:
                return "D"
            return "F"

        duration = round(time.perf_counter() - start_time, 2)

        return ScanResult(
            target=target,
            scan_type=f"TCP ({len(port_list)} ports)" if target_type != "network" else f"Subnet + Ports ({len(port_list)})",
            engine_used=engine_used,
            timestamp=timestamp,
            duration_seconds=duration,
            total_hosts_scanned=len(host_results),
            hosts=host_results,
            network_posture_score=avg_score,
            network_posture_grade=score_to_grade(avg_score)
        )
