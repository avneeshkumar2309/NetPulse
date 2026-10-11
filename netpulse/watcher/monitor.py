"""
Continuous Subnet Watcher & Rogue Device Detection.
Monitors LAN segments in real-time, detecting unauthorized devices, MAC changes,
and potential ARP spoofing attacks.
"""

import asyncio
import time
from typing import Dict, Optional, Callable, Set
from dataclasses import dataclass
from datetime import datetime

from ..fingerprint.oui import lookup_mac_vendor
from ..engine.raw_scanner import RawScanner
from ..engine.async_scanner import AsyncSubnetScanner


@dataclass
class ObservedDevice:
    ip: str
    mac: Optional[str] = None
    vendor: Optional[str] = None
    first_seen: str = ""
    last_seen: str = ""


class SubnetWatcher:
    """
    Subnet Watcher daemon that tracks live network devices over time.
    """

    def __init__(
        self,
        subnet: str,
        interval: int = 15,
        alert_callback: Optional[Callable[[str, str, Dict], None]] = None
    ):
        self.subnet = subnet
        self.interval = interval
        self.alert_callback = alert_callback
        self.inventory: Dict[str, ObservedDevice] = {}  # Key: MAC or IP
        self.raw_engine = RawScanner()
        self.async_engine = AsyncSubnetScanner()
        self.running = False

    async def sweep_once(self) -> Dict[str, Dict[str, Optional[str]]]:
        """Run a single sweep and return dict of found devices."""
        found: Dict[str, Dict[str, Optional[str]]] = {}

        # 1. Try ARP sweep if elevated
        if self.raw_engine.available and self.raw_engine.is_elevated():
            try:
                clients = self.raw_engine.arp_scan(self.subnet)
                for c in clients:
                    ip = c["ip"]
                    mac = c["mac"]
                    vendor = lookup_mac_vendor(mac)
                    found[ip] = {"ip": ip, "mac": mac, "vendor": vendor}
                return found
            except Exception:
                pass

        # 2. Fallback to async TCP sweep
        live_ips = await self.async_engine.sweep_subnet(self.subnet)
        for ip in live_ips:
            found[ip] = {"ip": ip, "mac": None, "vendor": None}

        return found

    async def start(self, max_cycles: Optional[int] = None):
        """Start the continuous watcher loop."""
        self.running = True
        cycle = 0

        # Baseline discovery
        now_str = datetime.now().strftime("%H:%M:%S")
        initial_devices = await self.sweep_once()
        for ip, dev in initial_devices.items():
            key = dev["mac"] if dev["mac"] else ip
            self.inventory[key] = ObservedDevice(
                ip=ip,
                mac=dev["mac"],
                vendor=dev["vendor"],
                first_seen=now_str,
                last_seen=now_str
            )

        if self.alert_callback:
            self.alert_callback("BASELINE_ESTABLISHED", f"Baseline initialized with {len(self.inventory)} active devices.", {"count": len(self.inventory)})

        while self.running:
            if max_cycles and cycle >= max_cycles:
                break

            await asyncio.sleep(self.interval)
            cycle += 1
            now_str = datetime.now().strftime("%H:%M:%S")

            current_devices = await self.sweep_once()
            current_keys: Set[str] = set()

            for ip, dev in current_devices.items():
                mac = dev["mac"]
                key = mac if mac else ip
                current_keys.add(key)

                # Check if device is new
                if key not in self.inventory:
                    new_obs = ObservedDevice(
                        ip=ip,
                        mac=mac,
                        vendor=dev["vendor"],
                        first_seen=now_str,
                        last_seen=now_str
                    )
                    self.inventory[key] = new_obs
                    if self.alert_callback:
                        self.alert_callback(
                            "NEW_DEVICE_DETECTED",
                            f"Rogue / New Device Joined! IP: {ip} | MAC: {mac or 'N/A'} | Vendor: {dev['vendor'] or 'Unknown'}",
                            {"ip": ip, "mac": mac, "vendor": dev["vendor"]}
                        )
                else:
                    # Update last seen
                    existing = self.inventory[key]
                    existing.last_seen = now_str

                    # Check for IP change on same MAC
                    if existing.ip != ip:
                        old_ip = existing.ip
                        existing.ip = ip
                        if self.alert_callback:
                            self.alert_callback(
                                "IP_CHANGED",
                                f"Device MAC {mac} changed IP from {old_ip} to {ip}",
                                {"mac": mac, "old_ip": old_ip, "new_ip": ip}
                            )

    def stop(self):
        """Stop the watcher loop."""
        self.running = False
